//! Conversions that go through plug-in modules: the conversion descriptor in glibc's layout (`struct __gconv_info` with one
//! `struct __gconv_step` and `struct __gconv_step_data` per step), the loading and initialising of the modules, the
//! driver `iconv` runs (glibc's `__gconv`) and the built-in steps that sit between the modules.
//!
//! A module's `gconv` function is the one glibc's skeleton generates: it converts into its step data's output buffer
//! (or, as the last step, the caller's buffer) and calls the next step's function itself. A run of built-in charset
//! conversion between or beside modules is therefore a step with a function of the same shape ([`builtin_fct`]) that
//! drives a [`Converter`] the way the skeleton drives a module's loops: convert into the buffer, hand the buffer to the
//! next step, and if the next step stopped early, redo the round from the saved state so that exactly the input that
//! produced the accepted output is used.
use crate::conv::{Converter, Error};
use crate::engine::St;
use crate::gconv_abi::{
    self as abi, EMPTY_INPUT, ENCOUNTERED_ILLEGAL_INPUT, FULL_OUTPUT, GconvFn, ILLEGAL_DESCRIPTOR,
    ILLEGAL_INPUT, INCOMPLETE_INPUT, InfoHead, OK, Step, StepData,
};
use crate::gconv_conf::{self, Name, Path, PathStep};
use crate::gconv_shlib::{self, LoadError};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::{null, null_mut};
use rusty_libc_core::errno;
use rusty_libc_core::ffi::{bytes, bytes_mut, out, slice_mut};

const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;
const EBADF: i32 = 9;
const E2BIG: i32 = 7;
const EILSEQ: i32 = 84;

/// What a built-in step holds in its `__data`.
struct Builtin {
    conv: Converter,
}

/// Why an open failed: the errno to report, or `Keep` when the module that failed has set it (glibc sets EINVAL only for
/// "no conversion" statuses and leaves errno alone for the others, which is how a module reports ENOMEM).
pub(crate) enum Failure {
    Errno(c_int),
    Keep,
}

/// glibc's status code for the status a built-in loop ended with (`Ok` is `__GCONV_OK`, which differs from
/// `__GCONV_EMPTY_INPUT` for the step before: it goes on and forgets an error of its own, as glibc's modules do).
fn status_code(st: St) -> c_int {
    match st {
        St::Ok => OK,
        St::Empty => EMPTY_INPUT,
        St::Full => FULL_OUTPUT,
        St::Illegal => ILLEGAL_INPUT,
        St::Incomplete => INCOMPLETE_INPUT,
    }
}

fn status_of(r: Result<usize, Error>) -> (c_int, usize) {
    match r {
        Ok(irr) => (EMPTY_INPUT, irr),
        Err(Error::Ilseq) => (ILLEGAL_INPUT, 0),
        Err(Error::Inval) => (INCOMPLETE_INPUT, 0),
        Err(Error::E2big) => (FULL_OUTPUT, 0),
    }
}

/// The next step of the chain.
struct Next {
    step: *mut Step,
    data: *mut StepData,
}

impl Next {
    /// Call the next step's function.
    ///
    /// # Safety
    /// This step is not the last, so the next step and its data exist, and `inptrp` is NULL or points to the input pointer.
    unsafe fn call(
        &self,
        inptrp: *mut *const u8,
        inend: *const u8,
        irreversible: *mut usize,
        do_flush: c_int,
        consume_incomplete: c_int,
    ) -> c_int {
        // SAFETY: the next step exists and is initialised (the caller's contract).
        let Some(f) = (unsafe { abi::step_fct(self.step) }) else {
            return ILLEGAL_DESCRIPTOR;
        };
        // SAFETY: the step function of a chain is called as glibc's skeleton calls it: its own step and data, the input
        // range (or NULLs when flushing), no error-handler output pointer.
        unsafe {
            f(
                self.step,
                self.data,
                inptrp,
                inend,
                null_mut(),
                irreversible,
                do_flush,
                consume_incomplete,
            )
        }
    }
}

/// The step function of a run of built-in conversion.
///
/// # Safety
/// Called as a `__gconv_fct`: `step` is a step made by [`open`] with its data, `data + 1` and `step + 1` exist unless the data
/// say this is the last step, and the pointers are NULL or valid as `gconv.h` describes them.
unsafe extern "C" fn builtin_fct(
    step: *mut Step,
    data: *mut StepData,
    inptrp: *mut *const u8,
    inend: *const u8,
    outbufstart: *mut *mut u8,
    irreversible: *mut usize,
    do_flush: c_int,
    consume_incomplete: c_int,
) -> c_int {
    let next = Next {
        step: step.wrapping_add(1),
        data: data.wrapping_add(1),
    };
    // SAFETY: `data` is this step's data (the caller's contract), used by this call alone.
    let d = unsafe { &mut *data };
    // SAFETY: `step` is this step (the caller's contract).
    let own = unsafe { (*step).data };
    // SAFETY: `__data` of a built-in step is the `Builtin` that `open` made; nothing else touches it during a call.
    let b = unsafe { &mut *own.cast::<Builtin>() };
    let last = d.flags & abi::IS_LAST != 0;
    let mut total = 0usize;
    let status = if do_flush != 0 {
        flush(
            b,
            d,
            &next,
            last,
            irreversible,
            do_flush,
            consume_incomplete,
            &mut total,
        )
    } else {
        // SAFETY: without a flush the caller passes the input pointer.
        let ip = unsafe { &mut *inptrp };
        // SAFETY: the input is the `inend - *ip` bytes at `*ip` (the caller's contract).
        let input = unsafe { bytes(*ip, inend as usize - *ip as usize) };
        let mut used = 0usize;
        let st = if !outbufstart.is_null() {
            error_handler_round(b, d, outbufstart, input, &mut used, &mut total)
        } else if last {
            last_round(b, d, input, &mut used, &mut total)
        } else {
            middle_rounds(
                b,
                d,
                &next,
                input,
                &mut used,
                irreversible,
                consume_incomplete,
                &mut total,
            )
        };
        *ip = ip.wrapping_add(used);
        st
    };
    // SAFETY: `irreversible` is NULL or the caller's counter.
    if let Some(count) = unsafe { out(irreversible) } {
        *count += total;
    }
    if b.conv.illegal_seen() {
        d.flags |= ENCOUNTERED_ILLEGAL_INPUT;
    }
    status
}

/// Convert once into the range `*outbufstart .. data.outbufend` (the caller is an error handler such as
/// `__gconv_transliterate` asking for a replacement to be written there).
fn error_handler_round(
    b: &mut Builtin,
    d: &StepData,
    outbufstart: *mut *mut u8,
    input: &[u8],
    used: &mut usize,
    total: &mut usize,
) -> c_int {
    // SAFETY: the handler passes the output position it wants written to.
    let at = unsafe { *outbufstart };
    // SAFETY: `at .. outbufend` is the handler's room for output.
    let room = unsafe { bytes_mut(at, d.outbufend as usize - at as usize) };
    let mut op = 0usize;
    let (st, irr) = b.conv.convert_status(input, used, room, &mut op);
    let st = status_code(st);
    *total += irr;
    // SAFETY: `outbufstart` is valid (checked by the caller); the new position is inside the room.
    unsafe { *outbufstart = at.wrapping_add(op) };
    st
}

/// The last step: convert into the caller's output buffer.
fn last_round(
    b: &mut Builtin,
    d: &mut StepData,
    input: &[u8],
    used: &mut usize,
    total: &mut usize,
) -> c_int {
    // SAFETY: `outbuf .. outbufend` is the caller's output room (set by the driver for the last step).
    let room = unsafe { bytes_mut(d.outbuf, d.outbufend as usize - d.outbuf as usize) };
    let mut op = 0usize;
    let (st, irr) = b.conv.convert_status(input, used, room, &mut op);
    let st = status_code(st);
    *total += irr;
    d.outbuf = d.outbuf.wrapping_add(op);
    d.invocation_counter += 1;
    st
}

/// A step with a next step: convert into this step's buffer, pass the buffer on, repeat while the buffer fills and the next
/// step takes all of it.
fn middle_rounds(
    b: &mut Builtin,
    d: &mut StepData,
    next: &Next,
    input: &[u8],
    used: &mut usize,
    irreversible: *mut usize,
    consume_incomplete: c_int,
    total: &mut usize,
) -> c_int {
    let base = d.outbuf;
    let cap = d.outbufend as usize - base as usize;
    loop {
        let saved = b.conv.clone();
        let start = *used;
        // SAFETY: `base .. base + cap` is this step's own buffer, written only through this slice.
        let room = unsafe { bytes_mut(base, cap) };
        let mut op = 0usize;
        let (st, irr) = b.conv.convert_status(input, used, room, &mut op);
        let mut st = status_code(st);
        *total += irr;
        d.invocation_counter += 1;
        if op > 0 {
            let produced_end = base.wrapping_add(op).cast_const();
            let mut consumed = base.cast_const();
            // SAFETY: this is not the last step; `consumed` and the end are the range just written.
            let result = unsafe {
                next.call(
                    &mut consumed,
                    produced_end,
                    irreversible,
                    0,
                    consume_incomplete,
                )
            };
            if result != EMPTY_INPUT {
                if consumed != produced_end {
                    // The next step stopped early: go back and convert again into just the room it used, which ends with
                    // exactly the input that made that output.
                    b.conv = saved;
                    *used = start;
                    let limit = consumed as usize - base as usize;
                    // SAFETY: as above, a prefix of the buffer.
                    let room = unsafe { bytes_mut(base, limit) };
                    let mut redo = 0usize;
                    let _ = b.conv.convert_raw(input, used, room, &mut redo);
                    if *used == start {
                        d.invocation_counter -= 1;
                    }
                }
                st = result;
            } else if st == FULL_OUTPUT {
                st = OK;
            }
        }
        if st != OK {
            return st;
        }
    }
}

/// `do_flush`: 1 writes the reset sequence and flushes the steps after this one, 2 only resets.
fn flush(
    b: &mut Builtin,
    d: &mut StepData,
    next: &Next,
    last: bool,
    irreversible: *mut usize,
    do_flush: c_int,
    consume_incomplete: c_int,
    total: &mut usize,
) -> c_int {
    if do_flush != 1 {
        let _ = b.conv.flush_raw(None);
        d.invocation_counter = 0;
        if last {
            return OK;
        }
        // SAFETY: not the last step; a flush passes NULL input.
        return unsafe {
            next.call(
                null_mut(),
                null(),
                irreversible,
                do_flush,
                consume_incomplete,
            )
        };
    }
    let base = d.outbuf;
    let saved = b.conv.clone();
    // SAFETY: `outbuf .. outbufend` is this step's room (the caller's output for the last step).
    let room = unsafe { bytes_mut(base, d.outbufend as usize - base as usize) };
    let mut op = 0usize;
    match b.conv.flush_raw(Some((room, &mut op))) {
        Ok(irr) => *total += irr,
        Err(e) => return status_of(Err(e)).0,
    }
    if last {
        d.outbuf = base.wrapping_add(op);
        return OK;
    }
    let mut status = OK;
    if op > 0 {
        let end = base.wrapping_add(op).cast_const();
        let mut consumed = base.cast_const();
        // SAFETY: not the last step; the range is what the reset just wrote.
        let result = unsafe { next.call(&mut consumed, end, irreversible, 0, consume_incomplete) };
        if result != EMPTY_INPUT {
            if consumed != end {
                b.conv = saved;
            }
            status = result;
        }
    }
    if status == OK {
        // SAFETY: not the last step; a flush passes NULL input.
        status = unsafe { next.call(null_mut(), null(), irreversible, 1, consume_incomplete) };
    }
    status
}

/// Every allocation of an open in progress, so a failure can give them back.
struct Pending {
    steps: *mut Step,
    count: usize,
    names: *mut u8,
}

/// Give back a step: the module's end function and the unloading, or the built-in step's data.
///
/// # Safety
/// `step` is a step made by [`open`] and is released once; it is not used afterwards.
unsafe fn release_step(step: *mut Step) {
    // SAFETY: `step` is valid (the caller's contract).
    let obj = unsafe { (*step).shlib_handle };
    if obj.is_null() {
        // SAFETY: `step` is valid (the caller's contract).
        let data = unsafe { (*step).data };
        // SAFETY: a built-in step's data is the malloc'ed `Builtin`, or NULL if the step was never set up.
        unsafe { rusty_libc_malloc::free(data) };
        return;
    }
    // SAFETY: `step` is valid (the caller's contract).
    let end_fct = unsafe { (*step).end_fct };
    let end = abi::demangle(end_fct);
    if end != 0 {
        // SAFETY: a non-NULL `gconv_end` of the module, called with the module's step as glibc does.
        let f = unsafe { core::mem::transmute::<usize, abi::EndFn>(end) };
        // SAFETY: the module is still loaded (this step counts as a user); its `gconv_init` ran on this step.
        unsafe { f(step) };
    }
    gconv_shlib::release(obj);
}

/// Release the steps from `from` up to the last, in ascending order (the order glibc's failure path uses).
///
/// # Safety
/// As [`release_step`], for each step in the range.
unsafe fn release_from(p: &Pending, from: usize) {
    for i in from..p.count {
        // SAFETY: the steps of the range were set up (the caller's contract).
        unsafe { release_step(p.steps.wrapping_add(i)) };
    }
}

/// Free what `open` allocated for the steps themselves.
///
/// # Safety
/// The steps are released and not used again.
unsafe fn free_steps(p: &Pending) {
    // SAFETY: `names` and `steps` were malloc'ed by `open`.
    unsafe { rusty_libc_malloc::free(p.names.cast()) };
    // SAFETY: as above.
    unsafe { rusty_libc_malloc::free(p.steps.cast()) };
}

fn upper_eq(a: *const c_char, b: &[u8]) -> bool {
    // SAFETY: step names are NUL-terminated strings made by `open`.
    unsafe { rusty_libc_core::ffi::cstr_bytes(a) }.eq_ignore_ascii_case(b)
}

/// The name a built-in `Converter` opens a node by: the canonical charset name with its slashes, or `INTERNAL`.
fn converter_name(node: &Name, suffix: &[u8]) -> Option<Name> {
    let cs = gconv_conf::builtin(node.as_bytes())?;
    // (`INTERNAL` itself is not a name `iconv_open` takes; its alias `WCHAR_T` is)
    let base = if matches!(cs, crate::names::Cs::Special(crate::names::SP_INTERNAL)) {
        Name::new(b"WCHAR_T//")?
    } else {
        gconv_conf::plain_name(cs)?
    };
    let mut buf = [0u8; gconv_conf::NAME_MAX];
    let n = base.as_bytes().len();
    let m = suffix.len();
    if n + m > buf.len() {
        return None;
    }
    buf[..n].copy_from_slice(base.as_bytes());
    buf[n..n + m].copy_from_slice(suffix);
    Name::new(&buf[..n + m])
}

/// Set up a built-in step.
///
/// # Safety
/// `step` is a zeroed step of a chain being opened.
unsafe fn init_builtin(
    step: *mut Step,
    ps: &PathStep,
    translit: bool,
    ignore: bool,
) -> Result<(), Failure> {
    let mut suffix = [0u8; 16];
    let mut n = 0;
    for (on, word) in [(translit, &b"TRANSLIT"[..]), (ignore, &b"IGNORE"[..])] {
        if on {
            if n > 0 {
                suffix[n] = b',';
                n += 1;
            }
            suffix[n..n + word.len()].copy_from_slice(word);
            n += word.len();
        }
    }
    let (Some(to), Some(from)) = (
        converter_name(&ps.to, &suffix[..n]),
        converter_name(&ps.from, b""),
    ) else {
        return Err(Failure::Errno(EINVAL));
    };
    let Ok(conv) = Converter::open(to.as_bytes(), from.as_bytes()) else {
        return Err(Failure::Errno(EINVAL));
    };
    // SAFETY: malloc may be called with any size; the result is checked below.
    let p = unsafe { rusty_libc_malloc::malloc(size_of::<Builtin>()) }.cast::<Builtin>();
    if p.is_null() {
        return Err(Failure::Errno(ENOMEM));
    }
    // SAFETY: `p` is a fresh allocation for a `Builtin`, aligned (malloc gives 16); writing does not drop old contents.
    unsafe { p.write(Builtin { conv }) };
    let from_internal = ps.from.as_bytes() == gconv_conf::INTERNAL;
    let to_internal = ps.to.as_bytes() == gconv_conf::INTERNAL;
    // SAFETY: `step` is the chain's step being set up.
    let s = unsafe { &mut *step };
    s.fct = builtin_fct as GconvFn as usize;
    s.min_needed_from = if from_internal { 4 } else { 1 };
    s.max_needed_from = if from_internal { 4 } else { 6 };
    s.min_needed_to = if to_internal { 4 } else { 1 };
    s.max_needed_to = if to_internal { 4 } else { 8 };
    s.data = p.cast();
    Ok(())
}

/// Get a module and run its `gconv_init` (the init call of glibc's `gen_steps`).
///
/// # Safety
/// `step` is a zeroed step of a chain being opened, with its names set.
unsafe fn init_module(step: *mut Step, path: &Name) -> Result<(), Failure> {
    let obj = match gconv_shlib::acquire(path.as_bytes()) {
        Ok(obj) => obj,
        Err(LoadError::NoModule) => return Err(Failure::Errno(EINVAL)),
        Err(LoadError::NoMemory) => return Err(Failure::Errno(ENOMEM)),
    };
    // SAFETY: `obj` is a loaded object that `acquire` counted this step as a user of.
    let o = unsafe { &*obj };
    // SAFETY: `step` is the chain's step being set up.
    let s = unsafe { &mut *step };
    s.shlib_handle = obj;
    s.modname = o.name;
    s.fct = o.fct;
    s.init_fct = o.init_fct;
    s.end_fct = o.end_fct;
    s.btowc_fct = 0;
    let init = abi::demangle(s.init_fct);
    if init != 0 {
        // SAFETY: a non-NULL `gconv_init` of the module.
        let f = unsafe { core::mem::transmute::<usize, abi::InitFn>(init) };
        // SAFETY: the module's init function is called with its step as glibc calls it.
        let status = unsafe { f(step) };
        if status != OK {
            // the end function must not run for a step whose init failed
            s.end_fct = abi::mangle(0);
            return Err(if status == abi::NOCONV || status == abi::NODB {
                Failure::Errno(EINVAL)
            } else {
                Failure::Keep
            });
        }
    }
    s.btowc_fct = abi::mangle(s.btowc_fct);
    Ok(())
}

/// The steps and the step data of a descriptor of [`open`] as slices.
struct View<'a> {
    steps: &'a mut [Step],
    data: &'a mut [StepData],
}

/// The descriptor `cd` as slices.
///
/// # Safety
/// `cd` came from [`open`], is not closed during `'a` and is not accessed in any other way during `'a`.
unsafe fn view<'a>(cd: *mut c_void) -> View<'a> {
    let head = cd.cast::<InfoHead>();
    // SAFETY: `cd` is a descriptor made by `open` (the caller's contract).
    let n = unsafe { (*head).nsteps };
    // SAFETY: as above.
    let steps = unsafe { (*head).steps };
    // SAFETY: the `n` steps were allocated by `open` and are not accessed otherwise during `'a`.
    let steps = unsafe { slice_mut(steps, n) };
    // SAFETY: the `n` step data follow the head in the same allocation.
    let data = unsafe { slice_mut(head.wrapping_add(1).cast::<StepData>(), n) };
    View { steps, data }
}

/// Give back the allocations of an open that failed after its steps were set up.
///
/// # Safety
/// `pending`'s steps are all set up and nothing refers to them.
unsafe fn abandon(pending: &Pending) {
    let saved = errno::get();
    // SAFETY: the steps are set up (the caller's contract).
    unsafe { release_from(pending, 0) };
    // SAFETY: nothing refers to the steps any more.
    unsafe { free_steps(pending) };
    errno::set(saved);
}

/// `__gconv_open` for a path through modules: the descriptor, or why not.
pub(crate) fn open(path: &Path, translit: bool, ignore: bool) -> Result<*mut c_void, Failure> {
    let n = path.len;
    // SAFETY: calloc may be called with any sizes; the result is checked below.
    let steps = unsafe { rusty_libc_malloc::calloc(n, size_of::<Step>()) }.cast::<Step>();
    let name_bytes: usize = path.steps[..n].iter().map(|s| s.from.as_bytes().len() + 1).sum::<usize>() + path.steps[n - 1].to.as_bytes().len() + 1;
    // SAFETY: as above.
    let names = unsafe { rusty_libc_malloc::calloc(1, name_bytes) }.cast::<u8>();
    let pending = Pending { steps, count: n, names };
    if steps.is_null() || names.is_null() {
        // SAFETY: both are NULL or fresh allocations that nothing else refers to.
        unsafe { free_steps(&pending) };
        return Err(Failure::Errno(ENOMEM));
    }
    // The names: step i reads `from[i]` and writes `from[i + 1]`; the last writes `to`. They share one block.
    // SAFETY: `names` is a zeroed block of `name_bytes` bytes that only this function touches until it is stored in a step.
    let block = unsafe { bytes_mut(names, name_bytes) };
    let mut at = 0;
    let mut starts = [0usize; gconv_conf::MAX_STEPS + 1];
    for (i, start) in starts[..=n].iter_mut().enumerate() {
        let name = if i < n { &path.steps[i].from } else { &path.steps[n - 1].to };
        let b = name.as_bytes();
        block[at..at + b.len()].copy_from_slice(b);
        *start = at;
        at += b.len() + 1;
    }
    // SAFETY: `steps` holds `n` zeroed steps (all-zero is a valid `Step`) that nothing else refers to.
    let step_mem = unsafe { slice_mut(steps, n) };
    for (i, s) in step_mem.iter_mut().enumerate() {
        s.counter = 1;
        s.from_name = names.wrapping_add(starts[i]).cast::<c_char>();
        s.to_name = names.wrapping_add(starts[i + 1]).cast::<c_char>();
    }
    // Set the steps up from the last to the first, as glibc does.
    for i in (0..n).rev() {
        let ps = &path.steps[i];
        let step: *mut Step = &raw mut step_mem[i];
        let r = match &ps.module {
            // SAFETY: the step is zeroed apart from its names.
            Some(module) => unsafe { init_module(step, module) },
            // SAFETY: as above.
            None => unsafe { init_builtin(step, ps, translit, ignore) },
        };
        if let Err(fail) = r {
            // A step whose init failed is released too (its module is unloaded, `gconv_end` is not called); one that
            // did not load is not.
            let from = if step_mem[i].shlib_handle.is_null() { i + 1 } else { i };
            let saved = errno::get();
            // SAFETY: the steps from `from` on are set up (the failed module loaded, without an end function).
            unsafe { release_from(&pending, from) };
            // SAFETY: nothing refers to the steps any more.
            unsafe { free_steps(&pending) };
            errno::set(saved);
            return Err(fail);
        }
    }
    // The descriptor: the info head and one step data per step.
    // SAFETY: calloc may be called with any sizes; the result is checked below.
    let cd = unsafe { rusty_libc_malloc::calloc(1, size_of::<InfoHead>() + n * size_of::<StepData>()) }.cast::<InfoHead>();
    if cd.is_null() {
        // SAFETY: all steps are set up and not shared yet.
        unsafe { abandon(&pending) };
        return Err(Failure::Errno(ENOMEM));
    }
    // SAFETY: `cd` is a zeroed allocation of the head and `n` step data.
    unsafe { *cd = InfoHead { nsteps: n, steps } };
    // SAFETY: the `n` step data follow the head in the same allocation, zeroed (all-zero is a valid `StepData`).
    let data_mem = unsafe { slice_mut(cd.wrapping_add(1).cast::<StepData>(), n) };
    let mut flags = if ignore { abi::IGNORE_ERRORS } else { 0 };
    #[allow(clippy::needless_range_loop)]
    for i in 0..n {
        let s = &step_mem[i];
        let d = &mut data_mem[i];
        d.statep = (&raw mut d.state).cast();
        if translit && upper_eq(s.from_name, b"INTERNAL") {
            flags |= abi::TRANSLIT;
        }
        if i + 1 == n {
            d.flags = flags | abi::IS_LAST;
            break;
        }
        d.flags = flags;
        let size = abi::NCHAR_GOAL * usize::try_from(s.max_needed_to).unwrap_or(1).max(1);
        // SAFETY: malloc may be called with any size; the result is checked below.
        let buf = unsafe { rusty_libc_malloc::malloc(size) }.cast::<u8>();
        if buf.is_null() {
            for earlier in &data_mem[..i] {
                // SAFETY: the buffer of a step before this one was malloc'ed above.
                unsafe { rusty_libc_malloc::free(earlier.outbuf.cast()) };
            }
            // SAFETY: nothing else refers to the descriptor yet.
            unsafe { rusty_libc_malloc::free(cd.cast()) };
            // SAFETY: all steps are set up and not shared.
            unsafe { abandon(&pending) };
            return Err(Failure::Errno(ENOMEM));
        }
        d.outbuf = buf;
        d.outbufend = buf.wrapping_add(size);
    }
    Ok(cd.cast())
}

/// `iconv_close` for a descriptor of [`open`] (`__gconv_close`).
///
/// # Safety
/// `cd` came from [`open`] and is not used again.
pub(crate) unsafe fn close(cd: *mut c_void) {
    // SAFETY: `cd` is a descriptor of `open` that is closed here (the caller's contract).
    let v = unsafe { view(cd) };
    for d in v.data.iter().filter(|d| d.flags & abi::IS_LAST == 0) {
        // SAFETY: the buffer of a step that is not last was malloc'ed by `open`.
        unsafe { rusty_libc_malloc::free(d.outbuf.cast()) };
    }
    let (steps, names) = (v.steps.as_mut_ptr(), v.steps[0].from_name);
    let count = v.steps.len();
    // SAFETY: the descriptor is not used again.
    unsafe { rusty_libc_malloc::free(cd) };
    for i in (0..count).rev() {
        // SAFETY: each step was set up by `open` and is released once.
        unsafe { release_step(steps.wrapping_add(i)) };
    }
    // SAFETY: the name block starts at the first step's `from_name`; it and the steps were malloc'ed by `open` and nothing
    // refers to them now.
    unsafe { rusty_libc_malloc::free(names.cast()) };
    // SAFETY: as above.
    unsafe { rusty_libc_malloc::free(steps.cast()) };
}

/// The value a caller's pointer to a pointer points to, or `none` if the outer pointer is NULL.
///
/// # Safety
/// `pp` is NULL or points to a readable pointer.
unsafe fn load<P: Copy>(pp: *const P, none: P) -> P {
    // SAFETY: NULL or a readable pointer (the caller's contract).
    unsafe { pp.as_ref() }.copied().unwrap_or(none)
}

/// glibc's `__gconv`: run the chain over `[*inbuf, inend)`, or flush when `inbuf` is NULL.
///
/// # Safety
/// `cd` came from [`open`]; the pointers are NULL or valid as in `iconv`.
unsafe fn gconv(cd: *mut c_void, inbuf: *mut *const u8, inend: *const u8, outbuf: *mut *mut u8, outend: *mut u8, irreversible: &mut usize) -> c_int {
    // SAFETY: `cd` is a live descriptor (the caller's contract) used by this call alone.
    let v = unsafe { view(cd) };
    let n = v.steps.len();
    *irreversible = 0;
    // SAFETY: `outbuf` is NULL or points to the caller's output pointer.
    v.data[n - 1].outbuf = unsafe { load(outbuf, null_mut()) };
    v.data[n - 1].outbufend = outend;
    // SAFETY: `inbuf` is NULL or points to the caller's input pointer.
    let flushing = unsafe { load(inbuf, null()) }.is_null();
    let steps = v.steps.as_mut_ptr();
    let data = v.data.as_mut_ptr();
    // SAFETY: the first step is set up.
    let Some(f) = (unsafe { abi::step_fct(steps) }) else { return ILLEGAL_DESCRIPTOR };
    let result = if flushing {
        let mode = if v.data[n - 1].outbuf.is_null() { 2 } else { 1 };
        // SAFETY: a flush call as glibc makes it: NULL input and output position.
        let r = unsafe { f(steps, data, null_mut(), null(), null_mut(), irreversible, mode, 0) };
        if r == OK {
            v.data.iter_mut().for_each(|d| d.invocation_counter = 0);
        }
        r
    } else {
        let min_from = usize::try_from(v.steps[0].min_needed_from).unwrap_or(1);
        loop {
            // SAFETY: `inbuf` is non-NULL here.
            let before = unsafe { load(inbuf, null()) };
            // SAFETY: the call is the driver's call of the first step: the whole chain, the input range, no handler.
            let r = unsafe { f(steps, data, inbuf, inend, null_mut(), irreversible, 0, 0) };
            // SAFETY: as above.
            let after = unsafe { load(inbuf, null()) };
            if !(r == EMPTY_INPUT && before != after && after.wrapping_add(min_from) <= inend) {
                break r;
            }
        }
    };
    if !outbuf.is_null() {
        // SAFETY: `outbuf` points to the caller's output pointer.
        if let Some(p) = unsafe { out(outbuf) }
            && !p.is_null()
        {
            *p = v.data[n - 1].outbuf;
        }
    }
    result
}

/// How far a caller's pointer has moved since `start`, taken off the room it has left.
///
/// # Safety
/// `pp` points to the caller's pointer, `left` to its count.
unsafe fn account(pp: *const *mut c_char, start: *mut c_char, left: *mut usize) {
    // SAFETY: `pp` is valid (the caller's contract).
    let moved = unsafe { load(pp, null_mut()) } as usize - start as usize;
    // SAFETY: `left` is valid (the caller's contract).
    if let Some(count) = unsafe { out(left) } {
        *count -= moved;
    }
}

/// `iconv` on a descriptor of [`open`] (glibc's iconv/iconv.c).
///
/// # Safety
/// `cd` came from [`open`]; the pointers are as `iconv` documents.
pub(crate) unsafe fn convert(cd: *mut c_void, inbuf: *mut *mut c_char, inbytesleft: *mut usize, outbuf: *mut *mut c_char, outbytesleft: *mut usize) -> usize {
    // SAFETY: `outbuf` is NULL or points to the caller's output pointer.
    let outstart = unsafe { load(outbuf, null_mut()) }.cast::<u8>();
    // SAFETY: `inbuf` is NULL or points to the caller's input pointer.
    let instart = unsafe { load(inbuf, null_mut()) };
    // SAFETY: `outbytesleft` is given with an output buffer.
    let room = if outstart.is_null() { 0 } else { unsafe { outbytesleft.read() } };
    let outend = outstart.wrapping_add(room);
    let mut irreversible = 0usize;
    let result = if instart.is_null() {
        // a flush or a reset
        // SAFETY: the buffers are the caller's, or NULL for a reset.
        unsafe { gconv(cd, null_mut(), null(), outbuf.cast(), outend, &mut irreversible) }
    } else if outstart.is_null() {
        // glibc reads through the NULL output pointer here; report a full output instead
        FULL_OUTPUT
    } else {
        // SAFETY: with an input buffer, `inbytesleft` is its length.
        let len = unsafe { inbytesleft.read() };
        let inend = instart.wrapping_add(len).cast_const().cast::<u8>();
        // SAFETY: the caller's buffers, as `iconv` documents.
        let r = unsafe { gconv(cd, inbuf.cast(), inend, outbuf.cast(), outend, &mut irreversible) };
        // SAFETY: `inbuf` and `inbytesleft` are valid with an input buffer.
        unsafe { account(inbuf, instart, inbytesleft) };
        r
    };
    if !outstart.is_null() {
        // SAFETY: `outbuf` and `outbytesleft` are valid with an output buffer.
        unsafe { account(outbuf, outstart.cast(), outbytesleft) };
    }
    let failed = |e: i32| {
        errno::set(e);
        usize::MAX
    };
    match result {
        ILLEGAL_DESCRIPTOR => failed(EBADF),
        ILLEGAL_INPUT => failed(EILSEQ),
        FULL_OUTPUT => failed(E2BIG),
        INCOMPLETE_INPUT => failed(EINVAL),
        _ => irreversible,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(n: Option<Name>) -> Option<String> {
        n.map(|n| String::from_utf8(n.as_bytes().to_vec()).unwrap())
    }

    #[test]
    fn built_in_nodes_open_as_converters() {
        for (node, want) in [(&b"ISO-10646/UTF8/"[..], "UTF-8//"), (b"INTERNAL", "WCHAR_T//"), (b"ISO-8859-1//", "ISO-8859-1//")] {
            let node = Name::new(node).unwrap();
            assert_eq!(text(converter_name(&node, b"")).as_deref(), Some(want));
        }
        assert!(converter_name(&Name::new(b"MYCS//").unwrap(), b"").is_none());
        let node = Name::new(b"ISO-10646/UTF8/").unwrap();
        assert_eq!(text(converter_name(&node, b"TRANSLIT,IGNORE")).as_deref(), Some("UTF-8//TRANSLIT,IGNORE"));
        assert!(Converter::open(b"UTF-8//", b"WCHAR_T//").is_ok());
        assert!(Converter::open(b"UTF-8//TRANSLIT,IGNORE", b"WCHAR_T//").is_ok());
    }
}
