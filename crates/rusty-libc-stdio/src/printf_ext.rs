//! printf.h: user-defined conversions for the printf family: `register_printf_specifier`,
//! `register_printf_function`, `register_printf_modifier`, `register_printf_type`,
//! `parse_printf_format`, `printf_size` and `printf_size_info`.
//!
//! The registry is three tables like glibc's: handler and arginfo function per conversion character
//! (0..=255), user argument types (numbers from `PA_LAST` up, each with a function that takes the
//! argument from the `va_list`) and user modifiers (strings that set a bit in `printf_info.user`).
//! While nothing is registered the printf engine is untouched: it looks at one flag per call. Once something is
//! registered every narrow printf call takes the path in [`format_ext`], which follows glibc's
//! `printf_positional`: the whole format is parsed first (calling the arginfo functions), all arguments are
//! read from the argument list by type, then each conversion is handled in order: by the registered function
//! (output written to a temporary stream, whose bytes are inserted; a return of -2 means "not mine" and the
//! built-in conversion runs), or by the built-in code. The built-ins are run by the ordinary engine on a
//! rebuilt one-conversion format with the arguments already read, so their output is the engine's.
//!
//! The wide printf functions (`swprintf`, `fwprintf`, `wprintf` and the `v` forms) call the handlers too: the
//! format is parsed as wide characters, the handler gets a wide-oriented stream (glibc: it has to write with
//! `fwprintf`, `fputwc`), `printf_info.wide` is 1. Structure follows glibc 2.43 stdio-common/printf-parsemb.c, reg-printf.c, reg-modifier.c,
//! reg-type.c, printf-prs.c, printf_size.c and the positional part of vfprintf-internal.c (read as
//! reference; code written in Rust).
#![allow(clippy::deref_addrof, clippy::manual_range_contains, clippy::needless_late_init)]
use crate::file::File;
use crate::fmt::{self, Args, FmtChar, Kind, Sink, Val};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use rusty_libc_core::errno;
use rusty_libc_core::sync_cell::SyncCell;

pub const PA_INT: c_int = 0;
pub const PA_CHAR: c_int = 1;
pub const PA_WCHAR: c_int = 2;
pub const PA_STRING: c_int = 3;
pub const PA_WSTRING: c_int = 4;
pub const PA_POINTER: c_int = 5;
pub const PA_FLOAT: c_int = 6;
pub const PA_DOUBLE: c_int = 7;
pub const PA_LAST: c_int = 8;
pub const PA_FLAG_MASK: c_int = 0xff00;
pub const PA_FLAG_LONG_LONG: c_int = 1 << 8;
pub const PA_FLAG_LONG_DOUBLE: c_int = PA_FLAG_LONG_LONG;
pub const PA_FLAG_LONG: c_int = 1 << 9;
pub const PA_FLAG_SHORT: c_int = 1 << 10;
pub const PA_FLAG_PTR: c_int = 1 << 11;

/// `struct printf_info` (20 bytes): what a handler is told about the conversion.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrintfInfo {
    pub prec: c_int,
    pub width: c_int,
    pub spec: i32,
    /// is_long_double:1 is_short:1 is_long:1 alt:1 space:1 left:1 showsign:1 group:1 extra:1 is_char:1 wide:1
    /// i18n:1 is_binary128:1 (bit 0 first), then 3 unused bits.
    pub flags: u16,
    pub user: u16,
    pub pad: i32,
}
const _: () = assert!(size_of::<PrintfInfo>() == 20);

pub const INFO_LONG_DOUBLE: u16 = 1 << 0;
pub const INFO_SHORT: u16 = 1 << 1;
pub const INFO_LONG: u16 = 1 << 2;
pub const INFO_ALT: u16 = 1 << 3;
pub const INFO_SPACE: u16 = 1 << 4;
pub const INFO_LEFT: u16 = 1 << 5;
pub const INFO_SHOWSIGN: u16 = 1 << 6;
pub const INFO_GROUP: u16 = 1 << 7;
pub const INFO_EXTRA: u16 = 1 << 8;
pub const INFO_CHAR: u16 = 1 << 9;
pub const INFO_WIDE: u16 = 1 << 10;
pub const INFO_I18N: u16 = 1 << 11;
pub const INFO_BINARY128: u16 = 1 << 12;

impl PrintfInfo {
    fn has(&self, bit: u16) -> bool {
        self.flags & bit != 0
    }
    fn set(&mut self, bit: u16) {
        self.flags |= bit;
    }
    const fn zero() -> PrintfInfo {
        PrintfInfo { prec: -1, width: 0, spec: 0, flags: 0, user: 0, pad: b' ' as i32 }
    }
}

pub type PrintfFunction = unsafe extern "C" fn(*mut File, *const PrintfInfo, *const *const c_void) -> c_int;
pub type ArginfoSizeFunction = unsafe extern "C" fn(*const PrintfInfo, usize, *mut c_int, *mut c_int) -> c_int;
pub type ArginfoFunction = unsafe extern "C" fn(*const PrintfInfo, usize, *mut c_int) -> c_int;
pub type VaArgFunction = unsafe extern "C" fn(*mut c_void, *mut c_void);

// ---------------------------------------------------------------------------------------- registry

/// Non-zero once anything is registered: the only thing the fast path looks at.
static ACTIVE: AtomicU8 = AtomicU8::new(0);
static LOCK: AtomicU32 = AtomicU32::new(0);

// The registry tables (heap arrays, allocated on first registration) and counters. Written only with `LOCK` held; the printf
// calls read them without the lock once `ACTIVE` is set (its Release store follows the writes), as glibc reads its tables:
// programs register their conversions before other threads print.
static FUNC_TABLE: SyncCell<*mut Option<PrintfFunction>> = SyncCell::new(null_mut());
static ARGINFO_TABLE: SyncCell<*mut Option<ArginfoSizeFunction>> = SyncCell::new(null_mut());
static VAARG_TABLE: SyncCell<*mut Option<VaArgFunction>> = SyncCell::new(null_mut());
static MOD_TABLE: SyncCell<*mut *mut ModRecord> = SyncCell::new(null_mut());
static NEXT_BIT: SyncCell<c_int> = SyncCell::new(0);
static NEXT_TYPE: SyncCell<c_int> = SyncCell::new(PA_LAST);

/// A registry value, read under the rule above (a registering thread holds `LOCK`; printf calls read after `ACTIVE`).
#[inline(always)]
fn get<T: Copy>(c: &SyncCell<T>) -> T {
    // SAFETY: the registry rule (see the tables): writes happen under `LOCK` before `ACTIVE` publishes them.
    unsafe { c.read() }
}

/// A registry write.
///
/// # Safety
/// The caller holds `LOCK`.
#[inline(always)]
unsafe fn put<T: Copy>(c: &SyncCell<T>, v: T) {
    // SAFETY: the caller's promise.
    unsafe { c.write(v) }
}

/// Entry `i` of a registry table (null table: `None`).
///
/// # Safety
/// `t` is null or a table of at least `i + 1` entries.
#[inline(always)]
unsafe fn entry<T: Copy>(t: *mut Option<T>, i: usize) -> Option<T> {
    if t.is_null() {
        return None;
    }
    // SAFETY: the caller's promise.
    unsafe { *t.wrapping_add(i) }
}

struct ModRecord {
    next: *mut ModRecord,
    bit: c_int,
    len: usize,
    text: *mut u8,
}

/// Has anything been registered? (Cheap: one relaxed load.)
#[inline(always)]
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed) != 0
}

fn lock() {
    while LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
}

fn unlock() {
    LOCK.store(0, Ordering::Release);
}

/// `register_printf_specifier (spec, func, arginfo)`: use `func` for conversion `spec` and `arginfo` to
/// find what arguments it takes. 0, or -1 with EINVAL (spec not in 0..=255) or ENOMEM.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn register_printf_specifier(spec: c_int, converter: Option<PrintfFunction>, arginfo: Option<ArginfoSizeFunction>) -> c_int {
    if !(0..=255).contains(&spec) {
        errno::set(22);
        return -1;
    }
    lock();
    let mut result = 0;
    if get(&FUNC_TABLE).is_null() {
        // SAFETY: calloc has no precondition.
        let f = unsafe { rusty_libc_malloc::calloc(256, size_of::<Option<PrintfFunction>>()) } as *mut Option<PrintfFunction>;
        // SAFETY: as above.
        let a = unsafe { rusty_libc_malloc::calloc(256, size_of::<Option<ArginfoSizeFunction>>()) } as *mut Option<ArginfoSizeFunction>;
        if f.is_null() || a.is_null() {
            // SAFETY: each is null or the block just allocated, unused.
            unsafe { crate::file::free(f.cast()) };
            // SAFETY: as above.
            unsafe { crate::file::free(a.cast()) };
            result = -1;
        } else {
            // SAFETY: `LOCK` is held (this and the next write).
            unsafe { put(&ARGINFO_TABLE, a) };
            // SAFETY: as above.
            unsafe { put(&FUNC_TABLE, f) };
        }
    }
    if result == 0 {
        // SAFETY: `LOCK` is held; the tables have 256 entries (zeroed by calloc: `None`) and `spec` is below 256.
        unsafe { *get(&FUNC_TABLE).wrapping_add(spec as usize) = converter };
        // SAFETY: as above.
        unsafe { *get(&ARGINFO_TABLE).wrapping_add(spec as usize) = arginfo };
        ACTIVE.store(1, Ordering::Release);
    }
    unlock();
    result
}

/// `register_printf_function (spec, func, arginfo)`: the old form of `register_printf_specifier` (the arginfo
/// function has no size argument).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn register_printf_function(spec: c_int, converter: Option<PrintfFunction>, arginfo: Option<ArginfoFunction>) -> c_int {
    // the two function types differ in the trailing argument only, which the caller's function never reads
    // SAFETY: same size and representation (nullable function pointers); called with one extra integer argument, which
    // the C calling convention lets the callee ignore.
    let a = unsafe { core::mem::transmute::<Option<ArginfoFunction>, Option<ArginfoSizeFunction>>(arginfo) };
    register_printf_specifier(spec, converter, a)
}

/// `register_printf_modifier (str)`: a new modifier (a wide string of characters in 0..=255) that sets a bit of
/// `printf_info.user`; returns that bit, or -1 (EINVAL for an empty or wide string, ENOSPC after 16, ENOMEM).
///
/// # Safety
/// `s` is a wide string ending in 0.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn register_printf_modifier(s: *const i32) -> c_int {
    // SAFETY: the caller's contract.
    let n = unsafe { rusty_libc_wchar::wstring::wcslen(s as *const rusty_libc_wchar::wchar_t) };
    // SAFETY: the caller's contract: `n` characters before the terminating 0.
    let text = unsafe { core::slice::from_raw_parts(s, n) };
    register_modifier(text)
}

/// The safe core of `register_printf_modifier`: the modifier's characters.
fn register_modifier(s: &[i32]) -> c_int {
    let n = s.len();
    if n == 0 {
        errno::set(22);
        return -1;
    }
    if s.iter().any(|c| !(0..=255).contains(c)) {
        errno::set(22);
        return -1;
    }
    if get(&NEXT_BIT) / 8 == size_of::<u16>() as c_int {
        errno::set(28);
        return -1;
    }
    lock();
    let mut result = -1;
    'out: {
        if get(&MOD_TABLE).is_null() {
            // SAFETY: calloc has no precondition.
            let t = unsafe { rusty_libc_malloc::calloc(256, size_of::<*mut ModRecord>()) } as *mut *mut ModRecord;
            // SAFETY: `LOCK` is held.
            unsafe { put(&MOD_TABLE, t) };
            if t.is_null() {
                break 'out;
            }
        }
        let rec: *mut ModRecord = crate::file::alloc(size_of::<ModRecord>()).cast();
        if rec.is_null() {
            break 'out;
        }
        let text = crate::file::alloc(n);
        if text.is_null() {
            // SAFETY: the block just allocated, unused.
            unsafe { crate::file::free(rec.cast()) };
            break 'out;
        }
        for (i, &c) in s.iter().enumerate().skip(1) {
            // SAFETY: `i - 1 < n - 1`: inside the fresh block of `n` bytes.
            unsafe { *text.wrapping_add(i - 1) = c as u8 };
        }
        let first = s[0] as u8 as usize;
        let t = get(&MOD_TABLE);
        let bit = 1 << get(&NEXT_BIT);
        // (`LOCK` is held; the table has 256 entries and `first` is below 256)
        let head = t.wrapping_add(first);
        // SAFETY: as above (an entry of the zeroed table: null or a record).
        let old = unsafe { *head };
        // SAFETY: a fresh block of `ModRecord`'s size from malloc, aligned for it.
        unsafe { rec.write(ModRecord { next: old, bit, len: n - 1, text }) };
        // SAFETY: `LOCK` is held.
        unsafe { put(&NEXT_BIT, get(&NEXT_BIT) + 1) };
        // SAFETY: as for the read of the entry.
        unsafe { *head = rec };
        result = bit;
        ACTIVE.store(1, Ordering::Release);
    }
    unlock();
    result
}

/// `register_printf_type (fct)`: a new argument type (a number from `PA_LAST` up) whose values are taken from the
/// argument list by `fct (memory, &va_list)`. -1 with ENOSPC when the numbers are used up.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn register_printf_type(fct: Option<VaArgFunction>) -> c_int {
    lock();
    let mut result = -1;
    if get(&VAARG_TABLE).is_null() {
        // SAFETY: calloc has no precondition.
        let t = unsafe { rusty_libc_malloc::calloc((0x100 - PA_LAST) as usize, size_of::<Option<VaArgFunction>>()) } as *mut Option<VaArgFunction>;
        // SAFETY: `LOCK` is held.
        unsafe { put(&VAARG_TABLE, t) };
    }
    if !get(&VAARG_TABLE).is_null() {
        if get(&NEXT_TYPE) == 0x100 {
            errno::set(28);
        } else {
            result = get(&NEXT_TYPE);
            // SAFETY: `LOCK` is held.
            unsafe { put(&NEXT_TYPE, result + 1) };
            // SAFETY: `LOCK` is held; the table has `0x100 - PA_LAST` entries and `result` is in `PA_LAST..0x100`.
            unsafe { *get(&VAARG_TABLE).wrapping_add((result - PA_LAST) as usize) = fct };
            ACTIVE.store(1, Ordering::Release);
        }
    }
    unlock();
    result
}

fn func_for(spec: i32) -> Option<PrintfFunction> {
    if !(0..=255).contains(&spec) {
        return None;
    }
    // SAFETY: the table is null or has 256 entries; `spec` is below 256.
    unsafe { entry(get(&FUNC_TABLE), spec as usize) }
}

fn arginfo_for(spec: i32) -> Option<ArginfoSizeFunction> {
    if !(0..=255).contains(&spec) {
        return None;
    }
    // SAFETY: the table is null or has 256 entries; `spec` is below 256.
    unsafe { entry(get(&ARGINFO_TABLE), spec as usize) }
}

fn vaarg_for(ty: c_int) -> Option<VaArgFunction> {
    if !(PA_LAST..0x100).contains(&ty) {
        return None;
    }
    // SAFETY: the table is null or has `0x100 - PA_LAST` entries; `ty` is in `PA_LAST..0x100`.
    unsafe { entry(get(&VAARG_TABLE), (ty - PA_LAST) as usize) }
}

// ---------------------------------------------------------------------------------------- parsing

/// One parsed conversion (glibc's `struct printf_spec`); format positions are offsets into the format string.
#[derive(Clone, Copy)]
struct SpecRec {
    info: PrintfInfo,
    end_of_fmt: usize,
    next_fmt: usize,
    prec_arg: i32,
    width_arg: i32,
    data_arg: i32,
    data_arg_type: c_int,
    ndata_args: usize,
    size: c_int,
}

impl SpecRec {
    const fn zero() -> SpecRec {
        SpecRec { info: PrintfInfo::zero(), end_of_fmt: 0, next_fmt: 0, prec_arg: -1, width_arg: -1, data_arg: -1, data_arg_type: 0, ndata_args: 0, size: -1 }
    }
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

/// `read_int`: the first character is a digit; -1 on overflow. Leaves `*i` after the digits.
///
/// # Safety
/// `p` is a NUL-terminated format and `*i` is not past its NUL.
unsafe fn read_int<F: FmtChar>(p: *const F, i: &mut usize) -> i32 {
    let mut retval = i32::from(fmt_at!(p, *i)) - i32::from(b'0');
    loop {
        *i += 1;
        let c = fmt_at!(p, *i);
        if !is_digit(c) {
            break;
        }
        if retval >= 0 {
            if i32::MAX / 10 < retval {
                retval = -1;
            } else {
                let digit = i32::from(c) - i32::from(b'0');
                retval *= 10;
                if i32::MAX - digit < retval {
                    retval = -1;
                } else {
                    retval += digit;
                }
            }
        }
    }
    retval
}

/// A registered modifier at `*i` (the longest match wins); sets its bit and moves `*i` past it. false = none.
///
/// # Safety
/// `p` is a NUL-terminated format and `*i` is not past its NUL.
unsafe fn handle_registered_modifier<F: FmtChar>(p: *const F, i: &mut usize, info: &mut PrintfInfo) -> bool {
    let t = get(&MOD_TABLE);
    if t.is_null() {
        return false;
    }
    let first = fmt_raw!(p, *i);
    if first > 255 {
        return false;
    }
    // SAFETY: the table has 256 entries (null or a record list) and `first` is below 256.
    let mut runp = unsafe { *t.wrapping_add(first as usize) };
    let mut best_bit = 0;
    let mut best_len = 0usize;
    while !runp.is_null() {
        // SAFETY: a record of the list: allocated by `register_modifier`, never freed.
        let r = unsafe { &*runp };
        // SAFETY: the record's text: `len` bytes of its own block.
        let text = unsafe { core::slice::from_raw_parts(r.text, r.len) };
        let mut k = 0;
        while fmt_raw!(p, *i + 1 + k) != 0 && k < r.len && fmt_raw!(p, *i + 1 + k) == u32::from(text[k]) {
            k += 1;
        }
        if k == r.len && k + 1 > best_len {
            best_len = k + 1;
            best_bit = r.bit;
        }
        runp = r.next;
    }
    if best_bit != 0 {
        info.user |= best_bit as u16;
        *i += best_len;
        return true;
    }
    false
}

/// Parse the conversion starting at the `%` at offset `start` (glibc's `__parse_one_specmb`). Returns the number of
/// arguments it takes sequentially, or Err when the format is invalid (errno set).
///
/// # Safety
/// `p` is a NUL-terminated format with a `%` at `start`.
unsafe fn parse_one<F: FmtChar>(p: *const F, start: usize, posn: usize, max_ref_arg: &mut usize, spec: &mut SpecRec) -> (usize, bool) {
    let mut posn = posn;
    let mut nargs = 0usize;
    let mut failed = false;
    let mut i = start + 1;
    *spec = SpecRec::zero();
    spec.info = PrintfInfo::zero();
    if F::WIDE {
        spec.info.set(INFO_WIDE);
    }
    // positional argument
    if is_digit(fmt_at!(p, i)) {
        let begin = i;
        // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
        let n = unsafe { read_int::<F>(p, &mut i) };
        if n != 0 && fmt_at!(p, i) == b'$' {
            i += 1;
            if n != -1 {
                spec.data_arg = n - 1;
                *max_ref_arg = (*max_ref_arg).max(n as usize);
            }
        } else {
            i = begin;
        }
    }
    // flags
    loop {
        match fmt_at!(p, i) {
            b' ' => spec.info.set(INFO_SPACE),
            b'+' => spec.info.set(INFO_SHOWSIGN),
            b'-' => spec.info.set(INFO_LEFT),
            b'#' => spec.info.set(INFO_ALT),
            b'0' => spec.info.pad = i32::from(b'0'),
            b'\'' => spec.info.set(INFO_GROUP),
            b'I' => spec.info.set(INFO_I18N),
            _ => break,
        }
        i += 1;
        if fmt_at!(p, i) == 0 {
            break;
        }
    }
    if spec.info.has(INFO_LEFT) {
        spec.info.pad = i32::from(b' ');
    }
    // width
    spec.width_arg = -1;
    spec.info.width = 0;
    if fmt_at!(p, i) == b'*' {
        i += 1;
        let begin = i;
        if is_digit(fmt_at!(p, i)) {
            // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
            let n = unsafe { read_int::<F>(p, &mut i) };
            if n != 0 && fmt_at!(p, i) == b'$' {
                if n != -1 {
                    spec.width_arg = n - 1;
                    *max_ref_arg = (*max_ref_arg).max(n as usize);
                }
                i += 1;
            }
        }
        if spec.width_arg < 0 {
            spec.width_arg = posn as i32;
            posn += 1;
            nargs += 1;
            i = begin;
        }
    } else if is_digit(fmt_at!(p, i)) {
        // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
        let n = unsafe { read_int::<F>(p, &mut i) };
        if n != -1 {
            spec.info.width = n;
        }
    }
    // precision
    spec.prec_arg = -1;
    spec.info.prec = -1;
    if fmt_at!(p, i) == b'.' {
        i += 1;
        if fmt_at!(p, i) == b'*' {
            i += 1;
            let begin = i;
            if is_digit(fmt_at!(p, i)) {
                // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
                let n = unsafe { read_int::<F>(p, &mut i) };
                if n != 0 && fmt_at!(p, i) == b'$' {
                    if n != -1 {
                        spec.prec_arg = n - 1;
                        *max_ref_arg = (*max_ref_arg).max(n as usize);
                    }
                    i += 1;
                }
            }
            if spec.prec_arg < 0 {
                spec.prec_arg = posn as i32;
                posn += 1;
                nargs += 1;
                i = begin;
            }
        } else if is_digit(fmt_at!(p, i)) {
            // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
            let n = unsafe { read_int::<F>(p, &mut i) };
            if n != -1 {
                spec.info.prec = n;
            }
        } else {
            spec.info.prec = 0;
        }
    }
    // type modifiers
    spec.info.user = 0;
    // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
    if !unsafe { handle_registered_modifier(p, &mut i, &mut spec.info) } {
        let c = fmt_at!(p, i);
        i += 1;
        match c {
            b'h' => {
                if fmt_at!(p, i) != b'h' {
                    spec.info.set(INFO_SHORT);
                } else {
                    i += 1;
                    spec.info.set(INFO_CHAR);
                }
            }
            b'l' => {
                spec.info.set(INFO_LONG);
                if fmt_at!(p, i) == b'l' {
                    i += 1;
                    spec.info.set(INFO_LONG_DOUBLE);
                }
            }
            b'L' | b'q' => spec.info.set(INFO_LONG_DOUBLE),
            b'z' | b'Z' | b't' | b'j' => spec.info.set(INFO_LONG),
            b'w' => {
                let mut is_fast = false;
                if fmt_at!(p, i) == b'f' {
                    i += 1;
                    is_fast = true;
                }
                let mut bitwidth = 0;
                if is_digit(fmt_at!(p, i)) {
                    // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
                    bitwidth = unsafe { read_int::<F>(p, &mut i) };
                }
                if is_fast {
                    bitwidth = match bitwidth {
                        8 => 8,
                        16 => 64,
                        32 => 64,
                        64 => 64,
                        b => b,
                    };
                }
                match bitwidth {
                    8 => spec.info.set(INFO_CHAR),
                    16 => spec.info.set(INFO_SHORT),
                    32 => {}
                    64 => {
                        spec.info.set(INFO_LONG_DOUBLE);
                        spec.info.set(INFO_LONG);
                    }
                    _ => {
                        errno::set(22);
                        failed = true;
                    }
                }
            }
            _ => i -= 1,
        }
    }
    // the conversion
    let craw = fmt_raw!(p, i);
    let c = fmt_at!(p, i);
    i += 1;
    spec.info.spec = craw as i32;
    spec.size = -1;
    let mut ndata: Option<usize> = None;
    if let Some(ai) = arginfo_for(spec.info.spec) {
        let mut ty = 0;
        let mut size = -1;
        // SAFETY: the program's arginfo function, called as glibc calls it: the info and room for one type and one size.
        let r = unsafe { ai(&spec.info, 1, &mut ty, &mut size) } as c_int;
        if r >= 0 {
            spec.data_arg_type = ty;
            spec.size = size;
            ndata = Some(r as usize);
        }
    }
    match ndata {
        Some(n) => spec.ndata_args = n,
        None => {
            spec.ndata_args = 1;
            let i_ = &spec.info;
            match c {
                b'i' | b'd' | b'u' | b'o' | b'X' | b'x' | b'B' | b'b' => {
                    spec.data_arg_type = if i_.has(INFO_LONG) {
                        PA_INT | PA_FLAG_LONG
                    } else if i_.has(INFO_SHORT) {
                        PA_INT | PA_FLAG_SHORT
                    } else if i_.has(INFO_CHAR) {
                        PA_CHAR
                    } else {
                        PA_INT
                    };
                    // (as in glibc on x86-64, where long and long long are alike: a `q` or `L` alone, which sets
                    // only the long-long bit, is read as a plain int)
                }
                b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => {
                    spec.data_arg_type = if i_.has(INFO_LONG_DOUBLE) { PA_DOUBLE | PA_FLAG_LONG_DOUBLE } else { PA_DOUBLE };
                }
                b'c' => spec.data_arg_type = PA_CHAR,
                b'C' => spec.data_arg_type = PA_WCHAR,
                b's' => spec.data_arg_type = PA_STRING,
                b'S' => spec.data_arg_type = PA_WSTRING,
                b'p' => spec.data_arg_type = PA_POINTER,
                b'n' => spec.data_arg_type = PA_INT | PA_FLAG_PTR,
                _ => spec.ndata_args = 0,
            }
        }
    }
    if spec.data_arg == -1 && spec.ndata_args > 0 {
        spec.data_arg = posn as i32;
        nargs += spec.ndata_args;
    }
    if c == 0 {
        spec.end_of_fmt = i - 1;
        spec.next_fmt = i - 1;
    } else {
        spec.end_of_fmt = i;
        let mut j = i;
        while fmt_at!(p, j) != 0 && fmt_at!(p, j) != b'%' {
            j += 1;
        }
        spec.next_fmt = j;
    }
    (nargs, failed)
}

// ---------------------------------------------------------------------------------------- small growable arrays

struct Arr<T: Copy> {
    p: *mut T,
    len: usize,
    cap: usize,
}

// Invariant: `p` is null (`len` = `cap` = 0) or the array's own malloc'd block of `cap` elements, the first `len` of them
// initialised.
impl<T: Copy> Arr<T> {
    const fn new() -> Arr<T> {
        Arr { p: null_mut(), len: 0, cap: 0 }
    }
    /// Append; false when out of memory.
    fn push(&mut self, v: T) -> bool {
        if self.len == self.cap {
            let ncap = if self.cap == 0 { 8 } else { self.cap * 2 };
            // SAFETY: `p` is null or our own malloc'd block (the invariant).
            let np = unsafe { rusty_libc_malloc::realloc(self.p.cast(), ncap * size_of::<T>()) } as *mut T;
            if np.is_null() {
                return false;
            }
            self.p = np;
            self.cap = ncap;
        }
        // SAFETY: `len < cap`: room in the block (malloc's alignment suits the element types used here, all of 16 bytes or
        // less).
        unsafe { self.p.wrapping_add(self.len).write(v) };
        self.len += 1;
        true
    }
    fn as_slice(&self) -> &[T] {
        if self.p.is_null() {
            return &[];
        }
        // SAFETY: the invariant: `len` initialised elements.
        unsafe { core::slice::from_raw_parts(self.p, self.len) }
    }
    fn as_mut_slice(&mut self) -> &mut [T] {
        if self.p.is_null() {
            return &mut [];
        }
        // SAFETY: the invariant: `len` initialised elements, borrowed mutably through `self`.
        unsafe { core::slice::from_raw_parts_mut(self.p, self.len) }
    }
    fn free(&mut self) {
        // SAFETY: null or our own block, forgotten right below.
        unsafe { crate::file::free(self.p.cast()) };
        self.p = null_mut();
        self.len = 0;
        self.cap = 0;
    }
}

/// One argument slot: glibc's `union printf_arg` (16 bytes, 16 aligned).
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Slot([u8; 16]);

/// Feeds one pre-read value to the engine.
struct OneArg(Val);

impl Args for OneArg {
    fn get(&mut self, _kind: Kind, _pos: Option<usize>) -> Val {
        self.0
    }
}

/// Read the value of type `ty` from the argument list into a slot (`va` is the C va_list for user types).
///
/// # Safety
/// The argument at `pos` has the type `ty` (for a user type: what its registered function takes from a `va_list`).
unsafe fn read_slot<A: Args>(args: &mut A, ty: c_int, pos: usize, user: &mut Arr<*mut c_void>, size: c_int) -> Option<Slot> {
    let mut s = Slot([0; 16]);
    let put64 = |s: &mut Slot, v: u64| s.0[..8].copy_from_slice(&v.to_le_bytes());
    if ty == PA_WCHAR || ty == PA_CHAR || ty == PA_INT || ty == PA_INT | PA_FLAG_SHORT {
        if let Val::I(v) = args.get(Kind::Int, Some(pos)) {
            s.0[..4].copy_from_slice(&(v as u32).to_le_bytes());
        }
    } else if ty == PA_INT | PA_FLAG_LONG_LONG || ty == PA_INT | PA_FLAG_LONG {
        if let Val::I(v) = args.get(Kind::Long, Some(pos)) {
            put64(&mut s, v);
        }
    } else if ty == PA_FLOAT || ty == PA_DOUBLE {
        if let Val::D(d) = args.get(Kind::Double, Some(pos)) {
            put64(&mut s, d.to_bits());
        }
    } else if ty == PA_DOUBLE | PA_FLAG_LONG_DOUBLE {
        if let Val::LD(b) = args.get(Kind::LongDouble, Some(pos)) {
            s.0 = b;
        }
    } else if ty == PA_STRING || ty == PA_WSTRING || ty == PA_POINTER || ty & PA_FLAG_PTR != 0 {
        if let Val::I(v) = args.get(Kind::Ptr, Some(pos)) {
            put64(&mut s, v);
        }
    } else if let Some(f) = vaarg_for(ty) {
        // SAFETY: calloc has no precondition.
        let mem = unsafe { rusty_libc_malloc::calloc(1, (size.max(1)) as usize) };
        if mem.is_null() {
            return None;
        }
        if !user.push(mem) {
            // SAFETY: the block just allocated, unused.
            unsafe { crate::file::free(mem.cast()) };
            return None;
        }
        put64(&mut s, mem as usize as u64);
        // (a caller without a C va_list, the Rust API, leaves user types zeroed)
        let va = args.raw_va();
        if !va.is_null() {
            // SAFETY: the program's va_arg function for its type: a block of the size its arginfo gave and the C va_list,
            // whose next argument is of that type (the function's contract).
            unsafe { f(mem, va) };
        }
    }
    Some(s)
}

/// The value of an already read slot, for the engine.
fn slot_val(ty: c_int, s: &Slot) -> Val {
    let u32v = u32::from_le_bytes([s.0[0], s.0[1], s.0[2], s.0[3]]);
    let u64v = u64::from_le_bytes([s.0[0], s.0[1], s.0[2], s.0[3], s.0[4], s.0[5], s.0[6], s.0[7]]);
    match ty {
        PA_FLOAT | PA_DOUBLE => Val::D(f64::from_bits(u64v)),
        x if x == PA_DOUBLE | PA_FLAG_LONG_DOUBLE => Val::LD(s.0),
        x if x == PA_INT | PA_FLAG_LONG_LONG || x == PA_INT | PA_FLAG_LONG => Val::I(u64v),
        PA_STRING | PA_WSTRING | PA_POINTER => Val::I(u64v),
        x if x & PA_FLAG_PTR != 0 => Val::I(u64v),
        _ => Val::I(u64::from(u32v)),
    }
}

// ---------------------------------------------------------------------------------------- the engine

struct Mini {
    buf: [u8; 80],
    len: usize,
}

impl Mini {
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() - 1 {
            self.buf[self.len] = b;
            self.len += 1;
        }
    }
    fn push_num(&mut self, mut v: u64) {
        let mut tmp = [0u8; 20];
        let mut k = tmp.len();
        loop {
            k -= 1;
            tmp[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for &d in &tmp[k..] {
            self.push(d);
        }
    }
}

/// A one-conversion format equal to what `info` describes, with width and precision as numbers.
fn build_mini(info: &PrintfInfo, conv: u8) -> Mini {
    let mut m = Mini { buf: [0; 80], len: 0 };
    m.push(b'%');
    if info.has(INFO_ALT) {
        m.push(b'#');
    }
    if info.has(INFO_GROUP) {
        m.push(b'\'');
    }
    if info.has(INFO_SHOWSIGN) {
        m.push(b'+');
    } else if info.has(INFO_SPACE) {
        m.push(b' ');
    }
    if info.has(INFO_LEFT) {
        m.push(b'-');
    }
    if info.pad == i32::from(b'0') && !info.has(INFO_LEFT) {
        m.push(b'0');
    }
    if info.has(INFO_I18N) {
        m.push(b'I');
    }
    if info.width > 0 {
        m.push_num(info.width as u64);
    }
    if info.prec >= 0 {
        m.push(b'.');
        m.push_num(info.prec as u64);
    }
    let is_float = matches!(conv, b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A');
    if is_float {
        if info.has(INFO_LONG_DOUBLE) {
            m.push(b'L');
        }
    } else if info.has(INFO_CHAR) {
        m.push(b'h');
        m.push(b'h');
    } else if info.has(INFO_SHORT) {
        m.push(b'h');
    } else if info.has(INFO_LONG_DOUBLE) {
        m.push(b'l');
        m.push(b'l');
    } else if info.has(INFO_LONG) {
        m.push(b'l');
    }
    m.push(conv);
    m
}

/// `printf_unknown`: print the conversion as it was written, canonicalized.
fn print_unknown<S: Sink>(sink: &mut S, info: &PrintfInfo) -> Option<usize> {
    let mut m = Mini { buf: [0; 80], len: 0 };
    m.push(b'%');
    if info.has(INFO_ALT) {
        m.push(b'#');
    }
    if info.has(INFO_GROUP) {
        m.push(b'\'');
    }
    if info.has(INFO_SHOWSIGN) {
        m.push(b'+');
    } else if info.has(INFO_SPACE) {
        m.push(b' ');
    }
    if info.has(INFO_LEFT) {
        m.push(b'-');
    }
    if info.pad == i32::from(b'0') {
        m.push(b'0');
    }
    if info.has(INFO_I18N) {
        m.push(b'I');
    }
    if info.width != 0 {
        m.push_num(i64::from(info.width).unsigned_abs());
    }
    if info.prec != -1 {
        m.push(b'.');
        m.push_num(i64::from(info.prec).unsigned_abs());
    }
    if info.spec != 0 {
        m.push(info.spec as u8);
    }
    if sink.put(&m.buf[..m.len]) { Some(m.len) } else { None }
}

/// The printf engine with registered conversions (narrow and wide formats). See the module notes.
///
/// # Safety
/// `fmt` is a NUL-terminated format; the arguments are what it asks for.
pub(crate) unsafe fn format_ext<S: Sink, A: Args, F: FmtChar>(sink: &mut S, fmt: *const F, args: &mut A) -> i32 {
    if sink.partial_output_on_error() {
        // SAFETY: the function's contract.
        return unsafe { format_ext_to::<S, A, F>(sink, fmt, args) };
    }
    // a stream gets nothing when the formatting fails: collect the text and hand it over at the end
    if F::WIDE {
        let mut hold = HoldSinkW { buf: Arr::new() };
        // SAFETY: the function's contract.
        let r = unsafe { format_ext_to::<HoldSinkW, A, F>(&mut hold, fmt, args) };
        let ok = r >= 0 && (hold.buf.len == 0 || sink.put_wide(hold.buf.as_slice()));
        hold.buf.free();
        return if ok { r } else { -1 };
    }
    let mut hold = HoldSink { buf: Arr::new() };
    // SAFETY: the function's contract.
    let r = unsafe { format_ext_to::<HoldSink, A, F>(&mut hold, fmt, args) };
    let ok = r >= 0 && (hold.buf.len == 0 || sink.put(hold.buf.as_slice()));
    hold.buf.free();
    if ok { r } else { -1 }
}

/// Collects output in memory.
struct HoldSink {
    buf: Arr<u8>,
}

impl Sink for HoldSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        for &b in bytes {
            if !self.buf.push(b) {
                errno::set(12);
                return false;
            }
        }
        true
    }
}

/// Collects wide output in memory.
struct HoldSinkW {
    buf: Arr<u32>,
}

impl Sink for HoldSinkW {
    const WIDE: bool = true;
    fn put_wide(&mut self, w: &[u32]) -> bool {
        for &c in w {
            if !self.buf.push(c) {
                errno::set(12);
                return false;
            }
        }
        true
    }
    fn put(&mut self, bytes: &[u8]) -> bool {
        for &b in bytes {
            if !self.buf.push(u32::from(b)) {
                errno::set(12);
                return false;
            }
        }
        true
    }
}

/// Write the literal text `fmt[start..start + len]` of the format.
///
/// # Safety
/// `fmt[start..start + len]` lies inside the format.
unsafe fn emit_lit<S: Sink, F: FmtChar>(sink: &mut S, fmt: *const F, start: usize, len: usize) -> bool {
    if !F::WIDE {
        // SAFETY: the caller's contract (a narrow format: one byte per character).
        return sink.put(unsafe { core::slice::from_raw_parts(fmt.wrapping_add(start) as *const u8, len) });
    }
    let mut chunk = [0u32; 64];
    let mut i = 0usize;
    while i < len {
        let k = (len - i).min(64);
        for (j, c) in chunk.iter_mut().enumerate().take(k) {
            *c = fmt_raw!(fmt, start + i + j);
        }
        if !sink.put_wide(&chunk[..k]) {
            return false;
        }
        i += k;
    }
    true
}

/// # Safety
/// As `format_ext`.
unsafe fn format_ext_to<S: Sink, A: Args, F: FmtChar>(sink: &mut S, fmt: *const F, args: &mut A) -> i32 {
    let saved_errno = errno::get();
    let mut total: usize = 0;
    let mut f = 0usize;
    while fmt_raw!(fmt, f) != 0 && fmt_raw!(fmt, f) != u32::from(b'%') {
        f += 1;
    }
    if f > 0 {
        // SAFETY: `fmt[..f]` was just scanned (no NUL in it).
        if !unsafe { emit_lit::<S, F>(sink, fmt, 0, f) } {
            return -1;
        }
        total += f;
    }
    if fmt_raw!(fmt, f) == 0 {
        return total.min(i32::MAX as usize) as i32;
    }
    let mut specs: Arr<SpecRec> = Arr::new();
    let mut types: Arr<c_int> = Arr::new();
    let mut sizes: Arr<c_int> = Arr::new();
    let mut slots: Arr<Slot> = Arr::new();
    let mut user_mem: Arr<*mut c_void> = Arr::new();
    // SAFETY: the function's contract.
    let r = unsafe { format_ext_inner::<S, A, F>(sink, fmt, f, args, saved_errno, &mut total, &mut specs, &mut types, &mut sizes, &mut slots, &mut user_mem) };
    for &m in user_mem.as_slice() {
        // SAFETY: each is a block `read_slot` allocated for a user type, freed once here.
        unsafe { crate::file::free(m.cast()) };
    }
    specs.free();
    types.free();
    sizes.free();
    slots.free();
    user_mem.free();
    if !r {
        return -1;
    }
    if total > i32::MAX as usize {
        errno::set(75);
        return -1;
    }
    total as i32
}

/// # Safety
/// As `format_ext`; `first` is not past the format's NUL.
#[allow(clippy::too_many_arguments)]
unsafe fn format_ext_inner<S: Sink, A: Args, F: FmtChar>(
    sink: &mut S,
    fmt: *const F,
    first: usize,
    args: &mut A,
    saved_errno: i32,
    total: &mut usize,
    specs: &mut Arr<SpecRec>,
    types: &mut Arr<c_int>,
    sizes: &mut Arr<c_int>,
    slots: &mut Arr<Slot>,
    user_mem: &mut Arr<*mut c_void>,
) -> bool {
    // parse every conversion
    let mut nargs = 0usize;
    let mut max_ref_arg = 0usize;
    let mut f = first;
    while fmt_raw!(fmt, f) != 0 {
        let mut spec = SpecRec::zero();
        // SAFETY: the function's contract: a NUL-terminated format; `f` is at a `%` (the literal scan stops there).
        let (n, failed) = unsafe { parse_one::<F>(fmt, f, nargs, &mut max_ref_arg, &mut spec) };
        if failed {
            return false;
        }
        nargs += n;
        f = spec.next_fmt;
        if !specs.push(spec) {
            errno::set(12);
            return false;
        }
    }
    nargs = nargs.max(max_ref_arg);
    for _ in 0..nargs {
        if !types.push(PA_INT) || !sizes.push(0) || !slots.push(Slot([0; 16])) {
            errno::set(12);
            return false;
        }
    }
    // the types of all arguments
    for k in 0..specs.len {
        let s = specs.as_slice()[k];
        if s.width_arg != -1 && (s.width_arg as usize) < nargs {
            types.as_mut_slice()[s.width_arg as usize] = PA_INT;
        }
        if s.prec_arg != -1 && (s.prec_arg as usize) < nargs {
            types.as_mut_slice()[s.prec_arg as usize] = PA_INT;
        }
        match s.ndata_args {
            0 => {}
            1 => {
                if s.data_arg >= 0 && (s.data_arg as usize) < nargs {
                    types.as_mut_slice()[s.data_arg as usize] = s.data_arg_type;
                    sizes.as_mut_slice()[s.data_arg as usize] = s.size;
                }
            }
            n => {
                if let Some(ai) = arginfo_for(s.info.spec)
                    && s.data_arg >= 0
                    && (s.data_arg as usize) < nargs
                {
                    let room = nargs - s.data_arg as usize;
                    let tp = types.as_mut_slice()[s.data_arg as usize..].as_mut_ptr();
                    let sp = sizes.as_mut_slice()[s.data_arg as usize..].as_mut_ptr();
                    // SAFETY: the program's arginfo function, called as glibc calls it: the spec's info and two arrays
                    // with room for `n.min(room)` entries each.
                    unsafe { ai(&s.info, n.min(room), tp, sp) };
                }
            }
        }
    }
    // the values
    for cnt in 0..nargs {
        let (ty, size) = (types.as_slice()[cnt], sizes.as_slice()[cnt]);
        // SAFETY: the function's contract: the arguments are what the format (and the arginfo functions) say.
        match unsafe { read_slot(args, ty, cnt + 1, user_mem, size) } {
            Some(s) => slots.as_mut_slice()[cnt] = s,
            None => {
                errno::set(12);
                return false;
            }
        }
    }
    // the conversions
    for k in 0..specs.len {
        let mut s = specs.as_slice()[k];
        if s.width_arg != -1 && (s.width_arg as usize) < nargs {
            let b = &slots.as_slice()[s.width_arg as usize].0;
            s.info.width = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            if s.info.width < 0 {
                s.info.width = s.info.width.wrapping_neg();
                s.info.set(INFO_LEFT);
            }
        }
        if s.prec_arg != -1 && (s.prec_arg as usize) < nargs {
            let b = &slots.as_slice()[s.prec_arg as usize].0;
            s.info.prec = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            if s.info.prec < 0 {
                s.info.prec = -1;
            }
        }
        specs.as_mut_slice()[k] = s;
        let mut handled = false;
        if let Some(func) = func_for(s.info.spec) {
            match call_handler::<S, F>(sink, func, &s, slots, total) {
                Ok(true) => handled = true,
                Ok(false) => {}
                Err(()) => return false,
            }
        }
        if !handled {
            let spec = s.info.spec;
            let ty = if s.data_arg >= 0 && (s.data_arg as usize) < nargs { types.as_slice()[s.data_arg as usize] } else { PA_INT };
            let slot = if s.data_arg >= 0 && (s.data_arg as usize) < nargs { slots.as_slice()[s.data_arg as usize] } else { Slot([0; 16]) };
            match spec as u8 {
                b'%' if spec < 256 => {
                    if !sink.put(b"%") {
                        return false;
                    }
                    *total += 1;
                }
                b'n' if spec < 256 => {
                    let p = u64::from_le_bytes([slot.0[0], slot.0[1], slot.0[2], slot.0[3], slot.0[4], slot.0[5], slot.0[6], slot.0[7]]) as *mut u8;
                    if !p.is_null() {
                        let n = *total;
                        // The function's contract: a `%n` argument points to an integer of the size its length
                        // modifier names; each branch stores that one.
                        if s.info.has(INFO_CHAR) {
                            // SAFETY: see above.
                            unsafe { *(p as *mut i8) = n as i8 };
                        } else if s.info.has(INFO_SHORT) {
                            // SAFETY: see above.
                            unsafe { *(p as *mut i16) = n as i16 };
                        } else if s.info.has(INFO_LONG) || s.info.has(INFO_LONG_DOUBLE) {
                            // SAFETY: see above.
                            unsafe { *(p as *mut i64) = n as i64 };
                        } else {
                            // SAFETY: see above.
                            unsafe { *(p as *mut i32) = n as i32 };
                        }
                    }
                }
                b'm' | b'i' | b'd' | b'u' | b'o' | b'X' | b'x' | b'B' | b'b' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' | b'c' | b'C' | b's' | b'S' | b'p' if spec < 256 => {
                    let mini = build_mini(&s.info, spec as u8);
                    // (the one-conversion format has the type of the caller's format: `%s` of a wide format
                    // converts a multibyte string, `%c` is btowc ...)
                    let mut mf = [F::from_ascii(0); 80];
                    for (k, b) in mini.buf.iter().enumerate().take(mini.len) {
                        mf[k] = F::from_ascii(*b);
                    }
                    let mut v = OneArg(slot_val(ty, &slot));
                    errno::set(saved_errno);
                    // SAFETY: `mf` is a NUL-terminated one-conversion format (`mini` is shorter than it) and `v` holds the
                    // value read for it with the type the format names.
                    let n = unsafe { fmt::format_builtin::<S, OneArg, F>(sink, mf.as_ptr(), &mut v) };
                    if n < 0 {
                        return false;
                    }
                    *total += n as usize;
                }
                _ => match print_unknown(sink, &s.info) {
                    Some(n) => *total += n,
                    None => return false,
                },
            }
        }
        // the text after this conversion
        let (a, b) = (s.end_of_fmt, s.next_fmt);
        if b > a {
            // SAFETY: `fmt[a..b]` is literal text the parser stepped over: inside the format.
            if !unsafe { emit_lit::<S, F>(sink, fmt, a, b - a) } {
                return false;
            }
            *total += b - a;
        }
    }
    true
}

/// Run a registered handler on a temporary stream and insert what it wrote. Ok(true): done; Ok(false): the
/// handler declined (-2), run the built-in; Err: it failed (errno set by it) or the sink did.
/// The stream a handler gets is byte oriented for a narrow format and wide oriented for a wide one (as in
/// glibc: it must then write with `fwprintf`, `fputwc` ...; the byte functions fail on it).
fn call_handler<S: Sink, F: FmtChar>(sink: &mut S, func: PrintfFunction, s: &SpecRec, slots: &Arr<Slot>, total: &mut usize) -> Result<bool, ()> {
    // the handler gets an array of pointers to its argument slots (null past the arguments read)
    let mut ptrs: [*const c_void; 4] = [core::ptr::null(); 4];
    let mut heap: *mut *const c_void = null_mut();
    let n = s.ndata_args;
    let arr: &mut [*const c_void] = if n <= ptrs.len() {
        &mut ptrs[..n]
    } else {
        // SAFETY: calloc has no precondition.
        heap = unsafe { rusty_libc_malloc::calloc(n, size_of::<*const c_void>()) } as *mut *const c_void;
        if heap.is_null() {
            return Err(());
        }
        // SAFETY: a fresh zeroed block of `n` pointers (all null: valid values).
        unsafe { core::slice::from_raw_parts_mut(heap, n) }
    };
    let all = slots.as_slice();
    for (i, slot) in arr.iter_mut().enumerate() {
        let idx = s.data_arg + i as i32;
        *slot = if idx >= 0 && (idx as usize) < all.len() { (&raw const all[idx as usize]).cast() } else { core::ptr::null() };
    }
    let pp = arr.as_ptr();
    let mut buf: *mut c_char = null_mut();
    let mut size: usize = 0;
    // SAFETY: both locations are locals that outlive the stream (it is closed below).
    let fp = unsafe { crate::file_extra::open_memstream_unit(&mut buf, &mut size, if F::WIDE { 4 } else { 1 }) };
    if fp.is_null() {
        // SAFETY: null or the block allocated above, unused.
        unsafe { crate::file::free(heap.cast()) };
        return Err(());
    }
    // SAFETY: the program's handler, called as glibc calls it: an open stream, the spec's info and the array of `n` slot
    // pointers.
    let done = unsafe { func(fp, &s.info, pp) };
    // SAFETY: our memory stream, still open.
    unsafe { crate::file_api::fflush(fp) };
    // SAFETY: as above; closed once.
    unsafe { crate::file_api::fclose(fp) };
    // SAFETY: null or the block allocated above, no longer used.
    unsafe { crate::file::free(heap.cast()) };
    let ok = if buf.is_null() || size == 0 {
        true
    } else if F::WIDE {
        // SAFETY: the closed wide memory stream published `size` characters at `buf` (its own malloc'd block).
        sink.put_wide(unsafe { core::slice::from_raw_parts(buf as *const u32, size) })
    } else {
        // SAFETY: the closed memory stream published `size` bytes at `buf` (its own malloc'd block).
        sink.put(unsafe { core::slice::from_raw_parts(buf as *const u8, size) })
    };
    let written = size;
    // SAFETY: the stream's buffer, handed over at its close; freed once.
    unsafe { crate::file::free(buf.cast()) };
    if !ok {
        return Err(());
    }
    *total += written;
    if done == -2 {
        return Ok(false);
    }
    if done < 0 {
        return Err(());
    }
    Ok(true)
}

// ---------------------------------------------------------------------------------------- parse_printf_format

/// `parse_printf_format (fmt, n, argtypes)`: the argument types `fmt` needs (`PA_*` codes), up to `n` of them
/// stored; the number of arguments the format takes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn parse_printf_format(fmt: *const c_char, n: usize, argtypes: *mut c_int) -> usize {
    let p = fmt as *const u8;
    let mut nargs = 0usize;
    let mut max_ref_arg = 0usize;
    let mut f = 0usize;
    // (the caller's contract: `fmt` is NUL-terminated; `fmt_at!` reads it)
    while fmt_at!(p, f) != 0 && fmt_at!(p, f) != b'%' {
        f += 1;
    }
    // SAFETY: the caller's contract: room for `n` types (`n` 0: nothing is stored).
    let types = unsafe { rusty_libc_core::ffi::slice_mut(argtypes, n) };
    while fmt_at!(p, f) != 0 {
        let mut spec = SpecRec::zero();
        // (a format that fails to parse is not an error here: the spec is used as far as it was parsed)
        // SAFETY: a NUL-terminated format with a `%` at `f`.
        let (k, _failed) = unsafe { parse_one(p, f, nargs, &mut max_ref_arg, &mut spec) };
        nargs += k;
        if spec.width_arg != -1 && (spec.width_arg as usize) < n {
            types[spec.width_arg as usize] = PA_INT;
        }
        if spec.prec_arg != -1 && (spec.prec_arg as usize) < n {
            types[spec.prec_arg as usize] = PA_INT;
        }
        if spec.data_arg >= 0 && (spec.data_arg as usize) < n {
            match spec.ndata_args {
                0 => {}
                1 => types[spec.data_arg as usize] = spec.data_arg_type,
                k => {
                    if let Some(ai) = arginfo_for(spec.info.spec) {
                        // the function may store a size for each of its arguments: give it room
                        // (glibc hands it the one `size` field of the spec)
                        // SAFETY: calloc has no precondition.
                        let room = unsafe { rusty_libc_malloc::calloc(k.max(n), size_of::<c_int>()) } as *mut c_int;
                        let tp = types[spec.data_arg as usize..].as_mut_ptr();
                        // SAFETY: the program's arginfo function: room for `n - data_arg` types at `tp` and as many sizes in
                        // `room` (glibc's call; a failed calloc gives it null, as before).
                        unsafe { ai(&spec.info, n - spec.data_arg as usize, tp, room) };
                        // SAFETY: null or the block allocated above, freed once.
                        unsafe { crate::file::free(room.cast()) };
                    }
                }
            }
        }
        f = spec.next_fmt;
    }
    nargs.max(max_ref_arg)
}

// ---------------------------------------------------------------------------------------- printf_size

/// x87 helpers for `printf_size` on a long double (the scaling must be done in extended precision).
mod x87 {
    use core::arch::asm;

    /// `v >= d`?
    pub fn ge(v: &[u8; 16], d: i32) -> bool {
        let r: u8;
        // SAFETY: reads the 10-byte x87 value in `v` and the int `d` (both live references); the x87 stack is restored (one
        // load each, one pop each) and declared clobbered.
        unsafe {
            asm!(
                "fild dword ptr [{d}]",
                "fld tbyte ptr [{v}]",
                "fucomip st, st(1)",
                "fstp st(0)",
                "setae {r}",
                v = in(reg) v.as_ptr(),
                d = in(reg) &d,
                r = out(reg_byte) r,
                out("st(0)") _, out("st(1)") _, out("st(2)") _, out("st(3)") _, out("st(4)") _, out("st(5)") _, out("st(6)") _, out("st(7)") _,
                options(nostack)
            );
        }
        r != 0
    }

    /// `v /= d`
    pub fn div(v: &mut [u8; 16], d: i32) {
        // SAFETY: reads and writes back the 10-byte x87 value in `v` (a live mutable reference) and reads the int `d`; the
        // x87 stack is restored (one load, one pop) and declared clobbered.
        unsafe {
            asm!(
                "fld tbyte ptr [{v}]",
                "fidiv dword ptr [{d}]",
                "fstp tbyte ptr [{v}]",
                v = in(reg) v.as_mut_ptr(),
                d = in(reg) &d,
                out("st(0)") _, out("st(1)") _, out("st(2)") _, out("st(3)") _, out("st(4)") _, out("st(5)") _, out("st(6)") _, out("st(7)") _,
                options(nostack)
            );
        }
    }
}

/// Write `s` to the stream; false when it failed.
///
/// # Safety
/// `fp` is an open stream (the one a handler was given) the calling thread may use.
unsafe fn fput(fp: *mut File, s: &[u8]) -> bool {
    // SAFETY: the caller's contract (a short borrow for the orientation test).
    if unsafe { crate::file::stream(fp) }.flags & crate::file::F_WIDE != 0 {
        // a wide stream (the handler of a wide format gets one): the text is ASCII, written as wide characters
        for &b in s {
            // SAFETY: as above.
            if crate::wfile::putwc_raw(unsafe { crate::file::stream(fp) }, u32::from(b)) == rusty_libc_wchar::WEOF {
                return false;
            }
        }
        return true;
    }
    // SAFETY: the caller's contract; `s` is readable for its length.
    unsafe { crate::file_api::fwrite(s.as_ptr().cast(), 1, s.len(), fp) == s.len() }
}

/// # Safety
/// As `fput`.
unsafe fn fpad(fp: *mut File, n: usize) -> bool {
    let chunk = [b' '; 64];
    let mut left = n;
    while left > 0 {
        let k = left.min(64);
        // SAFETY: the caller's contract.
        if !unsafe { fput(fp, &chunk[..k]) } {
            return false;
        }
        left -= k;
    }
    true
}

struct VecSink<'a> {
    buf: [u8; 512],
    len: usize,
    more: &'a mut Arr<u8>,
}

impl Sink for VecSink<'_> {
    fn put(&mut self, bytes: &[u8]) -> bool {
        for &b in bytes {
            if self.len < self.buf.len() {
                self.buf[self.len] = b;
                self.len += 1;
            } else if !self.more.push(b) {
                return false;
            }
        }
        true
    }
}

/// Print `val` with the `%f` conversion the way `info` says (flags, width, precision); returns the characters
/// written, or -1.
///
/// # Safety
/// As `fput`.
unsafe fn printf_fp_f(fp: *mut File, info: &PrintfInfo, val: Val) -> c_int {
    // SAFETY: the caller's contract.
    unsafe { printf_fp_conv(fp, info, val, b'f') }
}

/// Print `val` with the floating-point conversion `conv` the way `info` says; returns the characters written, or -1.
///
/// # Safety
/// As `fput`.
unsafe fn printf_fp_conv(fp: *mut File, info: &PrintfInfo, val: Val, conv: u8) -> c_int {
    let mini = build_mini(info, conv);
    let mut more: Arr<u8> = Arr::new();
    let mut sink = VecSink { buf: [0; 512], len: 0, more: &mut more };
    let mut a = OneArg(val);
    // a nested format must not be taken over by user conversions registered for 'f'
    // SAFETY: `mini.buf` is a NUL-terminated one-conversion format; `a` holds a value of the type it names.
    let n = unsafe { fmt::format_builtin::<VecSink, OneArg, u8>(&mut sink, mini.buf.as_ptr(), &mut a) };
    let len = sink.len;
    // SAFETY: the caller's contract.
    let mut ok = n >= 0 && unsafe { fput(fp, &sink.buf[..len]) };
    if ok && more.len > 0 {
        // SAFETY: the caller's contract.
        ok = unsafe { fput(fp, more.as_slice()) };
    }
    more.free();
    if ok { n } else { -1 }
}

/// glibc's `__printf_fp (fp, info, args)` (exported, GLIBC_2.2.5): print the floating-point number `*args[0]` (a double, a long
/// double with `is_long_double`, a binary128 with `is_binary128`) as `%e`, `%f` or `%g` (by `info->spec`, case kept; any other
/// letter is taken as `g`) with the flags, width and precision in `info`, the way printf would. Returns the characters written,
/// or -1. User conversion handlers call it.
///
/// # Safety
/// `fp` is an open stream, `info` a valid `struct printf_info`, `args[0]` points to a value of the type `info` names.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __printf_fp(fp: *mut File, info: *const PrintfInfo, args: *const *const c_void) -> c_int {
    // SAFETY: the caller's contract (this and the reads below).
    let info = unsafe { &*info };
    // SAFETY: as above.
    let a0 = unsafe { *args };
    let val = if info.has(INFO_BINARY128) {
        // SAFETY: as above: a binary128 at `a0` (not necessarily aligned).
        Val::Q(unsafe { (a0 as *const u128).read_unaligned() })
    } else if info.has(INFO_LONG_DOUBLE) {
        // SAFETY: as above: a long double (16 bytes) at `a0`.
        Val::LD(unsafe { *(a0 as *const [u8; 16]) })
    } else {
        // SAFETY: as above: a double at `a0`.
        Val::D(unsafe { *(a0 as *const f64) })
    };
    let sp = if (0..256).contains(&info.spec) { info.spec as u8 } else { b'g' };
    let conv = match sp {
        b'e' | b'E' | b'f' | b'F' | b'g' | b'G' => sp,
        c if c.is_ascii_uppercase() => b'G',
        _ => b'g',
    };
    let mut fi = *info;
    if fi.has(INFO_BINARY128) {
        // the value says its own type; the mini format has no binary128 length modifier
        fi.flags &= !INFO_LONG_DOUBLE;
    }
    // SAFETY: the caller's contract.
    unsafe { printf_fp_conv(fp, &fi, val, conv) }
}

/// `printf_size (fp, info, args)`: print a floating-point number scaled to units of 1024 (conversion in lower
/// case: 'k', 'm', 'g' ...) or 1000 (upper case: 'K', 'M', 'G' ...), as `%f` followed by the unit letter (a space
/// for none). Register it with `register_printf_function ('b', printf_size, printf_size_info)`.
///
/// # Safety
/// As `__printf_fp`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn printf_size(fp: *mut File, info: *const PrintfInfo, args: *const *const c_void) -> c_int {
    // SAFETY: the caller's contract (this and the reads of the argument below).
    let info = unsafe { &*info };
    let upper = (info.spec as u8).is_ascii_uppercase() && info.spec < 256;
    let tag: &[u8] = if upper { b" KMGTPEZY" } else { b" kmgtpezy" };
    let divisor: i32 = if upper { 1000 } else { 1024 };
    let mut ti = 0usize;
    let mut is_neg = false;
    let mut special: Option<&[u8; 3]> = None;
    // SAFETY: as above.
    let a0 = unsafe { *args };
    let val: Val;
    if info.has(INFO_LONG_DOUBLE) {
        // SAFETY: as above: a long double (16 bytes) at `a0`.
        let mut b = unsafe { *(a0 as *const [u8; 16]) };
        let exp = u16::from_le_bytes([b[8], b[9]]) & 0x7fff;
        let mant = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        if exp == 0x7fff {
            if mant << 1 != 0 {
                special = Some(b"nan");
            } else {
                is_neg = b[9] & 0x80 != 0;
                special = Some(b"inf");
            }
        } else {
            while x87::ge(&b, divisor) && ti + 1 < tag.len() {
                x87::div(&mut b, divisor);
                ti += 1;
            }
        }
        val = Val::LD(b);
    } else {
        // SAFETY: as above: a double at `a0`.
        let mut d = unsafe { *(a0 as *const f64) };
        if d.is_nan() {
            special = Some(b"nan");
        } else if d.is_infinite() {
            is_neg = d.is_sign_negative();
            special = Some(b"inf");
        } else {
            while d >= f64::from(divisor) && ti + 1 < tag.len() {
                d /= f64::from(divisor);
                ti += 1;
            }
        }
        val = Val::D(d);
    }
    let mut done: c_int = 0;
    if let Some(sp) = special {
        let mut width = if info.prec > info.width { info.prec } else { info.width };
        if is_neg || info.has(INFO_SHOWSIGN) || info.has(INFO_SPACE) {
            width -= 1;
        }
        width -= 3;
        if !info.has(INFO_LEFT) && width > 0 {
            // SAFETY: the caller's contract: `fp` is the handler's open stream.
            if !unsafe { fpad(fp, width as usize) } {
                return -1;
            }
            done += width;
        }
        let sign: &[u8] = if is_neg {
            b"-"
        } else if info.has(INFO_SHOWSIGN) {
            b"+"
        } else if info.has(INFO_SPACE) {
            b" "
        } else {
            b""
        };
        // SAFETY: the caller's contract: `fp` is the handler's open stream (both writes).
        if !unsafe { fput(fp, sign) } || !unsafe { fput(fp, sp) } {
            return -1;
        }
        done += sign.len() as c_int + 3;
        if info.has(INFO_LEFT) && width > 0 {
            // SAFETY: the caller's contract: `fp` is the handler's open stream.
            if !unsafe { fpad(fp, width as usize) } {
                return -1;
            }
            done += width;
        }
        return done;
    }
    let mut fp_info = *info;
    fp_info.spec = i32::from(b'f');
    fp_info.prec = if info.prec < 0 { 3 } else { info.prec };
    if fp_info.has(INFO_LEFT) && fp_info.pad == i32::from(b' ') {
        // the unit goes before the padding spaces
        fp_info.width = 0;
        // SAFETY: the caller's contract.
        done = unsafe { printf_fp_f(fp, &fp_info, val) };
        if done > 0 {
            // SAFETY: the caller's contract.
            if !unsafe { fput(fp, &tag[ti..ti + 1]) } {
                return -1;
            }
            done += 1;
            if info.width > done {
                // SAFETY: the caller's contract: `fp` is the handler's open stream.
                if !unsafe { fpad(fp, (info.width - done) as usize) } {
                    return -1;
                }
                done = info.width;
            }
        }
    } else {
        fp_info.width = info.width - 1;
        // SAFETY: the caller's contract.
        done = unsafe { printf_fp_f(fp, &fp_info, val) };
        if done > 0 {
            // SAFETY: the caller's contract.
            if !unsafe { fput(fp, &tag[ti..ti + 1]) } {
                return -1;
            }
            done += 1;
        }
    }
    done
}

/// `printf_size_info (info, n, argtypes)`: the arginfo function for `printf_size`: one double (or long double).
///
/// # Safety
/// `info` is a valid `struct printf_info`; `argtypes` has room for `n` types.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn printf_size_info(info: *const PrintfInfo, n: usize, argtypes: *mut c_int) -> c_int {
    if n >= 1 {
        // SAFETY: the caller's contract.
        let long = unsafe { (*info).has(INFO_LONG_DOUBLE) };
        // SAFETY: the caller's contract: room for at least one type.
        unsafe { *argtypes = PA_DOUBLE | if long { PA_FLAG_LONG_DOUBLE } else { 0 } };
    }
    1
}
