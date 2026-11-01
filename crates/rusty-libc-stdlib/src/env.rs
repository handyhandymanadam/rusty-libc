//! stdlib.h: the environment (getenv, setenv, unsetenv, putenv, clearenv).
//!
//! `environ` itself is defined by the startup code and read through `rusty_libc_core::env`. Ownership
//! follows glibc: the array is heap-allocated on the first change (the initial one lives on the
//! process stack) and grown with realloc afterwards; strings made by `setenv` are copied and never
//! freed (a pointer from `getenv` stays valid); `putenv` keeps the caller's pointer.
//!
//! Shape (BRIEF-UNSAFE U2): the arrays setenv makes are `&'static [AtomicPtr]` (zero-filled, never freed), listed in a
//! `SyncCell` used only under `ENV_LOCK` ([`EnvLock`] is the proof); whatever array `environ` points to is walked with
//! [`EnvCur`], a cursor that reads an entry only after seeing the one before it is not NULL (the array's own terminator
//! bounds it, as for a C string). What stays unsafe: making a cursor from `environ` (the process-wide C contract: NULL or
//! a NULL-terminated array of C strings), the atomic accesses to that array's slots, reading an entry's string, the C
//! string arguments, and the allocation of a new array.
use crate::zstr::ZStr;
use core::ffi::c_char;
use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, Ordering};
use rusty_libc_core::{Errno, SyncCell, errno};

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;

/// The arrays setenv has made for `environ`, newest first (glibc 2.43's `__environ_array_list`). An array is never freed
/// or shrunk: a program that kept an old `environ` value, or a thread still scanning one, keeps seeing valid memory, and a
/// program that assigns `environ` its own array and then calls setenv gets the entries copied into the newest array.
struct EnvArray {
    next: Option<&'static EnvArray>,
    array: &'static [AtomicPtr<c_char>],
}
/// The newest array (only under `ENV_LOCK`: see [`EnvLock`]).
static ARRAY_LIST: SyncCell<Option<&'static EnvArray>> = SyncCell::new(None);
/// setenv, putenv, unsetenv and clearenv are serialised; getenv takes no lock.
static ENV_LOCK: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();

/// `ENV_LOCK` held (or the process has one thread): the list of arrays may be read and changed.
struct EnvLock<'a>(#[allow(dead_code)] rusty_libc_core::lock::Guard<'a>);

impl EnvLock<'_> {
    fn take() -> EnvLock<'static> {
        EnvLock(ENV_LOCK.guard())
    }
    fn head(&self) -> Option<&'static EnvArray> {
        // SAFETY: ARRAY_LIST is only touched with ENV_LOCK held, which `self` proves.
        unsafe { ARRAY_LIST.read() }
    }
    fn set_head(&self, a: &'static EnvArray) {
        // SAFETY: as in `head`.
        unsafe { ARRAY_LIST.write(Some(a)) }
    }
    /// The array of ours that `p` points into, and the index of `p` in it.
    fn array_containing(&self, p: *const AtomicPtr<c_char>) -> Option<(&'static EnvArray, usize)> {
        let mut a = self.head();
        while let Some(arr) = a {
            if arr.array.as_ptr_range().contains(&p) {
                return Some((arr, (p as usize - arr.array.as_ptr() as usize) / size_of::<AtomicPtr<c_char>>()));
            }
            a = arr.next;
        }
        None
    }
    /// A new zero-filled array with room for `required` pointers, put at the head of the list (None if out of memory).
    fn new_array(&self, required: usize) -> Option<&'static EnvArray> {
        let head = self.head();
        let new_size = match head {
            Some(h) if h.array.len() * 2 >= required => h.array.len() * 2,
            _ => required + 16,
        };
        // zero-filled, so that a concurrent getenv sees only valid or null pointers
        let p = crate::cmem::calloc(new_size, size_of::<*mut c_char>());
        if p.is_null() {
            return None;
        }
        // SAFETY: `new_size` zeroed pointer-sized slots of a fresh block, never freed: zero bytes are a valid (null)
        // AtomicPtr, and the block is only reached through this slice (and through `environ`, atomically) from now on.
        let array = unsafe { core::slice::from_raw_parts(p.cast::<AtomicPtr<c_char>>(), new_size) };
        let node = crate::cmem::malloc(size_of::<EnvArray>()).cast::<EnvArray>();
        if node.is_null() {
            // SAFETY: the block from above, not published anywhere.
            unsafe { crate::cmem::free(p) };
            return None;
        }
        // SAFETY: a fresh block of the right size (malloc's alignment suits any type).
        unsafe { node.write(EnvArray { next: head, array }) };
        // SAFETY: initialised just above; never freed or written again, so a shared 'static borrow is sound.
        let node: &'static EnvArray = unsafe { &*node };
        self.set_head(node);
        Some(node)
    }
}

/// The current value of `environ`.
#[inline]
fn environ_now() -> *mut *mut c_char {
    // SAFETY: a plain read of the process-wide variable (rusty_libc_core::env's relaxed load).
    unsafe { rusty_libc_core::env::load_environ() }
}

/// Publish a new `environ` (callers hold ENV_LOCK).
#[inline]
fn set_environ(p: *mut *mut c_char, order: Ordering) {
    // SAFETY: `environ` is a pointer-sized, aligned variable that is only ever accessed atomically by this library.
    unsafe { AtomicPtr::from_ptr(&raw mut environ) }.store(p, order);
}

/// A position in a NULL-terminated array of entry pointers (the array `environ` points to).
///
/// Invariant: slots `[0, pos]` are readable and writable for `'a` and slots `[0, pos)` were not NULL when the cursor passed
/// them (they stay non-NULL: the only writer, under ENV_LOCK, moves entries back and puts the NULL one slot earlier,
/// which is behind every cursor still in use).
#[derive(Clone, Copy)]
struct EnvCur {
    base: *mut *mut c_char,
    pos: usize,
}

impl EnvCur {
    /// # Safety
    /// `base` is not NULL and points to a NULL-terminated array of C strings that stays valid (as `environ` must: the
    /// process-wide C contract).
    unsafe fn new(base: *mut *mut c_char) -> EnvCur {
        EnvCur { base, pos: 0 }
    }
    #[inline]
    fn slot(&self, i: usize) -> &AtomicPtr<c_char> {
        debug_assert!(i <= self.pos + 1);
        let p = self.base.wrapping_add(i);
        // SAFETY: slot `i` is inside the array (the invariant covers `i <= pos`; `pos + 1` is used only right after the
        // entry at `pos` was seen not NULL), aligned, and every access to the slots is atomic.
        unsafe { AtomicPtr::from_ptr(p) }
    }
    /// The entry at the cursor (NULL at the end of the array).
    #[inline]
    fn cur(&self) -> *mut c_char {
        self.slot(self.pos).load(Ordering::Relaxed)
    }
    /// The entry `i` places from the start, for `i` not after the cursor.
    #[inline]
    fn get(&self, i: usize) -> *mut c_char {
        self.slot(i.min(self.pos)).load(Ordering::Relaxed)
    }
    /// The entry at the cursor, stepping over it; None (no move) at the end. One load per entry, and the step depends
    /// on a branch, not on the loaded value (a branchless conditional step made the next load wait for this one: 2x the
    /// time of setenv + unsetenv).
    #[inline]
    fn next_entry(&mut self) -> Option<*mut c_char> {
        let e = self.cur();
        if e.is_null() {
            return None;
        }
        self.pos += 1;
        Some(e)
    }
    /// Put `v` (a C string, never NULL) at the cursor.
    #[inline]
    fn set_cur(&self, v: *mut c_char) {
        self.slot(self.pos).store(v, Ordering::Release);
    }
    /// Remove the entry at the cursor (not NULL), keeping the order of the rest: later pointers are moved back one at a time
    /// with release stores, and the counter a concurrent `getenv` checks goes up after each move (glibc's unsetenv). The
    /// cursor then sits on the entry that followed.
    fn remove_cur(&self) {
        let mut dp = *self;
        loop {
            // the entry at dp is not NULL (the one removed, or one just moved there), so dp + 1 is inside the array
            let next = dp.slot(dp.pos + 1).load(Ordering::Relaxed);
            dp.slot(dp.pos).store(next, Ordering::Release);
            let c = rusty_libc_core::env::ENV_COUNTER.load(Ordering::Relaxed);
            rusty_libc_core::env::ENV_COUNTER.store(c + 1, Ordering::Release);
            if next.is_null() {
                break;
            }
            dp.pos += 1;
        }
    }
    /// The slot address at the cursor (for finding which array it is in).
    fn slot_ptr(&self, i: usize) -> *const AtomicPtr<c_char> {
        self.base.wrapping_add(i).cast()
    }
}

/// Does the entry `s` ("NAME=value") belong to `name` (no `=` or NUL in it)?
fn entry_is(s: *const c_char, name: &[u8]) -> bool {
    // SAFETY: every entry of the environment is a C string (the process-wide C contract), not NULL here.
    let mut z = unsafe { ZStr::new(s.cast::<u8>()) };
    for &c in name {
        if z.cur() != c {
            return false;
        }
        z.bump();
    }
    z.cur() == b'='
}

/// glibc's `__add_to_environ`: set `name` to `value` (a copy is made), or put the caller's `combined` string ("NAME=value")
/// in the environment as it is; an existing entry is replaced only with `replace`.
fn add_to_environ(name: &[u8], value: &[u8], combined: Option<*mut c_char>, replace: bool) -> Result<(), Errno> {
    // the copy of the string is made before the lock, as in glibc
    let (np_new, made) = match combined {
        Some(c) => (c, false),
        None => {
            let total = name.len().checked_add(value.len()).and_then(|t| t.checked_add(2)).ok_or(Errno(ENOMEM))?;
            let s = crate::cmem::malloc(total);
            if s.is_null() {
                return Err(Errno(ENOMEM));
            }
            // SAFETY: a fresh block of `total` bytes, ours.
            let b = unsafe { rusty_libc_core::ffi::bytes_mut(s, total) };
            b[..name.len()].copy_from_slice(name);
            b[name.len()] = b'=';
            b[name.len() + 1..total - 1].copy_from_slice(value);
            b[total - 1] = 0;
            (s.cast::<c_char>(), true)
        }
    };
    let drop_copy = || {
        if made {
            // SAFETY: our copy from above, never published.
            unsafe { crate::cmem::free(np_new) };
        }
    };
    let lk = EnvLock::take();
    let start = environ_now();
    let mut replace = replace;
    let mut result_environ = start;
    // where the entry goes: a slot of the array environ points to (found or at its end), or of one of our arrays
    enum Slot {
        Theirs(EnvCur),
        Ours(&'static AtomicPtr<c_char>),
    }
    let mut cur = None;
    if !start.is_null() {
        // SAFETY: environ is NULL or a NULL-terminated array of C strings (the process-wide C contract).
        let mut c = unsafe { EnvCur::new(start) };
        loop {
            let at = c;
            match c.next_entry() {
                Some(e) if !entry_is(e, name) => {}
                _ => {
                    c = at; // on the matching entry, or on the NULL at the end
                    break;
                }
            }
        }
        cur = Some(c);
    }
    let slot = match cur {
        Some(c) if !c.cur().is_null() => Slot::Theirs(c),
        _ => {
            // the scan reached the end: the entry is new
            replace = true;
            let used = cur.map_or(0, |c| c.pos);
            let required = used + 2; // the new entry and the NULL
            // (room is judged in the array `environ` points into: it may be an older, smaller one that a program put back)
            match cur.and_then(|c| lk.array_containing(c.slot_ptr(0))) {
                Some((own, at)) if at + used + 1 < own.array.len() => {
                    // the array is ours and has room: the end is the slot; the NULL after it covers a shorter earlier use
                    own.array[at + used + 1].store(null_mut(), Ordering::Relaxed);
                    Slot::Ours(&own.array[at + used])
                }
                _ => {
                    // copy the entries into an array of ours: the newest if it is big enough, else a new one. The copy runs
                    // forward, which is right when `environ` was moved into one of our arrays (`environ = &environ[1]`)
                    let target = match lk.head() {
                        Some(h) if required <= h.array.len() => Some(h),
                        _ => lk.new_array(required),
                    };
                    let Some(target) = target else {
                        drop_copy();
                        return Err(Errno(ENOMEM));
                    };
                    if let Some(c) = cur {
                        for (i, slot) in target.array[..used].iter().enumerate() {
                            slot.store(c.get(i), Ordering::Release);
                        }
                    }
                    target.array[used + 1].store(null_mut(), Ordering::Relaxed);
                    result_environ = target.array.as_ptr().cast_mut().cast();
                    Slot::Ours(&target.array[used])
                }
            }
        }
    };
    let empty = match &slot {
        Slot::Theirs(c) => c.cur().is_null(),
        Slot::Ours(s) => s.load(Ordering::Relaxed).is_null(),
    };
    if replace || empty {
        match slot {
            Slot::Theirs(c) => c.set_cur(np_new),
            Slot::Ours(s) => s.store(np_new, Ordering::Release),
        }
        set_environ(result_environ, Ordering::Release);
    } else {
        drop_copy(); // an existing entry stays (no overwrite): the copy is not needed
    }
    drop(lk);
    Ok(())
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && !name.contains(&b'=')
}

/// The value of `name` (as bytes, without the NUL), or None. Same lookup as `getenv`.
///
/// # Safety
/// The slice is valid until the entry changes (a putenv string the caller frees or edits); the lifetime is the caller's
/// choice.
pub unsafe fn get<'a>(name: &[u8]) -> Option<&'a [u8]> {
    // SAFETY: getenv only reads the environment block (safe against concurrent changes, see rusty_libc_core::env).
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    // SAFETY: NULL or a C string of the environment, valid for 'a (the caller's contract).
    unsafe { rusty_libc_core::ffi::cstr(p) }.map(core::ffi::CStr::to_bytes)
}

/// setenv(3) with byte slices: `EINVAL` for an empty name or one containing `=`.
pub fn set(name: &[u8], value: &[u8], replace: bool) -> Result<(), Errno> {
    if !valid_name(name) {
        return Err(Errno(EINVAL));
    }
    add_to_environ(name, value, None, replace)
}

/// unsetenv(3) with a byte slice: removes every entry named `name`.
pub fn unset(name: &[u8]) -> Result<(), Errno> {
    if !valid_name(name) {
        return Err(Errno(EINVAL));
    }
    remove_all(name);
    Ok(())
}

/// Remove every entry named `name`, keeping the order of the rest (see [`EnvCur::remove_cur`]).
fn remove_all(name: &[u8]) {
    let lk = EnvLock::take();
    let start = environ_now();
    if start.is_null() {
        return;
    }
    // SAFETY: environ is NULL or a NULL-terminated array of C strings (the process-wide C contract); not NULL here.
    let mut ep = unsafe { EnvCur::new(start) };
    loop {
        let at = ep;
        let Some(entry) = ep.next_entry() else { break };
        if entry_is(entry, name) {
            at.remove_cur();
            // the next entry now sits where this one was: look at it too
            ep = at;
        }
    }
    drop(lk);
}

/// getenv(3).
///
/// # Safety
/// `name` is a C string; the result points into the environment.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    // SAFETY: `name` is a C string (the caller's contract).
    let n = unsafe { rusty_libc_core::ffi::cstr_bytes(name) };
    // glibc: an empty name finds nothing, even next to an entry like "=x"
    if n.is_empty() {
        return null_mut();
    }
    // SAFETY: getenv only reads the environment block (safe against concurrent changes, see rusty_libc_core::env).
    unsafe { rusty_libc_core::env::getenv(n) }
}

/// secure_getenv(3): NULL in a set-user-ID/set-group-ID process (the kernel's AT_SECURE flag, as in glibc).
///
/// # Safety
/// As `getenv`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    use rusty_libc_core::unistd::{getegid, geteuid, getgid, getuid};
    // the kernel's AT_SECURE flag, kept by the startup code; before that (tests) the real and effective ids
    let secure = rusty_libc_core::lock::at_secure().unwrap_or_else(|| getuid() != geteuid() || getgid() != getegid());
    // SAFETY: the caller's contract is getenv's.
    if secure { null_mut() } else { unsafe { getenv(name) } }
}

/// Store a Result as a C return value (0, or -1 with errno).
fn ret(r: Result<(), Errno>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(Errno(e)) => {
            errno::set(e);
            -1
        }
    }
}

/// setenv(3).
///
/// # Safety
/// `name` and `value` are C strings.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setenv(name: *const c_char, value: *const c_char, overwrite: i32) -> i32 {
    // SAFETY: NULL or a C string (the caller's contract).
    let n = unsafe { rusty_libc_core::ffi::cstr(name) };
    // SAFETY: as above.
    let v = unsafe { rusty_libc_core::ffi::cstr(value) };
    let (Some(n), Some(v)) = (n, v) else {
        errno::set(EINVAL);
        return -1;
    };
    ret(set(n.to_bytes(), v.to_bytes(), overwrite != 0))
}

/// unsetenv(3).
///
/// # Safety
/// `name` is a C string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> i32 {
    // SAFETY: NULL or a C string (the caller's contract).
    let Some(n) = (unsafe { rusty_libc_core::ffi::cstr(name) }) else {
        errno::set(EINVAL);
        return -1;
    };
    ret(unset(n.to_bytes()))
}

/// putenv(3): the entry `string` ("NAME=value") is used as is, not copied, so it must stay valid
/// and the caller must not free it while it is in the environment. Without a `=` the name is
/// removed (the glibc behaviour).
///
/// # Safety
/// `string` is a writable C string that outlives its place in the environment.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> i32 {
    // SAFETY: NULL or a C string (the caller's contract).
    let Some(s) = (unsafe { rusty_libc_core::ffi::cstr(string) }) else {
        errno::set(EINVAL);
        return -1;
    };
    let s = s.to_bytes();
    let Some(eq) = s.iter().position(|&c| c == b'=') else {
        // glibc calls unsetenv and ignores its result: an empty string leaves errno at EINVAL
        if s.is_empty() {
            errno::set(EINVAL);
        } else {
            remove_all(s);
        }
        return 0;
    };
    ret(add_to_environ(&s[..eq], &[], Some(string), true))
}

/// clearenv(3): drop the whole environment (`environ` becomes NULL; the strings are not freed).
pub fn clear() {
    let lk = EnvLock::take();
    let start = environ_now();
    if let Some((own, at)) = lk.array_containing(start.cast_const().cast()) {
        // zero the entries so that a later setenv reusing the array starts clean, and tell concurrent getenv
        for slot in &own.array[at..] {
            if slot.load(Ordering::Relaxed).is_null() {
                break;
            }
            slot.store(null_mut(), Ordering::Relaxed);
        }
        let c = rusty_libc_core::env::ENV_COUNTER.load(Ordering::Relaxed);
        rusty_libc_core::env::ENV_COUNTER.store(c + 1, Ordering::Release);
    }
    set_environ(null_mut(), Ordering::Relaxed);
    drop(lk);
}

/// clearenv(3).
///
/// # Safety
/// Always safe to call (unsafe only as a C function).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clearenv() -> i32 {
    clear();
    0
}

/// Tests that touch the process environment, the working directory or signal dispositions take this
/// lock, so they do not disturb each other.
#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    crate::LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, clippy::deref_addrof)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};

    mod host {
        use core::ffi::c_char;
        unsafe extern "C" {
            pub fn getenv(name: *const c_char) -> *mut c_char;
            pub fn secure_getenv(name: *const c_char) -> *mut c_char;
            pub fn setenv(name: *const c_char, value: *const c_char, overwrite: i32) -> i32;
            pub fn unsetenv(name: *const c_char) -> i32;
            pub fn putenv(s: *mut c_char) -> i32;
            pub fn clearenv() -> i32;
            pub fn __errno_location() -> *mut i32;
        }
    }

    /// The whole environment as owned byte strings, in order.
    unsafe fn snapshot() -> Vec<Vec<u8>> {
        unsafe {
            let mut v = Vec::new();
            let mut e = environ;
            if !e.is_null() {
                while !(*e).is_null() {
                    v.push(CStr::from_ptr(*e).to_bytes().to_vec());
                    e = e.add(1);
                }
            }
            v
        }
    }

    /// Run `f` with `environ` replaced by `init` (a NULL-terminated array built here, or NULL for an
    /// empty environment), then put the real one back.
    fn with_env<R>(init: Option<&[&str]>, f: impl FnOnce() -> R) -> R {
        let saved = unsafe { environ };
        unsafe {
            environ = match init {
                None => null_mut(),
                Some(items) => {
                    let mut arr: Vec<*mut c_char> = items.iter().map(|s| CString::new(*s).unwrap().into_raw()).collect();
                    arr.push(null_mut());
                    Box::leak(arr.into_boxed_slice()).as_mut_ptr()
                }
            };
        }
        let r = f();
        unsafe { environ = saved };
        r
    }

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    #[derive(Clone, Debug)]
    enum Op {
        Set(String, String, i32),
        Unset(String),
        Put(String),
        Get(String),
        Clear,
    }

    fn gen_ops(seed: u64, n: usize) -> Vec<Op> {
        let names = ["A", "B", "CC", "D_1", "E", "", "A=B", "path", "PATH", "x y"];
        let vals = ["", "1", "two", "a=b", "long long value with spaces", "=="];
        let mut r = Rng(seed.wrapping_mul(2654435761).wrapping_add(88172645463325252));
        (0..n)
            .map(|_| {
                let name = names[r.below(names.len())].to_string();
                let val = vals[r.below(vals.len())].to_string();
                match r.below(10) {
                    0..=3 => Op::Set(name, val, r.below(2) as i32),
                    4 | 5 => Op::Unset(name),
                    6 | 7 => {
                        if r.below(4) == 0 {
                            Op::Put(name)
                        } else {
                            Op::Put(format!("{name}={val}"))
                        }
                    }
                    8 => Op::Get(name),
                    _ => {
                        if r.below(6) == 0 {
                            Op::Clear
                        } else {
                            Op::Get(name)
                        }
                    }
                }
            })
            .collect()
    }

    /// Apply `ops` with either our functions or the host's; record every result and the full
    /// environment after each step.
    fn run_ops(ours: bool, ops: &[Op]) -> Vec<String> {
        let mut log = Vec::new();
        unsafe {
            for op in ops {
                let (ret, err): (String, i32);
                let set_errno = |v: i32| {
                    if ours { errno::set(v) } else { *host::__errno_location() = v }
                };
                let get_errno = || if ours { errno::get() } else { *host::__errno_location() };
                set_errno(0);
                match op {
                    Op::Set(n, v, o) => {
                        let (n, v) = (CString::new(n.as_str()).unwrap(), CString::new(v.as_str()).unwrap());
                        let r = if ours { setenv(n.as_ptr(), v.as_ptr(), *o) } else { host::setenv(n.as_ptr(), v.as_ptr(), *o) };
                        (ret, err) = (r.to_string(), get_errno());
                    }
                    Op::Unset(n) => {
                        let n = CString::new(n.as_str()).unwrap();
                        let r = if ours { unsetenv(n.as_ptr()) } else { host::unsetenv(n.as_ptr()) };
                        (ret, err) = (r.to_string(), get_errno());
                    }
                    Op::Put(s) => {
                        let s = CString::new(s.as_str()).unwrap().into_raw(); // the environment keeps it
                        let r = if ours { putenv(s) } else { host::putenv(s) };
                        (ret, err) = (r.to_string(), get_errno());
                    }
                    Op::Get(n) => {
                        let n = CString::new(n.as_str()).unwrap();
                        let p = if ours { getenv(n.as_ptr()) } else { host::getenv(n.as_ptr()) };
                        let s = if p.is_null() { "NULL".to_string() } else { CStr::from_ptr(p).to_string_lossy().into_owned() };
                        (ret, err) = (s, 0);
                    }
                    Op::Clear => {
                        let r = if ours { clearenv() } else { host::clearenv() };
                        (ret, err) = (r.to_string(), 0);
                    }
                }
                let env: Vec<String> = snapshot().iter().map(|e| String::from_utf8_lossy(e).into_owned()).collect();
                log.push(format!("{op:?} -> {ret} errno {err} env {env:?}"));
            }
        }
        log
    }

    #[test]
    fn random_sequences_match_glibc() {
        let _g = test_lock();
        let inits: [Option<&[&str]>; 3] = [None, Some(&["A=old", "Z=zed", "A=dup", "PATH=/bin"]), Some(&["B=1"])];
        for seed in 1..=300u64 {
            let ops = gen_ops(seed, 60);
            let init = inits[(seed % 3) as usize];
            let mine = with_env(init, || run_ops(true, &ops));
            let theirs = with_env(init, || run_ops(false, &ops));
            for (i, (a, b)) in mine.iter().zip(theirs.iter()).enumerate() {
                assert_eq!(a, b, "seed {seed} step {i}");
            }
        }
    }

    #[test]
    fn setenv_copies_putenv_keeps_pointer() {
        let _g = test_lock();
        with_env(None, || unsafe {
            let mut name = *b"OWN_T\0";
            let mut val = *b"first\0";
            assert_eq!(setenv(name.as_ptr().cast(), val.as_ptr().cast(), 1), 0);
            let got = getenv(name.as_ptr().cast());
            assert_eq!(CStr::from_ptr(got).to_bytes(), b"first");
            val[0] = b'X';
            name[0] = b'Q';
            core::hint::black_box((&name, &val));
            assert_eq!(CStr::from_ptr(getenv(c"OWN_T".as_ptr())).to_bytes(), b"first", "setenv must copy");
            // putenv: same pointer comes back, and later edits show through
            let mut s = CString::new("PUT_T=abc").unwrap().into_bytes_with_nul();
            assert_eq!(putenv(s.as_mut_ptr().cast()), 0);
            let g = getenv(c"PUT_T".as_ptr());
            assert_eq!(g as *const u8, s.as_ptr().add(6));
            s[6] = b'Z';
            assert_eq!(CStr::from_ptr(getenv(c"PUT_T".as_ptr())).to_bytes(), b"Zbc");
            // overwrite=0 keeps, overwrite=1 replaces
            assert_eq!(setenv(c"OWN_T".as_ptr(), c"second".as_ptr(), 0), 0);
            assert_eq!(CStr::from_ptr(getenv(c"OWN_T".as_ptr())).to_bytes(), b"first");
            assert_eq!(setenv(c"OWN_T".as_ptr(), c"second".as_ptr(), 1), 0);
            assert_eq!(CStr::from_ptr(getenv(c"OWN_T".as_ptr())).to_bytes(), b"second");
        });
    }

    #[test]
    fn invalid_names_and_growth() {
        let _g = test_lock();
        with_env(None, || unsafe {
            for bad in [c"", c"A=B", c"="] {
                errno::set(0);
                assert_eq!(setenv(bad.as_ptr(), c"v".as_ptr(), 1), -1);
                assert_eq!(errno::get(), EINVAL);
                errno::set(0);
                assert_eq!(unsetenv(bad.as_ptr()), -1);
                assert_eq!(errno::get(), EINVAL);
            }
            // many variables force several reallocations; all stay findable
            for i in 0..500 {
                let n = CString::new(format!("GROW_{i}")).unwrap();
                let v = CString::new(format!("val{i}")).unwrap();
                assert_eq!(setenv(n.as_ptr(), v.as_ptr(), 1), 0);
            }
            assert_eq!(snapshot().len(), 500);
            for i in (0..500).step_by(7) {
                let n = CString::new(format!("GROW_{i}")).unwrap();
                assert_eq!(CStr::from_ptr(getenv(n.as_ptr())).to_str().unwrap(), format!("val{i}"));
            }
            assert_eq!(clearenv(), 0);
            assert!(environ.is_null());
            assert!(getenv(c"GROW_1".as_ptr()).is_null());
            assert_eq!(setenv(c"AFTER".as_ptr(), c"1".as_ptr(), 1), 0);
            assert_eq!(snapshot(), vec![b"AFTER=1".to_vec()]);
        });
    }

    #[test]
    fn unsetenv_removes_every_match_in_the_original_array() {
        let _g = test_lock();
        with_env(Some(&["A=1", "B=2", "A=3", "AB=4", "A=5"]), || unsafe {
            assert_eq!(unsetenv(c"A".as_ptr()), 0);
            assert_eq!(snapshot(), vec![b"B=2".to_vec(), b"AB=4".to_vec()]);
            assert_eq!(unsetenv(c"NOPE".as_ptr()), 0);
        });
    }

    #[test]
    fn secure_getenv_matches_when_not_setuid() {
        let _g = test_lock();
        with_env(Some(&["SG=1"]), || unsafe {
            let a = secure_getenv(c"SG".as_ptr());
            let b = host::secure_getenv(c"SG".as_ptr());
            assert_eq!(a.is_null(), b.is_null());
            assert_eq!(CStr::from_ptr(a).to_bytes(), b"1");
            assert!(secure_getenv(c"SG_MISSING".as_ptr()).is_null());
        });
    }

    #[test]
    fn rust_api() {
        let _g = test_lock();
        with_env(None, || unsafe {
            set(b"RA", b"x", true).unwrap();
            assert_eq!(get(b"RA"), Some(&b"x"[..]));
            assert_eq!(set(b"", b"x", true), Err(Errno(EINVAL)));
            unset(b"RA").unwrap();
            assert_eq!(get(b"RA"), None);
        });
    }
}
