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

struct EnvArray {
    next: Option<&'static EnvArray>,
    array: &'static [AtomicPtr<c_char>],
}
static ARRAY_LIST: SyncCell<Option<&'static EnvArray>> = SyncCell::new(None);
static ENV_LOCK: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();

struct EnvLock<'a>(#[allow(dead_code)] rusty_libc_core::lock::Guard<'a>);

impl EnvLock<'_> {
    fn take() -> EnvLock<'static> {
        EnvLock(ENV_LOCK.guard())
    }
    fn head(&self) -> Option<&'static EnvArray> {
        unsafe { ARRAY_LIST.read() }
    }
    fn set_head(&self, a: &'static EnvArray) {
        unsafe { ARRAY_LIST.write(Some(a)) }
    }
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
    fn new_array(&self, required: usize) -> Option<&'static EnvArray> {
        let head = self.head();
        let new_size = match head {
            Some(h) if h.array.len() * 2 >= required => h.array.len() * 2,
            _ => required + 16,
        };
        let p = crate::cmem::calloc(new_size, size_of::<*mut c_char>());
        if p.is_null() {
            return None;
        }
        let array = unsafe { core::slice::from_raw_parts(p.cast::<AtomicPtr<c_char>>(), new_size) };
        let node = crate::cmem::malloc(size_of::<EnvArray>()).cast::<EnvArray>();
        if node.is_null() {
            unsafe { crate::cmem::free(p) };
            return None;
        }
        unsafe { node.write(EnvArray { next: head, array }) };
        let node: &'static EnvArray = unsafe { &*node };
        self.set_head(node);
        Some(node)
    }
}

#[inline]
fn environ_now() -> *mut *mut c_char {
    unsafe { rusty_libc_core::env::load_environ() }
}

#[inline]
fn set_environ(p: *mut *mut c_char, order: Ordering) {
    unsafe { AtomicPtr::from_ptr(&raw mut environ) }.store(p, order);
}

#[derive(Clone, Copy)]
struct EnvCur {
    base: *mut *mut c_char,
    pos: usize,
}

impl EnvCur {
    unsafe fn new(base: *mut *mut c_char) -> EnvCur {
        EnvCur { base, pos: 0 }
    }
    #[inline]
    fn slot(&self, i: usize) -> &AtomicPtr<c_char> {
        debug_assert!(i <= self.pos + 1);
        let p = self.base.wrapping_add(i);
        unsafe { AtomicPtr::from_ptr(p) }
    }
    #[inline]
    fn cur(&self) -> *mut c_char {
        self.slot(self.pos).load(Ordering::Relaxed)
    }
    #[inline]
    fn get(&self, i: usize) -> *mut c_char {
        self.slot(i.min(self.pos)).load(Ordering::Relaxed)
    }
    #[inline]
    fn next_entry(&mut self) -> Option<*mut c_char> {
        let e = self.cur();
        if e.is_null() {
            return None;
        }
        self.pos += 1;
        Some(e)
    }
    #[inline]
    fn set_cur(&self, v: *mut c_char) {
        self.slot(self.pos).store(v, Ordering::Release);
    }
    fn remove_cur(&self) {
        let mut dp = *self;
        loop {
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
    fn slot_ptr(&self, i: usize) -> *const AtomicPtr<c_char> {
        self.base.wrapping_add(i).cast()
    }
}

fn entry_is(s: *const c_char, name: &[u8]) -> bool {
    let mut z = unsafe { ZStr::new(s.cast::<u8>()) };
    for &c in name {
        if z.cur() != c {
            return false;
        }
        z.bump();
    }
    z.cur() == b'='
}

fn add_to_environ(name: &[u8], value: &[u8], combined: Option<*mut c_char>, replace: bool) -> Result<(), Errno> {
    let (np_new, made) = match combined {
        Some(c) => (c, false),
        None => {
            let total = name.len().checked_add(value.len()).and_then(|t| t.checked_add(2)).ok_or(Errno(ENOMEM))?;
            let s = crate::cmem::malloc(total);
            if s.is_null() {
                return Err(Errno(ENOMEM));
            }
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
            unsafe { crate::cmem::free(np_new) };
        }
    };
    let lk = EnvLock::take();
    let start = environ_now();
    let mut replace = replace;
    let mut result_environ = start;
    enum Slot {
        Theirs(EnvCur),
        Ours(&'static AtomicPtr<c_char>),
    }
    let mut cur = None;
    if !start.is_null() {
        let mut c = unsafe { EnvCur::new(start) };
        loop {
            let at = c;
            match c.next_entry() {
                Some(e) if !entry_is(e, name) => {}
                _ => {
                    c = at;
                    break;
                }
            }
        }
        cur = Some(c);
    }
    let slot = match cur {
        Some(c) if !c.cur().is_null() => Slot::Theirs(c),
        _ => {
            replace = true;
            let used = cur.map_or(0, |c| c.pos);
            let required = used + 2;
            match cur.and_then(|c| lk.array_containing(c.slot_ptr(0))) {
                Some((own, at)) if at + used + 1 < own.array.len() => {
                    own.array[at + used + 1].store(null_mut(), Ordering::Relaxed);
                    Slot::Ours(&own.array[at + used])
                }
                _ => {
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
        drop_copy();
    }
    drop(lk);
    Ok(())
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && !name.contains(&b'=')
}

pub unsafe fn get<'a>(name: &[u8]) -> Option<&'a [u8]> {
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    unsafe { rusty_libc_core::ffi::cstr(p) }.map(core::ffi::CStr::to_bytes)
}

pub fn set(name: &[u8], value: &[u8], replace: bool) -> Result<(), Errno> {
    if !valid_name(name) {
        return Err(Errno(EINVAL));
    }
    add_to_environ(name, value, None, replace)
}

pub fn unset(name: &[u8]) -> Result<(), Errno> {
    if !valid_name(name) {
        return Err(Errno(EINVAL));
    }
    remove_all(name);
    Ok(())
}

fn remove_all(name: &[u8]) {
    let lk = EnvLock::take();
    let start = environ_now();
    if start.is_null() {
        return;
    }
    let mut ep = unsafe { EnvCur::new(start) };
    loop {
        let at = ep;
        let Some(entry) = ep.next_entry() else { break };
        if entry_is(entry, name) {
            at.remove_cur();
            ep = at;
        }
    }
    drop(lk);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    let n = unsafe { rusty_libc_core::ffi::cstr_bytes(name) };
    if n.is_empty() {
        return null_mut();
    }
    unsafe { rusty_libc_core::env::getenv(n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    use rusty_libc_core::unistd::{getegid, geteuid, getgid, getuid};
    let secure = rusty_libc_core::lock::at_secure().unwrap_or_else(|| getuid() != geteuid() || getgid() != getegid());
    if secure { null_mut() } else { unsafe { getenv(name) } }
}

fn ret(r: Result<(), Errno>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(Errno(e)) => {
            errno::set(e);
            -1
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setenv(name: *const c_char, value: *const c_char, overwrite: i32) -> i32 {
    let n = unsafe { rusty_libc_core::ffi::cstr(name) };
    let v = unsafe { rusty_libc_core::ffi::cstr(value) };
    let (Some(n), Some(v)) = (n, v) else {
        errno::set(EINVAL);
        return -1;
    };
    ret(set(n.to_bytes(), v.to_bytes(), overwrite != 0))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> i32 {
    let Some(n) = (unsafe { rusty_libc_core::ffi::cstr(name) }) else {
        errno::set(EINVAL);
        return -1;
    };
    ret(unset(n.to_bytes()))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> i32 {
    let Some(s) = (unsafe { rusty_libc_core::ffi::cstr(string) }) else {
        errno::set(EINVAL);
        return -1;
    };
    let s = s.to_bytes();
    let Some(eq) = s.iter().position(|&c| c == b'=') else {
        if s.is_empty() {
            errno::set(EINVAL);
        } else {
            remove_all(s);
        }
        return 0;
    };
    ret(add_to_environ(&s[..eq], &[], Some(string), true))
}

pub fn clear() {
    let lk = EnvLock::take();
    let start = environ_now();
    if let Some((own, at)) = lk.array_containing(start.cast_const().cast()) {
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clearenv() -> i32 {
    clear();
    0
}

