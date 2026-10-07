use core::ffi::c_char;
use core::ptr::null_mut;
use rusty_libc_core::{Errno, errno, syscall};

unsafe extern "C" {
    static mut environ: *mut *mut c_char;
}

const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;
const SYS_GETGID: usize = 104;
const SYS_GETEGID: usize = 108;

struct EnvArray {
    next: *mut EnvArray,
    array: *mut *mut c_char,
    allocated: usize,
}
static mut ARRAY_LIST: *mut EnvArray = null_mut();
static ENV_LOCK: rusty_libc_core::lock::RawMutex = rusty_libc_core::lock::RawMutex::new();

unsafe fn strlen(s: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(s.cast()) }
}

unsafe fn cstr<'a>(s: *const c_char) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(s.cast(), strlen(s)) }
}

#[inline]
unsafe fn load_entry(ep: *mut *mut c_char) -> *mut c_char {
    unsafe { core::sync::atomic::AtomicPtr::from_ptr(ep).load(core::sync::atomic::Ordering::Relaxed) }
}

#[inline]
unsafe fn store_entry(ep: *mut *mut c_char, v: *mut c_char) {
    unsafe { core::sync::atomic::AtomicPtr::from_ptr(ep).store(v, core::sync::atomic::Ordering::Release) }
}

unsafe fn entry_is(s: *const c_char, name: &[u8]) -> bool {
    unsafe {
        let s = s as *const u8;
        let mut i = 0;
        while i < name.len() && *s.add(i) == name[i] {
            i += 1;
        }
        i == name.len() && *s.add(i) == b'='
    }
}

unsafe fn array_containing(p: *mut *mut c_char) -> *mut EnvArray {
    unsafe {
        let mut a = ARRAY_LIST;
        while !a.is_null() {
            if p >= (*a).array && p < (*a).array.add((*a).allocated) {
                return a;
            }
            a = (*a).next;
        }
        null_mut()
    }
}

unsafe fn in_array_list(p: *mut *mut c_char) -> bool {
    unsafe { !array_containing(p).is_null() }
}

unsafe fn new_array(required: usize) -> *mut EnvArray {
    unsafe {
        let new_size = if ARRAY_LIST.is_null() || (*ARRAY_LIST).allocated * 2 < required { required + 16 } else { (*ARRAY_LIST).allocated * 2 };
        let array: *mut *mut c_char = rusty_libc_malloc::calloc(new_size, core::mem::size_of::<*mut c_char>()).cast();
        if array.is_null() {
            return null_mut();
        }
        let a: *mut EnvArray = rusty_libc_malloc::malloc(core::mem::size_of::<EnvArray>()).cast();
        if a.is_null() {
            rusty_libc_malloc::free(array.cast());
            return null_mut();
        }
        a.write(EnvArray { next: ARRAY_LIST, array, allocated: new_size });
        ARRAY_LIST = a;
        a
    }
}

unsafe fn add_to_environ(name: &[u8], value: &[u8], combined: *mut c_char, replace: bool) -> Result<(), Errno> {
    unsafe {
        let np_new: *mut c_char = if combined.is_null() {
            let total = name.len().checked_add(value.len()).and_then(|t| t.checked_add(2)).ok_or(Errno(ENOMEM))?;
            let s: *mut u8 = rusty_libc_malloc::malloc(total).cast();
            if s.is_null() {
                return Err(Errno(ENOMEM));
            }
            core::ptr::copy_nonoverlapping(name.as_ptr(), s, name.len());
            *s.add(name.len()) = b'=';
            core::ptr::copy_nonoverlapping(value.as_ptr(), s.add(name.len() + 1), value.len());
            *s.add(total - 1) = 0;
            s.cast()
        } else {
            combined
        };
        let g = ENV_LOCK.guard();
        let _ = &g;
        let start = rusty_libc_core::env::load_environ();
        let mut ep = start;
        let mut result_environ = start;
        let mut replace = replace;
        if !ep.is_null() {
            while !load_entry(ep).is_null() && !entry_is(load_entry(ep), name) {
                ep = ep.add(1);
            }
        }
        if ep.is_null() || load_entry(ep).is_null() {
            replace = true;
            let used = if ep.is_null() { 0 } else { ep.offset_from(start) as usize };
            let required = used + 2;
            let own = array_containing(start);
            if !own.is_null() && ep.add(1) < (*own).array.add((*own).allocated) {
                *ep.add(1) = null_mut();
            } else {
                let target = if !ARRAY_LIST.is_null() && required <= (*ARRAY_LIST).allocated { ARRAY_LIST } else { new_array(required) };
                if target.is_null() {
                    if combined.is_null() {
                        rusty_libc_malloc::free(np_new.cast());
                    }
                    return Err(Errno(ENOMEM));
                }
                for i in 0..used {
                    store_entry((*target).array.add(i), load_entry(start.add(i)));
                }
                ep = (*target).array.add(used);
                *ep.add(1) = null_mut();
                result_environ = (*target).array;
            }
        }
        if replace || load_entry(ep).is_null() {
            store_entry(ep, np_new);
            core::sync::atomic::AtomicPtr::from_ptr(core::ptr::addr_of_mut!(environ)).store(result_environ, core::sync::atomic::Ordering::Release);
        } else if combined.is_null() {
            rusty_libc_malloc::free(np_new.cast());
        }
        Ok(())
    }
}

fn valid_name(name: &[u8]) -> bool {
    !name.is_empty() && !name.contains(&b'=')
}

pub unsafe fn get<'a>(name: &[u8]) -> Option<&'a [u8]> {
    unsafe {
        let p = rusty_libc_core::env::getenv(name);
        if p.is_null() { None } else { Some(cstr(p)) }
    }
}

pub unsafe fn set(name: &[u8], value: &[u8], replace: bool) -> Result<(), Errno> {
    unsafe {
        if !valid_name(name) {
            return Err(Errno(EINVAL));
        }
        add_to_environ(name, value, null_mut(), replace)
    }
}

pub unsafe fn unset(name: &[u8]) -> Result<(), Errno> {
    unsafe {
        if !valid_name(name) {
            return Err(Errno(EINVAL));
        }
        remove_all(name);
        Ok(())
    }
}

unsafe fn remove_all(name: &[u8]) {
    unsafe {
        let g = ENV_LOCK.guard();
        let _ = &g;
        let mut ep = rusty_libc_core::env::load_environ();
        if ep.is_null() {
            return;
        }
        loop {
            let entry = load_entry(ep);
            if entry.is_null() {
                break;
            }
            if entry_is(entry, name) {
                let mut dp = ep;
                loop {
                    let next = load_entry(dp.add(1));
                    store_entry(dp, next);
                    let c = rusty_libc_core::env::ENV_COUNTER.load(core::sync::atomic::Ordering::Relaxed);
                    rusty_libc_core::env::ENV_COUNTER.store(c + 1, core::sync::atomic::Ordering::Release);
                    if next.is_null() {
                        break;
                    }
                    dp = dp.add(1);
                }
            } else {
                ep = ep.add(1);
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getenv(name: *const c_char) -> *mut c_char {
    unsafe {
        let n = cstr(name);
        if n.is_empty() { null_mut() } else { rusty_libc_core::env::getenv(n) }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn secure_getenv(name: *const c_char) -> *mut c_char {
    unsafe {
        let secure = syscall::syscall0(syscall::SYS_GETUID) != syscall::syscall0(syscall::SYS_GETEUID)
            || syscall::syscall0(SYS_GETGID) != syscall::syscall0(SYS_GETEGID);
        if secure { null_mut() } else { getenv(name) }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setenv(name: *const c_char, value: *const c_char, overwrite: i32) -> i32 {
    unsafe {
        if name.is_null() || value.is_null() {
            errno::set(EINVAL);
            return -1;
        }
        match set(cstr(name), cstr(value), overwrite != 0) {
            Ok(()) => 0,
            Err(Errno(e)) => {
                errno::set(e);
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn unsetenv(name: *const c_char) -> i32 {
    unsafe {
        if name.is_null() {
            errno::set(EINVAL);
            return -1;
        }
        match unset(cstr(name)) {
            Ok(()) => 0,
            Err(Errno(e)) => {
                errno::set(e);
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putenv(string: *mut c_char) -> i32 {
    unsafe {
        if string.is_null() {
            errno::set(EINVAL);
            return -1;
        }
        let s = cstr(string);
        let Some(eq) = s.iter().position(|&c| c == b'=') else {
            if s.is_empty() {
                errno::set(EINVAL);
            } else {
                remove_all(s);
            }
            return 0;
        };
        match add_to_environ(&s[..eq], &[], string, true) {
            Ok(()) => 0,
            Err(Errno(e)) => {
                errno::set(e);
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn clearenv() -> i32 {
    unsafe {
        let g = ENV_LOCK.guard();
        let _ = &g;
        let start = rusty_libc_core::env::load_environ();
        if in_array_list(start) {
            let mut ep = start;
            while !load_entry(ep).is_null() {
                core::sync::atomic::AtomicPtr::from_ptr(ep).store(null_mut(), core::sync::atomic::Ordering::Relaxed);
                ep = ep.add(1);
            }
            let c = rusty_libc_core::env::ENV_COUNTER.load(core::sync::atomic::Ordering::Relaxed);
            rusty_libc_core::env::ENV_COUNTER.store(c + 1, core::sync::atomic::Ordering::Release);
        }
        core::sync::atomic::AtomicPtr::from_ptr(core::ptr::addr_of_mut!(environ)).store(null_mut(), core::sync::atomic::Ordering::Relaxed);
        0
    }
}

