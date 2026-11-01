//! What the plug-in loader needs from the system: reading a file, listing a directory, the working directory, the
//! `GCONV_PATH` variable and the dynamic loader (`dlopen`, `dlsym`, `dlclose`: the loader's in the shared libc.so.6,
//! the host's in unit tests, absent in the static library).
use crate::heapvec::HeapVec;
use core::ffi::{CStr, c_char, c_int, c_void};
use rusty_libc_core::syscall::{self, SYS_CLOSE, SYS_READ, syscall1, syscall2, syscall3};

const SYS_GETCWD: usize = 79;
const SYS_GETDENTS64: usize = 217;
const O_RDONLY: i32 = 0;
const O_DIRECTORY: i32 = 0o200000;
const O_CLOEXEC: i32 = 0o2000000;

/// `path` (without a NUL) as a C string in a stack buffer; `None` if it does not fit.
fn with_cstr<R>(path: &[u8], f: impl FnOnce(&CStr) -> R) -> Option<R> {
    let mut buf = [0u8; 512];
    let slot = buf.get_mut(..path.len() + 1)?;
    slot[..path.len()].copy_from_slice(path);
    let c = CStr::from_bytes_until_nul(slot).ok()?;
    Some(f(c))
}

fn open(path: &[u8], flags: i32) -> Option<i32> {
    // SAFETY: `c` is NUL-terminated and lives through the call.
    with_cstr(path, |c| unsafe {
        rusty_libc_core::unistd::open(c.as_ptr(), flags, 0)
    })
    .and_then(Result::ok)
}

fn close(fd: i32) {
    // SAFETY: closing a descriptor this module opened and no longer uses.
    unsafe { syscall1(SYS_CLOSE, fd as usize) };
}

/// The whole of the file `path`, or `None` if it cannot be opened or read.
pub(crate) fn read_file(path: &[u8]) -> Option<HeapVec<u8>> {
    let fd = open(path, O_RDONLY | O_CLOEXEC)?;
    let mut text = HeapVec::<u8>::new();
    let mut chunk = [0u8; 4096];
    let ok = loop {
        // SAFETY: the kernel writes at most `chunk.len()` bytes into `chunk`.
        let r = syscall::check(unsafe {
            syscall3(
                SYS_READ,
                fd as usize,
                chunk.as_mut_ptr() as usize,
                chunk.len(),
            )
        });
        match r {
            Ok(0) => break true,
            Ok(n) => {
                if !text.extend_from(&chunk[..n]) {
                    break false;
                }
            }
            Err(e) if e.0 == 4 => {}
            Err(_) => break false,
        }
    };
    close(fd);
    ok.then_some(text)
}

/// The names in the directory `path` that end in `.conf` (and are longer than that), sorted, each followed by a NUL, in one
/// buffer. `None` if the directory cannot be opened.
pub(crate) fn conf_names(path: &[u8]) -> Option<HeapVec<u8>> {
    let fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)?;
    let mut names = HeapVec::<u8>::new();
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
        let n = match syscall::check(unsafe {
            syscall3(
                SYS_GETDENTS64,
                fd as usize,
                buf.as_mut_ptr() as usize,
                buf.len(),
            )
        }) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let mut pos = 0;
        while pos + 19 <= n {
            let reclen = usize::from(u16::from_ne_bytes([buf[pos + 16], buf[pos + 17]]));
            if reclen < 19 || pos + reclen > n {
                break;
            }
            let kind = buf[pos + 18];
            let raw = &buf[pos + 19..pos + reclen];
            let name = &raw[..raw.iter().position(|&c| c == 0).unwrap_or(raw.len())];
            // regular files, symbolic links and file systems that do not say (DT_REG, DT_LNK, DT_UNKNOWN)
            if matches!(kind, 8 | 10 | 0) && name.len() > 5 && name.ends_with(b".conf") {
                let _ = names.extend_from(name) && names.push(0);
            }
            pos += reclen;
        }
    }
    close(fd);
    sort_names(&mut names);
    Some(names)
}

/// Sort a buffer of NUL-terminated names (insertion sort on the names; there are a handful).
fn sort_names(names: &mut HeapVec<u8>) {
    let mut sorted = HeapVec::<u8>::new();
    let mut taken = 0usize;
    let count = names.split(|&c| c == 0).filter(|n| !n.is_empty()).count();
    let mut last: Option<(usize, usize)> = None;
    while taken < count {
        // the smallest name larger than the one taken last
        let mut best: Option<(usize, usize)> = None;
        let mut at = 0;
        for n in names.split(|&c| c == 0).filter(|n| !n.is_empty()) {
            let cand = &names[at..at + n.len()];
            let above = last.is_none_or(|(s, l)| cand > &names[s..s + l]);
            let below = best.is_none_or(|(s, l)| cand < &names[s..s + l]);
            if above && below {
                best = Some((at, n.len()));
            }
            at += n.len() + 1;
        }
        let Some((s, l)) = best else { break };
        let _ = sorted.extend_from(&names[s..s + l]) && sorted.push(0);
        last = Some((s, l));
        taken += 1;
    }
    *names = sorted;
}

/// The current directory (without a NUL), or `None`.
pub(crate) fn getcwd(buf: &mut [u8]) -> Option<usize> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`.
    let r = syscall::check(unsafe { syscall2(SYS_GETCWD, buf.as_mut_ptr() as usize, buf.len()) })
        .ok()?;
    // (the call returns the length including the NUL)
    r.checked_sub(1)
}

/// The value of the environment variable `name` (no `=`), copied; `None` if unset.
pub(crate) fn getenv(name: &[u8]) -> Option<HeapVec<u8>> {
    // SAFETY: `environ` is the process's environment, not modified during the call.
    let p = unsafe { rusty_libc_core::env::getenv(name) };
    if p.is_null() {
        return None;
    }
    // SAFETY: a non-NULL result of `getenv` points to the NUL-terminated value inside the environment block.
    let value = unsafe { rusty_libc_core::ffi::cstr_bytes(p.cast_const()) };
    let mut copy = HeapVec::new();
    copy.extend_from(value).then_some(copy)
}

#[cfg(any(feature = "shared", test))]
unsafe extern "C" {
    fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
}

/// `dlopen(path, RTLD_LAZY)`; NULL when the module cannot be loaded (always NULL in the static library).
///
/// # Safety
/// Loading a module runs its constructors.
pub(crate) unsafe fn load(path: &CStr) -> *mut c_void {
    #[cfg(any(feature = "shared", test))]
    {
        // SAFETY: `path` is a NUL-terminated name; the loader is the process's.
        unsafe { dlopen(path.as_ptr(), 1) }
    }
    #[cfg(not(any(feature = "shared", test)))]
    {
        let _ = path;
        core::ptr::null_mut()
    }
}

/// The address of the symbol `name` in a module, or 0.
///
/// # Safety
/// `handle` came from [`load`] and has not been unloaded.
pub(crate) unsafe fn symbol(handle: *mut c_void, name: &CStr) -> usize {
    #[cfg(any(feature = "shared", test))]
    {
        // SAFETY: `handle` is a live handle (the caller's contract) and `name` a NUL-terminated name.
        unsafe { dlsym(handle, name.as_ptr()) as usize }
    }
    #[cfg(not(any(feature = "shared", test)))]
    {
        let _ = (handle, name);
        0
    }
}

/// `dlclose`.
///
/// # Safety
/// `handle` came from [`load`] and is not used again; no code of the module runs afterwards.
pub(crate) unsafe fn unload(handle: *mut c_void) {
    #[cfg(any(feature = "shared", test))]
    {
        // SAFETY: a live handle that is given up here (the caller's contract).
        unsafe { dlclose(handle) };
    }
    #[cfg(not(any(feature = "shared", test)))]
    {
        let _ = handle;
    }
}
