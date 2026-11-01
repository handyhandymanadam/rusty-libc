//! libgen.h: the POSIX `basename` (exported by glibc as `__xpg_basename`; the header maps the name)
//! and `dirname`. Both may modify their argument (they write a NUL), like glibc's.
use core::ffi::c_char;

static DOT: [u8; 2] = *b".\0";

/// Range `(start, end)` of the POSIX basename of `path`, as byte offsets into `path`; the result is
/// `path[start..end]`. `None` means the string "." (empty path). Trailing slashes are excluded
/// (and, in the C function, overwritten by a NUL).
#[inline]
pub fn basename_range(path: &[u8]) -> Option<(usize, usize)> {
    let len = path.len();
    if len == 0 {
        return None;
    }
    match path.iter().rposition(|&c| c == b'/') {
        None => Some((0, len)),
        Some(l) if l + 1 == len => {
            let mut e = l;
            while e > 0 && path[e - 1] == b'/' {
                e -= 1;
            }
            if e > 0 {
                let mut p = e - 1;
                while p > 0 && path[p - 1] != b'/' {
                    p -= 1;
                }
                Some((p, e))
            } else {
                // only slashes: "/" (the C function returns a pointer to the last slash)
                Some((len - 1, len))
            }
        }
        Some(l) => Some((l + 1, len)),
    }
}

/// Length of the POSIX dirname of `path` (the result is `path[..n]`), or `None` for ".".
/// Note `//` stays `//` (POSIX leaves exactly two leading slashes alone).
#[inline]
pub fn dirname_len(path: &[u8]) -> Option<usize> {
    let mut last = path.iter().rposition(|&c| c == b'/');
    if let Some(l) = last
        && l != 0
        && l + 1 == path.len()
    {
        let mut r = l;
        while r != 0 && path[r - 1] == b'/' {
            r -= 1;
        }
        if r != 0 {
            last = path[..r].iter().rposition(|&c| c == b'/');
        }
    }
    let l = last?;
    let mut r = l;
    while r != 0 && path[r - 1] == b'/' {
        r -= 1;
    }
    Some(if r == 0 {
        if l == 1 { 2 } else { 1 }
    } else {
        r
    })
}

/// `basename` on a writable path (the bytes before its NUL, which the slice must not include): cuts trailing slashes by
/// writing a NUL after the name (when that is inside `path`) and returns where the name starts; `None` means ".".
#[inline]
pub fn basename_in_place(path: &mut [u8]) -> Option<usize> {
    let (start, end) = basename_range(path)?;
    if end < path.len() {
        path[end] = 0;
    }
    Some(start)
}

/// `dirname` on a writable path (the bytes before its NUL): writes a NUL where the directory part ends and returns that
/// length; `None` means "." (no slash, or empty).
#[inline]
pub fn dirname_in_place(path: &mut [u8]) -> Option<usize> {
    let n = path.len();
    // common case, one backward scan: a last slash that is neither the first nor the final character (trailing slashes
    // and "/x" go through `dirname_len`)
    let mut i = n;
    while i > 0 && path[i - 1] != b'/' {
        i -= 1;
    }
    if i == 0 {
        return None; // no slash (or empty)
    }
    let l = i - 1;
    let k = if l != 0 && i != n {
        let mut r = l;
        while r != 0 && path[r - 1] == b'/' {
            r -= 1;
        }
        if r == 0 { if l == 1 { 2 } else { 1 } } else { r }
    } else {
        dirname_len(path)?
    };
    // `k` < n here except for "//" style inputs, where it equals n and the NUL is already there
    if k < n {
        path[k] = 0;
    }
    Some(k)
}

/// The C string at `path` as its writable bytes (without the NUL), or `None` for NULL or "".
///
/// # Safety
/// `path` is NULL or a writable C string that nothing else accesses during the borrow `'a`.
#[inline]
unsafe fn path_bytes<'a>(path: *mut c_char) -> Option<&'a mut [u8]> {
    if path.is_null() {
        return None;
    }
    // SAFETY: `path` is a non-NULL C string (caller's contract).
    let n = unsafe { rusty_libc_core::ffi::cstr_len(path) };
    if n == 0 {
        // "" gives "." in both callers; answering here keeps the empty-slice case (a pointer select on the path's address
        // before the scan) out of the common path
        return None;
    }
    // SAFETY: its `n` bytes before the NUL are writable and exclusively ours for `'a` (caller's contract).
    Some(unsafe { rusty_libc_core::ffi::bytes_mut(path.cast(), n) })
}

/// The POSIX `basename` (`__xpg_basename`): NULL or "" give ".".
///
/// # Safety
/// `path` must be NULL or a writable NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __xpg_basename(path: *mut c_char) -> *mut c_char {
    // SAFETY: forwarded contract.
    match unsafe { path_bytes(path) }.and_then(basename_in_place) {
        None => DOT.as_ptr() as *mut c_char,
        Some(start) => path.wrapping_add(start),
    }
}

/// The POSIX `dirname`: NULL gives ".", a path without a directory part gives "." too.
///
/// # Safety
/// `path` must be NULL or a writable NUL-terminated string.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dirname(path: *mut c_char) -> *mut c_char {
    // SAFETY: forwarded contract.
    match unsafe { path_bytes(path) }.and_then(dirname_in_place) {
        None => DOT.as_ptr() as *mut c_char,
        Some(_) => path,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use std::ffi::CStr;

    unsafe extern "C" {
        fn __xpg_basename(p: *mut c_char) -> *mut c_char;
        fn dirname(p: *mut c_char) -> *mut c_char;
    }

    fn rnd_path(r: &mut u64) -> Vec<u8> {
        let alpha = *b"//ab.x";
        let n = {
            *r ^= *r << 13;
            *r ^= *r >> 7;
            *r ^= *r << 17;
            (*r % 9) as usize
        };
        (0..n)
            .map(|_| {
                *r ^= *r << 13;
                *r ^= *r >> 7;
                *r ^= *r << 17;
                alpha[(*r % 6) as usize]
            })
            .collect()
    }

    #[test]
    fn matches_host_random() {
        let mut r = 0x1234_5678_9abc_def1u64;
        for _ in 0..50000 {
            let p = rnd_path(&mut r);
            let mut a = [p.clone(), vec![0]].concat();
            let mut b = a.clone();
            let mut c = a.clone();
            let mut d = a.clone();
            unsafe {
                let h = CStr::from_ptr(__xpg_basename(a.as_mut_ptr().cast())).to_owned();
                let o = CStr::from_ptr(super::__xpg_basename(b.as_mut_ptr().cast())).to_owned();
                assert_eq!(h, o, "basename {:?}", String::from_utf8_lossy(&p));
                assert_eq!(a, b, "basename buffer {:?}", String::from_utf8_lossy(&p));
                let h = CStr::from_ptr(dirname(c.as_mut_ptr().cast())).to_owned();
                let o = CStr::from_ptr(super::dirname(d.as_mut_ptr().cast())).to_owned();
                assert_eq!(h, o, "dirname {:?}", String::from_utf8_lossy(&p));
                assert_eq!(c, d, "dirname buffer {:?}", String::from_utf8_lossy(&p));
            }
        }
    }

    #[test]
    fn null_and_known() {
        unsafe {
            assert_eq!(CStr::from_ptr(super::__xpg_basename(core::ptr::null_mut())).to_bytes(), b".");
            assert_eq!(CStr::from_ptr(super::dirname(core::ptr::null_mut())).to_bytes(), b".");
        }
        assert_eq!(basename_range(b"/usr/lib/"), Some((5, 8)));
        assert_eq!(dirname_len(b"/usr/lib/"), Some(4));
        assert_eq!(dirname_len(b"//"), Some(2));
        assert_eq!(dirname_len(b"abc"), None);
    }
}
