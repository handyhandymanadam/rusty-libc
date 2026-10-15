use core::ffi::c_char;

static DOT: [u8; 2] = *b".\0";

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
                Some((len - 1, len))
            }
        }
        Some(l) => Some((l + 1, len)),
    }
}

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

#[inline]
pub fn basename_in_place(path: &mut [u8]) -> Option<usize> {
    let (start, end) = basename_range(path)?;
    if end < path.len() {
        path[end] = 0;
    }
    Some(start)
}

#[inline]
pub fn dirname_in_place(path: &mut [u8]) -> Option<usize> {
    let n = path.len();
    let mut i = n;
    while i > 0 && path[i - 1] != b'/' {
        i -= 1;
    }
    if i == 0 {
        return None;
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
    if k < n {
        path[k] = 0;
    }
    Some(k)
}

#[inline]
unsafe fn path_bytes<'a>(path: *mut c_char) -> Option<&'a mut [u8]> {
    if path.is_null() {
        return None;
    }
    let n = unsafe { rusty_libc_core::ffi::cstr_len(path) };
    if n == 0 {
        return None;
    }
    Some(unsafe { rusty_libc_core::ffi::bytes_mut(path.cast(), n) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __xpg_basename(path: *mut c_char) -> *mut c_char {
    match unsafe { path_bytes(path) }.and_then(basename_in_place) {
        None => DOT.as_ptr() as *mut c_char,
        Some(start) => path.wrapping_add(start),
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dirname(path: *mut c_char) -> *mut c_char {
    match unsafe { path_bytes(path) }.and_then(dirname_in_place) {
        None => DOT.as_ptr() as *mut c_char,
        Some(_) => path,
    }
}

