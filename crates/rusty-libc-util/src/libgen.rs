use core::ffi::c_char;

static DOT: [u8; 2] = *b".\0";

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __xpg_basename(path: *mut c_char) -> *mut c_char {
    unsafe {
        if path.is_null() {
            return DOT.as_ptr() as *mut c_char;
        }
        let n = rusty_libc_mem::strlen(path.cast());
        let s = core::slice::from_raw_parts(path as *const u8, n);
        match basename_range(s) {
            None => DOT.as_ptr() as *mut c_char,
            Some((start, end)) => {
                if end < n {
                    *path.add(end) = 0;
                }
                path.add(start)
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn dirname(path: *mut c_char) -> *mut c_char {
    unsafe {
        if path.is_null() {
            return DOT.as_ptr() as *mut c_char;
        }
        let n = rusty_libc_mem::strlen(path.cast());
        let p = path as *const u8;
        let mut i = n;
        while i > 0 && *p.add(i - 1) != b'/' {
            i -= 1;
        }
        if i == 0 {
            return DOT.as_ptr() as *mut c_char;
        }
        let l = i - 1;
        if l != 0 && i != n {
            let mut r = l;
            while r != 0 && *p.add(r - 1) == b'/' {
                r -= 1;
            }
            let k = if r == 0 { if l == 1 { 2 } else { 1 } } else { r };
            *path.add(k) = 0;
            return path;
        }
        match dirname_len(core::slice::from_raw_parts(p, n)) {
            None => DOT.as_ptr() as *mut c_char,
            Some(k) => {
                *path.add(k) = 0;
                path
            }
        }
    }
}

