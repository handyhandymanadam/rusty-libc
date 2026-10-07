use crate::find::{self, cstr_bytes};
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::errno;
use rusty_libc_core::syscall;

const CATGETS_MAGIC: u32 = 0x9604_08de;
const NL_CAT_LOCALE: c_int = 1;
const ENOMSG: i32 = 42;
const EBADF: i32 = 9;
const EINVAL: i32 = 22;
const DEFAULT_NLSPATH: &[u8] = b"/usr/share/locale/%L/%N:/usr/share/locale/%L/LC_MESSAGES/%N:/usr/share/locale/%l/%N:/usr/share/locale/%l/LC_MESSAGES/%N:";

#[repr(C)]
struct Catalog {
    status: c_int,
    plane_size: usize,
    plane_depth: usize,
    name_ptr: *const u32,
    strings: *const u8,
    file_ptr: *const u8,
    file_size: usize,
}

fn rd(p: *const u8, off: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(p.add(off) as *const u32) }
}

fn expand(elem: &[u8], cat_name: &[u8], env_var: &[u8], buf: &mut [u8; 1024]) -> Option<usize> {
    let mut n = 0;
    let mut put = |s: &[u8], n: &mut usize| -> bool {
        if *n + s.len() >= buf.len() {
            return false;
        }
        buf[*n..*n + s.len()].copy_from_slice(s);
        *n += s.len();
        true
    };
    if elem.is_empty() {
        return if put(cat_name, &mut n) { Some(n) } else { None };
    }
    let mut i = 0;
    while i < elem.len() {
        if elem[i] != b'%' {
            if !put(&elem[i..i + 1], &mut n) {
                return None;
            }
            i += 1;
            continue;
        }
        i += 1;
        let c = elem.get(i).copied().unwrap_or(0);
        i += 1;
        let ok = match c {
            b'N' => put(cat_name, &mut n),
            b'L' => put(env_var, &mut n),
            b'l' => {
                let mut e = 1.min(env_var.len());
                while e < env_var.len() && env_var[e] != b'_' && env_var[e] != b'.' {
                    e += 1;
                }
                put(&env_var[..e], &mut n)
            }
            b't' => {
                let mut k = 1;
                while k < env_var.len() && env_var[k] != b'_' && env_var[k] != b'.' {
                    k += 1;
                }
                if env_var.get(k) == Some(&b'_') {
                    let st = k + 1;
                    let mut e = st;
                    while e < env_var.len() && env_var[e] != b'.' {
                        e += 1;
                    }
                    put(&env_var[st..e], &mut n)
                } else {
                    true
                }
            }
            b'c' => {
                let mut k = 1;
                while k < env_var.len() && env_var[k] != b'.' {
                    k += 1;
                }
                if env_var.get(k) == Some(&b'.') { put(&env_var[k + 1..], &mut n) } else { true }
            }
            b'%' => put(b"%", &mut n),
            _ => return None,
        };
        if !ok {
            return None;
        }
    }
    Some(n)
}

fn open_file(path: &[u8]) -> Option<(*const u8, usize)> {
    const O_RDONLY: i32 = 0;
    const O_CLOEXEC: i32 = 0o2000000;
    const S_IFMT: u32 = 0o170000;
    const S_IFREG: u32 = 0o100000;
    let fd = match unsafe { rusty_libc_core::unistd::open(path.as_ptr().cast(), O_RDONLY | O_CLOEXEC, 0) } {
        Ok(fd) => fd,
        Err(e) => {
            errno::set(e.0);
            return None;
        }
    };
    let r = (|| {
        let (mode, _, size) = rusty_libc_core::unistd::fstat_basic(fd).ok()?;
        if mode & S_IFMT != S_IFREG || (size as usize) < 12 {
            errno::set(EINVAL);
            return None;
        }
        let a = unsafe { syscall::syscall6(syscall::SYS_MMAP, 0, size as usize, 1, 2, fd as usize, 0) };
        syscall::check(a).ok().map(|a| (a as *const u8, size as usize))
    })();
    let _ = rusty_libc_core::unistd::close(fd);
    r
}

fn open_catalog(cat_name: &[u8], nlspath: Option<&[u8]>, env_var: &[u8]) -> Option<Catalog> {
    let mut found: Option<(*const u8, usize)> = None;
    let mut name0 = [0u8; 1100];
    if cat_name.contains(&b'/') || nlspath.is_none() {
        if cat_name.len() < name0.len() {
            name0[..cat_name.len()].copy_from_slice(cat_name);
            found = open_file(&name0[..=cat_name.len()]);
        }
    } else {
        let mut run = nlspath.unwrap_or(b"");
        while !run.is_empty() {
            let e = run.iter().position(|&b| b == b':').unwrap_or(run.len());
            let elem = &run[..e];
            let mut buf = [0u8; 1024];
            if let Some(n) = expand(elem, cat_name, env_var, &mut buf)
                && n != 0
            {
                buf[n] = 0;
                if let Some(f) = open_file(&buf[..=n]) {
                    found = Some(f);
                    break;
                }
            }
            run = if e < run.len() { &run[e + 1..] } else { &run[e..] };
        }
    }
    let (ptr, size) = found?;
    if rd(ptr, 0) != CATGETS_MAGIC && rd(ptr, 0) != CATGETS_MAGIC.swap_bytes() {
        return None;
    }
    let swapping = rd(ptr, 0) != CATGETS_MAGIC;
    let sw = |x: u32| if swapping { x.swap_bytes() } else { x };
    let plane_size = sw(rd(ptr, 4)) as usize;
    let plane_depth = sw(rd(ptr, 8)) as usize;
    let tab_size = plane_size.checked_mul(plane_depth)?.checked_mul(3)?;
    let tables_end = 12usize.checked_add(tab_size.checked_mul(8)?)?;
    if tables_end > size {
        return None;
    }
    let name_ptr = unsafe { ptr.add(12) as *const u32 };
    let strings = unsafe { ptr.add(tables_end) };
    let mut max_offset = 0usize;
    let mut cnt = 2;
    while cnt < tab_size {
        let v = unsafe { core::ptr::read_unaligned(name_ptr.add(cnt)) } as usize;
        if v > max_offset {
            max_offset = v;
        }
        cnt += 3;
    }
    if size <= 12 + 2 * tab_size + max_offset {
        return None;
    }
    let mut lastp = max_offset;
    let mut left = size.wrapping_sub(12).wrapping_add(2 * tab_size).wrapping_add(max_offset);
    unsafe {
        while *strings.add(lastp) != 0 {
            left = left.wrapping_sub(1);
            if left == 0 || strings as usize + lastp + 1 >= ptr as usize + size {
                return None;
            }
            lastp += 1;
        }
    }
    Some(Catalog { status: 0, file_ptr: ptr, file_size: size, plane_size, plane_depth, name_ptr, strings })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __open_catalog(cat_name: *const c_char, nlspath: *const c_char, env_var: *const c_char, catalog: *mut c_void) -> c_int {
    unsafe {
        let name = cstr_bytes(cat_name.cast());
        let nls = if nlspath.is_null() { None } else { Some(cstr_bytes(nlspath.cast())) };
        let env: &[u8] = if env_var.is_null() { b"" } else { cstr_bytes(env_var.cast()) };
        match open_catalog(name, nls, env) {
            Some(c) => {
                core::ptr::write(catalog as *mut Catalog, c);
                0
            }
            None => -1,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn catopen(cat_name: *const c_char, flag: c_int) -> *mut c_void {
    unsafe {
        let name = cstr_bytes(cat_name.cast());
        let mut env_var: &[u8] = b"C";
        let mut nlspath_buf = [0u8; 2048];
        let mut nlspath: Option<&[u8]> = None;
        if !name.contains(&b'/') {
            let v: &[u8] = if flag == NL_CAT_LOCALE { cstr_bytes(crate::setlocale(crate::LC_MESSAGES, core::ptr::null()).cast()) } else { find::env(b"LANG").unwrap_or(b"") };
            env_var = if v.is_empty() { b"C" } else { v };
            let user = find::env(b"NLSPATH");
            let mut n = 0;
            if let Some(u) = user {
                if u.len() + 1 + DEFAULT_NLSPATH.len() < nlspath_buf.len() {
                    nlspath_buf[..u.len()].copy_from_slice(u);
                    nlspath_buf[u.len()] = b':';
                    n = u.len() + 1;
                } else {
                    return usize::MAX as *mut c_void;
                }
            }
            nlspath_buf[n..n + DEFAULT_NLSPATH.len()].copy_from_slice(DEFAULT_NLSPATH);
            nlspath = Some(&nlspath_buf[..n + DEFAULT_NLSPATH.len()]);
        }
        match open_catalog(name, nlspath, env_var) {
            Some(c) => {
                let p = rusty_libc_malloc::malloc(core::mem::size_of::<Catalog>()) as *mut Catalog;
                if p.is_null() {
                    return usize::MAX as *mut c_void;
                }
                core::ptr::write(p, c);
                p.cast()
            }
            None => usize::MAX as *mut c_void,
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn catgets(catalog: *mut c_void, set: c_int, message: c_int, string: *const c_char) -> *mut c_char {
    unsafe {
        let set = set.wrapping_add(1);
        if catalog as usize == usize::MAX || set <= 0 || message < 0 {
            return string as *mut c_char;
        }
        let cat = &*(catalog as *const Catalog);
        let set = set as u32 as usize;
        let message_u = message as u32;
        if cat.plane_size == 0 {
            errno::set(ENOMSG);
            return string as *mut c_char;
        }
        let mut idx = ((set.wrapping_mul(message as usize)) % cat.plane_size) * 3;
        let mut cnt = 0;
        loop {
            let a = core::ptr::read_unaligned(cat.name_ptr.add(idx));
            let b = core::ptr::read_unaligned(cat.name_ptr.add(idx + 1));
            if a == set as u32 && b == message_u {
                let off = core::ptr::read_unaligned(cat.name_ptr.add(idx + 2)) as usize;
                return cat.strings.add(off) as *mut c_char;
            }
            idx += cat.plane_size * 3;
            cnt += 1;
            if cnt >= cat.plane_depth {
                break;
            }
        }
        errno::set(ENOMSG);
        string as *mut c_char
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn catclose(catalog: *mut c_void) -> c_int {
    unsafe {
        if catalog as usize == usize::MAX {
            errno::set(EBADF);
            return -1;
        }
        let cat = &*(catalog as *const Catalog);
        let _ = syscall::syscall2(syscall::SYS_MUNMAP, cat.file_ptr as usize, cat.file_size);
        rusty_libc_malloc::free(catalog);
        0
    }
}
