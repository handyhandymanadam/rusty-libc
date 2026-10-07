use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api::{fclose, fflush, fgets, flockfile, fopen, fputc, fseek, funlockfile, fwrite, ferror};
use rusty_libc_stdio::rust_api::{Arg, snprintf, sscanf};

#[repr(C)]
pub struct Mntent {
    pub mnt_fsname: *mut c_char,
    pub mnt_dir: *mut c_char,
    pub mnt_type: *mut c_char,
    pub mnt_opts: *mut c_char,
    pub mnt_freq: c_int,
    pub mnt_passno: c_int,
}

static EMPTY: [c_char; 1] = [0];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setmntent(file: *const c_char, mode: *const c_char) -> *mut FILE {
    unsafe {
        let mlen = rusty_libc_mem::strlen(mode);
        let mut buf = [0 as c_char; 64];
        let long;
        let newmode: *mut c_char = if mlen + 3 <= buf.len() {
            buf.as_mut_ptr()
        } else {
            long = rusty_libc_malloc::malloc(mlen + 3) as *mut c_char;
            if long.is_null() {
                return null_mut();
            }
            long
        };
        core::ptr::copy_nonoverlapping(mode, newmode, mlen);
        *newmode.add(mlen) = b'c' as c_char;
        *newmode.add(mlen + 1) = b'e' as c_char;
        *newmode.add(mlen + 2) = 0;
        let f = fopen(file, newmode);
        if newmode != buf.as_mut_ptr() {
            rusty_libc_malloc::free(newmode.cast());
        }
        if !f.is_null() {
            rusty_libc_stdio::stdio_ext::__fsetlocking(f, 2);
        }
        f
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endmntent(stream: *mut FILE) -> c_int {
    if !stream.is_null() {
        unsafe { fclose(stream) };
    }
    1
}

unsafe fn decode_name(buf: *mut c_char) -> *mut c_char {
    unsafe {
        let mut rp = buf;
        let mut wp = buf;
        loop {
            let (a, b, c, d) = (*rp as u8, *rp.add(1) as u8, if *rp != 0 && *rp.add(1) != 0 { *rp.add(2) as u8 } else { 0 }, if *rp != 0 && *rp.add(1) != 0 && *rp.add(2) != 0 { *rp.add(3) as u8 } else { 0 });
            if a == b'\\' && b == b'0' && c == b'4' && d == b'0' {
                *wp = b' ' as c_char;
                wp = wp.add(1);
                rp = rp.add(3);
            } else if a == b'\\' && b == b'0' && c == b'1' && d == b'1' {
                *wp = b'\t' as c_char;
                wp = wp.add(1);
                rp = rp.add(3);
            } else if a == b'\\' && b == b'0' && c == b'1' && d == b'2' {
                *wp = b'\n' as c_char;
                wp = wp.add(1);
                rp = rp.add(3);
            } else if a == b'\\' && b == b'\\' {
                *wp = b'\\' as c_char;
                wp = wp.add(1);
                rp = rp.add(1);
            } else if a == b'\\' && b == b'1' && c == b'3' && d == b'4' {
                *wp = b'\\' as c_char;
                wp = wp.add(1);
                rp = rp.add(3);
            } else {
                *wp = *rp;
                wp = wp.add(1);
            }
            let done = *rp == 0;
            rp = rp.add(1);
            if done {
                break;
            }
        }
        buf
    }
}

unsafe fn strsep_ws(head: &mut *mut c_char) -> *mut c_char {
    unsafe {
        let start = *head;
        if start.is_null() {
            return null_mut();
        }
        let mut p = start;
        while *p != 0 && *p != b' ' as c_char && *p != b'\t' as c_char {
            p = p.add(1);
        }
        if *p != 0 {
            *p = 0;
            *head = p.add(1);
        } else {
            *head = null_mut();
        }
        start
    }
}

unsafe fn skip_ws(p: *mut c_char) -> *mut c_char {
    unsafe {
        let mut q = p;
        while *q == b' ' as c_char || *q == b'\t' as c_char {
            q = q.add(1);
        }
        q
    }
}

unsafe fn get_mnt_entry(stream: *mut FILE, mp: *mut Mntent, buffer: *mut c_char, bufsiz: c_int) -> bool {
    unsafe {
        let mut head;
        loop {
            if fgets(buffer, bufsiz, stream).is_null() {
                return false;
            }
            let nl = rusty_libc_mem::strchr(buffer, b'\n' as c_int);
            if !nl.is_null() {
                let mut end = nl;
                while end != buffer && (*end.sub(1) == b' ' as c_char || *end.sub(1) == b'\t' as c_char) {
                    end = end.sub(1);
                }
                *end = 0;
            } else {
                let mut tmp = [0 as c_char; 1024];
                while !fgets(tmp.as_mut_ptr(), 1024, stream).is_null() {
                    if !rusty_libc_mem::strchr(tmp.as_ptr(), b'\n' as c_int).is_null() {
                        break;
                    }
                }
            }
            head = skip_ws(buffer);
            if *head != 0 && *head != b'#' as c_char {
                break;
            }
        }
        let m = &mut *mp;
        let field = |head: &mut *mut c_char| -> *mut c_char {
            let cp = strsep_ws(head);
            if cp.is_null() { EMPTY.as_ptr() as *mut c_char } else { decode_name(cp) }
        };
        m.mnt_fsname = field(&mut head);
        if !head.is_null() {
            head = skip_ws(head);
        }
        m.mnt_dir = field(&mut head);
        if !head.is_null() {
            head = skip_ws(head);
        }
        m.mnt_type = field(&mut head);
        if !head.is_null() {
            head = skip_ws(head);
        }
        m.mnt_opts = field(&mut head);
        let n = if head.is_null() { 0 } else { sscanf(CStr::from_ptr(head), c" %d %d ", &[&raw mut m.mnt_freq as *mut c_void, &raw mut m.mnt_passno as *mut c_void]) };
        match n {
            0 => {
                m.mnt_freq = 0;
                m.mnt_passno = 0;
            }
            1 => m.mnt_passno = 0,
            _ => {}
        }
        true
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getmntent_r(stream: *mut FILE, mp: *mut Mntent, buffer: *mut c_char, bufsiz: c_int) -> *mut Mntent {
    unsafe {
        flockfile(stream);
        let result = loop {
            if get_mnt_entry(stream, mp, buffer, bufsiz) {
                if rusty_libc_mem::strcmp((*mp).mnt_type, c"autofs".as_ptr()) == 0 && !hasmntopt(mp, c"ignore".as_ptr()).is_null() {
                    core::ptr::write_bytes(mp, 0, 1);
                } else {
                    break mp;
                }
            } else {
                break null_mut();
            }
        };
        funlockfile(stream);
        result
    }
}

#[repr(C)]
struct MntentBuffer {
    m: Mntent,
    buffer: [c_char; 4096],
}

static MNTENT_BUFFER: core::sync::atomic::AtomicPtr<MntentBuffer> = core::sync::atomic::AtomicPtr::new(null_mut());

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getmntent(stream: *mut FILE) -> *mut Mntent {
    use core::sync::atomic::Ordering;
    unsafe {
        let mut b = MNTENT_BUFFER.load(Ordering::Acquire);
        if b.is_null() {
            let n = rusty_libc_malloc::malloc(size_of::<MntentBuffer>()) as *mut MntentBuffer;
            if n.is_null() {
                return null_mut();
            }
            match MNTENT_BUFFER.compare_exchange(null_mut(), n, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => b = n,
                Err(cur) => {
                    rusty_libc_malloc::free(n.cast());
                    b = cur;
                }
            }
        }
        getmntent_r(stream, &raw mut (*b).m, (*b).buffer.as_mut_ptr(), 4096)
    }
}

unsafe fn write_string(stream: *mut FILE, s: *const c_char) {
    unsafe {
        let mut p = s;
        while *p != 0 {
            let c = *p as u8;
            if c == b' ' || c == b'\t' || c == b'\n' || c == b'\\' {
                fputc(b'\\' as c_int, stream);
                fputc(((c & 0xc0) >> 6) as c_int + b'0' as c_int, stream);
                fputc(((c & 0x38) >> 3) as c_int + b'0' as c_int, stream);
                fputc((c & 0x07) as c_int + b'0' as c_int, stream);
            } else {
                fputc(c as c_int, stream);
            }
            p = p.add(1);
        }
        fputc(b' ' as c_int, stream);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn addmntent(stream: *mut FILE, mnt: *const Mntent) -> c_int {
    unsafe {
        if fseek(stream, 0, 2) != 0 {
            return 1;
        }
        flockfile(stream);
        let m = &*mnt;
        write_string(stream, m.mnt_fsname);
        write_string(stream, m.mnt_dir);
        write_string(stream, m.mnt_type);
        write_string(stream, m.mnt_opts);
        let mut tail = [0u8; 40];
        let n = snprintf(&mut tail, c"%d %d\n", &[Arg::Int(m.mnt_freq as i64), Arg::Int(m.mnt_passno as i64)]);
        fwrite(tail.as_ptr().cast(), 1, n as usize, stream);
        let ret = (ferror(stream) != 0 || fflush(stream) != 0) as c_int;
        funlockfile(stream);
        ret
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hasmntopt(mnt: *const Mntent, opt: *const c_char) -> *mut c_char {
    unsafe {
        let optlen = rusty_libc_mem::strlen(opt);
        let mut rest = (*mnt).mnt_opts;
        loop {
            let p = rusty_libc_mem::strstr(rest, opt);
            if p.is_null() {
                return null_mut();
            }
            let after = *p.add(optlen) as u8;
            if (p == rest || *p.sub(1) == b',' as c_char) && (after == 0 || after == b'=' || after == b',') {
                return p;
            }
            rest = rusty_libc_mem::strchr(p, b',' as c_int);
            if rest.is_null() {
                return null_mut();
            }
            rest = rest.add(1);
        }
    }
}
