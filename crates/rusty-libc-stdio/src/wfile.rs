use crate::flock::locked;
use crate::file::{self, F_BYTE, F_EOF, F_ERR, F_LBF, F_RDMODE, F_UNBUF, F_W32, F_WIDE, F_WRITE, F_WRMODE, File as FILE};
use core::ffi::c_int;
use core::ptr::null_mut;
use rusty_libc_core::errno;
use rusty_libc_wchar::mbyte::Decoded;
use rusty_libc_wchar::{Charset, wchar_t, wint_t};

use rusty_libc_wchar::WEOF;
const EBADF: i32 = 9;
const EILSEQ: i32 = 84;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WCs {
    C,
    Utf8,
    Other,
    Raw32,
    Ccs,
}

pub struct WideInfo {
    pub cs: WCs,
    pub push: *mut u32,
    pub npush: usize,
    pub cap: usize,
    pub extra: isize,
    pub tshift: usize,
    pub pchars: usize,
    pub putting: bool,
    pub raw: usize,
    pub wbuf: bool,
    pub ahead: bool,
    pub ccs: *mut Ccs,
}

pub struct Ccs {
    dec: rusty_libc_iconv::Converter,
    enc: rusty_libc_iconv::Converter,
}

pub(crate) unsafe fn set_ccs(f: *mut FILE, name: &[u8]) -> bool {
    unsafe {
        if name.len() > 255 {
            errno::set(22);
            return false;
        }
        let (Ok(dec), Ok(enc)) = (rusty_libc_iconv::Converter::open(b"UCS-4LE", name), rusty_libc_iconv::Converter::open(name, b"UCS-4LE")) else {
            return true;
        };
        let w = ensure_info(f);
        if w.is_null() {
            errno::set(12);
            return false;
        }
        let p = rusty_libc_malloc::malloc(core::mem::size_of::<Ccs>()) as *mut Ccs;
        if p.is_null() {
            errno::set(12);
            return false;
        }
        p.write(Ccs { dec, enc });
        if !(*w).ccs.is_null() {
            core::ptr::drop_in_place((*w).ccs);
            rusty_libc_malloc::free((*w).ccs.cast());
        }
        (*w).ccs = p;
        (*w).cs = WCs::Ccs;
        (*f).flags |= F_WIDE;
        true
    }
}

unsafe fn ccs_decode(w: *mut WideInfo, bytes: &[u8]) -> Decoded {
    unsafe {
        let c = &mut *(*w).ccs;
        let (mut ip, mut op) = (0usize, 0usize);
        let mut out = [0u8; 4];
        let r = c.dec.convert_raw(bytes, &mut ip, &mut out, &mut op);
        match r {
            Err(rusty_libc_iconv::Error::Ilseq) => Decoded::Invalid,
            _ if op == 4 => Decoded::Char(u32::from_le_bytes(out), ip),
            _ => Decoded::Incomplete,
        }
    }
}

unsafe fn ccs_encode(w: *mut WideInfo, wc: u32, out: &mut [u8; 16]) -> usize {
    unsafe {
        let c = &mut *(*w).ccs;
        let input = wc.to_le_bytes();
        let (mut ip, mut op) = (0usize, 0usize);
        match c.enc.convert_raw(&input, &mut ip, &mut out[..], &mut op) {
            Ok(_) if op > 0 => op,
            _ => {
                out[0] = b'?';
                1
            }
        }
    }
}

pub(crate) unsafe fn free_wide(f: *mut FILE) {
    unsafe {
        let w = (*f).wide;
        if !w.is_null() {
            if !(*w).ccs.is_null() {
                core::ptr::drop_in_place((*w).ccs);
                rusty_libc_malloc::free((*w).ccs.cast());
            }
            rusty_libc_malloc::free((*w).push.cast());
            rusty_libc_malloc::free(w.cast());
            (*f).wide = null_mut();
        }
    }
}

unsafe fn ensure_info(f: *mut FILE) -> *mut WideInfo {
    unsafe {
        if (*f).wide.is_null() {
            (*f).wide = rusty_libc_malloc::calloc(1, core::mem::size_of::<WideInfo>()) as *mut WideInfo;
        }
        (*f).wide
    }
}

unsafe fn make_wide(f: *mut FILE, cs: WCs) -> bool {
    unsafe {
        let fl = (*f).flags;
        if fl & F_BYTE != 0 {
            return false;
        }
        if fl & F_WIDE != 0 {
            return true;
        }
        let w = ensure_info(f);
        if w.is_null() {
            return false;
        }
        (*w).cs = cs;
        (*f).flags |= F_WIDE;
        true
    }
}

pub(crate) unsafe fn make_raw_wide(f: *mut FILE) -> bool {
    unsafe { make_wide(f, WCs::Raw32) }
}

#[inline]
pub(crate) unsafe fn wide_ok(f: *mut FILE) -> bool {
    unsafe {
        let fl = (*f).flags;
        if fl & F_WIDE != 0 {
            return true;
        }
        let cs = match rusty_libc_wchar::charset() {
            Charset::Utf8 => WCs::Utf8,
            Charset::C => WCs::C,
            Charset::Other => WCs::Other,
        };
        make_wide(f, cs)
    }
}

pub unsafe fn fwide_raw(f: *mut FILE, mode: c_int) -> c_int {
    unsafe {
        if (*f).flags & (F_WIDE | F_BYTE) == 0 {
            if mode > 0 {
                wide_ok(f);
            } else if mode < 0 {
                (*f).flags |= F_BYTE;
            }
        }
        if (*f).flags & F_WIDE != 0 {
            1
        } else if (*f).flags & F_BYTE != 0 {
            -1
        } else {
            0
        }
    }
}

fn decode(cs: WCs, bytes: &[u8]) -> Decoded {
    match cs {
        WCs::C => rusty_libc_wchar::mbyte::decode_cs(Charset::C, bytes),
        WCs::Utf8 => rusty_libc_wchar::mbyte::decode_cs(Charset::Utf8, bytes),
        WCs::Other => rusty_libc_wchar::mbyte::decode_cs(Charset::Other, bytes),
        WCs::Ccs => Decoded::Invalid,
        WCs::Raw32 => {
            if bytes.len() < 4 {
                Decoded::Incomplete
            } else {
                Decoded::Char(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), 4)
            }
        }
    }
}

#[inline]
pub(crate) fn encode(cs: WCs, wc: u32, out: &mut [u8; 16]) -> usize {
    match cs {
        WCs::Ccs => 0,
        WCs::Raw32 => {
            out[..4].copy_from_slice(&wc.to_le_bytes());
            4
        }
        WCs::C => {
            if wc < 0x80 {
                out[0] = wc as u8;
                1
            } else {
                let t = crate::translit::lookup(wc);
                out[..t.len()].copy_from_slice(t);
                t.len()
            }
        }
        WCs::Utf8 | WCs::Other => {
            let mut b = [0u8; 6];
            match rusty_libc_wchar::mbyte::encode_cs(if cs == WCs::Utf8 { Charset::Utf8 } else { Charset::Other }, wc, &mut b) {
                Some(n) => {
                    out[..n].copy_from_slice(&b[..n]);
                    n
                }
                None => {
                    out[0] = b'?';
                    1
                }
            }
        }
    }
}

unsafe fn read_core(f: *mut FILE) -> wint_t {
    unsafe {
        let cs = (*(*f).wide).cs;
        (*(*f).wide).putting = false;
        (*(*f).wide).ahead = true;
        loop {
            let have = if (*f).flags & F_RDMODE != 0 { (*f).rend() - (*f).rpos() } else { 0 };
            if have > 0 {
                let bytes = core::slice::from_raw_parts((*f).buf.add((*f).rpos()), have);
                match if cs == WCs::Ccs { ccs_decode((*f).wide, bytes) } else { decode(cs, bytes) } {
                    Decoded::Char(c, n) => {
                        (*f).set_rpos((*f).rpos() + n);
                        return c;
                    }
                    Decoded::Invalid => {
                        errno::set(EILSEQ);
                        (*f).flags |= F_ERR;
                        return WEOF;
                    }
                    Decoded::Incomplete => {}
                }
            }
            if (*f).flags & F_UNBUF == 0 && !(*f).buf.is_null() && (*f).bufsize < 8 {
                if (*f).flags & file::F_USERBUF == 0 {
                    rusty_libc_malloc::free((*f).buf.cast());
                }
                let nb = rusty_libc_malloc::malloc(8) as *mut u8;
                (*f).flags &= !(file::F_USERBUF | F_RDMODE);
                (*f).set_buffer(nb, if nb.is_null() { 0 } else { 8 });
                if (*f).buf.is_null() {
                    (*f).flags |= F_ERR;
                    return WEOF;
                }
                continue;
            }
            (*(*f).wide).tshift = 0;
            if !file::underflow_keep(f, have) {
                return WEOF;
            }
        }
    }
}

#[inline]
pub unsafe fn getwc_raw(f: *mut FILE) -> wint_t {
    unsafe {
        let fl = (*f).flags;
        if fl & (F_WIDE | F_BYTE | F_RDMODE | F_W32) == (F_WIDE | F_RDMODE)
            && (*f).rpos() < (*f).rend()
            && (*(*f).wide).npush == 0
            && (*(*f).wide).cs != WCs::Ccs
        {
            let b = *(*f).buf.add((*f).rpos());
            if b < 0x80 {
                (*f).set_rpos((*f).rpos() + 1);
                return wint_t::from(b);
            }
        }
        getwc_slow(f)
    }
}

#[inline(never)]
unsafe fn getwc_slow(f: *mut FILE) -> wint_t {
    unsafe {
        if !wide_ok(f) {
            return WEOF;
        }
        let w = (*f).wide;
        if (*w).npush > 0 {
            (*w).npush -= 1;
            if (*w).npush == 0 && (*w).cs == WCs::Utf8 {
                (*w).tshift = if (*f).flags & F_RDMODE != 0 { (*f).rpos() } else { 0 };
            }
            return *(*w).push.add((*w).npush);
        }
        read_core(f)
    }
}

pub unsafe fn fgetws_raw(s: *mut wchar_t, n: c_int, f: *mut FILE) -> *mut wchar_t {
    unsafe {
        if n <= 0 {
            return null_mut();
        }
        if n == 1 {
            *s = 0;
            return s;
        }
        let old_err = (*f).flags & F_ERR;
        (*f).flags &= !F_ERR;
        let first = getwc_raw(f);
        let mut bulk_nl = false;
        if first == WEOF {
            (*f).flags |= old_err;
            return null_mut();
        }
        let mut i = 0usize;
        *s = first as wchar_t;
        i += 1;
        let max = (n - 1) as usize;
        if first != u32::from(b'\n') {
            while i < max {
                if (*f).flags & (F_WIDE | F_BYTE | F_RDMODE | F_W32) == (F_WIDE | F_RDMODE) && (*f).rpos() < (*f).rend() && (*(*f).wide).npush == 0 && (*(*f).wide).cs != WCs::Ccs {
                    let lim = ((*f).rend() - (*f).rpos()).min(max - i);
                    let p = (*f).buf.add((*f).rpos());
                    let mut k = 0usize;
                    while k < lim {
                        let b = *p.add(k);
                        if b >= 0x80 {
                            break;
                        }
                        *s.add(i + k) = b as wchar_t;
                        k += 1;
                        if b == b'\n' {
                            bulk_nl = true;
                            break;
                        }
                    }
                    (*f).set_rpos((*f).rpos() + k);
                    i += k;
                    if bulk_nl {
                        break;
                    }
                    if k > 0 && i >= max {
                        break;
                    }
                }
                let c = getwc_raw(f);
                if c == WEOF {
                    break;
                }
                *s.add(i) = c as wchar_t;
                i += 1;
                if c == u32::from(b'\n') {
                    break;
                }
            }
        }
        let failed = (*f).flags & F_ERR != 0;
        (*f).flags |= old_err;
        if failed {
            return null_mut();
        }
        *s.add(i) = 0;
        s
    }
}

fn exact_encode(cs: WCs, wc: u32, out: &mut [u8; 16]) -> usize {
    match cs {
        WCs::Raw32 => encode(cs, wc, out),
        WCs::Ccs => 0,
        WCs::C => {
            if wc <= 0x7f {
                out[0] = wc as u8;
                1
            } else {
                0
            }
        }
        WCs::Utf8 | WCs::Other => {
            let mut b = [0u8; 6];
            match rusty_libc_wchar::mbyte::encode_cs(if cs == WCs::Utf8 { Charset::Utf8 } else { Charset::Other }, wc, &mut b) {
                Some(n) => {
                    out[..n].copy_from_slice(&b[..n]);
                    n
                }
                None => 0,
            }
        }
    }
}

pub unsafe fn ungetwc_raw(wc: wint_t, f: *mut FILE) -> wint_t {
    unsafe {
        if wc == WEOF {
            return WEOF;
        }
        if (*f).flags & (F_WIDE | F_BYTE) == F_BYTE {
            return wint_t::from(file::ungetc_force(c_int::from(wc as u8), f) as u8);
        }
        let w = ensure_info(f);
        if w.is_null() {
            return WEOF;
        }
        if (*w).npush == 0 && (*f).flags & F_RDMODE != 0 && (*f).rpos() > 0 {
            let mut enc = [0u8; 16];
            let n = exact_encode((*w).cs, wc, &mut enc);
            if n > 0 && n <= (*f).rpos() && core::slice::from_raw_parts((*f).buf.add((*f).rpos() - n), n) == &enc[..n] {
                (*f).set_rpos((*f).rpos() - n);
                (*f).flags &= !F_EOF;
                return wc;
            }
        }
        if (*w).npush == (*w).cap {
            let nc = if (*w).cap == 0 { 16 } else { (*w).cap * 2 };
            let np = rusty_libc_malloc::realloc((*w).push.cast(), nc * 4) as *mut u32;
            if np.is_null() {
                return WEOF;
            }
            (*w).push = np;
            (*w).cap = nc;
        }
        *(*w).push.add((*w).npush) = wc;
        (*w).npush += 1;
        (*f).flags &= !F_EOF;
        wc
    }
}

#[inline]
pub unsafe fn putwc_raw(f: *mut FILE, wc: wint_t) -> wint_t {
    unsafe {
        let fl = (*f).flags;
        if fl & (F_WIDE | F_BYTE | F_WRMODE | F_UNBUF | F_W32) == (F_WIDE | F_WRMODE)
            && wc < 0x80
            && (*f).wpos() < (*f).bufsize
            && !(fl & F_LBF != 0 && wc == u32::from(b'\n'))
            && (*(*f).wide).cs != WCs::Raw32
            && (*(*f).wide).cs != WCs::Ccs
        {
            *(*f).wptr = wc as u8;
            (*f).wptr = (*f).wptr.add(1);
            (*(*f).wide).pchars += 1;
            return wc;
        }
        putwc_slow(f, wc)
    }
}

#[inline(never)]
unsafe fn putwc_slow(f: *mut FILE, wc: wint_t) -> wint_t {
    unsafe {
        if !wide_ok(f) {
            return WEOF;
        }
        if (*f).flags & F_WRITE == 0 {
            (*f).flags |= F_ERR;
            errno::set(EBADF);
            return WEOF;
        }
        if wc == WEOF && (!(*(*f).wide).putting || (*f).flags & (F_UNBUF | F_LBF) != 0 || (*f).wpos() >= (*f).bufsize) {
            return if file::flush_write(f) { 0 } else { WEOF };
        }
        let mut enc = [0u8; 16];
        let n = if (*(*f).wide).cs == WCs::Ccs { ccs_encode((*f).wide, wc, &mut enc) } else { encode((*(*f).wide).cs, wc, &mut enc) };
        if file::write_bytes_raw(f, enc.as_ptr(), n) == n {
            note_extra(f, n);
            wc
        } else {
            WEOF
        }
    }
}

pub(crate) unsafe fn put_wide_chars(f: *mut FILE, s: &[u32]) -> bool {
    unsafe {
        let cs = (*(*f).wide).cs;
        let mut chunk = [0u8; 512];
        let mut k = 0usize;
        let mut extra = 0isize;
        for &wc in s {
            if k + 16 > chunk.len() {
                if file::write_bytes_raw(f, chunk.as_ptr(), k) != k {
                    return false;
                }
                k = 0;
            }
            if wc < 0x80 && cs != WCs::Raw32 && cs != WCs::Ccs {
                chunk[k] = wc as u8;
                k += 1;
                continue;
            }
            let mut enc = [0u8; 16];
            let n = if cs == WCs::Ccs { ccs_encode((*f).wide, wc, &mut enc) } else { encode(cs, wc, &mut enc) };
            chunk[k..k + n].copy_from_slice(&enc[..n]);
            k += n;
            if cs == WCs::C && n != 1 {
                extra += n as isize - 1;
            }

        }
        let ok = k == 0 || file::write_bytes_raw(f, chunk.as_ptr(), k) == k;
        if ok {
            (*(*f).wide).extra += extra;
            (*(*f).wide).pchars += s.len();
            (*(*f).wide).putting = true;
            (*(*f).wide).wbuf = true;
        }
        ok
    }
}

#[inline]
unsafe fn note_extra(f: *mut FILE, n: usize) {
    unsafe {
        (*(*f).wide).pchars += 1;
        (*(*f).wide).putting = true;
        (*(*f).wide).wbuf = true;

        if n != 1 && (*(*f).wide).cs == WCs::C {
            (*(*f).wide).extra += n as isize - 1;
        }
    }
}

pub unsafe fn fputws_raw(s: *const wchar_t, f: *mut FILE) -> c_int {
    unsafe {
        if !wide_ok(f) {
            return -1;
        }
        let n = rusty_libc_wchar::wstring::wcslen(s);
        if n == 0 {
            return 1;
        }
        if (*f).flags & F_WRITE == 0 {
            (*f).flags |= F_ERR;
            errno::set(EBADF);
            return -1;
        }
        if put_wide_chars(f, core::slice::from_raw_parts(s as *const u32, n)) { 1 } else { -1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fwide(f: *mut FILE, mode: c_int) -> c_int {
    unsafe { locked!(f, move || fwide_raw(f, mode)) }
}

macro_rules! getters {
    ($($name:ident),*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(f: *mut FILE) -> wint_t {
            unsafe { locked!(f, move || getwc_raw(f)) }
        }
    )*};
}
getters!(fgetwc, getwc);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetwc_unlocked(f: *mut FILE) -> wint_t {
    unsafe { getwc_raw(f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwc_unlocked(f: *mut FILE) -> wint_t {
    unsafe { getwc_raw(f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wuflow(f: *mut FILE) -> wint_t {
    unsafe { getwc_raw(f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wunderflow(f: *mut FILE) -> wint_t {
    unsafe {
        let wc = getwc_raw(f);
        if wc != WEOF {
            ungetwc_raw(wc, f);
        }
        wc
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __woverflow(f: *mut FILE, wc: wint_t) -> wint_t {
    unsafe {
        if (*f).flags & (F_WIDE | F_BYTE) == F_BYTE {
            return if file::putc(c_int::from(wc as u8), f) == file::EOF { WEOF } else { wc };
        }
        putwc_raw(f, wc)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwchar() -> wint_t {
    unsafe {
        let f = file::stdin_ptr();
        locked!(f, move || getwc_raw(f))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwchar_unlocked() -> wint_t {
    unsafe { getwc_raw(file::stdin_ptr()) }
}

macro_rules! putters {
    ($($name:ident),*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(wc: wchar_t, f: *mut FILE) -> wint_t {
            unsafe { locked!(f, move || putwc_raw(f, wc as wint_t)) }
        }
    )*};
}
putters!(fputwc);

#[inline]
unsafe fn putwc_macro(f: *mut FILE, wc: wint_t) -> wint_t {
    unsafe {
        if (*f).flags & F_BYTE != 0 {
            if wc as c_int == -1 {
                return if file::flush_write(f) { 0 } else { WEOF };
            }
            let r = file::putc(wc as c_int, f);
            return if r == -1 { WEOF } else { r as wint_t };
        }
        putwc_raw(f, wc)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwc(wc: wchar_t, f: *mut FILE) -> wint_t {
    unsafe { locked!(f, move || putwc_macro(f, wc as wint_t)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputwc_unlocked(wc: wchar_t, f: *mut FILE) -> wint_t {
    unsafe { putwc_raw(f, wc as wint_t) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwc_unlocked(wc: wchar_t, f: *mut FILE) -> wint_t {
    unsafe { putwc_macro(f, wc as wint_t) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwchar(wc: wchar_t) -> wint_t {
    unsafe {
        let f = file::stdout_ptr();
        locked!(f, move || putwc_macro(f, wc as wint_t))
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwchar_unlocked(wc: wchar_t) -> wint_t {
    unsafe { putwc_macro(file::stdout_ptr(), wc as wint_t) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetws(s: *mut wchar_t, n: c_int, f: *mut FILE) -> *mut wchar_t {
    unsafe { locked!(f, move || fgetws_raw(s, n, f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetws_unlocked(s: *mut wchar_t, n: c_int, f: *mut FILE) -> *mut wchar_t {
    unsafe { fgetws_raw(s, n, f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputws(s: *const wchar_t, f: *mut FILE) -> c_int {
    unsafe { locked!(f, move || fputws_raw(s, f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputws_unlocked(s: *const wchar_t, f: *mut FILE) -> c_int {
    unsafe { fputws_raw(s, f) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ungetwc(wc: wint_t, f: *mut FILE) -> wint_t {
    unsafe { locked!(f, move || ungetwc_raw(wc, f)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_wmemstream(bufloc: *mut *mut wchar_t, sizeloc: *mut usize) -> *mut FILE {
    unsafe { crate::file_extra::open_memstream_unit(bufloc as *mut *mut core::ffi::c_char, sizeloc, 4) }
}

