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

impl WideInfo {
    #[inline]
    fn ccs_mut(&mut self) -> &mut Ccs {
        debug_assert!(!self.ccs.is_null());
        unsafe { &mut *self.ccs }
    }

    #[inline]
    fn pop(&mut self) -> u32 {
        self.npush -= 1;
        unsafe { *self.push.wrapping_add(self.npush) }
    }

    fn push_back(&mut self, wc: u32) -> bool {
        if self.npush == self.cap {
            let nc = if self.cap == 0 { 16 } else { self.cap * 2 };
            let np = unsafe { rusty_libc_malloc::realloc(self.push.cast(), nc * 4) } as *mut u32;
            if np.is_null() {
                return false;
            }
            self.push = np;
            self.cap = nc;
        }
        unsafe { *self.push.wrapping_add(self.npush) = wc };
        self.npush += 1;
        true
    }
}

#[inline(always)]
fn wi(f: &mut FILE) -> &mut WideInfo {
    f.wide_mut().expect("wide stream without its state")
}

pub(crate) fn set_ccs(f: &mut FILE, name: &[u8]) -> bool {
    let Ok((dec, enc)) = rusty_libc_iconv::Converter::open_ccs(name) else {
        errno::set(22);
        return false;
    };
    if !ensure_info(f) {
        errno::set(12);
        return false;
    }
    let p: *mut Ccs = file::alloc(core::mem::size_of::<Ccs>()).cast();
    if p.is_null() {
        errno::set(12);
        return false;
    }
    unsafe { p.write(Ccs { dec, enc }) };
    let w = wi(f);
    drop_ccs(w);
    w.ccs = p;
    w.cs = WCs::Ccs;
    f.hide_read_window();
    f.flags |= F_WIDE;
    true
}

fn drop_ccs(w: &mut WideInfo) {
    if !w.ccs.is_null() {
        unsafe { core::ptr::drop_in_place(w.ccs) };
        unsafe { file::free(w.ccs.cast()) };
        w.ccs = null_mut();
    }
}

fn ccs_decode(w: &mut WideInfo, bytes: &[u8]) -> Decoded {
    let c = w.ccs_mut();
    let (mut ip, mut op) = (0usize, 0usize);
    let mut out = [0u8; 4];
    let r = c.dec.convert_raw(bytes, &mut ip, &mut out, &mut op);
    match r {
        Err(rusty_libc_iconv::Error::Ilseq) => Decoded::Invalid,
        _ if op == 4 => Decoded::Char(u32::from_ne_bytes(out), ip),
        _ => Decoded::Incomplete,
    }
}

fn ccs_encode(w: &mut WideInfo, wc: u32, out: &mut [u8; 16]) -> usize {
    let c = w.ccs_mut();
    let input = wc.to_ne_bytes();
    let (mut ip, mut op) = (0usize, 0usize);
    match c.enc.convert_raw(&input, &mut ip, &mut out[..], &mut op) {
        Ok(_) if op > 0 => op,
        _ => {
            out[0] = b'?';
            1
        }
    }
}

#[inline]
fn encode_for(w: &mut WideInfo, wc: u32, out: &mut [u8; 16]) -> usize {
    if w.cs == WCs::Ccs { ccs_encode(w, wc, out) } else { encode(w.cs, wc, out) }
}

pub(crate) fn free_wide(f: &mut FILE) {
    if let Some(w) = f.wide_mut() {
        drop_ccs(w);
        unsafe { file::free(w.push.cast()) };
        unsafe { file::free(f.wide.cast()) };
        f.wide = null_mut();
    }
}

fn ensure_info(f: &mut FILE) -> bool {
    if f.wide.is_null() {
        f.wide = unsafe { rusty_libc_malloc::calloc(1, core::mem::size_of::<WideInfo>()) } as *mut WideInfo;
    }
    !f.wide.is_null()
}

fn make_wide(f: &mut FILE, cs: WCs) -> bool {
    let fl = f.flags;
    if fl & F_BYTE != 0 {
        return false;
    }
    if fl & F_WIDE != 0 {
        return true;
    }
    if !ensure_info(f) {
        return false;
    }
    wi(f).cs = cs;
    f.hide_read_window();
    f.flags |= F_WIDE;
    true
}

pub(crate) fn make_raw_wide(f: &mut FILE) -> bool {
    make_wide(f, WCs::Raw32)
}

#[inline]
pub(crate) fn wide_ok(f: &mut FILE) -> bool {
    let fl = f.flags;
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

pub fn fwide_raw(f: &mut FILE, mode: c_int) -> c_int {
    if f.flags & (F_WIDE | F_BYTE) == 0 {
        if mode > 0 {
            wide_ok(f);
        } else if mode < 0 {
            f.flags |= F_BYTE;
        }
    }
    if f.flags & F_WIDE != 0 {
        1
    } else if f.flags & F_BYTE != 0 {
        -1
    } else {
        0
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

#[inline(always)]
fn unread(f: &FILE) -> &[u8] {
    let (pos, end) = (f.rpos(), f.rend());
    unsafe { f.buf_slice(pos, end - pos) }
}

fn read_core(f: &mut FILE) -> wint_t {
    let w = wi(f);
    let cs = w.cs;
    w.putting = false;
    w.ahead = true;
    loop {
        let have = if f.flags & F_RDMODE != 0 { f.rend() - f.rpos() } else { 0 };
        if have > 0 {
            let bytes = unread(f);
            let d = if cs == WCs::Ccs {
                let bytes: &[u8] = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), bytes.len()) };
                ccs_decode(wi(f), bytes)
            } else {
                decode(cs, bytes)
            };
            match d {
                Decoded::Char(c, n) => {
                    f.set_rpos(f.rpos() + n);
                    return c;
                }
                Decoded::Invalid => {
                    errno::set(EILSEQ);
                    f.flags |= F_ERR;
                    return WEOF;
                }
                Decoded::Incomplete => {}
            }
        }
        if f.flags & F_UNBUF == 0 && !f.buf.is_null() && f.bufsize() < 8 {
            if f.flags & file::F_USERBUF == 0 {
                unsafe { file::free(f.buf) };
            }
            let nb = file::alloc(8);
            f.flags &= !(file::F_USERBUF | F_RDMODE);
            f.set_buffer(nb, if nb.is_null() { 0 } else { 8 });
            if f.buf.is_null() {
                f.flags |= F_ERR;
                return WEOF;
            }
            continue;
        }
        wi(f).tshift = 0;
        if !file::underflow_keep(f, have) {
            return WEOF;
        }
    }
}

#[inline]
pub fn getwc_raw(f: &mut FILE) -> wint_t {
    let fl = f.flags;
    if fl & (F_WIDE | F_BYTE | F_RDMODE | F_W32) == (F_WIDE | F_RDMODE) && f.rpos() < f.rend() {
        let w = wi(f);
        if w.npush == 0 && w.cs != WCs::Ccs {
            let b = unread(f)[0];
            if b < 0x80 {
                f.set_rpos(f.rpos() + 1);
                return wint_t::from(b);
            }
        }
    }
    getwc_slow(f)
}

#[inline(never)]
fn getwc_slow(f: &mut FILE) -> wint_t {
    if !wide_ok(f) {
        return WEOF;
    }
    let tshift = if f.flags & F_RDMODE != 0 { f.rpos() } else { 0 };
    let w = wi(f);
    if w.npush > 0 {
        let c = w.pop();
        if w.npush == 0 && w.cs == WCs::Utf8 {
            w.tshift = tshift;
        }
        return c;
    }
    read_core(f)
}

pub fn read_wide_line(s: &mut [wchar_t], f: &mut FILE) -> bool {
    let old_err = f.flags & F_ERR;
    f.flags &= !F_ERR;
    let first = getwc_raw(f);
    let mut bulk_nl = false;
    if first == WEOF {
        f.flags |= old_err;
        return false;
    }
    let mut i = 0usize;
    s[0] = first as wchar_t;
    i += 1;
    let max = s.len() - 1;
    if first != u32::from(b'\n') {
        while i < max {
            if f.flags & (F_WIDE | F_BYTE | F_RDMODE | F_W32) == (F_WIDE | F_RDMODE) && f.rpos() < f.rend() && {
                let w = wi(f);
                w.npush == 0 && w.cs != WCs::Ccs
            } {
                let bytes = unread(f);
                let lim = bytes.len().min(max - i);
                let mut k = 0usize;
                while k < lim {
                    let b = bytes[k];
                    if b >= 0x80 {
                        break;
                    }
                    s[i + k] = b as wchar_t;
                    k += 1;
                    if b == b'\n' {
                        bulk_nl = true;
                        break;
                    }
                }
                f.set_rpos(f.rpos() + k);
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
            s[i] = c as wchar_t;
            i += 1;
            if c == u32::from(b'\n') {
                break;
            }
        }
    }
    let failed = f.flags & F_ERR != 0;
    f.flags |= old_err;
    if failed {
        return false;
    }
    s[i] = 0;
    true
}

pub unsafe fn fgetws_raw(s: *mut wchar_t, n: c_int, f: &mut FILE) -> *mut wchar_t {
    if n <= 0 {
        return null_mut();
    }
    if n == 1 {
        unsafe { *s = 0 };
        return s;
    }
    let buf = unsafe { core::slice::from_raw_parts_mut(s, n as usize) };
    if read_wide_line(buf, f) { s } else { null_mut() }
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

pub fn ungetwc_raw(wc: wint_t, f: &mut FILE) -> wint_t {
    if wc == WEOF {
        return WEOF;
    }
    if f.flags & (F_WIDE | F_BYTE) == F_BYTE {
        return wint_t::from(file::ungetc_force(c_int::from(wc as u8), f) as u8);
    }
    if !ensure_info(f) {
        return WEOF;
    }
    let (npush, cs) = {
        let w = wi(f);
        (w.npush, w.cs)
    };
    if npush == 0 && f.flags & F_RDMODE != 0 && f.rpos() > 0 {
        let mut enc = [0u8; 16];
        let n = exact_encode(cs, wc, &mut enc);
        let pos = f.rpos();
        if n > 0 && n <= pos && unsafe { f.buf_slice(pos - n, n) } == &enc[..n] {
            f.set_rpos(pos - n);
            f.flags &= !F_EOF;
            return wc;
        }
    }
    if !wi(f).push_back(wc) {
        return WEOF;
    }
    f.flags &= !F_EOF;
    wc
}

#[inline]
pub fn putwc_raw(f: &mut FILE, wc: wint_t) -> wint_t {
    let fl = f.flags;
    if fl & (F_WIDE | F_BYTE | F_WRMODE | F_UNBUF | F_W32) == (F_WIDE | F_WRMODE)
        && wc < 0x80
        && f.wpos() < f.bufsize()
        && !(fl & F_LBF != 0 && wc == u32::from(b'\n'))
    {
        let cs = wi(f).cs;
        if cs != WCs::Raw32 && cs != WCs::Ccs {
            let p = f.wptr;
            unsafe { *p = wc as u8 };
            f.wptr = p.wrapping_add(1);
            wi(f).pchars += 1;
            return wc;
        }
    }
    putwc_slow(f, wc)
}

#[inline(never)]
fn putwc_slow(f: &mut FILE, wc: wint_t) -> wint_t {
    if !wide_ok(f) {
        return WEOF;
    }
    if f.flags & F_WRITE == 0 {
        f.flags |= F_ERR;
        errno::set(EBADF);
        return WEOF;
    }
    if wc == WEOF && (!wi(f).putting || f.flags & (F_UNBUF | F_LBF) != 0 || f.wpos() >= f.bufsize()) {
        return if file::flush_write(f) { 0 } else { WEOF };
    }
    let mut enc = [0u8; 16];
    let n = encode_for(wi(f), wc, &mut enc);
    if file::write_bytes_raw(f, &enc[..n]) == n {
        note_extra(f, n);
        wc
    } else {
        WEOF
    }
}

pub(crate) fn put_wide_chars(f: &mut FILE, s: &[u32]) -> bool {
    let cs = wi(f).cs;
    let mut chunk = [0u8; 512];
    let mut k = 0usize;
    let mut extra = 0isize;
    for &wc in s {
        if k + 16 > chunk.len() {
            if file::write_bytes_raw(f, &chunk[..k]) != k {
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
        let n = encode_for(wi(f), wc, &mut enc);
        chunk[k..k + n].copy_from_slice(&enc[..n]);
        k += n;
        if cs == WCs::C && n != 1 {
            extra += n as isize - 1;
        }

    }
    let ok = k == 0 || file::write_bytes_raw(f, &chunk[..k]) == k;
    if ok {
        let w = wi(f);
        w.extra += extra;
        w.pchars += s.len();
        w.putting = true;
        w.wbuf = true;
    }
    ok
}

#[inline]
fn note_extra(f: &mut FILE, n: usize) {
    let w = wi(f);
    w.pchars += 1;
    w.putting = true;
    w.wbuf = true;

    if n != 1 && w.cs == WCs::C {
        w.extra += n as isize - 1;
    }
}

pub fn put_wide_text(s: &[u32], f: &mut FILE) -> c_int {
    if !wide_ok(f) {
        return -1;
    }
    if s.is_empty() {
        return 1;
    }
    if f.flags & F_WRITE == 0 {
        f.flags |= F_ERR;
        errno::set(EBADF);
        return -1;
    }
    if put_wide_chars(f, s) { 1 } else { -1 }
}

unsafe fn wide_text<'a>(s: *const wchar_t) -> &'a [u32] {
    let n = unsafe { rusty_libc_wchar::wstring::wcslen(s) };
    unsafe { core::slice::from_raw_parts(s as *const u32, n) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fwide(f: *mut FILE, mode: c_int) -> c_int {
    locked!(f, |s| fwide_raw(s, mode))
}

macro_rules! getters {
    ($($name:ident),*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(f: *mut FILE) -> wint_t {
            locked!(f, |s| getwc_raw(s))
        }
    )*};
}
getters!(fgetwc, getwc);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetwc_unlocked(f: *mut FILE) -> wint_t {
    getwc_raw(unsafe { file::stream(f) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwc_unlocked(f: *mut FILE) -> wint_t {
    getwc_raw(unsafe { file::stream(f) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wuflow(f: *mut FILE) -> wint_t {
    getwc_raw(unsafe { file::stream(f) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wunderflow(f: *mut FILE) -> wint_t {
    let s = unsafe { file::stream(f) };
    let wc = getwc_raw(s);
    if wc != WEOF {
        ungetwc_raw(wc, s);
    }
    wc
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __woverflow(f: *mut FILE, wc: wint_t) -> wint_t {
    let s = unsafe { file::stream(f) };
    if s.flags & (F_WIDE | F_BYTE) == F_BYTE {
        return if file::putc(c_int::from(wc as u8), s) == file::EOF { WEOF } else { wc };
    }
    putwc_raw(s, wc)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getwchar() -> wint_t {
    locked!(file::stdin_ptr(), |s| getwc_raw(s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwchar_unlocked() -> wint_t {
    getwc_raw(unsafe { file::stream(file::stdin_ptr()) })
}

macro_rules! putters {
    ($($name:ident),*) => {$(
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(wc: wchar_t, f: *mut FILE) -> wint_t {
            locked!(f, |s| putwc_raw(s, wc as wint_t))
        }
    )*};
}
putters!(fputwc);

#[inline]
fn putwc_macro(f: &mut FILE, wc: wint_t) -> wint_t {
    if f.flags & F_BYTE != 0 {
        if wc as c_int == -1 {
            return if file::flush_write(f) { 0 } else { WEOF };
        }
        let r = file::putc(wc as c_int, f);
        return if r == -1 { WEOF } else { r as wint_t };
    }
    putwc_raw(f, wc)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwc(wc: wchar_t, f: *mut FILE) -> wint_t {
    locked!(f, |s| putwc_macro(s, wc as wint_t))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputwc_unlocked(wc: wchar_t, f: *mut FILE) -> wint_t {
    putwc_raw(unsafe { file::stream(f) }, wc as wint_t)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwc_unlocked(wc: wchar_t, f: *mut FILE) -> wint_t {
    putwc_macro(unsafe { file::stream(f) }, wc as wint_t)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn putwchar(wc: wchar_t) -> wint_t {
    locked!(file::stdout_ptr(), |s| putwc_macro(s, wc as wint_t))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwchar_unlocked(wc: wchar_t) -> wint_t {
    putwc_macro(unsafe { file::stream(file::stdout_ptr()) }, wc as wint_t)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetws(s: *mut wchar_t, n: c_int, f: *mut FILE) -> *mut wchar_t {
    locked!(f, |st| unsafe { fgetws_raw(s, n, st) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetws_unlocked(s: *mut wchar_t, n: c_int, f: *mut FILE) -> *mut wchar_t {
    let st = unsafe { file::stream(f) };
    unsafe { fgetws_raw(s, n, st) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputws(s: *const wchar_t, f: *mut FILE) -> c_int {
    let text = unsafe { wide_text(s) };
    locked!(f, |st| put_wide_text(text, st))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputws_unlocked(s: *const wchar_t, f: *mut FILE) -> c_int {
    let text = unsafe { wide_text(s) };
    put_wide_text(text, unsafe { file::stream(f) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ungetwc(wc: wint_t, f: *mut FILE) -> wint_t {
    locked!(f, |s| ungetwc_raw(wc, s))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_wmemstream(bufloc: *mut *mut wchar_t, sizeloc: *mut usize) -> *mut FILE {
    unsafe { crate::file_extra::open_memstream_unit(bufloc as *mut *mut core::ffi::c_char, sizeloc, 4) }
}

