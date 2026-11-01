//! wchar.h: wide-character stream I/O (fwide, fgetwc, fputwc, fgetws, fputws, ungetwc, open_wmemstream).
//!
//! Orientation follows glibc 2.43 as measured: the first use fixes a stream as byte or wide
//! (`fwide(f, 0)` only asks); a wide function on a byte stream, or a byte function on a wide one, fails
//! quietly (WEOF/EOF/0/-1, no flag, no errno). A wide stream shares the byte buffer of the `FILE`:
//! reads decode from the buffered bytes (an incomplete character stays in the buffer until more
//! bytes arrive, so `ftell` is always exact) and writes encode into it. The character set is a
//! snapshot taken when the stream becomes wide: the C locale (ASCII) or UTF-8 (or the locale's other charset, by its codeset
//! name: glibc's `_IO_fwide` copies the conversion steps of the locale in force into the stream, so a later `setlocale` or
//! `uselocale` does not change what the stream converts with). A character
//! the charset cannot represent is written as glibc's conversion writes it: transliterated with the table of the locale
//! current at the write (see `encode`).
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

/// The character set a wide stream converts with.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WCs {
    C,
    Utf8,
    /// Any other charset of the locale (rusty-libc-iconv).
    Other,
    /// `open_wmemstream`: wide characters are stored as they are (4 bytes each).
    Raw32,
    /// `fopen (..., "r,ccs=NAME")`: the stream's own charset, converted with rusty-libc-iconv (`WideInfo::ccs`).
    Ccs,
}

/// What a wide stream carries besides the shared byte buffer.
pub struct WideInfo {
    pub cs: WCs,
    /// Characters pushed back with `ungetwc` that the buffer cannot take back (last in, first out).
    pub push: *mut u32,
    pub npush: usize,
    pub cap: usize,
    /// Bytes pending in the write buffer beyond one per wide character (C locale transliterations): `ftell` ignores them until the flush.
    pub extra: isize,
    /// UTF-8: after a pushed-back character has been read again glibc's `ftell` forgets the bytes consumed
    /// before it in the current buffer; this many bytes are subtracted until the buffer is refilled or the stream positioned.
    pub tshift: usize,
    /// Wide characters written since the last flush, and whether the stream is in the middle of writing (glibc's wide
    /// write buffer is set up): a WEOF written then is stored, not taken as a flush request.
    pub pchars: usize,
    pub putting: bool,
    /// Raw bytes that `putc` stored at the front of the write buffer (ahead of the pending wide characters).
    pub raw: usize,
    /// A wide character has been written on this stream at some time (glibc's wide write buffer exists).
    /// Until then the first write after reading starts where the read-ahead ended, not at the logical position.
    pub wbuf: bool,
    /// The buffer holds read-ahead that a wide read took from the file and no seek has touched since.
    pub ahead: bool,
    /// The converters of a `ccs=` stream (null for the others).
    pub ccs: *mut Ccs,
    /// `WCs::Other`: the codeset of the locale in force when the stream became wide (its LC_CTYPE codeset name, locale data
    /// that lives forever), and that charset's longest character (MB_CUR_MAX then); `WCs::Ccs`: no name, 1 when the
    /// charset has one byte per character. None and 0 for the other charsets.
    pub cset: Option<&'static [u8]>,
    pub cset_max: usize,
    /// The ASCII fast paths of `putwc_raw` may store the byte (the charset is not raw 32-bit or `ccs=`, and `drop` is
    /// false).
    pub wfast: bool,
    /// Wide characters glibc's wide write buffer took since its last flush that was not a full buffer's: a fflush, seek,
    /// close or switch to reading, or a line-buffered newline (glibc flushes the full buffer when the next character
    /// comes, so the characters in its buffer are `gpend`). Kept for buffered streams only.
    pub gtot: usize,
    /// glibc's wide buffer holds a character the stream cannot write at all (no transliteration, no default replacement:
    /// tr_TR and the other Turkic locales): its next flush converts up to that character, writes those bytes, drops
    /// the rest and fails (`_IO_wdo_write`). The bytes before it are in our byte buffer; the character and the `ndrop - 1`
    /// after it are only counted.
    pub drop: bool,
    pub ndrop: usize,
}

/// The two directions of a stream's own charset: charset to INTERNAL (host-order UCS-4, from_ne_bytes) for reading, INTERNAL to
/// charset for writing.
pub struct Ccs {
    dec: rusty_libc_iconv::Converter,
    enc: rusty_libc_iconv::Converter,
}

impl WideInfo {
    /// The characters in glibc's wide buffer (see `gtot`) for a wide buffer of `wcap` characters.
    #[inline]
    fn gpend(&self, wcap: usize) -> usize {
        if self.gtot == 0 { 0 } else { (self.gtot - 1) % wcap + 1 }
    }

    /// The codeset a `WCs::Other` stream converts with (empty for the others).
    #[inline]
    fn cset(&self) -> &'static [u8] {
        self.cset.unwrap_or(b"")
    }

    /// The `ccs=` converters (`cs == WCs::Ccs`).
    #[inline]
    fn ccs_mut(&mut self) -> &mut Ccs {
        debug_assert!(!self.ccs.is_null());
        // SAFETY: `ccs` is set (with `cs = Ccs`) by `set_ccs` to a block of its own, freed only by `free_wide` with the whole
        // state; only `ccs=` streams call this.
        unsafe { &mut *self.ccs }
    }

    /// Take the last pushed-back character (`npush > 0`).
    #[inline]
    fn pop(&mut self) -> u32 {
        self.npush -= 1;
        // SAFETY: `push` holds `cap >= npush + 1` characters (`push_back` keeps it so); index `npush` was written by it.
        unsafe { *self.push.wrapping_add(self.npush) }
    }

    /// Push `wc` back, growing the array (doubling, from 16); false when there is no memory.
    fn push_back(&mut self, wc: u32) -> bool {
        if self.npush == self.cap {
            let nc = if self.cap == 0 { 16 } else { self.cap * 2 };
            // SAFETY: `push` is null or the array's own malloc'd block.
            let np = unsafe { rusty_libc_malloc::realloc(self.push.cast(), nc * 4) } as *mut u32;
            if np.is_null() {
                return false;
            }
            self.push = np;
            self.cap = nc;
        }
        // SAFETY: `npush < cap`: room in the array.
        unsafe { *self.push.wrapping_add(self.npush) = wc };
        self.npush += 1;
        true
    }
}

/// The wide state of a stream known to be wide (F_WIDE is set only once the state exists).
#[inline(always)]
fn wi(f: &mut FILE) -> &mut WideInfo {
    f.wide_mut().expect("wide stream without its state")
}

/// Make `f` a wide stream that converts with charset `name` (the `ccs=` part of a mode string). False with errno set when
/// it cannot: EINVAL for a name glibc 2.43's `_IO_new_file_fopen` finds no converters for (unknown or empty after its
/// `strip`, with a `//TRANSLIT`-style suffix, INTERNAL or WCHAR_T: `Converter::open_ccs`), ENOMEM without memory; the
/// caller then closes the stream and fails, as glibc's fopen and freopen do.
pub(crate) fn set_ccs(f: &mut FILE, name: &[u8]) -> bool {
    let Ok((dec, enc)) = rusty_libc_iconv::Converter::open_ccs(name) else {
        errno::set(22);
        return false;
    };
    if !ensure_info(f) {
        errno::set(12);
        return false;
    }
    let one_byte = dec.reads_one_byte_charset();
    let p: *mut Ccs = file::alloc(core::mem::size_of::<Ccs>()).cast();
    if p.is_null() {
        errno::set(12);
        return false;
    }
    // SAFETY: a fresh malloc'd block of `Ccs`'s size, aligned for it (malloc's alignment).
    unsafe { p.write(Ccs { dec, enc }) };
    let w = wi(f);
    drop_ccs(w);
    w.ccs = p;
    w.cs = WCs::Ccs;
    w.wfast = false;
    w.cset = None;
    w.cset_max = if one_byte { 1 } else { 0 };
    f.hide_read_window();
    f.flags |= F_WIDE;
    true
}

/// Free the `ccs=` converters of a wide state, if any.
fn drop_ccs(w: &mut WideInfo) {
    if !w.ccs.is_null() {
        // SAFETY: the converters' own block (see `ccs_mut`), dropped and freed once, then forgotten.
        unsafe { core::ptr::drop_in_place(w.ccs) };
        // SAFETY: as above.
        unsafe { file::free(w.ccs.cast()) };
        w.ccs = null_mut();
    }
}

/// The next character of a `ccs=` stream from `bytes`.
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

/// The bytes of `wc` in a `ccs=` stream's charset (`?` when it cannot be represented).
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

/// The encoding of `wc` in a wide stream's charset (see `encode`). (The UTF-8 path first and without the codeset name,
/// which only the other charsets and transliteration need.)
#[inline(always)]
fn encode_for(w: &mut WideInfo, wc: u32, out: &mut [u8; 16]) -> Option<usize> {
    match w.cs {
        WCs::Utf8 => {
            let mut b = [0u8; 6];
            match rusty_libc_wchar::mbyte::encode_cs(Charset::Utf8, wc, &mut b) {
                Some(n) => {
                    out[..n].copy_from_slice(&b[..n]);
                    Some(n)
                }
                None => translit(WCs::Utf8, b"", wc, out),
            }
        }
        WCs::Ccs => Some(ccs_encode(w, wc, out)),
        cs => encode(cs, w.cset(), wc, out),
    }
}

/// Release the wide state of a stream (close, reopen).
pub(crate) fn free_wide(f: &mut FILE) {
    if let Some(w) = f.wide_mut() {
        drop_ccs(w);
        // SAFETY: the pushback array's own block (or null).
        unsafe { file::free(w.push.cast()) };
        // SAFETY: the state's own block (calloc'd by `ensure_info`), forgotten right below.
        unsafe { file::free(f.wide.cast()) };
        f.wide = null_mut();
    }
}

/// The wide state of a stream, allocated on first need (an `ungetwc` works on any stream); false when there is no memory.
fn ensure_info(f: &mut FILE) -> bool {
    if f.wide.is_null() {
        // SAFETY: calloc has no precondition; all-zero bytes are a valid `WideInfo` (null pointers, zero counts, false, C).
        f.wide = unsafe { rusty_libc_malloc::calloc(1, core::mem::size_of::<WideInfo>()) } as *mut WideInfo;
    }
    !f.wide.is_null()
}

/// Make `f` wide (if it has no orientation yet) with the given charset. False if it is a byte stream.
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
    let w = wi(f);
    w.cs = cs;
    w.wfast = cs != WCs::Raw32;
    if cs == WCs::Other {
        // the codeset of the locale in force now stays the stream's (glibc: _IO_fwide copies its conversion steps)
        w.cset = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE).map(|d| d.bytes(14));
        w.cset_max = rusty_libc_wchar::mbyte::mb_cur_max();
    }
    f.hide_read_window();
    f.flags |= F_WIDE;
    true
}

/// open_wmemstream: wide oriented with raw 32-bit storage.
pub(crate) fn make_raw_wide(f: &mut FILE) -> bool {
    make_wide(f, WCs::Raw32)
}

/// The wide function entry check: fixes wide orientation on first use. False for a byte stream.
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

/// `fwide`: positive fixes wide, negative fixes byte (when still undecided); returns the orientation.
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

/// The next character of `bytes` in the stream charset `cs` (codeset `name` for `WCs::Other`).
fn decode(cs: WCs, name: &[u8], bytes: &[u8]) -> Decoded {
    match cs {
        WCs::C => rusty_libc_wchar::mbyte::decode_cs(Charset::C, bytes),
        WCs::Utf8 => rusty_libc_wchar::mbyte::decode_cs(Charset::Utf8, bytes),
        WCs::Other => rusty_libc_wchar::mbyte::decode_in(name, bytes),
        WCs::Ccs => Decoded::Invalid, // (callers with a ccs= stream use ccs_decode)
        WCs::Raw32 => {
            if bytes.len() < 4 {
                Decoded::Incomplete
            } else {
                Decoded::Char(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]), 4)
            }
        }
    }
}

/// The bytes a wide character is written as: encoded, or (when the charset cannot represent it) what glibc's conversion
/// writes instead: the transliteration of the calling thread's current LC_CTYPE (looked up when the character is written:
/// a stream made wide in the C locale and written after `setlocale (LC_ALL, "de_DE.UTF-8")` writes `ä` as `ae`), nothing
/// for an ignored character, or the locale's default replacement. None when none of them can be written (glibc's
/// conversion fails; locales without a default replacement, e.g. tr_TR). Returns the length (at most 16). `name` is the
/// codeset of a `WCs::Other` stream (see `WideInfo::cset`). (Always inlined: as a call it cost the UTF-8 `fputwc` path
/// about 40 instructions.)
#[inline(always)]
pub(crate) fn encode(cs: WCs, name: &[u8], wc: u32, out: &mut [u8; 16]) -> Option<usize> {
    match cs {
        WCs::Ccs => Some(0), // (callers with a ccs= stream use ccs_encode)
        WCs::Raw32 => {
            out[..4].copy_from_slice(&wc.to_le_bytes());
            Some(4)
        }
        WCs::C => {
            if wc < 0x80 {
                out[0] = wc as u8;
                Some(1)
            } else {
                translit(cs, name, wc, out)
            }
        }
        WCs::Utf8 => {
            let mut b = [0u8; 6];
            match rusty_libc_wchar::mbyte::encode_cs(Charset::Utf8, wc, &mut b) {
                Some(n) => {
                    out[..n].copy_from_slice(&b[..n]);
                    Some(n)
                }
                None => translit(cs, name, wc, out),
            }
        }
        WCs::Other => encode_other(name, wc, out),
    }
}

/// `encode` for a `WCs::Other` stream (out of line: the conversion goes through rusty-libc-locale's hook anyway).
#[inline(never)]
fn encode_other(name: &[u8], wc: u32, out: &mut [u8; 16]) -> Option<usize> {
    let mut b = [0u8; 6];
    match rusty_libc_wchar::mbyte::encode_in(name, wc, &mut b) {
        Some(n) => {
            out[..n].copy_from_slice(&b[..n]);
            Some(n)
        }
        None => translit(WCs::Other, name, wc, out),
    }
}

/// `wc` encoded in a stream charset (the C locale's is ASCII; `name` is a `WCs::Other` stream's codeset), None when the
/// charset cannot represent it.
#[inline]
fn encode_plain(cs: WCs, name: &[u8], wc: u32, b: &mut [u8; 6]) -> Option<usize> {
    match cs {
        WCs::Utf8 => rusty_libc_wchar::mbyte::encode_cs(Charset::Utf8, wc, b),
        WCs::Other => rusty_libc_wchar::mbyte::encode_in(name, wc, b),
        _ => {
            if wc < 0x80 {
                b[0] = wc as u8;
                Some(1)
            } else {
                None
            }
        }
    }
}

/// glibc's transliteration of a character the stream's charset cannot represent (`rusty_libc_iconv::translit_one`): a
/// replacement counts only when all of it can be written and fits in `out`.
#[inline(never)]
fn translit(cs: WCs, name: &[u8], wc: u32, out: &mut [u8; 16]) -> Option<usize> {
    if wc >> 7 == 0xe0000 >> 7 {
        return Some(0); // Unicode tag characters U+E0000..U+E007F: glibc's charset modules skip them (UNICODE_TAG_HANDLER)
    }
    let mut n = 0usize;
    let mut writable = |text: &[u32]| {
        n = 0;
        for &c in text {
            let mut b = [0u8; 6];
            let Some(k) = encode_plain(cs, name, c, &mut b) else { return false };
            if n + k > out.len() {
                return false;
            }
            out[n..n + k].copy_from_slice(&b[..k]);
            n += k;
        }
        true
    };
    match rusty_libc_iconv::translit_one(wc, &mut writable) {
        rusty_libc_iconv::Replacement::Text(_) => Some(n),
        rusty_libc_iconv::Replacement::Ignore => Some(0),
        rusty_libc_iconv::Replacement::Illegal => None,
    }
}

/// glibc counts one byte per pending wide character in `ftell` when the stream's charset has a fixed width of one byte
/// (`__libio_codecvt_encoding` 1): a transliteration of another length is off by the difference until the flush.
#[inline]
fn counts_one_byte(w: &WideInfo) -> bool {
    w.cs == WCs::C || matches!(w.cs, WCs::Other | WCs::Ccs) && w.cset_max == 1
}

// ---- reading ----

/// The unread bytes of the buffer (`buf[rpos..rend]`; the read window of a wide stream is the hidden one, see `File`).
#[inline(always)]
fn unread(f: &FILE) -> &[u8] {
    let (pos, end) = (f.rpos(), f.rend());
    // SAFETY: `rpos <= rend <= bufsize` (the buffer invariant); the slice borrows the stream.
    unsafe { f.buf_slice(pos, end - pos) }
}

/// Decode the next character of the stream (no pushback handling).
fn read_core(f: &mut FILE) -> wint_t {
    let w = wi(f);
    let cs = w.cs;
    let name = w.cset();
    w.putting = false;
    w.ahead = true;
    loop {
        let have = if f.flags & F_RDMODE != 0 { f.rend() - f.rpos() } else { 0 };
        if have > 0 {
            let bytes = unread(f);
            let d = if cs == WCs::Ccs {
                // SAFETY: the bytes are the buffer's, the wide state a block of its own: no overlap with `wi`'s borrow.
                let bytes: &[u8] = unsafe { core::slice::from_raw_parts(bytes.as_ptr(), bytes.len()) };
                ccs_decode(wi(f), bytes)
            } else {
                decode(cs, name, bytes)
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
        // a wide stream needs room for a whole character in the buffer
        if f.flags & F_UNBUF == 0 && !f.buf.is_null() && f.bufsize() < 8 {
            if f.flags & file::F_USERBUF == 0 {
                // SAFETY: the stream's own buffer (not F_USERBUF), replaced right below.
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

/// `fgetwc`.
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

/// `fgetws` on the caller's array `s` (`s.len()` = n > 1): up to `n - 1` characters, stopping after a newline, then a 0.
/// False when nothing was read or the call failed.
pub fn read_wide_line(s: &mut [wchar_t], f: &mut FILE) -> bool {
    // an error during this call (a bad byte after some characters) makes the whole call fail
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
            // buffered ASCII is copied straight out of the byte buffer
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

/// The encoding of `wc` when the charset can represent it exactly (no replacement text), else 0.
fn exact_encode(cs: WCs, name: &[u8], wc: u32, out: &mut [u8; 16]) -> usize {
    match cs {
        WCs::Raw32 => encode(cs, name, wc, out).unwrap_or(0),
        // (a pushed-back character is never matched against the buffer of a ccs= stream)
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
            match encode_plain(cs, name, wc, &mut b) {
                Some(n) => {
                    out[..n].copy_from_slice(&b[..n]);
                    n
                }
                None => 0,
            }
        }
    }
}

/// `ungetwc`: push `wc` back; WEOF if it cannot be.
pub fn ungetwc_raw(wc: wint_t, f: &mut FILE) -> wint_t {
    // glibc does not look at the orientation here: the character is kept on any stream
    if wc == WEOF {
        return WEOF;
    }
    if f.flags & (F_WIDE | F_BYTE) == F_BYTE {
        // a byte stream: glibc's pushback is the byte one (the character as an unsigned char)
        return wint_t::from(file::ungetc_force(c_int::from(wc as u8), f) as u8);
    }
    // a wide stream, or one without orientation yet (glibc pushes into the wide backup area of both; the first wide read
    // then returns the character, tst-ungetwc1)
    if !ensure_info(f) {
        return WEOF;
    }
    // step back inside the buffer when it holds exactly this character just before the read position
    let (npush, cs, name) = {
        let w = wi(f);
        (w.npush, w.cs, w.cset())
    };
    if npush == 0 && f.flags & F_RDMODE != 0 && f.rpos() > 0 {
        let mut enc = [0u8; 16];
        let n = exact_encode(cs, name, wc, &mut enc);
        let pos = f.rpos();
        // SAFETY: `n <= rpos`: consumed bytes of the buffer, just before the read position.
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

// ---- writing ----

/// `fputwc`: returns `wc`, or WEOF on failure.
#[inline]
pub fn putwc_raw(f: &mut FILE, wc: wint_t) -> wint_t {
    let fl = f.flags;
    if fl & (F_WIDE | F_BYTE | F_WRMODE | F_UNBUF | F_W32) == (F_WIDE | F_WRMODE)
        && wc < 0x80
        && f.wpos() < f.bufsize()
        && !(fl & F_LBF != 0 && wc == u32::from(b'\n'))
        && wi(f).wfast
    {
        let p = f.wptr;
        // SAFETY: write mode, `wpos < bufsize`: `p` is a byte of the buffer (`wbase` = `buf`).
        unsafe { *p = wc as u8 };
        f.wptr = p.wrapping_add(1);
        let w = wi(f);
        w.pchars += 1;
        w.gtot += 1;
        return wc;
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
        // glibc: WEOF into a stream that is not in the middle of writing (or line buffered, or whose buffer is full)
        // is a request to flush, not a character; the result is the flush status (0)
        return if file::flush_write(f) { 0 } else { WEOF };
    }
    let buffered = f.flags & F_UNBUF == 0;
    let w = wi(f);
    if w.drop && buffered {
        return if put_glibc(f, &[wc], 0, true) == 1 { wc } else { WEOF };
    }
    let mut enc = [0u8; 16];
    // (a character that cannot be written: on an unbuffered stream WEOF, nothing written, no error flag or errno, as
    // glibc's; a buffered stream takes it into glibc's wide buffer, whose next flush fails)
    let Some(n) = encode_for(w, wc, &mut enc) else {
        return if buffered && put_glibc(f, &[wc], 0, true) == 1 { wc } else { WEOF };
    };
    if file::write_bytes_raw(f, &enc[..n]) == n {
        note_extra(f, n, wc);
        wc
    } else {
        WEOF
    }
}

/// Write the wide characters `s` (all of them): true on success.
pub(crate) fn put_wide_chars(f: &mut FILE, s: &[u32]) -> bool {
    let buffered = f.flags & F_UNBUF == 0;
    if wi(f).drop && buffered {
        return put_glibc(f, s, 0, false) == s.len();
    }
    let putting = wi(f).putting;
    let cs = wi(f).cs;
    let mut chunk = [0u8; 512];
    let mut k = 0usize;
    let mut extra = 0isize;
    for wcr in s {
        let wc = *wcr;
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
        let Some(n) = encode_for(wi(f), wc, &mut enc) else {
            // (the index from the element's address: a counter kept in the loop slowed the ASCII path)
            let done = (wcr as *const u32 as usize - s.as_ptr() as usize) / 4;
            if buffered {
                // glibc's wide buffer takes it; the string goes on as glibc's _IO_wfile_xsputn puts it
                if !put_wide_pending(f, &chunk[..k], extra, done) {
                    return false;
                }
                return put_glibc(f, s, done, false) == s.len();
            }
            put_wide_failed(f, &chunk[..k], extra, done);
            return false;
        };
        chunk[k..k + n].copy_from_slice(&enc[..n]);
        k += n;
        if n != 1 && counts_one_byte(wi(f)) && f.flags & F_UNBUF == 0 {
            extra += n as isize - 1;
        }
    }
    let ok = k == 0 || file::write_bytes_raw(f, &chunk[..k]) == k;
    if ok {
        let lbf = f.flags & F_LBF != 0;
        let wcap = if lbf { wcap(f) } else { 0 };
        let w = wi(f);
        w.extra += extra;
        w.pchars += s.len();
        w.putting = true;
        w.wbuf = true;
        if !lbf {
            w.gtot += s.len();
        } else {
            note_lbf_string(w, s, putting, wcap);
        }
    }
    ok
}

/// glibc's wide buffer after a line-buffered stream took the string `s` (`putting`: it was writing before): flushed by
/// `_IO_wfile_xsputn` when the string fits and has a newline, else at each newline as the characters go in one by one.
#[cold]
fn note_lbf_string(w: &mut WideInfo, s: &[u32], putting: bool, wcap: usize) {
    let fits = putting && wcap - w.gpend(wcap) >= s.len();
    match s.iter().rposition(|&c| c == u32::from(b'\n')) {
        Some(_) if fits => w.gtot = 0,
        Some(l) => w.gtot = s.len() - l - 1,
        None => w.gtot += s.len(),
    }
}

/// The size of glibc's wide buffer in characters: the byte buffer's size, or for a buffer the caller gave (setvbuf) its
/// size in `wchar_t`s rounded up (`_IO_wfile_doallocate`).
#[inline]
fn wcap(f: &FILE) -> usize {
    let b = f.bufsize();
    let c = if f.flags & file::F_USERBUF != 0 { b.div_ceil(4) } else { b };
    c.max(1)
}

/// `put_wide_chars` met a character it cannot write on a buffered stream at index `done`: write the pending bytes of the
/// characters before it (they are glibc's wide buffer's too). False when the write fails.
#[cold]
fn put_wide_pending(f: &mut FILE, pending: &[u8], extra: isize, done: usize) -> bool {
    if !pending.is_empty() && file::write_bytes_raw(f, pending) != pending.len() {
        return false;
    }
    let w = wi(f);
    w.extra += extra;
    w.pchars += done;
    if done > 0 {
        w.putting = true;
        w.wbuf = true;
    }
    true
}

/// glibc's wide write buffer for a buffered stream that holds, or is about to take, a character it cannot write
/// (`WideInfo::drop`): the characters of `s` go in as `_IO_wfile_xsputn` (or, `single`, `_IO_putwc_unlocked`) puts them,
/// the buffer is flushed when full before the next character and on a line-buffered stream after a newline; a flush
/// while `drop` is set writes the bytes before the character and fails (the call stops there, the character that
/// needed the room is not taken), except the flush of a line-buffered string that fits, whose result glibc ignores.
/// The first `skip` characters are already written (only counted). Returns how many characters were taken.
#[cold]
#[inline(never)]
fn put_glibc(f: &mut FILE, s: &[u32], skip: usize, single: bool) -> usize {
    // (the stream writes from now on, with its buffer: glibc's overflow sets up both buffers, and a flush or a switch to
    // reading must find the stream writing even when no byte is pending)
    if f.flags & F_WRMODE == 0 && !file::start_write(f) {
        return 0;
    }
    let lbf = f.flags & F_LBF != 0;
    let cap = wcap(f);
    let putting = wi(f).putting;
    let n = s.len();
    let mut gp = wi(f).gpend(cap);
    // glibc's first copy, without overflow: the room of a stream that is writing (a line-buffered one: all of a string
    // that fits, up to its last newline, which flushes once at the end)
    let mut must_flush = false;
    let mut count = 0usize;
    if !single && putting {
        count = cap - gp;
        if lbf {
            if count >= n {
                if let Some(l) = s.iter().rposition(|&c| c == u32::from(b'\n')) {
                    count = l + 1;
                    must_flush = true;
                }
            } else {
                count = 0; // (a line-buffered stream's write end is its base: no room)
            }
        }
        count = count.min(n);
    }
    for (i, &c) in s[..count].iter().enumerate() {
        if !glibc_store(f, c, i < skip, &mut gp) {
            wi(f).gtot = gp;
            return i;
        }
    }
    for (i, &c) in s.iter().enumerate().skip(count) {
        if gp >= cap && !glibc_flush(f, &mut gp) {
            return i;
        }
        if !glibc_store(f, c, i < skip, &mut gp) {
            wi(f).gtot = gp;
            return i;
        }
        if lbf && c == u32::from(b'\n') && !glibc_flush(f, &mut gp) {
            return i;
        }
    }
    if must_flush && gp > 0 {
        glibc_flush(f, &mut gp);
    }
    wi(f).gtot = gp;
    n
}

/// Put `c` into glibc's wide buffer (see `put_glibc`): written into the byte buffer while the buffer holds no unwritable
/// character, else only counted. False when the write fails.
fn glibc_store(f: &mut FILE, c: u32, already: bool, gp: &mut usize) -> bool {
    *gp += 1;
    if already {
        return true;
    }
    let w = wi(f);
    w.pchars += 1;
    w.putting = true;
    w.wbuf = true;
    if w.drop {
        w.ndrop += 1;
        return true;
    }
    let mut enc = [0u8; 16];
    match encode_for(w, c, &mut enc) {
        Some(n) => {
            if file::write_bytes_raw(f, &enc[..n]) != n {
                return false;
            }
            let w = wi(f);
            if n != 1 && counts_one_byte(w) {
                w.extra += n as isize - 1;
            }
        }
        None => {
            w.drop = true;
            w.wfast = false;
            w.ndrop = 1;
        }
    }
    true
}

/// glibc's flush of its wide buffer (see `put_glibc`): empty afterwards; false when it held an unwritable character.
fn glibc_flush(f: &mut FILE, gp: &mut usize) -> bool {
    *gp = 0;
    wi(f).gtot = 0;
    if !wi(f).drop {
        return true; // (our byte buffer writes the converted characters out by itself)
    }
    drop_flush(f)
}

/// Is `f` a wide stream whose buffer holds a character it cannot write (see `WideInfo::drop`)?
#[inline]
pub(crate) fn dropping(f: &FILE) -> bool {
    f.flags & F_WIDE != 0 && f.wide_ref().is_some_and(|w| w.drop)
}

/// The flush of a wide buffer holding a character the stream cannot write (glibc's failing `_IO_wdo_write`): the bytes
/// before it are written, the rest is dropped; always false (no error flag, no errno, unless writing the bytes fails).
#[cold]
#[inline(never)]
pub(crate) fn drop_flush(f: &mut FILE) -> bool {
    let w = wi(f);
    w.drop = false;
    w.ndrop = 0;
    w.gtot = 0;
    w.wfast = w.cs != WCs::Raw32 && w.cs != WCs::Ccs;
    file::flush_write_keep(f);
    false
}

/// `ftell` of a stream whose wide buffer holds a character it cannot write (`dropping`): glibc counts one byte for each
/// pending character in a one-byte charset; in another it converts them to count the bytes, which fails: WEOF as the
/// position (4294967295). `pos` is the position of the bytes before that character.
pub(crate) fn drop_tell(f: &FILE, pos: i64) -> i64 {
    let w = f.wide_ref().expect("dropping stream without its state");
    if !counts_one_byte(w) {
        return 4_294_967_295;
    }
    if pos < 0 { pos } else { pos + w.ndrop as i64 }
}

/// `put_wide_chars` stopped at character `done` (it cannot be written at all): glibc writes what came before, not the rest
/// of the string, and sets no error flag.
#[cold]
#[inline(never)]
fn put_wide_failed(f: &mut FILE, pending: &[u8], extra: isize, done: usize) {
    if done > 0 && (pending.is_empty() || file::write_bytes_raw(f, pending) == pending.len()) {
        let w = wi(f);
        w.extra += extra;
        w.pchars += done;
        w.putting = true;
        w.wbuf = true;
    }
}

#[inline]
fn note_extra(f: &mut FILE, n: usize, wc: wint_t) {
    let buffered = f.flags & F_UNBUF == 0;
    let lbf = f.flags & F_LBF != 0;
    let w = wi(f);
    w.pchars += 1;
    w.putting = true;
    w.wbuf = true;
    w.gtot = if lbf && wc == u32::from(b'\n') { 0 } else { w.gtot + 1 };

    // (an unbuffered stream has written the bytes already: nothing pending to estimate)
    if n != 1 && counts_one_byte(w) && buffered {
        w.extra += n as isize - 1;
    }
}

/// `fputws` on the characters of a wide string: 1 on success, -1 on failure.
pub fn put_wide_text(s: &[u32], f: &mut FILE) -> c_int {
    if !wide_ok(f) {
        return -1;
    }
    if s.is_empty() {
        return 1; // nothing to write: fine even on a stream that cannot be written
    }
    if f.flags & F_WRITE == 0 {
        f.flags |= F_ERR;
        errno::set(EBADF);
        return -1;
    }
    if put_wide_chars(f, s) { 1 } else { -1 }
}

/// The characters of a NUL-terminated wide string.
///
/// # Safety
/// `s` is a NUL-terminated wide string that outlives `'a`.
unsafe fn wide_text<'a>(s: *const wchar_t) -> &'a [u32] {
    // SAFETY: the caller's contract.
    let n = unsafe { rusty_libc_wchar::wstring::wcslen(s) };
    // SAFETY: as above: `n` characters before the terminator.
    unsafe { core::slice::from_raw_parts(s as *const u32, n) }
}

// ---- C functions ----

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fwide(f: *mut FILE, mode: c_int) -> c_int {
    locked!(f, |s| fwide_raw(s, mode))
}

macro_rules! getters {
    ($($name:ident),*) => {$(
        /// # Safety
        /// `f` must be an open stream.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(f: *mut FILE) -> wint_t {
            locked!(f, |s| getwc_raw(s))
        }
    )*};
}
getters!(fgetwc, getwc);

/// # Safety
/// `f` must be an open stream (locked by the caller).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetwc_unlocked(f: *mut FILE) -> wint_t {
    // SAFETY: the caller's contract.
    getwc_raw(unsafe { file::stream(f) })
}

/// # Safety
/// `f` must be an open stream (locked by the caller).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwc_unlocked(f: *mut FILE) -> wint_t {
    // SAFETY: the caller's contract.
    getwc_raw(unsafe { file::stream(f) })
}

/// The wide forms of `__uflow` / `__underflow` / `__overflow` (glibc's libio entry points for the inline
/// `getwc` / `putwc` code): take the next wide character, look at it without taking it, write one. No lock.
/// The two readers make an unoriented stream wide and give WEOF on a byte stream. glibc's `__woverflow`
/// does not look at the orientation either: on a byte stream it writes the character as one byte (observed).
///
/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wuflow(f: *mut FILE) -> wint_t {
    // SAFETY: the caller's contract.
    getwc_raw(unsafe { file::stream(f) })
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __wunderflow(f: *mut FILE) -> wint_t {
    // SAFETY: the caller's contract.
    let s = unsafe { file::stream(f) };
    let wc = getwc_raw(s);
    if wc != WEOF {
        ungetwc_raw(wc, s);
    }
    wc
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __woverflow(f: *mut FILE, wc: wint_t) -> wint_t {
    // SAFETY: the caller's contract.
    let s = unsafe { file::stream(f) };
    if s.flags & (F_WIDE | F_BYTE) == F_BYTE {
        return if file::putc(c_int::from(wc as u8), s) == file::EOF { WEOF } else { wc };
    }
    putwc_raw(s, wc)
}

/// (The stream `stdin` names must be open, as C requires.)
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getwchar() -> wint_t {
    locked!(file::stdin_ptr(), |s| getwc_raw(s))
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getwchar_unlocked() -> wint_t {
    // SAFETY: `stdin` names an open stream; the caller holds its lock or needs none.
    getwc_raw(unsafe { file::stream(file::stdin_ptr()) })
}

macro_rules! putters {
    ($($name:ident),*) => {$(
        /// # Safety
        /// `f` must be an open stream.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub unsafe extern "C" fn $name(wc: wchar_t, f: *mut FILE) -> wint_t {
            locked!(f, |s| putwc_raw(s, wc as wint_t))
        }
    )*};
}
putters!(fputwc);

/// `putwc`, `putwc_unlocked`, `putwchar`: glibc's macro `_IO_putwc_unlocked` does not look at the
/// orientation, so on a byte stream these call the stream's byte `__overflow` with the wide character
/// as an `int`: the low byte is written (WEOF, being -1, is a flush request) and the result is that
/// byte. `fputwc` and `fputwc_unlocked` check the orientation first and fail instead.
#[inline]
fn putwc_macro(f: &mut FILE, wc: wint_t) -> wint_t {
    if f.flags & F_BYTE != 0 {
        if wc as c_int == -1 {
            // (int)WEOF is EOF: the byte stream's __overflow flushes what is buffered
            return if file::flush_write(f) { 0 } else { WEOF };
        }
        let r = file::putc(wc as c_int, f);
        return if r == -1 { WEOF } else { r as wint_t };
    }
    putwc_raw(f, wc)
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwc(wc: wchar_t, f: *mut FILE) -> wint_t {
    locked!(f, |s| putwc_macro(s, wc as wint_t))
}

/// # Safety
/// `f` must be an open stream (locked by the caller).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputwc_unlocked(wc: wchar_t, f: *mut FILE) -> wint_t {
    // SAFETY: the caller's contract.
    putwc_raw(unsafe { file::stream(f) }, wc as wint_t)
}

/// # Safety
/// `f` must be an open stream (locked by the caller).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwc_unlocked(wc: wchar_t, f: *mut FILE) -> wint_t {
    // SAFETY: the caller's contract.
    putwc_macro(unsafe { file::stream(f) }, wc as wint_t)
}

/// (The stream `stdout` names must be open, as C requires.)
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn putwchar(wc: wchar_t) -> wint_t {
    locked!(file::stdout_ptr(), |s| putwc_macro(s, wc as wint_t))
}

/// # Safety
/// Always safe to call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn putwchar_unlocked(wc: wchar_t) -> wint_t {
    // SAFETY: `stdout` names an open stream; the caller holds its lock or needs none.
    putwc_macro(unsafe { file::stream(file::stdout_ptr()) }, wc as wint_t)
}

/// # Safety
/// `s` must be valid for `n` wide characters; `f` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetws(s: *mut wchar_t, n: c_int, f: *mut FILE) -> *mut wchar_t {
    // glibc (libio/iofgetws.c): n <= 1 neither reads nor takes the lock
    if n <= 0 {
        return null_mut();
    }
    // SAFETY: the caller's contract: `n` (> 0) writable characters.
    let buf = unsafe { core::slice::from_raw_parts_mut(s, n as usize) };
    if n == 1 {
        buf[0] = 0;
        return s;
    }
    if locked!(f, |st| read_wide_line(buf, st)) { s } else { null_mut() }
}

/// # Safety
/// As `fgetws`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fgetws_unlocked(s: *mut wchar_t, n: c_int, f: *mut FILE) -> *mut wchar_t {
    if n <= 0 {
        return null_mut();
    }
    // SAFETY: the caller's contract: `n` (> 0) writable characters.
    let buf = unsafe { core::slice::from_raw_parts_mut(s, n as usize) };
    if n == 1 {
        buf[0] = 0;
        return s;
    }
    // SAFETY: the caller's contract.
    let st = unsafe { file::stream(f) };
    if read_wide_line(buf, st) { s } else { null_mut() }
}

/// # Safety
/// `s` must be a NUL-terminated wide string; `f` an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputws(s: *const wchar_t, f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract for `s`.
    let text = unsafe { wide_text(s) };
    locked!(f, |st| put_wide_text(text, st))
}

/// # Safety
/// As `fputws`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn fputws_unlocked(s: *const wchar_t, f: *mut FILE) -> c_int {
    // SAFETY: the caller's contract.
    let text = unsafe { wide_text(s) };
    // SAFETY: the caller's contract.
    put_wide_text(text, unsafe { file::stream(f) })
}

/// # Safety
/// `f` must be an open stream.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn ungetwc(wc: wint_t, f: *mut FILE) -> wint_t {
    locked!(f, |s| ungetwc_raw(wc, s))
}

// ---- open_wmemstream ----

/// A write stream into a growing heap buffer of wide characters; `*bufloc` and `*sizeloc` (in wide
/// characters) describe it after each flush and at close.
///
/// # Safety
/// Both pointers must be valid for writing for as long as the stream is open.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn open_wmemstream(bufloc: *mut *mut wchar_t, sizeloc: *mut usize) -> *mut FILE {
    // SAFETY: the caller's contract.
    unsafe { crate::file_extra::open_memstream_unit(bufloc as *mut *mut core::ffi::c_char, sizeloc, 4) }
}

