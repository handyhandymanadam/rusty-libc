//! mntent.h: setmntent, getmntent, getmntent_r, addmntent, endmntent, hasmntopt.
//!
//! The file format is the one of /etc/fstab and /proc/self/mounts: six whitespace separated fields per
//! line, `#` comment lines and empty lines skipped, the escapes `\040` (space), `\011` (tab), `\012`
//! (newline), `\134` and `\\` (backslash) decoded in the first four fields. Missing fields read as the
//! empty string, a missing frequency or pass number as 0. Lines longer than the buffer are cut (the rest
//! of the line is dropped). An `autofs` entry carrying the option `ignore` is skipped. Behaviour follows
//! glibc 2.43, including its quirks (see `getmntent_r`).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api as io;
use rusty_libc_stdio::rust_api::{Arg, snprintf, sscanf};

/// `struct mntent`.
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

/// malloc(3) of the library's own allocator. Safe to call: it has no precondition and returns a raw pointer (NULL on
/// failure); using the block is what needs care. (Shared by fork D's modules; candidate for one crate-wide helper.)
#[inline(always)]
pub(crate) fn malloc(n: usize) -> *mut u8 {
    // SAFETY: malloc has no precondition.
    unsafe { rusty_libc_malloc::malloc(n) }.cast::<u8>()
}

/// An open stdio stream borrowed for the library's own use (mntent, fstab, ttyent): the stdio calls these modules make,
/// each behind one audited block. The C side keeps plain `FILE *`.
pub struct Stream(*mut FILE);

impl Stream {
    /// Borrow `f`.
    ///
    /// # Safety
    /// `f` is an open stream that stays open (not closed through another pointer) while this value is used.
    #[inline]
    pub unsafe fn new(f: *mut FILE) -> Stream {
        Stream(f)
    }

    /// The stream pointer.
    #[inline]
    pub fn as_ptr(&self) -> *mut FILE {
        self.0
    }

    /// `fgets(buf, n, f) != NULL`: `n <= 0` is passed on as it is (fgets fails with EINVAL and writes nothing); a positive
    /// `n` is bounded by the buffer.
    #[inline]
    pub fn fgets(&self, buf: &mut [u8], n: c_int) -> bool {
        let n = if n > 0 { n.min(buf.len().min(c_int::MAX as usize) as c_int) } else { n };
        // SAFETY: the stream is open (`new`'s contract); fgets writes at most `n` bytes, and a positive `n` is at most
        // `buf.len()`; with `n <= 0` it writes nothing.
        !unsafe { io::fgets(buf.as_mut_ptr().cast(), n, self.0) }.is_null()
    }

    /// `getc(f)`.
    #[inline]
    pub fn getc(&self) -> c_int {
        // SAFETY: the stream is open.
        unsafe { io::getc(self.0) }
    }

    /// `fputc(c, f)`.
    #[inline]
    pub fn putc(&self, c: c_int) -> c_int {
        // SAFETY: the stream is open.
        unsafe { io::fputc(c, self.0) }
    }

    /// `fwrite(data, 1, len, f)`.
    #[inline]
    pub fn write(&self, data: &[u8]) -> usize {
        // SAFETY: the stream is open; `data` is readable for its length.
        unsafe { io::fwrite(data.as_ptr().cast(), 1, data.len(), self.0) }
    }

    /// `flockfile(f)`.
    #[inline]
    pub fn lock(&self) {
        // SAFETY: the stream is open.
        unsafe { io::flockfile(self.0) }
    }

    /// `funlockfile(f)` (after `lock` on this thread).
    #[inline]
    pub fn unlock(&self) {
        // SAFETY: the stream is open and locked by this thread.
        unsafe { io::funlockfile(self.0) }
    }

    /// `fseek(f, off, whence)`.
    #[inline]
    pub fn seek(&self, off: i64, whence: c_int) -> c_int {
        // SAFETY: the stream is open.
        unsafe { io::fseek(self.0, off, whence) }
    }

    /// `rewind(f)`.
    #[inline]
    pub fn rewind(&self) {
        // SAFETY: the stream is open.
        unsafe { io::rewind(self.0) }
    }

    /// `ferror(f)`.
    #[inline]
    pub fn error(&self) -> c_int {
        // SAFETY: the stream is open.
        unsafe { io::ferror(self.0) }
    }

    /// `fflush(f)`.
    #[inline]
    pub fn flush(&self) -> c_int {
        // SAFETY: the stream is open.
        unsafe { io::fflush(self.0) }
    }

    /// `__fsetlocking(f, type)`.
    #[inline]
    pub fn set_locking(&self, ty: c_int) -> c_int {
        // SAFETY: the stream is open.
        unsafe { rusty_libc_stdio::stdio_ext::__fsetlocking(self.0, ty) }
    }

    /// `fclose(f)`: the stream is gone afterwards (whatever the result).
    #[inline]
    pub fn close(self) -> c_int {
        // SAFETY: the stream is open; `self` is consumed, so this value cannot reach it again (the contract of `new`
        // makes the caller drop its other copies of the pointer).
        unsafe { io::fclose(self.0) }
    }
}

/// Where setmntent built the fopen mode: `mode` followed by "ce" (no cancellation in the stream functions, and FD_CLOEXEC),
/// in a 64-byte local buffer when it fits, in a malloc block otherwise.
enum Mode<'a> {
    Small(&'a CStr),
    Heap(*mut u8),
}

/// setmntent: open `file` with `mode` (as fopen; the stream is also made close-on-exec).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setmntent(file: *const c_char, mode: *const c_char) -> *mut FILE {
    // SAFETY: `mode` is a C string (caller's contract; glibc takes its strlen unconditionally).
    let mode = unsafe { rusty_libc_core::ffi::cstr_bytes(mode) };
    let mut buf = [0u8; 64];
    let newmode = if mode.len() + 3 <= buf.len() {
        Mode::Small(fill_mode(&mut buf[..mode.len() + 3], mode))
    } else {
        let long = malloc(mode.len() + 3);
        if long.is_null() {
            return null_mut();
        }
        // SAFETY: `long` is a fresh malloc block of `mode.len() + 3` bytes, only used through this slice until it is freed.
        fill_mode(unsafe { rusty_libc_core::ffi::bytes_mut(long, mode.len() + 3) }, mode);
        Mode::Heap(long)
    };
    let mp = match newmode {
        Mode::Small(c) => c.as_ptr(),
        Mode::Heap(p) => p.cast::<c_char>(),
    };
    // SAFETY: `file` is the caller's C string; `mp` is the NUL-terminated mode built above.
    let f = unsafe { io::fopen(file, mp) };
    if let Mode::Heap(p) = newmode {
        // SAFETY: `p` is the malloc block made above, freed once.
        unsafe { rusty_libc_malloc::free(p.cast()) };
    }
    if !f.is_null() {
        // we do the locking ourselves
        // SAFETY: `f` was just opened.
        unsafe { Stream::new(f) }.set_locking(2);
    }
    f
}

fn fill_mode<'a>(out: &'a mut [u8], mode: &[u8]) -> &'a CStr {
    let n = mode.len();
    out[..n].copy_from_slice(mode);
    out[n] = b'c';
    out[n + 1] = b'e';
    out[n + 2] = 0;
    // the mode has no NUL of its own (it came from a C string), so the string ends at out[n + 2]
    CStr::from_bytes_until_nul(out).unwrap_or(c"")
}

/// endmntent: close the stream (a null stream is allowed). Always returns 1.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endmntent(stream: *mut FILE) -> c_int {
    if !stream.is_null() {
        // SAFETY: a non-NULL `stream` is an open stream the caller gives up.
        unsafe { Stream::new(stream) }.close();
    }
    1
}

/// Byte `i` of a NUL-terminated buffer, read only while no NUL came before it (`known` is the byte before, nonzero).
#[inline]
fn after(buf: &[u8], i: usize, known: u8) -> u8 {
    if known != 0 { buf[i] } else { 0 }
}

/// Decode the escapes of the field starting at `start` (it ends at a NUL) in place.
fn decode_name(buf: &mut [u8], start: usize) {
    let mut rp = start;
    let mut wp = start;
    loop {
        let a = buf[rp];
        if a != b'\\' {
            // the common case: a plain byte (or the NUL that ends the field)
            buf[wp] = a;
            if a == 0 {
                break;
            }
            wp += 1;
            rp += 1;
            continue;
        }
        let b = after(buf, rp + 1, a);
        let c = if b != 0 { buf[rp + 2] } else { 0 };
        let d = if c != 0 { buf[rp + 3] } else { 0 };
        if a == b'\\' && b == b'0' && c == b'4' && d == b'0' {
            buf[wp] = b' ';
            wp += 1;
            rp += 3;
        } else if a == b'\\' && b == b'0' && c == b'1' && d == b'1' {
            buf[wp] = b'\t';
            wp += 1;
            rp += 3;
        } else if a == b'\\' && b == b'0' && c == b'1' && d == b'2' {
            buf[wp] = b'\n';
            wp += 1;
            rp += 3;
        } else if a == b'\\' && b == b'\\' {
            buf[wp] = b'\\';
            wp += 1;
            rp += 1;
        } else if a == b'\\' && b == b'1' && c == b'3' && d == b'4' {
            buf[wp] = b'\\';
            wp += 1;
            rp += 3;
        } else {
            buf[wp] = buf[rp];
            wp += 1;
        }
        let done = buf[rp] == 0;
        rp += 1;
        if done {
            break;
        }
    }
}

/// strsep with the delimiter set " \t" on offsets: the field's start, and the next head (None at the end of the string).
fn strsep_ws(buf: &mut [u8], head: &mut Option<usize>) -> Option<usize> {
    let start = (*head)?;
    let mut p = start;
    while buf[p] != 0 && buf[p] != b' ' && buf[p] != b'\t' {
        p += 1;
    }
    if buf[p] != 0 {
        buf[p] = 0;
        *head = Some(p + 1);
    } else {
        *head = None;
    }
    Some(start)
}

fn skip_ws(buf: &[u8], mut q: usize) -> usize {
    while buf[q] == b' ' || buf[q] == b'\t' {
        q += 1;
    }
    q
}

/// The bytes of the NUL-terminated string at `at` (without the NUL).
fn str_at(buf: &[u8], at: usize) -> &[u8] {
    let n = rusty_libc_core::string::memchr(&buf[at..], 0).unwrap_or(buf.len() - at);
    &buf[at..at + n]
}

/// The type and options fields of a parsed line, as offsets into the line buffer (None: the empty string).
struct Fields {
    ty: Option<usize>,
    opts: Option<usize>,
}

/// Read lines until one holds an entry and split it in place; None at end of file or on a read error. `n` is the
/// caller's buffer size as fgets gets it.
fn get_mnt_entry(stream: &Stream, m: &mut Mntent, buf: &mut [u8], n: c_int) -> Option<Fields> {
    let mut head;
    loop {
        if !stream.fgets(buf, n) {
            return None;
        }
        // fgets succeeded, so `buf` holds a NUL-terminated line
        let len = str_at(buf, 0).len();
        if let Some(nl) = rusty_libc_core::string::memchr(&buf[..len], b'\n') {
            // chop the newline and the blanks before it (never walking past the start)
            let mut end = nl;
            while end != 0 && (buf[end - 1] == b' ' || buf[end - 1] == b'\t') {
                end -= 1;
            }
            buf[end] = 0;
        } else {
            // not the whole line was read: read the rest and forget it
            let mut tmp = [0u8; 1024];
            while stream.fgets(&mut tmp, 1024) {
                if str_at(&tmp, 0).contains(&b'\n') {
                    break;
                }
            }
        }
        head = skip_ws(buf, 0);
        if buf[head] != 0 && buf[head] != b'#' {
            break;
        }
    }
    let mut head = Some(head);
    let field = |buf: &mut [u8], head: &mut Option<usize>| -> Option<usize> {
        let cp = strsep_ws(buf, head)?;
        decode_name(buf, cp);
        Some(cp)
    };
    let fsname = field(buf, &mut head);
    head = head.map(|h| skip_ws(buf, h));
    let dir = field(buf, &mut head);
    head = head.map(|h| skip_ws(buf, h));
    let ty = field(buf, &mut head);
    head = head.map(|h| skip_ws(buf, h));
    let opts = field(buf, &mut head);
    let at = |f: Option<usize>, buf: &mut [u8]| -> *mut c_char {
        match f {
            Some(i) => buf[i..].as_mut_ptr().cast(),
            None => EMPTY.as_ptr().cast_mut(),
        }
    };
    m.mnt_fsname = at(fsname, buf);
    m.mnt_dir = at(dir, buf);
    m.mnt_type = at(ty, buf);
    m.mnt_opts = at(opts, buf);
    // frequency and pass number: like sscanf(head, " %d %d ", ...), including what it leaves alone
    // when the input is empty (a final line without a newline that ends in a blank)
    let k = match head {
        None => 0,
        Some(h) => match CStr::from_bytes_until_nul(&buf[h..]) {
            Ok(rest) => {
                let outs = [(&raw mut m.mnt_freq).cast::<c_void>(), (&raw mut m.mnt_passno).cast::<c_void>()];
                // SAFETY: " %d %d " stores at most two ints, through `outs`, which point to the two int fields of `m`.
                unsafe { sscanf(rest, c" %d %d ", &outs) }
            }
            Err(_) => 0,
        },
    };
    match k {
        0 => {
            m.mnt_freq = 0;
            m.mnt_passno = 0;
        }
        1 => m.mnt_passno = 0,
        _ => {}
    }
    Some(Fields { ty, opts })
}

/// The safe core of getmntent_r (the Rust API): the next entry of `stream` into `m`, its strings in `buf`; `n` is the size
/// fgets gets (the C caller's `bufsiz`, passed on as it is when it is not positive). False at end of file or error.
pub fn getmntent_into(stream: &Stream, m: &mut Mntent, buf: &mut [u8], n: c_int) -> bool {
    stream.lock();
    let found = loop {
        match get_mnt_entry(stream, m, buf, n) {
            Some(f) => {
                let ty = f.ty.map_or(&b""[..], |i| str_at(buf, i));
                let opts = f.opts.map_or(&b""[..], |i| str_at(buf, i));
                if ty == b"autofs" && has_opt(opts, b"ignore").is_some() {
                    *m = Mntent { mnt_fsname: null_mut(), mnt_dir: null_mut(), mnt_type: null_mut(), mnt_opts: null_mut(), mnt_freq: 0, mnt_passno: 0 };
                } else {
                    break true;
                }
            }
            None => break false,
        }
    };
    stream.unlock();
    found
}

/// getmntent_r: the next entry of `stream`, stored in `mp` with its strings in `buffer`; null at end
/// of file (check feof/ferror). An autofs entry with the option "ignore" is skipped.
///
/// glibc quirk kept: the entry for an ignored autofs mount is zeroed before the next line is read.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getmntent_r(stream: *mut FILE, mp: *mut Mntent, buffer: *mut c_char, bufsiz: c_int) -> *mut Mntent {
    // SAFETY: `stream` is an open stream (caller's contract).
    let stream = unsafe { Stream::new(stream) };
    // SAFETY: `buffer` has `bufsiz` writable bytes (caller's contract); a size of 0 or less gives an empty slice.
    let buf = unsafe { rusty_libc_core::ffi::bytes_mut(buffer.cast::<u8>(), bufsiz.max(0) as usize) };
    // SAFETY: `mp` points to a `struct mntent` the caller lends for the call (glibc writes it unconditionally).
    let m = unsafe { &mut *mp };
    if getmntent_into(&stream, m, buf, bufsiz) { mp } else { null_mut() }
}

#[repr(C)]
struct MntentBuffer {
    m: Mntent,
    buffer: [c_char; 4096],
}

static MNTENT_BUFFER: core::sync::atomic::AtomicPtr<MntentBuffer> = core::sync::atomic::AtomicPtr::new(null_mut());

/// getmntent: like getmntent_r with one process-wide buffer (allocated on first use).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getmntent(stream: *mut FILE) -> *mut Mntent {
    use core::sync::atomic::Ordering;
    let mut b = MNTENT_BUFFER.load(Ordering::Acquire);
    if b.is_null() {
        let n = malloc(size_of::<MntentBuffer>()).cast::<MntentBuffer>();
        if n.is_null() {
            return null_mut();
        }
        match MNTENT_BUFFER.compare_exchange(null_mut(), n, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => b = n,
            Err(cur) => {
                // SAFETY: `n` is the block allocated above, which lost the race and was never published.
                unsafe { rusty_libc_malloc::free(n.cast()) };
                b = cur;
            }
        }
    }
    // the entry is the first field (repr(C)), the line buffer the second
    let m = b.cast::<Mntent>();
    let buffer = b.cast::<c_char>().wrapping_add(core::mem::offset_of!(MntentBuffer, buffer));
    // SAFETY: `b` is the process-wide buffer (never freed); its two fields are passed as getmntent_r's entry and 4096-byte
    // buffer; getmntent is MT-Unsafe in glibc too (race:mntentbuf), so callers do not share it concurrently.
    unsafe { getmntent_r(stream, m, buffer, 4096) }
}

/// Write one field, escaping space, tab, newline and backslash as `\ooo`, and a separating space.
fn write_string(stream: &Stream, s: &[u8]) {
    for &c in s {
        if c == b' ' || c == b'\t' || c == b'\n' || c == b'\\' {
            stream.putc(b'\\' as c_int);
            stream.putc(((c & 0xc0) >> 6) as c_int + b'0' as c_int);
            stream.putc(((c & 0x38) >> 3) as c_int + b'0' as c_int);
            stream.putc((c & 0x07) as c_int + b'0' as c_int);
        } else {
            stream.putc(c as c_int);
        }
    }
    stream.putc(b' ' as c_int);
}

/// The safe core of addmntent (the Rust API): append an entry with these fields (seeks to the end first). 0 on success,
/// 1 on failure.
pub fn add_entry(stream: &Stream, fields: [&[u8]; 4], freq: c_int, passno: c_int) -> c_int {
    if stream.seek(0, 2) != 0 {
        return 1;
    }
    write_entry(stream, fields, freq, passno)
}

/// addmntent after its seek to the end.
fn write_entry(stream: &Stream, fields: [&[u8]; 4], freq: c_int, passno: c_int) -> c_int {
    stream.lock();
    for f in fields {
        write_string(stream, f);
    }
    let mut tail = [0u8; 40];
    let n = snprintf(&mut tail, c"%d %d\n", &[Arg::Int(freq as i64), Arg::Int(passno as i64)]);
    stream.write(&tail[..n as usize]);
    let ret = (stream.error() != 0 || stream.flush() != 0) as c_int;
    stream.unlock();
    ret
}

/// addmntent: append `mnt` to the stream (seeks to the end first). 0 on success, 1 on failure.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn addmntent(stream: *mut FILE, mnt: *const Mntent) -> c_int {
    // SAFETY: `stream` is an open stream (caller's contract).
    let stream = unsafe { Stream::new(stream) };
    // glibc seeks before it reads the entry
    if stream.seek(0, 2) != 0 {
        return 1;
    }
    // SAFETY: `mnt` points to a valid `struct mntent` (caller's contract).
    let m = unsafe { &*mnt };
    // SAFETY: the four strings of a valid entry are C strings.
    let fsname = unsafe { rusty_libc_core::ffi::cstr_bytes(m.mnt_fsname) };
    // SAFETY: as above.
    let dir = unsafe { rusty_libc_core::ffi::cstr_bytes(m.mnt_dir) };
    // SAFETY: as above.
    let ty = unsafe { rusty_libc_core::ffi::cstr_bytes(m.mnt_type) };
    // SAFETY: as above.
    let opts = unsafe { rusty_libc_core::ffi::cstr_bytes(m.mnt_opts) };
    write_entry(&stream, [fsname, dir, ty, opts], m.mnt_freq, m.mnt_passno)
}

/// The safe core of hasmntopt (the Rust API): the offset in `opts` of the option `opt` (a whole option, optionally
/// followed by `=value`), or None. glibc searches with strstr from the start of each option and jumps to the option
/// after a bad match; that never passes over an option start (one between the match and the next comma would need a
/// comma before it), so the first option start that begins with `opt` followed by the end, `=` or `,` is the same
/// answer. Walking the option starts directly skips the substring search: one first-byte test per option.
#[inline]
pub fn has_opt(opts: &[u8], opt: &[u8]) -> Option<usize> {
    let mut s = 0;
    loop {
        let o = &opts[s..];
        if (o.first() == opt.first() || opt.is_empty())
            && o.starts_with(opt)
            && matches!(o.get(opt.len()), None | Some(b'=' | b','))
        {
            return Some(s);
        }
        s += rusty_libc_core::string::memchr(o, b',')? + 1;
    }
}

/// hasmntopt: the address of the option `opt` inside `mnt_opts` (a whole option, optionally followed
/// by `=value`), or null.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hasmntopt(mnt: *const Mntent, opt: *const c_char) -> *mut c_char {
    // SAFETY: `mnt` points to a valid `struct mntent` (caller's contract).
    let p = unsafe { (*mnt).mnt_opts };
    // SAFETY: its option string is a C string.
    let opts = unsafe { rusty_libc_core::ffi::cstr_bytes(p) };
    // SAFETY: `opt` is a C string (caller's contract).
    let opt = unsafe { rusty_libc_core::ffi::cstr_bytes(opt) };
    match has_opt(opts, opt) {
        Some(i) => p.wrapping_add(i),
        None => null_mut(),
    }
}
