#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_stdio::file::File as FILE;
use rusty_libc_stdio::file_api as io;
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

#[inline(always)]
pub(crate) fn malloc(n: usize) -> *mut u8 {
    unsafe { rusty_libc_malloc::malloc(n) }.cast::<u8>()
}

pub struct Stream(*mut FILE);

impl Stream {
    #[inline]
    pub unsafe fn new(f: *mut FILE) -> Stream {
        Stream(f)
    }

    #[inline]
    pub fn as_ptr(&self) -> *mut FILE {
        self.0
    }

    #[inline]
    pub fn fgets(&self, buf: &mut [u8], n: c_int) -> bool {
        let n = if n > 0 { n.min(buf.len().min(c_int::MAX as usize) as c_int) } else { n };
        !unsafe { io::fgets(buf.as_mut_ptr().cast(), n, self.0) }.is_null()
    }

    #[inline]
    pub fn getc(&self) -> c_int {
        unsafe { io::getc(self.0) }
    }

    #[inline]
    pub fn putc(&self, c: c_int) -> c_int {
        unsafe { io::fputc(c, self.0) }
    }

    #[inline]
    pub fn write(&self, data: &[u8]) -> usize {
        unsafe { io::fwrite(data.as_ptr().cast(), 1, data.len(), self.0) }
    }

    #[inline]
    pub fn lock(&self) {
        unsafe { io::flockfile(self.0) }
    }

    #[inline]
    pub fn unlock(&self) {
        unsafe { io::funlockfile(self.0) }
    }

    #[inline]
    pub fn seek(&self, off: i64, whence: c_int) -> c_int {
        unsafe { io::fseek(self.0, off, whence) }
    }

    #[inline]
    pub fn rewind(&self) {
        unsafe { io::rewind(self.0) }
    }

    #[inline]
    pub fn error(&self) -> c_int {
        unsafe { io::ferror(self.0) }
    }

    #[inline]
    pub fn flush(&self) -> c_int {
        unsafe { io::fflush(self.0) }
    }

    #[inline]
    pub fn set_locking(&self, ty: c_int) -> c_int {
        unsafe { rusty_libc_stdio::stdio_ext::__fsetlocking(self.0, ty) }
    }

    #[inline]
    pub fn close(self) -> c_int {
        unsafe { io::fclose(self.0) }
    }
}

enum Mode<'a> {
    Small(&'a CStr),
    Heap(*mut u8),
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn setmntent(file: *const c_char, mode: *const c_char) -> *mut FILE {
    let mode = unsafe { rusty_libc_core::ffi::cstr_bytes(mode) };
    let mut buf = [0u8; 64];
    let newmode = if mode.len() + 3 <= buf.len() {
        Mode::Small(fill_mode(&mut buf[..mode.len() + 3], mode))
    } else {
        let long = malloc(mode.len() + 3);
        if long.is_null() {
            return null_mut();
        }
        fill_mode(unsafe { rusty_libc_core::ffi::bytes_mut(long, mode.len() + 3) }, mode);
        Mode::Heap(long)
    };
    let mp = match newmode {
        Mode::Small(c) => c.as_ptr(),
        Mode::Heap(p) => p.cast::<c_char>(),
    };
    let f = unsafe { io::fopen(file, mp) };
    if let Mode::Heap(p) = newmode {
        unsafe { rusty_libc_malloc::free(p.cast()) };
    }
    if !f.is_null() {
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
    CStr::from_bytes_until_nul(out).unwrap_or(c"")
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn endmntent(stream: *mut FILE) -> c_int {
    if !stream.is_null() {
        unsafe { Stream::new(stream) }.close();
    }
    1
}

#[inline]
fn after(buf: &[u8], i: usize, known: u8) -> u8 {
    if known != 0 { buf[i] } else { 0 }
}

fn decode_name(buf: &mut [u8], start: usize) {
    let mut rp = start;
    let mut wp = start;
    loop {
        let a = buf[rp];
        if a != b'\\' {
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

fn str_at(buf: &[u8], at: usize) -> &[u8] {
    let n = rusty_libc_core::string::memchr(&buf[at..], 0).unwrap_or(buf.len() - at);
    &buf[at..at + n]
}

struct Fields {
    ty: Option<usize>,
    opts: Option<usize>,
}

fn get_mnt_entry(stream: &Stream, m: &mut Mntent, buf: &mut [u8], n: c_int) -> Option<Fields> {
    let mut head;
    loop {
        if !stream.fgets(buf, n) {
            return None;
        }
        let len = str_at(buf, 0).len();
        if let Some(nl) = rusty_libc_core::string::memchr(&buf[..len], b'\n') {
            let mut end = nl;
            while end != 0 && (buf[end - 1] == b' ' || buf[end - 1] == b'\t') {
                end -= 1;
            }
            buf[end] = 0;
        } else {
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
    let k = match head {
        None => 0,
        Some(h) => match CStr::from_bytes_until_nul(&buf[h..]) {
            Ok(rest) => {
                let outs = [(&raw mut m.mnt_freq).cast::<c_void>(), (&raw mut m.mnt_passno).cast::<c_void>()];
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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getmntent_r(stream: *mut FILE, mp: *mut Mntent, buffer: *mut c_char, bufsiz: c_int) -> *mut Mntent {
    let stream = unsafe { Stream::new(stream) };
    let buf = unsafe { rusty_libc_core::ffi::bytes_mut(buffer.cast::<u8>(), bufsiz.max(0) as usize) };
    let m = unsafe { &mut *mp };
    if getmntent_into(&stream, m, buf, bufsiz) { mp } else { null_mut() }
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
    let mut b = MNTENT_BUFFER.load(Ordering::Acquire);
    if b.is_null() {
        let n = malloc(size_of::<MntentBuffer>()).cast::<MntentBuffer>();
        if n.is_null() {
            return null_mut();
        }
        match MNTENT_BUFFER.compare_exchange(null_mut(), n, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => b = n,
            Err(cur) => {
                unsafe { rusty_libc_malloc::free(n.cast()) };
                b = cur;
            }
        }
    }
    let m = b.cast::<Mntent>();
    let buffer = b.cast::<c_char>().wrapping_add(core::mem::offset_of!(MntentBuffer, buffer));
    unsafe { getmntent_r(stream, m, buffer, 4096) }
}

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

pub fn add_entry(stream: &Stream, fields: [&[u8]; 4], freq: c_int, passno: c_int) -> c_int {
    if stream.seek(0, 2) != 0 {
        return 1;
    }
    write_entry(stream, fields, freq, passno)
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn addmntent(stream: *mut FILE, mnt: *const Mntent) -> c_int {
    let stream = unsafe { Stream::new(stream) };
    if stream.seek(0, 2) != 0 {
        return 1;
    }
    let m = unsafe { &*mnt };
    let fsname = unsafe { rusty_libc_core::ffi::cstr_bytes(m.mnt_fsname) };
    let dir = unsafe { rusty_libc_core::ffi::cstr_bytes(m.mnt_dir) };
    let ty = unsafe { rusty_libc_core::ffi::cstr_bytes(m.mnt_type) };
    let opts = unsafe { rusty_libc_core::ffi::cstr_bytes(m.mnt_opts) };
    write_entry(&stream, [fsname, dir, ty, opts], m.mnt_freq, m.mnt_passno)
}

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hasmntopt(mnt: *const Mntent, opt: *const c_char) -> *mut c_char {
    let p = unsafe { (*mnt).mnt_opts };
    let opts = unsafe { rusty_libc_core::ffi::cstr_bytes(p) };
    let opt = unsafe { rusty_libc_core::ffi::cstr_bytes(opt) };
    match has_opt(opts, opt) {
        Some(i) => p.wrapping_add(i),
        None => null_mut(),
    }
}
