use core::ffi::c_char;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use rusty_libc_core::syscall;

const PROT_READ: usize = 1;
const MAP_PRIVATE: usize = 2;
const O_RDONLY: i32 = 0;
const O_CLOEXEC: i32 = 0o2000000;
const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

pub const ARCHIVE_PATH: &[u8] = b"/usr/lib/locale/locale-archive\0";
pub const DEFAULT_DIR: &[u8] = b"/usr/lib/locale";
pub const AR_MAGIC: u32 = 0xde02_0109;

pub fn map_file(path: &[u8], sys_name: Option<&[u8]>) -> Option<(*const u8, usize)> {
    debug_assert_eq!(path.last(), Some(&0));
    let fd = unsafe { rusty_libc_core::unistd::open(path.as_ptr().cast::<c_char>(), O_RDONLY | O_CLOEXEC, 0) }.ok()?;
    let mut fd = fd;
    let (mut mode, _, mut size) = rusty_libc_core::unistd::fstat_basic(fd).ok().or_else(|| {
        let _ = rusty_libc_core::unistd::close(fd);
        None
    })?;
    if mode & S_IFMT == S_IFDIR {
        let _ = rusty_libc_core::unistd::close(fd);
        let sys = sys_name?;
        let mut buf = [0u8; 600];
        let pl = path.len() - 1;
        if pl + 5 + sys.len() + 1 > buf.len() {
            return None;
        }
        buf[..pl].copy_from_slice(&path[..pl]);
        buf[pl..pl + 5].copy_from_slice(b"/SYS_");
        buf[pl + 5..pl + 5 + sys.len()].copy_from_slice(sys);
        fd = unsafe { rusty_libc_core::unistd::open(buf.as_ptr().cast::<c_char>(), O_RDONLY | O_CLOEXEC, 0) }.ok()?;
        let st = rusty_libc_core::unistd::fstat_basic(fd).ok().or_else(|| {
            let _ = rusty_libc_core::unistd::close(fd);
            None
        })?;
        mode = st.0;
        size = st.2;
        let _ = mode;
    }
    if size <= 0 {
        let _ = rusty_libc_core::unistd::close(fd);
        return None;
    }
    let r = unsafe { syscall::syscall6(syscall::SYS_MMAP, 0, size as usize, PROT_READ, MAP_PRIVATE, fd as usize, 0) };
    let _ = rusty_libc_core::unistd::close(fd);
    syscall::check(r).ok().map(|a| (a as *const u8, size as usize))
}

fn rd32(p: *const u8, off: usize) -> u32 {
    unsafe { core::ptr::read_unaligned(p.add(off).cast::<u32>()) }
}

struct Arch {
    base: *const u8,
    len: usize,
}
static ARCH_STATE: AtomicU8 = AtomicU8::new(0);
static ARCH_BASE: AtomicUsize = AtomicUsize::new(0);
static ARCH_LEN: AtomicUsize = AtomicUsize::new(0);

fn archive() -> Option<Arch> {
    match ARCH_STATE.load(Ordering::Acquire) {
        1 => return Some(Arch { base: ARCH_BASE.load(Ordering::Relaxed) as *const u8, len: ARCH_LEN.load(Ordering::Relaxed) }),
        2 => return None,
        _ => {}
    }
    let ok = match map_file(ARCHIVE_PATH, None) {
        Some((base, len)) if len >= 60 && rd32(base, 0) == AR_MAGIC => {
            let nh_end = rd32(base, 8) as usize + rd32(base, 16) as usize * 12;
            let str_end = rd32(base, 20) as usize + rd32(base, 24) as usize;
            let lr_end = rd32(base, 32) as usize + rd32(base, 36) as usize * 108;
            if nh_end <= len && str_end <= len && lr_end <= len && rd32(base, 16) > 2 {
                ARCH_BASE.store(base as usize, Ordering::Relaxed);
                ARCH_LEN.store(len, Ordering::Relaxed);
                true
            } else {
                false
            }
        }
        _ => false,
    };
    ARCH_STATE.store(if ok { 1 } else { 2 }, Ordering::Release);
    if ok { Some(Arch { base: ARCH_BASE.load(Ordering::Relaxed) as *const u8, len: ARCH_LEN.load(Ordering::Relaxed) }) } else { None }
}

pub fn hashval(key: &[u8]) -> u32 {
    let mut h = key.len() as u32;
    for &b in key {
        h = h.rotate_left(9).wrapping_add(b as u32);
    }
    if h != 0 { h } else { !0 }
}

pub fn lookup(name: &[u8]) -> Option<[(*const u8, usize); 13]> {
    let a = archive()?;
    let size = rd32(a.base, 16) as usize;
    let table = rd32(a.base, 8) as usize;
    let hv = hashval(name);
    let mut idx = hv as usize % size;
    let incr = 1 + hv as usize % (size - 2);
    let mut tries = 0;
    loop {
        let e = table + idx * 12;
        let name_off = rd32(a.base, e + 4) as usize;
        if name_off == 0 {
            return None;
        }
        if rd32(a.base, e) == hv && name_off < a.len {
            let s = unsafe { core::slice::from_raw_parts(a.base.add(name_off), (a.len - name_off).min(512)) };
            let n = s.iter().position(|&b| b == 0).unwrap_or(s.len());
            if &s[..n] == name {
                break;
            }
        }
        idx += incr;
        if idx >= size {
            idx -= size;
        }
        tries += 1;
        if tries > size {
            return None;
        }
    }
    let e = table + idx * 12;
    let rec = rd32(a.base, e + 8) as usize;
    if rec == 0 || rec + 108 > a.len {
        return None;
    }
    let mut out = [(core::ptr::null::<u8>(), 0usize); 13];
    for (c, slot) in out.iter_mut().enumerate() {
        if c == 6 {
            continue;
        }
        let off = rd32(a.base, rec + 4 + c * 8) as usize;
        let len = rd32(a.base, rec + 8 + c * 8) as usize;
        if off.checked_add(len)? > a.len {
            return None;
        }
        *slot = (unsafe { a.base.add(off) }, len);
    }
    Some(out)
}

