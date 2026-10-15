use crate::mem::{self, rd32};
use core::sync::atomic::{AtomicU8, Ordering};
use rusty_libc_core::sync_cell::SyncCell;

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;

pub const ARCHIVE_PATH: &[u8] = b"/usr/lib/locale/locale-archive\0";
pub const DEFAULT_DIR: &[u8] = b"/usr/lib/locale";
pub const AR_MAGIC: u32 = 0xde02_0109;

pub fn map_file(path: &[u8], sys_name: Option<&[u8]>) -> Option<&'static [u8]> {
    debug_assert_eq!(path.last(), Some(&0));
    let fd = mem::open_ro(path).ok()?;
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
        fd = mem::open_ro(&buf[..=pl + 5 + sys.len()]).ok()?;
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
    let r = mem::map_forever(fd, size as usize);
    let _ = rusty_libc_core::unistd::close(fd);
    r
}

struct FileEnt {
    path: &'static [u8],
    img: &'static [u8],
    newer: mem::Published<FileEnt>,
}

const FILE_BUCKETS: usize = 64;
static FILES: [mem::Published<FileEnt>; FILE_BUCKETS] = [const { mem::Published::empty() }; FILE_BUCKETS];

fn file_bucket(path: &[u8]) -> &'static mem::Published<FileEnt> {
    let h = path.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| (h ^ b as u64).wrapping_mul(0x0000_0100_0000_01b3));
    &FILES[(h ^ (h >> 32)) as usize & (FILE_BUCKETS - 1)]
}

pub fn map_file_cached(path: &[u8], sys_name: Option<&[u8]>) -> Option<&'static [u8]> {
    let mut link = file_bucket(path);
    while let Some(e) = link.get() {
        if e.path == path {
            return Some(e.img);
        }
        link = &e.newer;
    }
    let img = map_file(path, sys_name)?;
    let Some(copy) = mem::leak_default::<u8>(path.len()) else { return Some(img) };
    copy.copy_from_slice(path);
    let Some(node) = mem::leak(FileEnt { path: copy, img, newer: mem::Published::empty() }) else { return Some(img) };
    let node: &'static FileEnt = node;
    while let Err(other) = link.publish(node) {
        link = &other.newer;
    }
    Some(img)
}

static ARCH_STATE: AtomicU8 = AtomicU8::new(0);
static ARCH: SyncCell<&'static [u8]> = SyncCell::new(&[]);

fn archive() -> Option<&'static [u8]> {
    match ARCH_STATE.load(Ordering::Acquire) {
        1 => return Some(unsafe { ARCH.read() }),
        2 => return None,
        _ => {}
    }
    let a = match map_file(ARCHIVE_PATH, None) {
        Some(a) if a.len() >= 60 && rd32(a, 0) == AR_MAGIC => {
            let nh_end = rd32(a, 8) as usize + rd32(a, 16) as usize * 12;
            let str_end = rd32(a, 20) as usize + rd32(a, 24) as usize;
            let lr_end = rd32(a, 32) as usize + rd32(a, 36) as usize * 108;
            if nh_end <= a.len() && str_end <= a.len() && lr_end <= a.len() && rd32(a, 16) > 2 { Some(a) } else { None }
        }
        _ => None,
    };
    if let Some(a) = a {
        unsafe { ARCH.write(a) };
    }
    ARCH_STATE.store(if a.is_some() { 1 } else { 2 }, Ordering::Release);
    a
}

pub fn hashval(key: &[u8]) -> u32 {
    let mut h = key.len() as u32;
    for &b in key {
        h = h.rotate_left(9).wrapping_add(b as u32);
    }
    if h != 0 { h } else { !0 }
}

pub fn lookup(name: &[u8]) -> Option<[&'static [u8]; 13]> {
    let a = archive()?;
    let size = rd32(a, 16) as usize;
    let table = rd32(a, 8) as usize;
    let hv = hashval(name);
    let mut idx = hv as usize % size;
    let incr = 1 + hv as usize % (size - 2);
    let mut tries = 0;
    loop {
        let e = table + idx * 12;
        let name_off = rd32(a, e + 4) as usize;
        if name_off == 0 {
            return None;
        }
        if rd32(a, e) == hv && name_off < a.len() {
            let s = &a[name_off..a.len().min(name_off + 512)];
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
    let rec = rd32(a, e + 8) as usize;
    if rec == 0 || rec + 108 > a.len() {
        return None;
    }
    let mut out: [&'static [u8]; 13] = [&[]; 13];
    for (c, slot) in out.iter_mut().enumerate() {
        if c == 6 {
            continue;
        }
        let off = rd32(a, rec + 4 + c * 8) as usize;
        let len = rd32(a, rec + 8 + c * 8) as usize;
        if off.checked_add(len)? > a.len() {
            return None;
        }
        *slot = &a[off..off + len];
    }
    Some(out)
}

