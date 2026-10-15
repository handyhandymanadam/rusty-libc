use crate::syscall::{nr, syscall3, syscall6};

pub fn online() -> i32 {
    count(c"/sys/devices/system/cpu/online")
}

pub fn configured() -> i32 {
    count(c"/sys/devices/system/cpu/possible")
}

fn count(sysfs: &core::ffi::CStr) -> i32 {
    let n = from_sysfs(sysfs);
    if n != 0 {
        return n;
    }
    let n = from_proc_stat();
    if n != 0 {
        return n;
    }
    let n = from_affinity();
    if n != 0 { n } else { 2 }
}

fn open(path: &core::ffi::CStr) -> Option<i32> {
    const AT_FDCWD: isize = -100;
    const O_CLOEXEC: usize = 0o2000000;
    let fd = unsafe { syscall6(nr::OPENAT, AT_FDCWD as usize, path.as_ptr() as usize, O_CLOEXEC, 0, 0, 0) };
    (!crate::syscall::is_err(fd)).then_some(fd as i32)
}

fn read(fd: i32, buf: &mut [u8]) -> usize {
    let r = unsafe { syscall3(nr::READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) };
    if crate::syscall::is_err(r) { 0 } else { r as usize }
}

fn close(fd: i32) {
    let _ = unsafe { syscall3(nr::CLOSE, fd as usize, 0, 0) };
}

#[inline(never)]
pub fn from_sysfs(path: &core::ffi::CStr) -> i32 {
    let Some(fd) = open(path) else { return 0 };
    let mut buf = [0u8; 1024];
    let mut n = 0;
    while n < buf.len() {
        match read(fd, &mut buf[n..]) {
            0 => break,
            k => n += k,
        }
    }
    close(fd);
    range_count(&buf[..n])
}

fn parse_uint(s: &[u8]) -> Option<(u64, usize)> {
    let k = s.iter().take_while(|c| c.is_ascii_digit()).count();
    (k > 0).then(|| (s[..k].iter().fold(0u64, |v, &d| v.wrapping_mul(10).wrapping_add(u64::from(d - b'0'))), k))
}

pub fn range_count(s: &[u8]) -> i32 {
    if s.is_empty() {
        return 0;
    }
    let (mut i, mut result) = (0usize, 0i64);
    loop {
        let Some((a, k)) = parse_uint(&s[i..]) else { return 0 };
        i += k;
        let mut b = a;
        if s.get(i) == Some(&b'-') {
            i += 1;
            let Some((m, k)) = parse_uint(&s[i..]) else { return 0 };
            i += k;
            b = m;
        }
        if b >= a {
            result += (b - a + 1) as i64;
        }
        if s.get(i) == Some(&b',') {
            i += 1;
        }
        if !(i < s.len() && s[i] != b'\n') {
            break;
        }
    }
    result as i32
}

#[inline(never)]
pub fn from_proc_stat() -> i32 {
    let Some(fd) = open(c"/proc/stat") else { return 0 };
    let mut counter = StatCounter::default();
    let mut chunk = [0u8; 512];
    loop {
        let r = read(fd, &mut chunk);
        if r == 0 || !counter.feed(&chunk[..r]) {
            break;
        }
    }
    close(fd);
    counter.count
}

#[derive(Default)]
struct StatCounter {
    pfx: [u8; 4],
    col: usize,
    count: i32,
}

impl StatCounter {
    fn feed(&mut self, bytes: &[u8]) -> bool {
        for &c in bytes {
            if c == b'\n' {
                if self.col < 3 || &self.pfx[..3] != b"cpu" {
                    return false;
                }
                self.col = 0;
                continue;
            }
            if self.col < 4 {
                self.pfx[self.col] = c;
                if self.col == 3 {
                    if &self.pfx[..3] != b"cpu" {
                        return false;
                    }
                    if c.is_ascii_digit() {
                        self.count += 1;
                    }
                }
            }
            self.col += 1;
        }
        true
    }
}

#[inline(never)]
pub fn from_affinity() -> i32 {
    let mut mask = [0u64; 512];
    let r = unsafe { syscall3(nr::SCHED_GETAFFINITY, 0, core::mem::size_of_val(&mask), mask.as_mut_ptr() as usize) };
    match crate::errno::Errno::of(r) {
        None if r > 0 => mask[..(r as usize).div_ceil(8)].iter().map(|w| w.count_ones() as i32).sum(),
        Some(crate::errno::Errno::EINVAL) => 32768,
        _ => 0,
    }
}

