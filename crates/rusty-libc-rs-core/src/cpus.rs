//! The processor counts of get_nprocs(3) / get_nprocs_conf(3) and sysconf(_SC_NPROCESSORS_ONLN / _CONF), as glibc 2.43
//! computes them (sysdeps/unix/sysv/linux/getsysstats.c): the CPU ranges in /sys/devices/system/cpu/online (or
//! `possible`), else the `cpuN` lines of /proc/stat, else the bits of sched_getaffinity, else 2. One copy for the C face
//! (rusty-libc-sys's get_nprocs, get_nprocs_conf and sysconf; rusty-libc-malloc's arena limit) and the Rust face
//! (`sysconf`). Raw system calls only (non-cancelling, no allocation, no C library), and small frames (at most 4 KiB, one
//! step at a time): malloc calls it on the first allocation of a thread, which may have a minimum-size stack.

use crate::syscall::{nr, syscall3, syscall6};

/// Online processors (get_nprocs).
pub fn online() -> i32 {
    count(c"/sys/devices/system/cpu/online")
}

/// Configured processors (get_nprocs_conf).
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

/// open(path, O_RDONLY | O_CLOEXEC): the descriptor, or None.
fn open(path: &core::ffi::CStr) -> Option<i32> {
    const AT_FDCWD: isize = -100;
    const O_CLOEXEC: usize = 0o2000000;
    // SAFETY: the kernel reads the NUL-terminated path; the new descriptor is this module's until the matching close.
    let fd = unsafe { syscall6(nr::OPENAT, AT_FDCWD as usize, path.as_ptr() as usize, O_CLOEXEC, 0, 0, 0) };
    (!crate::syscall::is_err(fd)).then_some(fd as i32)
}

/// read(fd, buf): the byte count, 0 at the end or on an error.
fn read(fd: i32, buf: &mut [u8]) -> usize {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`; `fd` is the descriptor `open` gave this module.
    let r = unsafe { syscall3(nr::READ, fd as usize, buf.as_mut_ptr() as usize, buf.len()) };
    if crate::syscall::is_err(r) { 0 } else { r as usize }
}

fn close(fd: i32) {
    // SAFETY: `fd` is the descriptor `open` gave this module, closed once, not used afterwards.
    let _ = unsafe { syscall3(nr::CLOSE, fd as usize, 0, 0) };
}

/// The CPU count of a sysfs range list ("0-7,9"), from its first 1024 bytes; 0 when unreadable or malformed (glibc's
/// read_sysfs_file).
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

/// The count of a range list ("0-7,9\n"); 0 for an empty or malformed one.
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

/// The `cpuN` lines at the start of /proc/stat (glibc's get_nproc_stat), read in 512-byte pieces.
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

/// The state of the /proc/stat line scan: the first four bytes of the current line, how far into it, the count.
#[derive(Default)]
struct StatCounter {
    pfx: [u8; 4],
    col: usize,
    count: i32,
}

impl StatCounter {
    /// Scan more bytes; false once a line that does not start with "cpu" ends the scan.
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

/// The CPUs in the calling thread's affinity mask (glibc's __get_nprocs_sched): sched_getaffinity with room for 32768
/// CPUs; EINVAL (more than that) gives 32768, another error 0.
#[inline(never)]
pub fn from_affinity() -> i32 {
    let mut mask = [0u64; 512];
    // SAFETY: the kernel writes at most 4096 bytes (the size passed) into the local `mask`.
    let r = unsafe { syscall3(nr::SCHED_GETAFFINITY, 0, core::mem::size_of_val(&mask), mask.as_mut_ptr() as usize) };
    match crate::errno::Errno::of(r) {
        None if r > 0 => mask[..(r as usize).div_ceil(8)].iter().map(|w| w.count_ones() as i32).sum(),
        Some(crate::errno::Errno::EINVAL) => 32768,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    #[test]
    fn range_lists() {
        assert_eq!(range_count(b"0-7\n"), 8);
        assert_eq!(range_count(b"0-3,8,10-11\n"), 7);
        assert_eq!(range_count(b"0"), 1);
        assert_eq!(range_count(b""), 0);
        assert_eq!(range_count(b"x"), 0);
        assert_eq!(range_count(b"0-x"), 0);
        assert_eq!(range_count(b"0-7,\n"), 8);
        assert_eq!(range_count(b"5-2,1\n"), 1);
        assert_eq!(range_count(b"0-3junk"), 0);
    }

    #[test]
    fn stat_lines() {
        let mut c = StatCounter::default();
        assert!(c.feed(b"cpu  1 2 3\ncpu0 1\ncp"));
        assert!(c.feed(b"u1 2\ncpu"));
        assert!(!c.feed(b"\nintr 5\ncpu2 9\n"));
        assert_eq!(c.count, 2);
        let mut c = StatCounter::default();
        assert!(!c.feed(b"ab\ncpu0\n"));
        assert_eq!(c.count, 0);
    }

    #[test]
    fn counts_agree_with_the_system() {
        let n = std::thread::available_parallelism().map(|n| n.get() as i32).unwrap_or(0);
        assert!(online() >= 1 && configured() >= online());
        // without taskset limits the affinity count is the online count
        assert!(from_affinity() >= 1 && from_affinity() <= online().max(n));
        assert_eq!(from_proc_stat(), online());
    }
}
