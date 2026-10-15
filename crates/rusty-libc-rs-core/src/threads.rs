use crate::errno::{Errno, cvt};
use crate::syscall::{nr, syscall3};
use std::io::Read;
use std::string::String;
use std::os::fd::AsRawFd;

const PROC_SUPER_MAGIC: i64 = 0x9fa0;

pub fn thread_count() -> Result<usize, Errno> {
    let mut f = std::fs::File::open("/proc/self/status").map_err(io_errno)?;
    let mut st = [0i64; 15];
    cvt(unsafe { syscall3(nr::FSTATFS, f.as_raw_fd() as usize, st.as_mut_ptr() as usize, 0) })?;
    if st[0] != PROC_SUPER_MAGIC {
        return Err(Errno::ENODEV);
    }
    let mut text = String::new();
    f.read_to_string(&mut text).map_err(io_errno)?;
    let field = |k: &str| text.lines().find_map(|l| l.strip_prefix(k)).and_then(|v| v.trim().parse::<i64>().ok());
    let me = i64::from(crate::process::getpid());
    match (field("Tgid:"), field("Pid:"), field("Threads:")) {
        (Some(t), Some(p), Some(n)) if t == me && p == me && n > 0 => Ok(n as usize),
        _ => Err(Errno::ENODEV),
    }
}

pub fn single_threaded() -> Result<bool, Errno> {
    thread_count().map(|n| n == 1)
}

fn io_errno(e: std::io::Error) -> Errno {
    Errno(e.raw_os_error().unwrap_or(Errno::EINVAL.0))
}

