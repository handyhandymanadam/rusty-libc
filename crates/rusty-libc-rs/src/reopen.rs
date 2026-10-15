use std::fs::File;
use std::io::{self, Seek, SeekFrom};
use std::os::fd::RawFd;

fn fd_flags(fd: RawFd) -> io::Result<(u32, u64)> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{fd}"))?;
    let mut flags = None;
    let mut pos = 0;
    for line in text.lines() {
        if let Some(v) = line.strip_prefix("flags:") {
            flags = u32::from_str_radix(v.trim(), 8).ok();
        } else if let Some(v) = line.strip_prefix("pos:") {
            pos = v.trim().parse().unwrap_or(0);
        }
    }
    flags.map(|f| (f, pos)).ok_or_else(|| io::Error::other("no flags line in /proc/self/fdinfo"))
}

pub fn reopen_fd(fd: RawFd) -> io::Result<File> {
    if fd < 0 {
        return Err(io::Error::from_raw_os_error(9));
    }
    let (flags, pos) = fd_flags(fd)?;
    let mut opts = std::fs::OpenOptions::new();
    match flags & 3 {
        0 => opts.read(true),
        1 => opts.write(true),
        _ => opts.read(true).write(true),
    };
    if flags & 0o2000 != 0 {
        opts.append(true);
    }
    let mut file = opts.open(format!("/proc/self/fd/{fd}"))?;
    if flags & 0o2000 == 0 && pos > 0 && file.metadata()?.is_file() {
        file.seek(SeekFrom::Start(pos))?;
    }
    Ok(file)
}
