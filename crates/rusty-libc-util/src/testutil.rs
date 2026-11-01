//! Helpers shared by the differential tests.
use core::ffi::c_int;

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
}

unsafe extern "C" {
    static mut _IO_2_1_stdin_: [u8; 1];
    static mut _IO_2_1_stdout_: [u8; 1];
    static mut _IO_2_1_stderr_: [u8; 1];
}

/// rusty-libc-stdio exports the data symbols `stdin`, `stdout`, `stderr` even without its `export` feature,
/// so glibc, inside this test process, would read OUR variables and crash on our FILE structs. While
/// host code runs, point them at glibc's own streams (`host_streams`); while our code runs, point
/// them back at our own (`ours_streams`): our code reads `stderr` like any C program (an assigned
/// `stderr` is honoured), so it must never be handed glibc's FILE.
static OURS: std::sync::Mutex<Option<[usize; 3]>> = std::sync::Mutex::new(None);

pub fn host_streams() {
    unsafe {
        let mut o = OURS.lock().unwrap_or_else(|e| e.into_inner());
        if o.is_none() {
            *o = Some([rusty_libc_stdio::stdin.read() as usize, rusty_libc_stdio::stdout.read() as usize, rusty_libc_stdio::stderr.read() as usize]);
        }
        rusty_libc_stdio::stdin.write(core::ptr::addr_of_mut!(_IO_2_1_stdin_) as *mut _);
        rusty_libc_stdio::stdout.write(core::ptr::addr_of_mut!(_IO_2_1_stdout_) as *mut _);
        rusty_libc_stdio::stderr.write(core::ptr::addr_of_mut!(_IO_2_1_stderr_) as *mut _);
    }
}

/// Our own streams again (a no-op until `host_streams` has run once).
pub fn ours_streams() {
    unsafe {
        if let Some(v) = *OURS.lock().unwrap_or_else(|e| e.into_inner()) {
            rusty_libc_stdio::stdin.write(v[0] as *mut _);
            rusty_libc_stdio::stdout.write(v[1] as *mut _);
            rusty_libc_stdio::stderr.write(v[2] as *mut _);
        }
    }
}

/// Redirects file descriptor 2 to a temporary file; `take` returns what was written since the last
/// call. Drop restores fd 2.
pub struct Stderr {
    fd: c_int,
    saved: c_int,
    path: String,
}

impl Stderr {
    pub fn new(tag: &str) -> Stderr {
        let path = format!("/tmp/rusty-libc-util-test-{}-{}", std::process::id(), tag);
        let cpath = std::ffi::CString::new(path.clone()).unwrap();
        unsafe {
            let fd = libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_CLOEXEC, 0o600);
            assert!(fd >= 0);
            let saved = libc::dup(2);
            libc::dup2(fd, 2);
            Stderr { fd, saved, path }
        }
    }
    pub fn take(&mut self) -> Vec<u8> {
        unsafe {
            let len = libc::lseek(self.fd, 0, libc::SEEK_CUR);
            let mut buf = vec![0u8; len as usize];
            if len > 0 {
                let n = libc::pread(self.fd, buf.as_mut_ptr().cast(), len as usize, 0);
                assert_eq!(n as i64, len);
            }
            libc::ftruncate(self.fd, 0);
            libc::lseek(self.fd, 0, libc::SEEK_SET);
            buf
        }
    }
}

impl Drop for Stderr {
    fn drop(&mut self) {
        unsafe {
            libc::dup2(self.saved, 2);
            libc::close(self.saved);
            libc::close(self.fd);
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
