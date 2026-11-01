//! getpass(3) as glibc 2.43's misc/getpass.c: the terminal (/dev/tty, opened "w+ce") when it can be opened, otherwise standard
//! input and standard error, all through stdio: the prompt goes out with the stream's other pending output, the line is read
//! with getline (no length limit; text stdin already buffered is used; a stream in the error state gives an empty answer, or
//! NULL before the first allocation), echo and the signal keys are turned off while reading from a terminal, and the newline
//! that was not echoed is written only when the line ended with one.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_stdio::file_api as io;
use rusty_libc_sys::termios::{tcgetattr_r, tcsetattr_r};

const ECHO: u32 = 0o10;
const ISIG: u32 = 0o1;
const TCSAFLUSH: c_int = 2;

/// getline's buffer and its size, kept between calls as glibc's static `buf`/`bufsize`. Rule: getpass is MT-Unsafe (glibc:
/// race:getpass, the answer lives in this one buffer): concurrent calls are the caller's error, as in glibc; each call
/// touches the two cells only between its start and its return.
static BUF: SyncCell<*mut c_char> = SyncCell::new(null_mut());
static BUFSIZE: SyncCell<usize> = SyncCell::new(0);

/// getpass(3) (obsolete): print `prompt` and read a line with echo off; the answer, without its newline, stays valid until
/// the next call.
///
/// # Safety
/// `prompt` must be a valid C string; no other thread calls getpass at the same time.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpass(prompt: *const c_char) -> *mut c_char {
    // SAFETY: both arguments are C string literals.
    let tty = unsafe { io::fopen(c"/dev/tty".as_ptr(), c"w+ce".as_ptr()) };
    // SAFETY: stdin/stderr are set once at start-up and only read here.
    let (inp, out) = if tty.is_null() { (unsafe { io::stdin.read() }, unsafe { io::stderr.read() }) } else { (tty, tty) };
    // SAFETY: `out` is an open stream (the tty just opened, or stderr).
    unsafe { io::flockfile(out) };
    // SAFETY: `inp` is an open stream.
    let fd = unsafe { io::fileno(inp) };
    let saved = tcgetattr_r(fd).ok();
    let mut changed = false;
    if let Some(t) = &saved {
        let mut n = *t;
        n.c_lflag &= !(ECHO | ISIG);
        changed = tcsetattr_r(fd, TCSAFLUSH, &n).is_ok();
    }
    // SAFETY: `prompt` is a C string (caller's contract); `out` is open.
    unsafe { io::fputs(prompt, out) };
    // SAFETY: `out` is open.
    unsafe { io::fflush(out) };
    // SAFETY: getpass's rule (one caller at a time) gives this call the two cells, which getline keeps as a malloc buffer
    // and its size; `inp` is open.
    let nread = unsafe { io::getline(BUF.as_ptr(), BUFSIZE.as_ptr(), inp) };
    // SAFETY: as above, nothing else writes BUF during the call.
    let buf = unsafe { BUF.read() };
    if !buf.is_null() {
        // SAFETY: getline left a NUL-terminated line of `nread` bytes (or kept an allocation of at least one byte) in `buf`.
        let text = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), if nread < 0 { 1 } else { nread as usize + 1 }) };
        trim_answer(text, nread, changed, || {
            // SAFETY: `out` is open.
            unsafe { io::fputs(c"\n".as_ptr(), out) };
        });
    }
    if changed && let Some(t) = &saved {
        let _ = tcsetattr_r(fd, TCSAFLUSH, t);
    }
    // SAFETY: `out` was locked above by this thread.
    unsafe { io::funlockfile(out) };
    // SAFETY: stdin is only read.
    if inp != unsafe { io::stdin.read() } {
        // SAFETY: `inp` is the tty stream this call opened; it is closed once.
        unsafe { io::fclose(inp) };
    }
    buf
}

/// The answer's fix-up as glibc does it: a read error empties the buffer; a trailing newline is removed, and echoed with
/// `echo_newline` when echo was turned off. `text` is the line with its NUL (one byte when `nread < 0`).
fn trim_answer(text: &mut [u8], nread: isize, changed: bool, echo_newline: impl FnOnce()) {
    if nread < 0 {
        text[0] = 0;
    } else if nread > 0 && text[nread as usize - 1] == b'\n' {
        text[nread as usize - 1] = 0;
        if changed {
            echo_newline();
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    unsafe fn host_getpass(p: *const c_char) -> *mut c_char {
        unsafe extern "C" {
            #[link_name = "getpass"]
            fn host(p: *const c_char) -> *mut c_char;
        }
        unsafe { host(p) }
    }

    /// The child side of `on_pty`: this test binary run again for this test alone (a fork of the multi-threaded test process
    /// could inherit a stdio or malloc lock another test holds). Does nothing in a normal test run.
    #[test]
    fn getpass_child_entry() {
        let Ok(out) = std::env::var("RL_GETPASS_OUT") else { return };
        let r = unsafe {
            if std::env::var("RL_GETPASS_HOST").is_ok() { host_getpass(c"Password: ".as_ptr()) } else { getpass(c"Password: ".as_ptr()) }
        };
        let text = if r.is_null() { b"(null)".to_vec() } else { unsafe { core::ffi::CStr::from_ptr(r) }.to_bytes().to_vec() };
        std::fs::write(out, text).unwrap();
    }

    /// Run getpass (ours or the host's) in a new session whose standard input and standard error are the slave side of a pty;
    /// type `typed` on the master; return what the terminal showed and what getpass returned.
    fn on_pty(typed: &[u8], host: bool) -> (Vec<u8>, Vec<u8>) {
        unsafe {
            let (mut m, mut s) = (0, 0);
            assert_eq!(libc::openpty(&mut m, &mut s, core::ptr::null_mut(), core::ptr::null(), core::ptr::null()), 0);
            let out = std::env::temp_dir().join(format!("rl-getpass-{}-{}", std::process::id(), host as u8));
            let _ = std::fs::remove_file(&out);
            let mut cmd = Command::new(std::env::current_exe().unwrap());
            cmd.args(["--exact", "getpass::tests::getpass_child_entry", "--test-threads=1", "-q"])
                .env("RL_GETPASS_OUT", &out)
                .stdin(Stdio::from_raw_fd(libc::dup(s)))
                .stderr(Stdio::from_raw_fd(libc::dup(s)))
                .stdout(Stdio::null());
            if host {
                cmd.env("RL_GETPASS_HOST", "1");
            }
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
            let mut child = cmd.spawn().unwrap();
            libc::close(s);
            // let the child reach the prompt, then type
            let mut prompt = Vec::new();
            let mut b = [0u8; 256];
            let mut tries = 0;
            while prompt.len() < 10 && tries < 400 {
                let mut pfd = libc::pollfd { fd: m, events: libc::POLLIN, revents: 0 };
                if libc::poll(&mut pfd, 1, 50) > 0 {
                    let n = libc::read(m, b.as_mut_ptr().cast(), b.len());
                    if n > 0 {
                        prompt.extend_from_slice(&b[..n as usize]);
                    }
                }
                tries += 1;
            }
            libc::write(m, typed.as_ptr().cast(), typed.len());
            child.wait().unwrap();
            // whatever else the child wrote to the terminal after the prompt (the newline)
            loop {
                let mut pfd = libc::pollfd { fd: m, events: libc::POLLIN, revents: 0 };
                if libc::poll(&mut pfd, 1, 20) <= 0 {
                    break;
                }
                let n = libc::read(m, b.as_mut_ptr().cast(), b.len());
                if n <= 0 {
                    break;
                }
                prompt.extend_from_slice(&b[..n as usize]);
            }
            libc::close(m);
            let got = std::fs::read(&out).unwrap_or_default();
            let _ = std::fs::remove_file(&out);
            (prompt, got)
        }
    }

    #[test]
    fn getpass_matches_host_on_a_pty() {
        for typed in [&b"secret\n"[..], b"\n", b"with space\n"] {
            let a = on_pty(typed, false);
            let h = on_pty(typed, true);
            assert_eq!(a.1, h.1, "returned text for {typed:?}");
            assert!(!a.1.is_empty() || typed == b"\n", "no answer for {typed:?}");
            // the terminal sees the prompt, no echo of the secret, then a newline
            assert_eq!(a.0, h.0, "terminal output for {typed:?}");
        }
    }
}
