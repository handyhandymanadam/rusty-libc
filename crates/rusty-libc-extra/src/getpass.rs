#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_stdio::file_api as io;
use rusty_libc_sys::termios::{tcgetattr_r, tcsetattr_r};

const ECHO: u32 = 0o10;
const ISIG: u32 = 0o1;
const TCSAFLUSH: c_int = 2;

static BUF: SyncCell<*mut c_char> = SyncCell::new(null_mut());
static BUFSIZE: SyncCell<usize> = SyncCell::new(0);

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getpass(prompt: *const c_char) -> *mut c_char {
    let tty = unsafe { io::fopen(c"/dev/tty".as_ptr(), c"w+ce".as_ptr()) };
    let (inp, out) = if tty.is_null() { (unsafe { io::stdin.read() }, unsafe { io::stderr.read() }) } else { (tty, tty) };
    unsafe { io::flockfile(out) };
    let fd = unsafe { io::fileno(inp) };
    let saved = tcgetattr_r(fd).ok();
    let mut changed = false;
    if let Some(t) = &saved {
        let mut n = *t;
        n.c_lflag &= !(ECHO | ISIG);
        changed = tcsetattr_r(fd, TCSAFLUSH, &n).is_ok();
    }
    unsafe { io::fputs(prompt, out) };
    unsafe { io::fflush(out) };
    let nread = unsafe { io::getline(BUF.as_ptr(), BUFSIZE.as_ptr(), inp) };
    let buf = unsafe { BUF.read() };
    if !buf.is_null() {
        let text = unsafe { rusty_libc_core::ffi::bytes_mut(buf.cast::<u8>(), if nread < 0 { 1 } else { nread as usize + 1 }) };
        trim_answer(text, nread, changed, || {
            unsafe { io::fputs(c"\n".as_ptr(), out) };
        });
    }
    if changed && let Some(t) = &saved {
        let _ = tcsetattr_r(fd, TCSAFLUSH, t);
    }
    unsafe { io::funlockfile(out) };
    if inp != unsafe { io::stdin.read() } {
        unsafe { io::fclose(inp) };
    }
    buf
}

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

