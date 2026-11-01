//! termios.h and the pty.h/utmp.h helpers (openpty, forkpty, login_tty).
//!
//! `struct termios` is glibc's 60-byte x86_64 layout (speeds as real baud rates in `c_ispeed` and
//! `c_ospeed`, glibc 2.42 and later). The kernel's `termios2` (44 bytes, 19 control characters)
//! is translated in both directions, with glibc's canonicalisation of the legacy CBAUD bits.
use crate::misc::sci;
use core::ffi::{c_char, c_int};
use crate::kernel::plain;
use rusty_libc_core::syscall::{SYS_IOCTL, check, syscall3};
use rusty_libc_core::{Errno, errno};

const SYS_DUP2: usize = 33;
const SYS_SETSID: usize = 112;
const SYS_GETSID: usize = 124;
const SYS_CLOSE: usize = 3;

const TCGETS2: usize = 0x802C_542A;
const TCSETS2: usize = 0x402C_542B;
const TCSBRK: usize = 0x5409;
const TCXONC: usize = 0x540A;
const TCFLSH: usize = 0x540B;
const TIOCSCTTY: usize = 0x540E;
const TIOCGPGRP: usize = 0x540F;
const TIOCSPGRP: usize = 0x5410;
const TIOCSWINSZ: usize = 0x5414;
const TCSBRKP: usize = 0x5425;
const TIOCGSID: usize = 0x5429;
const TIOCGPTPEER: usize = 0x5441;

const EINVAL: i32 = 22;
const EBUSY: i32 = 16;
const ENOTTY: i32 = 25;
const ESRCH: i32 = 3;
const O_RDWR: usize = 2;
const O_NOCTTY: usize = 0o400;

pub const NCCS: usize = 32;
const KERNEL_NCCS: usize = 19;

const CBAUD: u32 = 0o010017;
const CBAUDEX: u32 = 0o010000;
const CIBAUD: u32 = CBAUD << 16;
const IBSHIFT: u32 = 16;
const BOTHER: u32 = 0o010000;
const CBAUDMASK: u32 = 0xf | CBAUDEX;

// c_iflag, c_oflag, c_cflag, c_lflag bits used by cfmakeraw
const IGNBRK: u32 = 0o1;
const BRKINT: u32 = 0o2;
const PARMRK: u32 = 0o10;
const ISTRIP: u32 = 0o40;
const INLCR: u32 = 0o100;
const IGNCR: u32 = 0o200;
const ICRNL: u32 = 0o400;
const IXON: u32 = 0o2000;
const OPOST: u32 = 0o1;
const ECHO: u32 = 0o10;
const ECHONL: u32 = 0o100;
const ICANON: u32 = 0o2;
const ISIG: u32 = 0o1;
const IEXTEN: u32 = 0o100000;
const CSIZE: u32 = 0o60;
const PARENB: u32 = 0o400;
const CS8: u32 = 0o60;
const VTIME: usize = 5;
const VMIN: usize = 6;

/// glibc's `struct termios` (60 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct termios {
    pub c_iflag: u32,
    pub c_oflag: u32,
    pub c_cflag: u32,
    pub c_lflag: u32,
    pub c_line: u8,
    pub c_cc: [u8; NCCS],
    pub c_ispeed: u32,
    pub c_ospeed: u32,
}

/// The kernel's `struct termios2` (44 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Termios2 {
    c_iflag: u32,
    c_oflag: u32,
    c_cflag: u32,
    c_lflag: u32,
    c_line: u8,
    c_cc: [u8; KERNEL_NCCS],
    c_ispeed: u32,
    c_ospeed: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct winsize {
    pub ws_row: u16,
    pub ws_col: u16,
    pub ws_xpixel: u16,
    pub ws_ypixel: u16,
}

// ---------------------------------------------------------------- speed tables

/// (baud rate, CBAUD field value), the legacy codes in kernel order.
const SPEEDS: [(u32, u32); 31] = [
    (0, 0),
    (50, 1),
    (75, 2),
    (110, 3),
    (134, 4),
    (150, 5),
    (200, 6),
    (300, 7),
    (600, 8),
    (1200, 9),
    (1800, 10),
    (2400, 11),
    (4800, 12),
    (9600, 13),
    (19200, 14),
    (38400, 15),
    (57600, 0o10001),
    (115200, 0o10002),
    (230400, 0o10003),
    (460800, 0o10004),
    (500000, 0o10005),
    (576000, 0o10006),
    (921600, 0o10007),
    (1000000, 0o10010),
    (1152000, 0o10011),
    (1500000, 0o10012),
    (2000000, 0o10013),
    (2500000, 0o10014),
    (3000000, 0o10015),
    (3500000, 0o10016),
    (4000000, 0o10017),
];

/// Speed for a CBAUD field; `other` when the code is unknown or has stray bits.
fn cbaud_to_speed(cflag: u32, other: u32) -> u32 {
    if cflag & !CBAUDMASK != 0 {
        return other;
    }
    for &(s, c) in SPEEDS.iter() {
        if c == cflag {
            return s;
        }
    }
    other
}

/// CBAUD field for a baud rate (BOTHER when it has no legacy code).
fn speed_to_cbaud(speed: u32) -> u32 {
    for &(s, c) in SPEEDS.iter() {
        if s == speed {
            return c;
        }
    }
    BOTHER
}

/// Make the legacy CBAUD bits and the numeric speeds agree (the kernel does not).
fn canonicalize(k: &mut Termios2) {
    k.c_ospeed = cbaud_to_speed(k.c_cflag & CBAUD, k.c_ospeed);
    k.c_ispeed = cbaud_to_speed((k.c_cflag >> IBSHIFT) & CBAUD, k.c_ispeed);
    if k.c_ispeed == 0 {
        k.c_ispeed = k.c_ospeed;
    }
    k.c_cflag &= !(CBAUD | CIBAUD);
    k.c_cflag |= speed_to_cbaud(k.c_ospeed);
    k.c_cflag |= speed_to_cbaud(k.c_ispeed) << IBSHIFT;
}

// ---------------------------------------------------------------- Rust API

/// Read the attributes of a terminal.
pub fn tcgetattr_r(fd: i32) -> Result<termios, Errno> {
    let mut k = Termios2::default();
    // SAFETY: TCGETS2 writes one `struct termios2` into the local `k` (same layout).
    unsafe { check(syscall3(SYS_IOCTL, fd as usize, TCGETS2, &mut k as *mut Termios2 as usize))? };
    canonicalize(&mut k);
    let mut t = termios {
        c_iflag: k.c_iflag,
        c_oflag: k.c_oflag,
        c_cflag: k.c_cflag,
        c_lflag: k.c_lflag,
        c_line: k.c_line,
        c_ospeed: k.c_ospeed,
        c_ispeed: k.c_ispeed,
        ..termios::default()
    };
    t.c_cc[..KERNEL_NCCS].copy_from_slice(&k.c_cc);
    Ok(t)
}

/// Set the attributes (`action`: 0 now, 1 after output drains, 2 after draining and flushing input).
pub fn tcsetattr_r(fd: i32, action: i32, t: &termios) -> Result<(), Errno> {
    let mut k = Termios2 {
        c_iflag: t.c_iflag,
        c_oflag: t.c_oflag,
        c_cflag: t.c_cflag,
        c_lflag: t.c_lflag,
        c_line: t.c_line,
        c_cc: [0; KERNEL_NCCS],
        c_ispeed: t.c_ispeed,
        c_ospeed: t.c_ospeed,
    };
    canonicalize(&mut k);
    k.c_cc.copy_from_slice(&t.c_cc[..KERNEL_NCCS]);
    let cmd = action as i64;
    if !(0..=2).contains(&cmd) {
        return Err(Errno(EINVAL));
    }
    if k.c_ospeed == k.c_ispeed {
        k.c_cflag &= !CIBAUD;
    }
    // SAFETY: TCSETS2 (+0, 1 or 2: TCSETSW2, TCSETSF2) reads one `struct termios2`, the local `k`.
    unsafe { check(syscall3(SYS_IOCTL, fd as usize, TCSETS2 + cmd as usize, &k as *const Termios2 as usize)).map(|_| ()) }
}

/// Put `t` in raw mode (no processing of input or output, 8 bit characters).
pub fn makeraw(t: &mut termios) {
    t.c_iflag &= !(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    t.c_oflag &= !OPOST;
    t.c_lflag &= !(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t.c_cflag &= !(CSIZE | PARENB);
    t.c_cflag |= CS8;
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
}

/// Set the output speed (a baud rate; a rate without a legacy code is stored with BOTHER). Never fails.
pub fn setospeed(t: &mut termios, speed: u32) {
    t.c_ospeed = speed;
    t.c_cflag &= !CBAUD;
    t.c_cflag |= speed_to_cbaud(speed);
}

/// Set the input speed (a baud rate). Never fails.
pub fn setispeed(t: &mut termios, speed: u32) {
    t.c_ispeed = speed;
    t.c_cflag &= !CIBAUD;
    t.c_cflag |= speed_to_cbaud(speed) << IBSHIFT;
}

/// Set both speeds (a baud rate). Never fails.
pub fn setspeed(t: &mut termios, speed: u32) {
    let cb = speed_to_cbaud(speed);
    t.c_ospeed = speed;
    t.c_ispeed = speed;
    t.c_cflag &= !(CBAUD | CIBAUD);
    t.c_cflag |= cb | (cb << IBSHIFT);
}

/// The glibc 2.2.5 `cfset*speed` rules: `code` is a legacy `Bnnn` code; the baud rate it stands for, or None (EINVAL).
fn old_code_speed(code: u32) -> Option<u32> {
    let real = cbaud_to_speed(code, u32::MAX);
    if real == u32::MAX { None } else { Some(real) }
}

fn apply_ospeed_old(t: &mut termios, real: u32, code: u32) {
    t.c_ospeed = real;
    t.c_cflag &= !CBAUD;
    t.c_cflag |= code;
}

fn apply_ispeed_old(t: &mut termios, real: u32, code: u32) {
    t.c_ispeed = real;
    t.c_cflag &= !CIBAUD;
    t.c_cflag |= code << IBSHIFT;
}

fn apply_speed_old(t: &mut termios, real: u32, code: u32) {
    t.c_ospeed = real;
    t.c_ispeed = real;
    t.c_cflag &= !(CBAUD | CIBAUD);
    t.c_cflag |= code | (code << IBSHIFT);
}

/// EINVAL for a `Bnnn` code that names no speed (the 2.2.5 setters).
fn bad_code() -> c_int {
    errno::set(EINVAL);
    -1
}

/// `cfsetospeed@GLIBC_2.2.5` on a reference: `code` is a `Bnnn` code; -1 with EINVAL (and `t` untouched) for an unknown one.
pub fn setospeed_old(t: &mut termios, code: u32) -> c_int {
    let Some(real) = old_code_speed(code) else { return bad_code() };
    apply_ospeed_old(t, real, code);
    0
}

/// `cfsetispeed@GLIBC_2.2.5` on a reference.
pub fn setispeed_old(t: &mut termios, code: u32) -> c_int {
    let Some(real) = old_code_speed(code) else { return bad_code() };
    apply_ispeed_old(t, real, code);
    0
}

/// `cfsetspeed@GLIBC_2.2.5` on a reference.
pub fn setspeed_old(t: &mut termios, code: u32) -> c_int {
    let Some(real) = old_code_speed(code) else { return bad_code() };
    apply_speed_old(t, real, code);
    0
}

// ---------------------------------------------------------------- C ABI

/// # Safety
/// `t` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tcgetattr(fd: c_int, t: *mut termios) -> c_int {
    match tcgetattr_r(fd) {
        Ok(v) => {
            // the 60 bytes glibc stores: memset to 0 (so C code may memcmp the padding), then the fields; `t` is only touched
            // on success
            use core::mem::{offset_of, size_of};
            let mut img = [0u8; size_of::<termios>()];
            let mut put = |off: usize, b: &[u8]| img[off..off + b.len()].copy_from_slice(b);
            put(offset_of!(termios, c_iflag), &v.c_iflag.to_ne_bytes());
            put(offset_of!(termios, c_oflag), &v.c_oflag.to_ne_bytes());
            put(offset_of!(termios, c_cflag), &v.c_cflag.to_ne_bytes());
            put(offset_of!(termios, c_lflag), &v.c_lflag.to_ne_bytes());
            put(offset_of!(termios, c_line), &[v.c_line]);
            put(offset_of!(termios, c_cc), &v.c_cc);
            put(offset_of!(termios, c_ispeed), &v.c_ispeed.to_ne_bytes());
            put(offset_of!(termios, c_ospeed), &v.c_ospeed.to_ne_bytes());
            // SAFETY: `t` is a writable `struct termios` (contract), whose bytes `img` are.
            unsafe { t.cast::<[u8; size_of::<termios>()]>().write(img) };
            0
        }
        Err(Errno(e)) => {
            errno::set(e);
            -1
        }
    }
}

/// # Safety
/// `t` is readable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tcsetattr(fd: c_int, action: c_int, t: *const termios) -> c_int {
    // SAFETY: `t` is a readable `struct termios` (contract).
    match tcsetattr_r(fd, action, unsafe { &*t }) {
        Ok(()) => 0,
        Err(Errno(e)) => {
            errno::set(e);
            -1
        }
    }
}

/// # Safety
/// `t` is readable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetospeed(t: *const termios) -> u32 {
    // SAFETY: `t` is a readable `struct termios` (contract).
    unsafe { &*t }.c_ospeed
}

/// # Safety
/// `t` is readable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetispeed(t: *const termios) -> u32 {
    // SAFETY: `t` is a readable `struct termios` (contract).
    unsafe { &*t }.c_ispeed
}

crate::unistd::alias!(
    /// # Safety
    /// `t` is readable.
    cfgetobaud => cfgetospeed(t: *const termios) -> u32
);

crate::unistd::alias!(
    /// # Safety
    /// `t` is readable.
    cfgetibaud => cfgetispeed(t: *const termios) -> u32
);

// The Rust `libc` crate binds these five by their versioned names on x86_64 glibc
// (`link_name = "cfsetispeed@GLIBC_2.2.5"`), so a static link needs a symbol with that literal name.
// Those are glibc's legacy versions (sysdeps/unix/sysv/linux/speed.c, cfsetspeed.c): speeds are the
// old B* codes (B9600 = 0o15), not baud rates; the plain names above take baud rates since glibc 2.42.
#[cfg(all(feature = "export", not(feature = "shared")))]
mod versioned {
    use super::*;
    /// # Safety
    /// `t` is readable.
    #[unsafe(export_name = "cfgetospeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfgetospeed_v(t: *const termios) -> u32 {
        // SAFETY: the caller's contract.
        unsafe { cfgetospeed_old(t) }
    }
    /// # Safety
    /// `t` is readable.
    #[unsafe(export_name = "cfgetispeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfgetispeed_v(t: *const termios) -> u32 {
        // SAFETY: the caller's contract.
        unsafe { cfgetispeed_old(t) }
    }
    /// # Safety
    /// `t` is writable.
    #[unsafe(export_name = "cfsetospeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfsetospeed_v(t: *mut termios, speed: u32) -> c_int {
        // SAFETY: the caller's contract.
        unsafe { cfsetospeed_old(t, speed) }
    }
    /// # Safety
    /// `t` is writable.
    #[unsafe(export_name = "cfsetispeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfsetispeed_v(t: *mut termios, speed: u32) -> c_int {
        // SAFETY: the caller's contract.
        unsafe { cfsetispeed_old(t, speed) }
    }
    /// # Safety
    /// `t` is writable.
    #[unsafe(export_name = "cfsetspeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfsetspeed_v(t: *mut termios, speed: u32) -> c_int {
        // SAFETY: the caller's contract.
        unsafe { cfsetspeed_old(t, speed) }
    }
}

/// Never fails: a rate without a legacy code is stored as given with BOTHER.
///
/// # Safety
/// `t` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetospeed(t: *mut termios, speed: u32) -> c_int {
    // SAFETY: `t` is a writable `struct termios` (contract).
    setospeed(unsafe { &mut *t }, speed);
    0
}

/// # Safety
/// `t` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetispeed(t: *mut termios, speed: u32) -> c_int {
    // SAFETY: `t` is a writable `struct termios` (contract).
    setispeed(unsafe { &mut *t }, speed);
    0
}

crate::unistd::alias!(
    /// # Safety
    /// `t` is writable.
    cfsetobaud => cfsetospeed(t: *mut termios, speed: u32) -> c_int
);

crate::unistd::alias!(
    /// # Safety
    /// `t` is writable.
    cfsetibaud => cfsetispeed(t: *mut termios, speed: u32) -> c_int
);

/// # Safety
/// `t` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetspeed(t: *mut termios, speed: u32) -> c_int {
    // SAFETY: `t` is a writable `struct termios` (contract).
    setspeed(unsafe { &mut *t }, speed);
    0
}

crate::unistd::alias!(
    /// # Safety
    /// `t` is writable.
    cfsetbaud => cfsetspeed(t: *mut termios, speed: u32) -> c_int
);

// The versions glibc kept for old programs (cfgetispeed@GLIBC_2.2.5 ...): the speeds are the legacy `Bnnn`
// codes of c_cflag and a speed without a code is EINVAL. rusty-libc-cabi exports them under the old version name.

/// `cfgetospeed@GLIBC_2.2.5`: the CBAUD code.
///
/// # Safety
/// `t` is readable.
pub unsafe fn cfgetospeed_old(t: *const termios) -> u32 {
    // SAFETY: `t` is a readable `struct termios` (contract).
    unsafe { &*t }.c_cflag & CBAUD
}

/// `cfgetispeed@GLIBC_2.2.5`: the CIBAUD code (shifted down).
///
/// # Safety
/// `t` is readable.
pub unsafe fn cfgetispeed_old(t: *const termios) -> u32 {
    // SAFETY: `t` is a readable `struct termios` (contract).
    (unsafe { &*t }.c_cflag >> IBSHIFT) & CBAUD
}

/// `cfsetospeed@GLIBC_2.2.5`: `speed` is a `Bnnn` code.
///
/// # Safety
/// `t` is writable.
pub unsafe fn cfsetospeed_old(t: *mut termios, speed: u32) -> c_int {
    let Some(real) = old_code_speed(speed) else { return bad_code() };
    // SAFETY: `t` is a writable `struct termios` (contract); it is touched only for a valid code, as in glibc.
    apply_ospeed_old(unsafe { &mut *t }, real, speed);
    0
}

/// `cfsetispeed@GLIBC_2.2.5`.
///
/// # Safety
/// `t` is writable.
pub unsafe fn cfsetispeed_old(t: *mut termios, speed: u32) -> c_int {
    let Some(real) = old_code_speed(speed) else { return bad_code() };
    // SAFETY: `t` is a writable `struct termios` (contract); it is touched only for a valid code, as in glibc.
    apply_ispeed_old(unsafe { &mut *t }, real, speed);
    0
}

/// `cfsetspeed@GLIBC_2.2.5`.
///
/// # Safety
/// `t` is writable.
pub unsafe fn cfsetspeed_old(t: *mut termios, speed: u32) -> c_int {
    let Some(real) = old_code_speed(speed) else { return bad_code() };
    // SAFETY: `t` is a writable `struct termios` (contract); it is touched only for a valid code, as in glibc.
    apply_speed_old(unsafe { &mut *t }, real, speed);
    0
}

/// # Safety
/// `t` is writable.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfmakeraw(t: *mut termios) {
    // SAFETY: `t` is a writable `struct termios` (contract).
    makeraw(unsafe { &mut *t })
}

/// A terminal ioctl whose third argument is an integer (TCSBRK, TCXONC, TCFLSH, TCSBRKP, TIOCSCTTY): the raw result.
#[inline]
fn tty_ioctl_int(fd: c_int, request: usize, arg: usize) -> usize {
    // SAFETY: these requests take the argument as a number; the kernel dereferences nothing.
    unsafe { syscall3(SYS_IOCTL, fd as usize, request, arg) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcdrain(fd: c_int) -> c_int {
    // a cancellation point
    // SAFETY: TCSBRK takes its argument (1: no break, wait for output to drain) as a number.
    unsafe { sci(rusty_libc_core::tls::syscall_cp(SYS_IOCTL, fd as usize, TCSBRK, 1, 0, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcflow(fd: c_int, action: c_int) -> c_int {
    sci(tty_ioctl_int(fd, TCXONC, action as isize as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcflush(fd: c_int, queue: c_int) -> c_int {
    sci(tty_ioctl_int(fd, TCFLSH, queue as isize as usize))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcsendbreak(fd: c_int, duration: c_int) -> c_int {
    if duration <= 0 {
        sci(tty_ioctl_int(fd, TCSBRK, 0))
    } else {
        sci(tty_ioctl_int(fd, TCSBRKP, ((duration as i64 + 99) / 100) as usize))
    }
}

/// Foreground process group of the terminal, or -1.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let (r, pgrp) = crate::kernel::ioctl_get_int(fd as usize, TIOCGPGRP);
    let r = sci(r);
    if r < 0 { r } else { pgrp }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    sci(crate::kernel::ioctl_set_int(fd as usize, TIOCSPGRP, &pgrp))
}

/// Session id of the terminal's session. Uses TIOCGSID, falling back (when the kernel says
/// EINVAL) to the session of the foreground group, like glibc.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcgetsid(fd: c_int) -> c_int {
    let serrno = errno::get();
    let (r, sid) = crate::kernel::ioctl_get_int(fd as usize, TIOCGSID);
    if sci(r) >= 0 {
        return sid;
    }
    if errno::get() != EINVAL {
        return -1;
    }
    errno::set(serrno);
    let pgrp = tcgetpgrp(fd);
    if pgrp == -1 {
        return -1;
    }
    let s = sci(plain!(SYS_GETSID, pgrp as usize));
    if s == -1 && errno::get() == ESRCH {
        errno::set(ENOTTY);
    }
    s
}

// ---------------------------------------------------------------- pty helpers

/// Open a pseudo-terminal pair: master in `*amaster`, slave in `*aslave`, slave name in `name`
/// (at least 4096 bytes if used, like glibc's PATH_MAX buffer). `termp` and `winp` may be NULL.
///
/// # Safety
/// All pointers valid as for openpty(3).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openpty(amaster: *mut c_int, aslave: *mut c_int, name: *mut c_char, termp: *const termios, winp: *const winsize) -> c_int {
    let ptmx = rusty_libc_stdlib::misc::getpt();
    if ptmx == -1 {
        return -1;
    }
    let mut buf = [0 as c_char; 4096];
    let mut slave: c_int = -1;
    let ok = 'body: {
        if rusty_libc_stdlib::misc::grantpt(ptmx) != 0 || rusty_libc_stdlib::misc::unlockpt(ptmx) != 0 {
            break 'body false;
        }
        slave = sci(tty_ioctl_int(ptmx, TIOCGPTPEER, O_RDWR | O_NOCTTY));
        if slave == -1 {
            // SAFETY: the local `buf` has room for `buf.len()` bytes.
            if unsafe { rusty_libc_stdlib::misc::ptsname_r(ptmx, buf.as_mut_ptr(), buf.len()) } != 0 {
                break 'body false;
            }
            // SAFETY: ptsname_r stored a NUL-terminated name in `buf`, which the kernel only reads.
            slave = sci(unsafe { rusty_libc_core::syscall::sys_open(buf.as_ptr() as usize, O_RDWR | O_NOCTTY, 0) });
            if slave == -1 {
                break 'body false;
            }
        }
        if !termp.is_null() {
            // SAFETY: `termp` is not NULL, so it is a readable `struct termios` (contract).
            let _ = unsafe { tcsetattr(slave, 2, termp) };
        }
        if !winp.is_null() {
            // SAFETY: `winp` is the caller's `struct winsize`, passed to the kernel untouched (it checks it: EFAULT).
            unsafe { syscall3(SYS_IOCTL, slave as usize, TIOCSWINSZ, winp as usize) };
        }
        // SAFETY: `amaster` and `aslave` are writable ints (contract).
        unsafe { amaster.write(ptmx) };
        // SAFETY: as above.
        unsafe { aslave.write(slave) };
        if !name.is_null() {
            // SAFETY: the local `buf` has room for `buf.len()` bytes.
            if buf[0] == 0 && unsafe { rusty_libc_stdlib::misc::ptsname_r(ptmx, buf.as_mut_ptr(), buf.len()) } != 0 {
                break 'body false;
            }
            // SAFETY: `buf` holds a NUL-terminated name (shorter than 4096 bytes); `name` has room for 4096 (contract).
            unsafe { rusty_libc_mem::strcpy(name.cast(), buf.as_ptr().cast()) };
        }
        true
    };
    if !ok {
        let e = errno::get();
        plain!(SYS_CLOSE, ptmx as usize);
        if slave != -1 {
            plain!(SYS_CLOSE, slave as usize);
        }
        errno::set(e);
        return -1;
    }
    0
}

/// Make `fd` the controlling terminal of a new session and the standard descriptors.
///
/// # Safety
/// `fd` is a terminal descriptor.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn login_tty(fd: c_int) -> c_int {
    plain!(SYS_SETSID, 0);
    if sci(tty_ioctl_int(fd, TIOCSCTTY, 0)) == -1 {
        return -1;
    }
    for target in 0..3usize {
        while sci(plain!(SYS_DUP2, fd as usize, target)) == -1 && errno::get() == EBUSY {}
    }
    if fd > 2 {
        plain!(SYS_CLOSE, fd as usize);
    }
    0
}

/// openpty plus fork; in the child the slave becomes stdin, stdout, stderr and the controlling
/// terminal. Returns the child's pid in the parent, 0 in the child, -1 on error.
///
/// # Safety
/// As [`openpty`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn forkpty(amaster: *mut c_int, name: *mut c_char, termp: *const termios, winp: *const winsize) -> c_int {
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: the two out-parameters are locals; `name`, `termp` and `winp` are the caller's, with openpty's contract.
    if unsafe { openpty(&mut master, &mut slave, name, termp, winp) } == -1 {
        return -1;
    }
    // fork() as the program calls it, with its atfork handlers (glibc's forkpty calls __fork)
    match crate::unistd::fork() {
        -1 => {
            let e = errno::get();
            plain!(SYS_CLOSE, master as usize);
            plain!(SYS_CLOSE, slave as usize);
            errno::set(e);
            -1
        }
        0 => {
            plain!(SYS_CLOSE, master as usize);
            // SAFETY: `slave` is the terminal openpty just opened.
            if unsafe { login_tty(slave) } != 0 {
                plain!(rusty_libc_core::syscall::SYS_EXIT_GROUP, 1);
            }
            0
        }
        pid => {
            // SAFETY: `amaster` is a writable int (contract).
            unsafe { amaster.write(master) };
            plain!(SYS_CLOSE, slave as usize);
            pid
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;
    use crate::LOCK;

    mod host {
        use core::ffi::c_int;
        // The libc crate links the speed functions to their GLIBC_2.2.5 compatibility versions
        // (speeds as legacy B-codes). The current ones are the GLIBC_2.42 versions: look those up.
        unsafe fn sym(name: &core::ffi::CStr) -> *mut core::ffi::c_void {
            let p = unsafe { libc::dlvsym(libc::RTLD_DEFAULT, name.as_ptr(), c"GLIBC_2.42".as_ptr()) };
            assert!(!p.is_null(), "{name:?}@GLIBC_2.42 not found");
            p
        }
        type Set = unsafe extern "C" fn(*mut libc::termios, u32) -> c_int;
        type Get = unsafe extern "C" fn(*const libc::termios) -> u32;
        pub unsafe fn cfsetospeed(t: *mut libc::termios, s: u32) -> c_int {
            unsafe { core::mem::transmute::<*mut core::ffi::c_void, Set>(sym(c"cfsetospeed"))(t, s) }
        }
        pub unsafe fn cfsetispeed(t: *mut libc::termios, s: u32) -> c_int {
            unsafe { core::mem::transmute::<*mut core::ffi::c_void, Set>(sym(c"cfsetispeed"))(t, s) }
        }
        pub unsafe fn cfsetspeed(t: *mut libc::termios, s: u32) -> c_int {
            unsafe { core::mem::transmute::<*mut core::ffi::c_void, Set>(sym(c"cfsetspeed"))(t, s) }
        }
        pub unsafe fn cfgetospeed(t: *const libc::termios) -> u32 {
            unsafe { core::mem::transmute::<*mut core::ffi::c_void, Get>(sym(c"cfgetospeed"))(t) }
        }
        pub unsafe fn cfgetispeed(t: *const libc::termios) -> u32 {
            unsafe { core::mem::transmute::<*mut core::ffi::c_void, Get>(sym(c"cfgetispeed"))(t) }
        }
        unsafe extern "C" {
            pub fn cfsetbaud(t: *mut libc::termios, s: u32) -> core::ffi::c_int;
            pub fn cfsetibaud(t: *mut libc::termios, s: u32) -> core::ffi::c_int;
            pub fn cfsetobaud(t: *mut libc::termios, s: u32) -> core::ffi::c_int;
            pub fn cfgetibaud(t: *const libc::termios) -> u32;
            pub fn cfgetobaud(t: *const libc::termios) -> u32;
        }
    }

    fn as_bytes<T>(t: &T) -> &[u8] {
        unsafe { core::slice::from_raw_parts(t as *const T as *const u8, core::mem::size_of::<T>()) }
    }

    /// A pty pair opened through the host: (master, slave).
    fn host_pty() -> (c_int, c_int) {
        unsafe {
            let m = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
            assert!(m >= 0);
            assert_eq!(libc::grantpt(m), 0);
            assert_eq!(libc::unlockpt(m), 0);
            let name = libc::ptsname(m);
            let s = libc::open(name, libc::O_RDWR | libc::O_NOCTTY);
            assert!(s >= 0);
            (m, s)
        }
    }

    unsafe fn host_get(fd: c_int) -> libc::termios {
        unsafe {
            let mut t: libc::termios = core::mem::zeroed();
            assert_eq!(libc::tcgetattr(fd, &mut t), 0);
            t
        }
    }

    unsafe fn our_get(fd: c_int) -> termios {
        unsafe {
            let mut t: termios = core::mem::zeroed();
            assert_eq!(tcgetattr(fd, &mut t), 0);
            t
        }
    }

    #[test]
    fn struct_sizes() {
        assert_eq!(core::mem::size_of::<termios>(), 60);
        assert_eq!(core::mem::size_of::<termios>(), core::mem::size_of::<libc::termios>());
        assert_eq!(core::mem::size_of::<Termios2>(), 44);
        assert_eq!(core::mem::size_of::<winsize>(), 8);
    }

    #[test]
    fn tcgetattr_tcsetattr_match_host_on_a_pty() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (m, s) = host_pty();
        unsafe {
            let a = our_get(s);
            let h = host_get(s);
            assert_eq!(as_bytes(&a), as_bytes(&h));
            assert_eq!(a.c_ispeed, 38400);
            // change some flags and a speed, set through ours, read through the host
            let mut t = a;
            t.c_lflag &= !(0o10 | 0o2); // ECHO, ICANON
            t.c_cc[VMIN] = 3;
            t.c_cc[VTIME] = 9;
            cfsetspeed(&mut t, 9600);
            assert_eq!(tcsetattr(s, 0, &t), 0);
            let h = host_get(s);
            let o = our_get(s);
            assert_eq!(as_bytes(&o), as_bytes(&h));
            assert_eq!(h.c_lflag & 0o12, 0);
            assert_eq!((h.c_cc[VMIN], h.c_cc[VTIME]), (3, 9));
            assert_eq!(h.c_ospeed, 9600);
            assert_eq!(cfgetospeed(&o), 9600);
            // set through the host, read through ours; split speeds and a non-standard speed
            let mut ht = h;
            host::cfsetispeed(&mut ht, 19200);
            host::cfsetospeed(&mut ht, 57600);
            assert_eq!(libc::tcsetattr(s, libc::TCSADRAIN, &ht), 0);
            let o = our_get(s);
            assert_eq!(as_bytes(&o), as_bytes(&host_get(s)));
            assert_eq!((o.c_ispeed, o.c_ospeed), (19200, 57600));
            let mut t = o;
            cfsetspeed(&mut t, 12345);
            assert_eq!(tcsetattr(s, 2, &t), 0);
            let (o, h) = (our_get(s), host_get(s));
            assert_eq!(as_bytes(&o), as_bytes(&h));
            // all three "when" values and the Rust API
            for act in 0..3 {
                assert_eq!(tcsetattr(s, act, &o), 0);
            }
            assert_eq!(tcsetattr_r(s, 1, &o), Ok(()));
            assert_eq!(tcgetattr_r(s).unwrap(), o);
            // errors
            assert_eq!(tcsetattr(s, 3, &o), -1);
            assert_eq!(errno::get(), libc::EINVAL);
            assert_eq!(libc::tcsetattr(s, 3, &h), -1);
            assert_eq!(*libc::__errno_location(), libc::EINVAL);
            let mut x: termios = core::mem::zeroed();
            assert_eq!(tcgetattr(-1, &mut x), -1);
            assert_eq!(errno::get(), libc::EBADF);
            let p = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
            assert_eq!(tcgetattr(p, &mut x), -1);
            let e = errno::get();
            let mut hx: libc::termios = core::mem::zeroed();
            assert_eq!(libc::tcgetattr(p, &mut hx), -1);
            assert_eq!(e, *libc::__errno_location());
            assert_eq!(e, libc::ENOTTY);
            libc::close(p);
            libc::close(m);
            libc::close(s);
        }
    }

    #[test]
    fn speed_functions_match_host() {
        let speeds = [
            0u32, 50, 75, 110, 134, 150, 200, 300, 600, 1200, 1800, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 500000, 576000,
            921600, 1000000, 1152000, 1500000, 2000000, 2500000, 3000000, 3500000, 4000000, 7, 12345, 76800, 5000000,
        ];
        unsafe {
            for &sp in &speeds {
                for start in [0u32, 0o10017 | (0o10017 << 16), 0o60 | 0o400 | 0o2000] {
                    let mut o: termios = core::mem::zeroed();
                    o.c_cflag = start;
                    o.c_ispeed = 111;
                    o.c_ospeed = 222;
                    let mut h: libc::termios = core::mem::zeroed();
                    h.c_cflag = start;
                    h.c_ispeed = 111;
                    h.c_ospeed = 222;
                    let (ro, rh) = (cfsetospeed(&mut o, sp), host::cfsetospeed(&mut h, sp));
                    assert_eq!(ro, rh, "cfsetospeed return for {sp}");
                    assert_eq!(as_bytes(&o), as_bytes(&h), "cfsetospeed {sp}");
                    assert_eq!(cfsetispeed(&mut o, sp / 2), host::cfsetispeed(&mut h, sp / 2));
                    assert_eq!(as_bytes(&o), as_bytes(&h), "cfsetispeed {sp}");
                    assert_eq!(cfgetispeed(&o), host::cfgetispeed(&h));
                    assert_eq!(cfgetospeed(&o), host::cfgetospeed(&h));
                    assert_eq!(cfgetibaud(&o), host::cfgetibaud(&h));
                    assert_eq!(cfgetobaud(&o), host::cfgetobaud(&h));
                    assert_eq!(cfsetspeed(&mut o, sp), host::cfsetspeed(&mut h, sp));
                    assert_eq!(as_bytes(&o), as_bytes(&h), "cfsetspeed {sp}");
                    assert_eq!(cfsetbaud(&mut o, sp / 3), host::cfsetbaud(&mut h, sp / 3));
                    assert_eq!(as_bytes(&o), as_bytes(&h), "cfsetbaud {sp}");
                    cfsetibaud(&mut o, sp);
                    host::cfsetibaud(&mut h, sp);
                    cfsetobaud(&mut o, sp / 5);
                    host::cfsetobaud(&mut h, sp / 5);
                    assert_eq!(as_bytes(&o), as_bytes(&h), "cfset{{i,o}}baud {sp}");
                }
            }
        }
    }

    #[test]
    fn cfmakeraw_matches_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (m, s) = host_pty();
        unsafe {
            let h0 = host_get(s);
            let mut h = h0;
            libc::cfmakeraw(&mut h);
            let mut o = our_get(s);
            cfmakeraw(&mut o);
            assert_eq!(as_bytes(&o), as_bytes(&h));
            // starting from all ones too
            let mut o2: termios = core::mem::zeroed();
            let mut h2: libc::termios = core::mem::zeroed();
            o2.c_iflag = !0;
            o2.c_oflag = !0;
            o2.c_cflag = !0;
            o2.c_lflag = !0;
            h2.c_iflag = !0;
            h2.c_oflag = !0;
            h2.c_cflag = !0;
            h2.c_lflag = !0;
            cfmakeraw(&mut o2);
            libc::cfmakeraw(&mut h2);
            assert_eq!(as_bytes(&o2), as_bytes(&h2));
            // applying it to the pty gives the same terminal state either way
            assert_eq!(tcsetattr(s, 0, &o), 0);
            let after = host_get(s);
            assert_eq!(after.c_lflag & (0o10 | 0o2 | 0o1 | 0o100000), 0);
            assert_eq!(after.c_cflag & 0o60, 0o60);
            let mut r = termios::default();
            makeraw(&mut r);
            assert_eq!((r.c_cc[VMIN], r.c_cc[VTIME]), (1, 0));
            libc::close(m);
            libc::close(s);
        }
    }

    #[test]
    fn flow_flush_drain_pgrp_sid_like_host() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let (m, s) = host_pty();
        unsafe {
            assert_eq!(tcdrain(s), libc::tcdrain(s));
            for q in [0, 1, 2, 3] {
                assert_eq!(tcflush(s, q), libc::tcflush(s, q), "tcflush {q}");
                assert_eq!(errno::get(), if q == 3 { libc::EINVAL } else { errno::get() });
            }
            for a in [0, 1, 2, 3, 4] {
                assert_eq!(tcflow(s, a), libc::tcflow(s, a), "tcflow {a}");
            }
            for d in [-3, 0, 1, 250] {
                let (a, ea) = (tcsendbreak(s, d), errno::get());
                let (b, eb) = (libc::tcsendbreak(s, d), *libc::__errno_location());
                assert_eq!(a, b, "tcsendbreak {d}");
                if a == -1 {
                    assert_eq!(ea, eb);
                }
            }
            // the pty is not our controlling terminal: both fail the same way
            let (a, ea) = (tcgetpgrp(s), errno::get());
            let (b, eb) = (libc::tcgetpgrp(s), *libc::__errno_location());
            assert_eq!((a, ea), (b, eb));
            let (a, ea) = (tcgetsid(s), errno::get());
            let (b, eb) = (libc::tcgetsid(s), *libc::__errno_location());
            assert_eq!((a, ea), (b, eb));
            let pg = libc::getpgrp();
            let (a, ea) = (tcsetpgrp(s, pg), errno::get());
            let (b, eb) = (libc::tcsetpgrp(s, pg), *libc::__errno_location());
            assert_eq!((a, ea), (b, eb));
            // bad descriptor
            assert_eq!(tcgetpgrp(-1), -1);
            assert_eq!(errno::get(), libc::EBADF);
            assert_eq!(tcflush(-1, 0), -1);
            assert_eq!(errno::get(), libc::EBADF);
            libc::close(m);
            libc::close(s);
        }
    }

    #[test]
    fn openpty_pair_works_and_applies_settings() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let (mut m, mut s) = (-1, -1);
            let mut name = [0 as c_char; 64];
            let mut want = {
                let (pm, ps) = host_pty();
                let t = host_get(ps);
                libc::close(pm);
                libc::close(ps);
                t
            };
            libc::cfmakeraw(&mut want);
            let ws = winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
            assert_eq!(openpty(&mut m, &mut s, name.as_mut_ptr(), (&want as *const libc::termios).cast(), &ws), 0);
            assert!(m >= 0 && s >= 0);
            // the name is the slave's /dev/pts/N and matches ptsname of the master
            assert_eq!(CStr_from(name.as_ptr()), CStr_from(libc::ptsname(m)));
            assert!(CStr_from(name.as_ptr()).starts_with("/dev/pts/"));
            // the settings were applied to the slave
            let got = host_get(s);
            assert_eq!(got.c_lflag, want.c_lflag);
            let mut w2 = [0u16; 4];
            assert_eq!(libc::ioctl(s, libc::TIOCGWINSZ, w2.as_mut_ptr()), 0);
            assert_eq!(w2[..2], [24, 80]);
            // data written to the master arrives on the slave (raw mode: no line editing)
            assert_eq!(libc::write(m, b"ping".as_ptr().cast(), 4), 4);
            let mut buf = [0u8; 8];
            assert_eq!(libc::read(s, buf.as_mut_ptr().cast(), 8), 4);
            assert_eq!(&buf[..4], b"ping");
            // slave -> master
            assert_eq!(libc::write(s, b"pong".as_ptr().cast(), 4), 4);
            assert_eq!(libc::read(m, buf.as_mut_ptr().cast(), 8), 4);
            assert_eq!(&buf[..4], b"pong");
            libc::close(m);
            libc::close(s);
            // no name, no termios, no winsize
            assert_eq!(openpty(&mut m, &mut s, core::ptr::null_mut(), core::ptr::null(), core::ptr::null()), 0);
            libc::close(m);
            libc::close(s);
        }
    }

    #[allow(non_snake_case)]
    unsafe fn CStr_from(p: *const c_char) -> String {
        unsafe { std::ffi::CStr::from_ptr(p).to_str().unwrap().to_owned() }
    }

    #[test]
    fn forkpty_child_gets_a_controlling_terminal() {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            let mut m = -1;
            let mut name = [0 as c_char; 64];
            let pid = forkpty(&mut m, name.as_mut_ptr(), core::ptr::null(), core::ptr::null());
            assert!(pid >= 0);
            if pid == 0 {
                // child: only async-signal-safe calls
                let ok = libc::isatty(0) == 1 && libc::isatty(1) == 1 && libc::isatty(2) == 1 && libc::getsid(0) == libc::getpid();
                let _ = libc::write(1, b"child says hi\n".as_ptr().cast(), 14);
                libc::_exit(if ok { 0 } else { 3 });
            }
            let mut out = Vec::new();
            let mut buf = [0u8; 64];
            loop {
                let n = libc::read(m, buf.as_mut_ptr().cast(), 64);
                if n <= 0 {
                    break; // EIO once the slave side is closed
                }
                out.extend_from_slice(&buf[..n as usize]);
            }
            let mut status = 0;
            assert_eq!(libc::waitpid(pid, &mut status, 0), pid);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0, "child checks failed");
            assert_eq!(String::from_utf8_lossy(&out), "child says hi\r\n");
            assert!(CStr_from(name.as_ptr()).starts_with("/dev/pts/"));
            libc::close(m);
        }
    }
}
