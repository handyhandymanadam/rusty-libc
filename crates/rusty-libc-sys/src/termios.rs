use crate::misc::sci;
use core::ffi::{c_char, c_int};
use rusty_libc_core::syscall::{SYS_IOCTL, check, syscall1, syscall2, syscall3};
use rusty_libc_core::{Errno, errno};

const SYS_DUP2: usize = 33;
const SYS_SETSID: usize = 112;
const SYS_GETSID: usize = 124;
const SYS_CLOSE: usize = 3;
const SYS_OPEN: usize = 2;

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

fn speed_to_cbaud(speed: u32) -> u32 {
    for &(s, c) in SPEEDS.iter() {
        if s == speed {
            return c;
        }
    }
    BOTHER
}

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

pub fn tcgetattr_r(fd: i32) -> Result<termios, Errno> {
    let mut k = Termios2::default();
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
    unsafe { check(syscall3(SYS_IOCTL, fd as usize, TCSETS2 + cmd as usize, &k as *const Termios2 as usize)).map(|_| ()) }
}

pub fn makeraw(t: &mut termios) {
    t.c_iflag &= !(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
    t.c_oflag &= !OPOST;
    t.c_lflag &= !(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
    t.c_cflag &= !(CSIZE | PARENB);
    t.c_cflag |= CS8;
    t.c_cc[VMIN] = 1;
    t.c_cc[VTIME] = 0;
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tcgetattr(fd: c_int, t: *mut termios) -> c_int {
    unsafe {
        match tcgetattr_r(fd) {
            Ok(v) => {
                core::ptr::write_bytes(t, 0, 1);
                (*t).c_iflag = v.c_iflag;
                (*t).c_oflag = v.c_oflag;
                (*t).c_cflag = v.c_cflag;
                (*t).c_lflag = v.c_lflag;
                (*t).c_line = v.c_line;
                (*t).c_cc = v.c_cc;
                (*t).c_ispeed = v.c_ispeed;
                (*t).c_ospeed = v.c_ospeed;
                0
            }
            Err(Errno(e)) => {
                errno::set(e);
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tcsetattr(fd: c_int, action: c_int, t: *const termios) -> c_int {
    unsafe {
        match tcsetattr_r(fd, action, &*t) {
            Ok(()) => 0,
            Err(Errno(e)) => {
                errno::set(e);
                -1
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetospeed(t: *const termios) -> u32 {
    unsafe { (*t).c_ospeed }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetispeed(t: *const termios) -> u32 {
    unsafe { (*t).c_ispeed }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetobaud(t: *const termios) -> u32 {
    unsafe { (*t).c_ospeed }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfgetibaud(t: *const termios) -> u32 {
    unsafe { (*t).c_ispeed }
}

#[cfg(all(feature = "export", not(feature = "shared")))]
mod versioned {
    use super::*;
    #[unsafe(export_name = "cfgetospeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfgetospeed_v(t: *const termios) -> u32 {
        unsafe { (*t).c_cflag & CBAUD }
    }
    #[unsafe(export_name = "cfgetispeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfgetispeed_v(t: *const termios) -> u32 {
        unsafe { ((*t).c_cflag >> IBSHIFT) & CBAUD }
    }
    #[unsafe(export_name = "cfsetospeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfsetospeed_v(t: *mut termios, speed: u32) -> c_int {
        let real = cbaud_to_speed(speed, u32::MAX);
        if real == u32::MAX {
            errno::set(EINVAL);
            return -1;
        }
        unsafe {
            (*t).c_ospeed = real;
            (*t).c_cflag &= !CBAUD;
            (*t).c_cflag |= speed;
        }
        0
    }
    #[unsafe(export_name = "cfsetispeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfsetispeed_v(t: *mut termios, speed: u32) -> c_int {
        let real = cbaud_to_speed(speed, u32::MAX);
        if real == u32::MAX {
            errno::set(EINVAL);
            return -1;
        }
        unsafe {
            (*t).c_ispeed = real;
            (*t).c_cflag &= !CIBAUD;
            (*t).c_cflag |= speed << IBSHIFT;
        }
        0
    }
    #[unsafe(export_name = "cfsetspeed@GLIBC_2.2.5")]
    pub unsafe extern "C" fn cfsetspeed_v(t: *mut termios, speed: u32) -> c_int {
        let real = cbaud_to_speed(speed, u32::MAX);
        if real == u32::MAX {
            errno::set(EINVAL);
            return -1;
        }
        unsafe {
            (*t).c_ospeed = real;
            (*t).c_ispeed = real;
            (*t).c_cflag &= !(CBAUD | CIBAUD);
            (*t).c_cflag |= speed | (speed << IBSHIFT);
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetospeed(t: *mut termios, speed: u32) -> c_int {
    unsafe {
        (*t).c_ospeed = speed;
        (*t).c_cflag &= !CBAUD;
        (*t).c_cflag |= speed_to_cbaud(speed);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetispeed(t: *mut termios, speed: u32) -> c_int {
    unsafe {
        (*t).c_ispeed = speed;
        (*t).c_cflag &= !CIBAUD;
        (*t).c_cflag |= speed_to_cbaud(speed) << IBSHIFT;
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetobaud(t: *mut termios, speed: u32) -> c_int {
    unsafe { cfsetospeed(t, speed) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetibaud(t: *mut termios, speed: u32) -> c_int {
    unsafe { cfsetispeed(t, speed) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetspeed(t: *mut termios, speed: u32) -> c_int {
    unsafe {
        let cb = speed_to_cbaud(speed);
        (*t).c_ospeed = speed;
        (*t).c_ispeed = speed;
        (*t).c_cflag &= !(CBAUD | CIBAUD);
        (*t).c_cflag |= cb | (cb << IBSHIFT);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfsetbaud(t: *mut termios, speed: u32) -> c_int {
    unsafe { cfsetspeed(t, speed) }
}

pub unsafe fn cfgetospeed_old(t: *const termios) -> u32 {
    unsafe { (*t).c_cflag & CBAUD }
}

pub unsafe fn cfgetispeed_old(t: *const termios) -> u32 {
    unsafe { ((*t).c_cflag >> IBSHIFT) & CBAUD }
}

pub unsafe fn cfsetospeed_old(t: *mut termios, speed: u32) -> c_int {
    unsafe {
        let real = cbaud_to_speed(speed, u32::MAX);
        if real == u32::MAX {
            errno::set(EINVAL);
            return -1;
        }
        (*t).c_ospeed = real;
        (*t).c_cflag &= !CBAUD;
        (*t).c_cflag |= speed;
        0
    }
}

pub unsafe fn cfsetispeed_old(t: *mut termios, speed: u32) -> c_int {
    unsafe {
        let real = cbaud_to_speed(speed, u32::MAX);
        if real == u32::MAX {
            errno::set(EINVAL);
            return -1;
        }
        (*t).c_ispeed = real;
        (*t).c_cflag &= !CIBAUD;
        (*t).c_cflag |= speed << IBSHIFT;
        0
    }
}

pub unsafe fn cfsetspeed_old(t: *mut termios, speed: u32) -> c_int {
    unsafe {
        let real = cbaud_to_speed(speed, u32::MAX);
        if real == u32::MAX {
            errno::set(EINVAL);
            return -1;
        }
        (*t).c_ospeed = real;
        (*t).c_ispeed = real;
        (*t).c_cflag &= !(CBAUD | CIBAUD);
        (*t).c_cflag |= speed | (speed << IBSHIFT);
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn cfmakeraw(t: *mut termios) {
    unsafe { makeraw(&mut *t) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcdrain(fd: c_int) -> c_int {
    unsafe { sci(rusty_libc_core::tls::syscall_cp(SYS_IOCTL, fd as usize, TCSBRK, 1, 0, 0, 0)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcflow(fd: c_int, action: c_int) -> c_int {
    unsafe { sci(syscall3(SYS_IOCTL, fd as usize, TCXONC, action as isize as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcflush(fd: c_int, queue: c_int) -> c_int {
    unsafe { sci(syscall3(SYS_IOCTL, fd as usize, TCFLSH, queue as isize as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcsendbreak(fd: c_int, duration: c_int) -> c_int {
    unsafe {
        if duration <= 0 {
            sci(syscall3(SYS_IOCTL, fd as usize, TCSBRK, 0))
        } else {
            sci(syscall3(SYS_IOCTL, fd as usize, TCSBRKP, ((duration as i64 + 99) / 100) as usize))
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcgetpgrp(fd: c_int) -> c_int {
    let mut pgrp: c_int = 0;
    unsafe {
        let r = sci(syscall3(SYS_IOCTL, fd as usize, TIOCGPGRP, &mut pgrp as *mut c_int as usize));
        if r < 0 { r } else { pgrp }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcsetpgrp(fd: c_int, pgrp: c_int) -> c_int {
    unsafe { sci(syscall3(SYS_IOCTL, fd as usize, TIOCSPGRP, &pgrp as *const c_int as usize)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn tcgetsid(fd: c_int) -> c_int {
    unsafe {
        let serrno = errno::get();
        let mut sid: c_int = 0;
        let r = sci(syscall3(SYS_IOCTL, fd as usize, TIOCGSID, &mut sid as *mut c_int as usize));
        if r >= 0 {
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
        let s = sci(syscall1(SYS_GETSID, pgrp as usize));
        if s == -1 && errno::get() == ESRCH {
            errno::set(ENOTTY);
        }
        s
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn openpty(amaster: *mut c_int, aslave: *mut c_int, name: *mut c_char, termp: *const termios, winp: *const winsize) -> c_int {
    unsafe {
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
            slave = sci(syscall3(SYS_IOCTL, ptmx as usize, TIOCGPTPEER, O_RDWR | O_NOCTTY));
            if slave == -1 {
                if rusty_libc_stdlib::misc::ptsname_r(ptmx, buf.as_mut_ptr(), buf.len()) != 0 {
                    break 'body false;
                }
                slave = sci(syscall3(SYS_OPEN, buf.as_ptr() as usize, O_RDWR | O_NOCTTY, 0));
                if slave == -1 {
                    break 'body false;
                }
            }
            if !termp.is_null() {
                let _ = tcsetattr(slave, 2, termp);
            }
            if !winp.is_null() {
                syscall3(SYS_IOCTL, slave as usize, TIOCSWINSZ, winp as usize);
            }
            *amaster = ptmx;
            *aslave = slave;
            if !name.is_null() {
                if buf[0] == 0 && rusty_libc_stdlib::misc::ptsname_r(ptmx, buf.as_mut_ptr(), buf.len()) != 0 {
                    break 'body false;
                }
                rusty_libc_mem::strcpy(name.cast(), buf.as_ptr().cast());
            }
            true
        };
        if !ok {
            let e = errno::get();
            syscall1(SYS_CLOSE, ptmx as usize);
            if slave != -1 {
                syscall1(SYS_CLOSE, slave as usize);
            }
            errno::set(e);
            return -1;
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn login_tty(fd: c_int) -> c_int {
    unsafe {
        syscall1(SYS_SETSID, 0);
        if sci(syscall3(SYS_IOCTL, fd as usize, TIOCSCTTY, 0)) == -1 {
            return -1;
        }
        for target in 0..3usize {
            while sci(syscall2(SYS_DUP2, fd as usize, target)) == -1 && errno::get() == EBUSY {}
        }
        if fd > 2 {
            syscall1(SYS_CLOSE, fd as usize);
        }
        0
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn forkpty(amaster: *mut c_int, name: *mut c_char, termp: *const termios, winp: *const winsize) -> c_int {
    unsafe {
        let mut master = -1;
        let mut slave = -1;
        if openpty(&mut master, &mut slave, name, termp, winp) == -1 {
            return -1;
        }
        match rusty_libc_core::unistd::fork() {
            Err(Errno(e)) => {
                syscall1(SYS_CLOSE, master as usize);
                syscall1(SYS_CLOSE, slave as usize);
                errno::set(e);
                -1
            }
            Ok(0) => {
                syscall1(SYS_CLOSE, master as usize);
                if login_tty(slave) != 0 {
                    rusty_libc_core::syscall::syscall1(rusty_libc_core::syscall::SYS_EXIT_GROUP, 1);
                }
                0
            }
            Ok(pid) => {
                *amaster = master;
                syscall1(SYS_CLOSE, slave as usize);
                pid
            }
        }
    }
}

