#![allow(non_snake_case)]

mod auxv;
mod ctype;
mod dirent;
mod err;
mod errno;
mod fcntl;
mod fnmatch;
mod getopt_ext;
mod glob;
mod grp;
mod iconv;
mod libgen;
mod malloc;
mod poll;
mod pwd;
mod sched;
mod search;
mod shadow;
mod stdio;
mod stdio_ext;
mod stdlib;
mod strings;
mod string;
mod sys_acct;
mod sys_epoll;
mod sys_eventfd;
mod sys_fanotify;
mod sys_file;
mod sys_inotify;
mod sys_ioctl;
mod sys_mman;
mod sys_mount;
mod sys_personality;
mod sys_pidfd;
mod sys_prctl;
mod sys_ptrace;
mod sys_quota;
mod sys_random;
mod sys_reboot;
mod sys_resource;
mod sys_select;
mod sys_signalfd;
mod sys_stat;
mod sys_statfs;
mod sys_statvfs;
mod sys_swap;
mod sys_syscall;
mod sys_sysmacros;
mod sys_timerfd;
mod sys_timex;
mod sys_ttydefaults;
mod sys_uio;
mod sys_utsname;
mod sys_wait;
mod sys_xattr;
mod systime;
mod termios;
mod time;
mod timeb;
mod types;
mod uchar;
mod ulimit;
mod unistd;
mod utime;
mod wchar;
mod wctype;

use crate::model::Item;

pub struct Text {
    pub header: Option<(&'static [Item], bool)>,
    pub after_includes: Option<(&'static [Item], bool)>,
    pub trailer: Option<(&'static [Item], bool)>,
}

pub static ALL: &[(&str, Text)] = &[
    ("auxv", Text { header: None, after_includes: Some((auxv::AFTER_INCLUDES, auxv::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("ctype", Text { header: None, after_includes: Some((ctype::AFTER_INCLUDES, ctype::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("dirent", Text { header: None, after_includes: Some((dirent::AFTER_INCLUDES, dirent::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("err", Text { header: None, after_includes: Some((err::AFTER_INCLUDES, err::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("errno", Text { header: None, after_includes: Some((errno::AFTER_INCLUDES, errno::AFTER_INCLUDES_CHOMP)), trailer: Some((errno::TRAILER, errno::TRAILER_CHOMP)) }),
    ("fcntl", Text { header: None, after_includes: Some((fcntl::AFTER_INCLUDES, fcntl::AFTER_INCLUDES_CHOMP)), trailer: Some((fcntl::TRAILER, fcntl::TRAILER_CHOMP)) }),
    ("fnmatch", Text { header: None, after_includes: Some((fnmatch::AFTER_INCLUDES, fnmatch::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("getopt_ext", Text { header: None, after_includes: Some((getopt_ext::AFTER_INCLUDES, getopt_ext::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("glob", Text { header: None, after_includes: Some((glob::AFTER_INCLUDES, glob::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("grp", Text { header: None, after_includes: Some((grp::AFTER_INCLUDES, grp::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("iconv", Text { header: None, after_includes: Some((iconv::AFTER_INCLUDES, iconv::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("libgen", Text { header: None, after_includes: Some((libgen::AFTER_INCLUDES, libgen::AFTER_INCLUDES_CHOMP)), trailer: Some((libgen::TRAILER, libgen::TRAILER_CHOMP)) }),
    ("malloc", Text { header: None, after_includes: Some((malloc::AFTER_INCLUDES, malloc::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("poll", Text { header: None, after_includes: Some((poll::AFTER_INCLUDES, poll::AFTER_INCLUDES_CHOMP)), trailer: Some((poll::TRAILER, poll::TRAILER_CHOMP)) }),
    ("pwd", Text { header: None, after_includes: Some((pwd::AFTER_INCLUDES, pwd::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sched", Text { header: None, after_includes: Some((sched::AFTER_INCLUDES, sched::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("search", Text { header: None, after_includes: Some((search::AFTER_INCLUDES, search::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("shadow", Text { header: None, after_includes: Some((shadow::AFTER_INCLUDES, shadow::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("stdio", Text { header: None, after_includes: Some((stdio::AFTER_INCLUDES, stdio::AFTER_INCLUDES_CHOMP)), trailer: Some((stdio::TRAILER, stdio::TRAILER_CHOMP)) }),
    ("stdio_ext", Text { header: None, after_includes: Some((stdio_ext::AFTER_INCLUDES, stdio_ext::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("stdlib", Text { header: None, after_includes: Some((stdlib::AFTER_INCLUDES, stdlib::AFTER_INCLUDES_CHOMP)), trailer: Some((stdlib::TRAILER, stdlib::TRAILER_CHOMP)) }),
    ("string", Text { header: None, after_includes: Some((string::AFTER_INCLUDES, string::AFTER_INCLUDES_CHOMP)), trailer: Some((string::TRAILER, string::TRAILER_CHOMP)) }),
    ("strings", Text { header: None, after_includes: Some((strings::AFTER_INCLUDES, strings::AFTER_INCLUDES_CHOMP)), trailer: Some((strings::TRAILER, strings::TRAILER_CHOMP)) }),
    ("sys_acct", Text { header: None, after_includes: Some((sys_acct::AFTER_INCLUDES, sys_acct::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_epoll", Text { header: None, after_includes: Some((sys_epoll::AFTER_INCLUDES, sys_epoll::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_eventfd", Text { header: None, after_includes: Some((sys_eventfd::AFTER_INCLUDES, sys_eventfd::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_fanotify", Text { header: None, after_includes: Some((sys_fanotify::AFTER_INCLUDES, sys_fanotify::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_file", Text { header: None, after_includes: Some((sys_file::AFTER_INCLUDES, sys_file::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_inotify", Text { header: None, after_includes: Some((sys_inotify::AFTER_INCLUDES, sys_inotify::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_ioctl", Text { header: None, after_includes: Some((sys_ioctl::AFTER_INCLUDES, sys_ioctl::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_mman", Text { header: None, after_includes: Some((sys_mman::AFTER_INCLUDES, sys_mman::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_mount", Text { header: None, after_includes: Some((sys_mount::AFTER_INCLUDES, sys_mount::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_personality", Text { header: None, after_includes: Some((sys_personality::AFTER_INCLUDES, sys_personality::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_pidfd", Text { header: None, after_includes: Some((sys_pidfd::AFTER_INCLUDES, sys_pidfd::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_prctl", Text { header: None, after_includes: Some((sys_prctl::AFTER_INCLUDES, sys_prctl::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_ptrace", Text { header: None, after_includes: Some((sys_ptrace::AFTER_INCLUDES, sys_ptrace::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_quota", Text { header: None, after_includes: Some((sys_quota::AFTER_INCLUDES, sys_quota::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_random", Text { header: None, after_includes: Some((sys_random::AFTER_INCLUDES, sys_random::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_reboot", Text { header: None, after_includes: Some((sys_reboot::AFTER_INCLUDES, sys_reboot::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_resource", Text { header: None, after_includes: Some((sys_resource::AFTER_INCLUDES, sys_resource::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_select", Text { header: None, after_includes: Some((sys_select::AFTER_INCLUDES, sys_select::AFTER_INCLUDES_CHOMP)), trailer: Some((sys_select::TRAILER, sys_select::TRAILER_CHOMP)) }),
    ("sys_signalfd", Text { header: None, after_includes: Some((sys_signalfd::AFTER_INCLUDES, sys_signalfd::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_stat", Text { header: None, after_includes: Some((sys_stat::AFTER_INCLUDES, sys_stat::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_statfs", Text { header: None, after_includes: Some((sys_statfs::AFTER_INCLUDES, sys_statfs::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_statvfs", Text { header: None, after_includes: Some((sys_statvfs::AFTER_INCLUDES, sys_statvfs::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_swap", Text { header: None, after_includes: Some((sys_swap::AFTER_INCLUDES, sys_swap::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_syscall", Text { header: None, after_includes: Some((sys_syscall::AFTER_INCLUDES, sys_syscall::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_sysmacros", Text { header: None, after_includes: Some((sys_sysmacros::AFTER_INCLUDES, sys_sysmacros::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_timerfd", Text { header: None, after_includes: Some((sys_timerfd::AFTER_INCLUDES, sys_timerfd::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_timex", Text { header: None, after_includes: Some((sys_timex::AFTER_INCLUDES, sys_timex::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_ttydefaults", Text { header: None, after_includes: Some((sys_ttydefaults::AFTER_INCLUDES, sys_ttydefaults::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_uio", Text { header: None, after_includes: Some((sys_uio::AFTER_INCLUDES, sys_uio::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_utsname", Text { header: None, after_includes: Some((sys_utsname::AFTER_INCLUDES, sys_utsname::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_wait", Text { header: None, after_includes: Some((sys_wait::AFTER_INCLUDES, sys_wait::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("sys_xattr", Text { header: None, after_includes: Some((sys_xattr::AFTER_INCLUDES, sys_xattr::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("systime", Text { header: None, after_includes: Some((systime::AFTER_INCLUDES, systime::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("termios", Text { header: None, after_includes: Some((termios::AFTER_INCLUDES, termios::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("time", Text { header: None, after_includes: Some((time::AFTER_INCLUDES, time::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("timeb", Text { header: None, after_includes: Some((timeb::AFTER_INCLUDES, timeb::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("types", Text { header: None, after_includes: Some((types::AFTER_INCLUDES, types::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("uchar", Text { header: None, after_includes: Some((uchar::AFTER_INCLUDES, uchar::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("ulimit", Text { header: None, after_includes: Some((ulimit::AFTER_INCLUDES, ulimit::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("unistd", Text { header: None, after_includes: Some((unistd::AFTER_INCLUDES, unistd::AFTER_INCLUDES_CHOMP)), trailer: Some((unistd::TRAILER, unistd::TRAILER_CHOMP)) }),
    ("utime", Text { header: None, after_includes: Some((utime::AFTER_INCLUDES, utime::AFTER_INCLUDES_CHOMP)), trailer: None }),
    ("wchar", Text { header: None, after_includes: Some((wchar::AFTER_INCLUDES, wchar::AFTER_INCLUDES_CHOMP)), trailer: Some((wchar::TRAILER, wchar::TRAILER_CHOMP)) }),
    ("wctype", Text { header: None, after_includes: Some((wctype::AFTER_INCLUDES, wctype::AFTER_INCLUDES_CHOMP)), trailer: None }),
];

pub fn lookup(config: &str) -> Option<&'static Text> {
    ALL.iter().find(|(n, _)| *n == config).map(|(_, t)| t)
}
