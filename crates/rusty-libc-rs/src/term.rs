use rustix::fd::AsFd;
use rustix::io;

pub fn set_controlling_terminal<Fd: AsFd>(fd: Fd, steal: bool) -> io::Result<()> {
    rusty_libc_rs_core::term::set_controlling_terminal(fd.as_fd().into(), steal).map_err(crate::errno)
}
