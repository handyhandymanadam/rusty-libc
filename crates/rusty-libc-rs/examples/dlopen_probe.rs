//! A shared object containing rusty-libc-rs (and so rusty-libc-rs-core's startup snapshot of inherited descriptors), for
//! tests/stage5.rs `dlopen::no_snapshot_in_a_dlopened_library`: loaded with dlopen, its copy of the snapshot must not
//! be taken (the program's own descriptors are open by then and would look inherited). Built by `cargo test` as a
//! cdylib example (target/<profile>/examples/libdlopen_probe.so); not part of the library.

use std::ffi::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

static CTOR_RAN: AtomicBool = AtomicBool::new(false);

extern "C" fn ctor() {
    CTOR_RAN.store(true, Ordering::SeqCst);
}

/// This object's own .init_array entry: proves the loader ran the initialisers of the dlopen'ed object (so the
/// snapshot's entry ran too and decided not to take it).
#[used]
#[unsafe(link_section = ".init_array")]
static INIT: extern "C" fn() = ctor;

/// 1 when this object's initialisers ran.
#[unsafe(no_mangle)]
pub extern "C" fn rlrs_probe_ctor_ran() -> c_int {
    CTOR_RAN.load(Ordering::SeqCst) as c_int
}

/// 1 when this object's copy of the snapshot was taken (it must not be).
#[unsafe(no_mangle)]
pub extern "C" fn rlrs_probe_snapshot_taken() -> c_int {
    rusty_libc_rs::fd::inherited_snapshot_taken() as c_int
}

/// 1 when this object's copy counts `fd` as inherited.
#[unsafe(no_mangle)]
pub extern "C" fn rlrs_probe_was_inherited(fd: c_int) -> c_int {
    rusty_libc_rs::fd::was_inherited(fd) as c_int
}

/// The descriptor take_inherited(fd) handed out (ownership given up again, never closed here), or -1 for None.
#[unsafe(no_mangle)]
pub extern "C" fn rlrs_probe_take(fd: c_int) -> c_int {
    use std::os::fd::IntoRawFd;
    rusty_libc_rs::fd::take_inherited(fd).map_or(-1, |o| o.into_raw_fd())
}
