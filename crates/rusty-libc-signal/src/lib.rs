#![no_std]
#![allow(clippy::missing_safety_doc)]

pub mod action;
pub mod consts;
pub mod context;
pub mod jmp;
pub mod names;
pub mod rt;
pub mod send;
pub mod sigset;
pub mod stack;
pub mod types;
pub mod wait;

use core::ffi::c_int;

#[inline]
pub(crate) fn fail(e: i32) -> c_int {
    rusty_libc_core::errno::set(e);
    -1
}

#[inline]
pub(crate) fn finish(ret: usize) -> c_int {
    match rusty_libc_core::syscall::check(ret) {
        Ok(_) => 0,
        Err(e) => fail(e.0),
    }
}
