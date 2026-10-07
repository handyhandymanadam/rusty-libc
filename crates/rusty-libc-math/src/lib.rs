#![no_std]
#![feature(f128)]
#![feature(core_float_math)]
#![allow(clippy::missing_safety_doc)]

pub(crate) const SVID: bool = cfg!(feature = "svid");

pub mod exp;
pub mod trig;
pub mod rounding;
pub mod classify;
pub mod fenv;
pub mod special;
pub mod complex;

pub mod longdouble;
pub mod quad;
