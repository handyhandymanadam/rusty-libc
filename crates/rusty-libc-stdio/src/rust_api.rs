use crate::fmt::{self, Args, Kind, Sink, Val};
use crate::printf_api::BufSink;
use crate::scan::{self, PtrArgs, StrSrc};
use core::ffi::{CStr, c_int, c_void};

#[derive(Clone, Copy)]
pub enum Arg<'a> {
    Int(i64),
    Uint(u64),
    Double(f64),
    Str(&'a CStr),
    Ptr(*const c_void),
    LongDouble([u8; 16]),
    Quad(u128),
    WStr(&'a [u32]),
}

struct SliceArgs<'a, 'b> {
    args: &'a [Arg<'b>],
    next: usize,
}

impl Args for SliceArgs<'_, '_> {
    fn get(&mut self, kind: Kind, pos: Option<usize>) -> Val {
        let i = match pos {
            Some(p) => p - 1,
            None => {
                self.next += 1;
                self.next - 1
            }
        };
        match (self.args.get(i), kind) {
            (Some(Arg::Int(v)), _) => Val::I(*v as u64),
            (Some(Arg::Uint(v)), _) => Val::I(*v),
            (Some(Arg::Double(d)), _) => Val::D(*d),
            (Some(Arg::Str(s)), _) => Val::I(s.as_ptr() as usize as u64),
            (Some(Arg::Ptr(p)), _) => Val::I(*p as usize as u64),
            (Some(Arg::LongDouble(b)), _) => Val::LD(*b),
            (Some(Arg::Quad(b)), _) => Val::Q(*b),
            (Some(Arg::WStr(w)), _) => Val::I(w.as_ptr() as usize as u64),
            (None, Kind::Double) => Val::D(0.0),
            (None, _) => Val::I(0),
        }
    }
}

pub fn snprintf(buf: &mut [u8], format: &CStr, args: &[Arg]) -> c_int {
    let mut sink = BufSink::new_snprintf(buf.as_mut_ptr(), buf.len());
    let mut a = SliceArgs { args, next: 0 };
    let n = unsafe { fmt::format(&mut sink, format.as_ptr() as *const u8, &mut a) };
    unsafe { sink.finish() };
    n
}

pub fn format_to<S: Sink>(sink: &mut S, format: &CStr, args: &[Arg]) -> c_int {
    let mut a = SliceArgs { args, next: 0 };
    unsafe { fmt::format(sink, format.as_ptr() as *const u8, &mut a) }
}

struct Slots<'a>(&'a [*mut c_void], usize);

impl PtrArgs for Slots<'_> {
    fn next(&mut self, pos: usize) -> *mut c_void {
        let i = if pos == 0 {
            self.1 += 1;
            self.1 - 1
        } else {
            pos - 1
        };
        self.0.get(i).copied().unwrap_or(core::ptr::null_mut())
    }
}

pub unsafe fn sscanf(input: &CStr, format: &CStr, outs: &[*mut c_void]) -> c_int {
    unsafe {
        let mut src = StrSrc::new(input.as_ptr() as *const u8);
        scan::scan(&mut src, format.as_ptr() as *const u8, &mut Slots(outs, 0), 0)
    }
}

pub fn wformat_to<S: Sink>(sink: &mut S, format: &[u32], args: &[Arg]) -> c_int {
    if format.last() != Some(&0) {
        rusty_libc_core::errno::set(22);
        return -1;
    }
    let mut a = SliceArgs { args, next: 0 };
    unsafe { fmt::format(sink, format.as_ptr(), &mut a) }
}

pub fn wsnprintf(buf: &mut [u32], format: &[u32], args: &[Arg]) -> c_int {
    if buf.is_empty() {
        return -1;
    }
    let mut sink = crate::wprintf_api::WBufSink::new(buf.as_mut_ptr(), buf.len());
    let r = wformat_to(&mut sink, format, args);
    unsafe { sink.terminate() };
    if r >= 0 && r as usize >= buf.len() { -1 } else { r }
}

pub unsafe fn wsscanf(input: &[u32], format: &[u32], outs: &[*mut c_void]) -> c_int {
    unsafe {
        if input.last() != Some(&0) || format.last() != Some(&0) {
            return -1;
        }
        let mut src = crate::wscan_api::WStrSrc::new(input.as_ptr());
        scan::scan(&mut src, format.as_ptr(), &mut Slots(outs, 0), 0)
    }
}
