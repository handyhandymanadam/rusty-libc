use core::ffi::c_char;
use rusty_libc_core::lock::Locked;
use rusty_libc_stdlib::rand::{RandomData, initstate_r, random_r};

struct Fry {
    init: bool,
    rdata: RandomData,
    state: [c_char; 32],
}

unsafe impl Send for Fry {}

const NULL_RDATA: RandomData = RandomData { fptr: core::ptr::null_mut(), rptr: core::ptr::null_mut(), state: core::ptr::null_mut(), rand_type: 0, rand_deg: 0, rand_sep: 0, end_ptr: core::ptr::null_mut() };
static FRY: Locked<Fry> = Locked::new(Fry { init: false, rdata: NULL_RDATA, state: [0; 32] });

pub fn strfry_bytes(s: &mut [u8]) {
    FRY.with(|f| {
        if !f.init {
            let mut ts = [0i64; 2];
            unsafe { rusty_libc_core::vdso::clock_gettime_raw(0, ts.as_mut_ptr().cast()) };
            let pid = rusty_libc_core::unistd::getpid() as u32;
            unsafe { initstate_r((ts[0] as u32) ^ pid, f.state.as_mut_ptr(), 32, &raw mut f.rdata) };
            f.init = true;
        }
        let len = s.len();
        for i in 0..len {
            let mut j: i32 = 0;
            unsafe { random_r(&raw mut f.rdata, &mut j) };
            s.swap(i, (j as usize) % len);
        }
    });
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strfry(string: *mut c_char) -> *mut c_char {
    let n = unsafe { rusty_libc_core::ffi::cstr_len(string) };
    strfry_bytes(unsafe { rusty_libc_core::ffi::bytes_mut(string.cast(), n) });
    string
}

