use core::ffi::c_char;
use rusty_libc_core::syscall::{syscall0, syscall2};
use rusty_libc_stdlib::rand::{RandomData, initstate_r, random_r};

static mut INIT: bool = false;
static mut RDATA: RandomData = RandomData { fptr: core::ptr::null_mut(), rptr: core::ptr::null_mut(), state: core::ptr::null_mut(), rand_type: 0, rand_deg: 0, rand_sep: 0, end_ptr: core::ptr::null_mut() };
static mut STATE: [c_char; 32] = [0; 32];

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn strfry(string: *mut c_char) -> *mut c_char {
    unsafe {
        let rdata = &raw mut RDATA;
        if !INIT {
            let mut ts = [0i64; 2];
            syscall2(228, 0, ts.as_mut_ptr() as usize);
            let pid = syscall0(39) as u32;
            initstate_r((ts[0] as u32) ^ pid, (&raw mut STATE) as *mut c_char, 32, rdata);
            INIT = true;
        }
        let mut len = 0usize;
        while *string.add(len) != 0 {
            len += 1;
        }
        for i in 0..len {
            let mut j: i32 = 0;
            random_r(rdata, &mut j);
            let j = (j as usize) % len;
            core::ptr::swap(string.add(i), string.add(j));
        }
        string
    }
}

