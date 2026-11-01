//! glibc's private `__gconv_transliterate`, which the gconv modules call when `//TRANSLIT` is set and a character is not
//! in their charset. The lookup is [`crate::translit::transliterate_raw`]; this file is the C entry: it hands each candidate
//! replacement to the calling module's own conversion function, as glibc's iconv/gconv_trans.c does.
use crate::gconv_abi::{
    self as abi, ENCOUNTERED_ILLEGAL_INPUT, ILLEGAL_DESCRIPTOR, ILLEGAL_INPUT, Step, StepData,
};
use crate::translit::transliterate_raw;
use core::ffi::c_int;
use core::ptr::null_mut;
use rusty_libc_core::ffi::{bytes, out};

/// `int __gconv_transliterate(struct __gconv_step *step, struct __gconv_step_data *step_data, const unsigned char
/// *inbufstart, const unsigned char **inbufp, const unsigned char *inbufend, unsigned char **outbufstart, size_t
/// *irreversible)`: transliterate the character (or longer source string) at `*inbufp`, writing the replacement at
/// `*outbufstart` through the step's own conversion function. Returns `__GCONV_OK` when the input pointer moved past the
/// replaced text, `__GCONV_EMPTY_INPUT`-style statuses of the step otherwise, `__GCONV_ILLEGAL_INPUT` when nothing fits.
///
/// # Safety
/// Called by a gconv module from inside its conversion function: `step` and `step_data` are the module's, `inbufp` points to
/// the input pointer into the UCS-4 text ending at `inbufend`, `outbufstart` to the output position, `irreversible` to the
/// count (or is NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __gconv_transliterate(
    step: *mut Step,
    step_data: *mut StepData,
    _inbufstart: *const u8,
    inbufp: *mut *const u8,
    inbufend: *const u8,
    outbufstart: *mut *mut u8,
    irreversible: *mut usize,
) -> c_int {
    // SAFETY: `step` is the calling module's step (the caller's contract).
    let Some(fct) = (unsafe { abi::step_fct(step) }) else {
        return ILLEGAL_DESCRIPTOR;
    };
    // SAFETY: `inbufp` points to the input pointer (the caller's contract).
    let at_in = unsafe { *inbufp };
    // SAFETY: the input is the text from `*inbufp` to `inbufend` (the caller's contract).
    let input = unsafe { bytes(at_in, inbufend as usize - at_in as usize) };
    // SAFETY: `outbufstart` points to the output position (the caller's contract).
    let at_out = unsafe { *outbufstart };
    let mut outptr = at_out;
    let mut attempt = |replacement: &[u32]| -> c_int {
        let mut from = replacement.as_ptr().cast::<u8>();
        let end = from.wrapping_add(4 * replacement.len());
        outptr = at_out;
        // SAFETY: the module's own function converts the replacement text into the output room at `at_out`, in the mode
        // glibc uses for this (an output position is given, no irreversible count, no flush).
        unsafe {
            fct(
                step,
                step_data,
                &mut from,
                end,
                &mut outptr,
                null_mut(),
                0,
                0,
            )
        }
    };
    let Some(done) = transliterate_raw(input, &mut attempt) else {
        // SAFETY: `step_data` is the module's data.
        unsafe { (*step_data).flags |= ENCOUNTERED_ILLEGAL_INPUT };
        return ILLEGAL_INPUT;
    };
    if done.commit {
        // SAFETY: `outbufstart` is valid (above).
        unsafe { *outbufstart = outptr };
    }
    // SAFETY: `inbufp` is valid (above); the new position is inside the input.
    unsafe { *inbufp = at_in.wrapping_add(done.consumed) };
    // SAFETY: `irreversible` is NULL or the module's counter.
    if let Some(count) = unsafe { out(irreversible) } {
        *count += done.irreversible;
    }
    done.status
}
