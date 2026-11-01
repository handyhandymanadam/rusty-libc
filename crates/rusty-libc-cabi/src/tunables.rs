//! `__tunable_get_val`, the entry point glibc's own programs use to read a tunable in a static program (the shared
//! library's comes from the loader).

use rusty_libc_core::tunables::{self, Ty};

/// glibc's `tunable_callback_t`: `void (*)(tunable_val_t *)`, the value being one 8-byte word.
type TunableCallback = Option<unsafe extern "C" fn(*mut u64)>;

/// glibc's `__tunable_get_val (id, valp, callback)` for a static program: store the tunable's current value at `valp` (a
/// number of the tunable's type, 4 or 8 bytes; its default when the environment did not set it; a null pointer for a string
/// tunable) and, for a tunable the environment set, call `callback` with the value.
///
/// # Safety
/// `valp` points to storage for the tunable's type (4 bytes for a 32-bit number, else 8), `callback` is null or a function
/// taking a pointer to one 64-bit value.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __tunable_get_val(id: u32, valp: *mut u8, callback: TunableCallback) {
    let i = id as usize;
    if i >= tunables::COUNT {
        return;
    }
    let def = tunables::num(i);
    let set = tunables::stored(i);
    let value = set.unwrap_or(def.def);
    let (bytes, len) = match def.ty {
        Ty::I32 => (u64::from(value as u32).to_ne_bytes(), 4),
        Ty::U64 | Ty::Size => (value.to_ne_bytes(), 8),
        Ty::Str => ([0; 8], 8),
    };
    // SAFETY: `valp` has room for the tunable's type, `len` bytes (caller's contract); `bytes` is a local array.
    unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), valp, len) };
    if let (Some(callback), Some(set)) = (callback, set) {
        let mut word = set as u64;
        // SAFETY: the caller's callback takes a pointer to one 64-bit value, which lives across the call.
        unsafe { callback(&raw mut word) };
    }
}
