//! sys/auxv.h: `getauxval`.
//!
//! The startup code does not keep the kernel's auxiliary vector, so it is read lazily from
//! `/proc/self/auxv` and cached. Like glibc on x86-64, `AT_HWCAP` does not return the kernel's
//! value but glibc's own word (`HWCAP_X86_64`, plus `HWCAP_X86_AVX512_1` on Intel parts with
//! AVX-512 BW, DQ, VL and CD but not ER; rule read from glibc's sysdeps/x86/cpu-features.c).
//! Unknown types set `errno` to `ENOENT` and return 0.
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_core::{errno, unistd};

pub const AT_NULL: u64 = 0;
pub const AT_IGNORE: u64 = 1;
pub const AT_EXECFD: u64 = 2;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_NOTELF: u64 = 10;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_BASE_PLATFORM: u64 = 24;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_RSEQ_FEATURE_SIZE: u64 = 27;
pub const AT_RSEQ_ALIGN: u64 = 28;
pub const AT_HWCAP3: u64 = 29;
pub const AT_HWCAP4: u64 = 30;
pub const AT_EXECFN: u64 = 31;
pub const AT_SYSINFO: u64 = 32;
pub const AT_SYSINFO_EHDR: u64 = 33;
pub const AT_MINSIGSTKSZ: u64 = 51;

const ENOENT: i32 = 2;
const MAX_PAIRS: usize = 64;

/// glibc's `HWCAP_X86_64` and `HWCAP_X86_AVX512_1`.
const HWCAP_X86_64: u64 = 1 << 1;
const HWCAP_X86_AVX512_1: u64 = 1 << 2;

/// The (type, value) pairs, ended by `AT_NULL`. Rule: written only by the one thread that moved `STATE` from 0 to 1 (or by
/// `init_vector` at start-up, before any other thread exists), before it stores 2 with Release; read only after a load of
/// `STATE` that saw 2 with Acquire. So no access races with a write.
static VEC: SyncCell<[u64; MAX_PAIRS * 2]> = SyncCell::new([0; MAX_PAIRS * 2]);
/// 0 = not read yet, 1 = being read by some thread, 2 = done.
static STATE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    (r.eax, r.ebx, r.ecx, r.edx)
}

/// glibc's computed `dl_hwcap` for x86-64.
fn hwcap() -> u64 {
    let mut hw = HWCAP_X86_64;
    let (max, b, c, d) = cpuid(0, 0);
    let intel = b == u32::from_le_bytes(*b"Genu") && d == u32::from_le_bytes(*b"ineI") && c == u32::from_le_bytes(*b"ntel");
    if intel && max >= 7 {
        let (_, ebx, _, _) = cpuid(7, 0);
        let (_, _, ecx1, _) = cpuid(1, 0);
        let osxsave = ecx1 & (1 << 27) != 0;
        let mut zmm_ok = false;
        if osxsave {
            let (lo, _hi): (u32, u32);
            // SAFETY: OSXSAVE is set, so xgetbv with ecx = 0 is available; it only reads XCR0 into eax:edx.
            unsafe { core::arch::asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") _hi, options(nomem, nostack)) };
            zmm_ok = lo & 0xe6 == 0xe6;
        }
        let cd = ebx & (1 << 28) != 0;
        let er = ebx & (1 << 27) != 0;
        let bw = ebx & (1 << 30) != 0;
        let dq = ebx & (1 << 17) != 0;
        let vl = ebx & (1 << 31) != 0;
        if zmm_ok && cd && !er && bw && dq && vl {
            hw |= HWCAP_X86_AVX512_1;
        }
    }
    hw
}

/// Make sure the vector is loaded (by this thread or another) before returning; afterwards `STATE` is 2.
fn load() {
    use core::sync::atomic::Ordering::{Acquire, Release};
    match STATE.compare_exchange(0, 1, Acquire, Acquire) {
        Ok(_) => {}
        Err(_) => {
            // another thread is reading (or has read) the vector: wait for it
            while STATE.load(Acquire) != 2 {
                core::hint::spin_loop();
            }
            return;
        }
    }
    let mut raw = [0u8; MAX_PAIRS * 16];
    let got = read_vector(&mut raw);
    // SAFETY: this thread moved STATE from 0 to 1, so it is the only writer and no reader looks before the store of 2 below
    // (the rule on VEC).
    let v = unsafe { &mut *VEC.as_ptr() };
    for (i, w) in raw[..got].as_chunks::<8>().0.iter().enumerate() {
        v[i] = u64::from_ne_bytes(*w);
    }
    STATE.store(2, Release);
}

/// Read `/proc/self/auxv` into `raw`; how many bytes arrived (0 when it cannot be opened).
fn read_vector(raw: &mut [u8]) -> usize {
    let Ok(fd) = crate::cmem::open(c"/proc/self/auxv", 0o2000000, 0) else { return 0 }; // O_RDONLY|O_CLOEXEC
    let mut got = 0usize;
    while got < raw.len() {
        match unistd::read_nocancel(fd, &mut raw[got..]) {
            Ok(0) => break,
            Ok(n) => got += n,
            Err(e) if e.0 == rusty_libc_core::errno::EINTR => {}
            Err(_) => break,
        }
    }
    let _ = unistd::close(fd);
    got
}

/// The loaded vector (loads it first).
fn vector() -> &'static [u64; MAX_PAIRS * 2] {
    load();
    // SAFETY: STATE is 2 (load returned after seeing it with Acquire, or after storing it), so VEC is not written any more
    // except by a later `init_vector`, which only start-up code and single-threaded tests call.
    unsafe { &*VEC.as_ptr() }
}

/// The value of auxiliary vector entry `kind`, or `None` when the kernel did not supply it.
pub fn get(kind: u64) -> Option<u64> {
    if kind == AT_HWCAP {
        return Some(hwcap());
    }
    for pair in vector().as_chunks::<2>().0 {
        if pair[0] == AT_NULL {
            break;
        }
        if pair[0] == kind {
            return Some(pair[1]);
        }
    }
    if kind == AT_HWCAP2 { Some(0) } else { None }
}

// The C names are defined in assembly, in one object, so that a program that uses `getauxval` also
// gets `__init_auxv` (which the startup code references weakly: a weak reference does not pull an
// archive member out of libc.a, and the compiler may put the two Rust functions in different
// objects).
#[cfg(feature = "export")]
core::arch::global_asm!(
    ".text",
    ".globl getauxval",
    ".globl __getauxval",
    ".globl __init_auxv",
    ".type getauxval, @function",
    ".type __getauxval, @function",
    ".type __init_auxv, @function",
    "getauxval:",
    "__getauxval:",
    "    jmp {get}",
    "__init_auxv:",
    "    jmp {init}",
    get = sym getauxval,
    init = sym __init_auxv,
);

/// # Safety
/// Always safe to call; `unsafe` only because it is a C function.
pub unsafe extern "C" fn getauxval(kind: u64) -> u64 {
    match get(kind) {
        Some(v) => v,
        None => {
            errno::set(ENOENT);
            0
        }
    }
}

/// Keep the kernel's auxiliary vector given by the startup code (the pairs after the environment's
/// terminating NULL, ended by `AT_NULL`), so `getauxval` needs no `/proc`. Call it before anything
/// asks for an entry; without it the vector is read lazily from `/proc/self/auxv`.
///
/// # Safety
/// `auxv` must point to a valid vector ended by an `AT_NULL` pair; no other thread may use `getauxval` meanwhile (the
/// start-up code calls it before any thread exists).
pub unsafe fn init_vector(auxv: *const u64) {
    use core::sync::atomic::Ordering::Release;
    let pairs = auxv.cast::<[u64; 2]>();
    // SAFETY: single-threaded (caller's contract), so this is the only access to VEC.
    let v = unsafe { &mut *VEC.as_ptr() };
    let mut n = 0;
    while n < MAX_PAIRS - 1 {
        // SAFETY: the vector is valid up to and including its AT_NULL pair (caller's contract), and the loop stops there,
        // so pair `n` is readable.
        let pair = unsafe { *pairs.wrapping_add(n) };
        if pair[0] == AT_NULL {
            break;
        }
        v[n * 2] = pair[0];
        v[n * 2 + 1] = pair[1];
        n += 1;
    }
    v[n * 2] = AT_NULL;
    v[n * 2 + 1] = 0;
    STATE.store(2, Release);
}

/// C name of [`init_vector`] for the startup code (rusty-libc-core's `_start` calls it with the address
/// just past `environ`'s NULL terminator).
///
/// # Safety
/// As `init_vector`.
pub unsafe extern "C" fn __init_auxv(auxv: *const u64) {
    // SAFETY: forwarded contract.
    unsafe { init_vector(auxv) }
}

/// Internal name of `getauxval` (glibc exports both; in the C runtime it is the same code).
///
/// # Safety
/// As `getauxval`.
pub unsafe extern "C" fn __getauxval(kind: u64) -> u64 {
    // SAFETY: no requirements.
    unsafe { getauxval(kind) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    unsafe extern "C" {
        fn getauxval(t: u64) -> u64;
        fn __errno_location() -> *mut i32;
    }

    #[test]
    fn matches_host() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        for t in 0..80u64 {
            unsafe {
                *__errno_location() = 0;
                let h = getauxval(t);
                let he = *__errno_location();
                errno::set(0);
                let o = super::getauxval(t);
                assert_eq!((o, errno::get()), (h, he), "type {t}");
            }
        }
    }

    #[test]
    fn rust_api() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(get(AT_PAGESZ), Some(4096));
        assert_eq!(get(9999), None);
        assert!(get(AT_RANDOM).unwrap() != 0);
    }

    #[test]
    fn startup_vector_is_used() {
        let _g = crate::LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let fake: [u64; 8] = [AT_PAGESZ, 65536, AT_CLKTCK, 250, AT_SECURE, 1, AT_NULL, 0];
        unsafe { init_vector(fake.as_ptr()) };
        assert_eq!(get(AT_PAGESZ), Some(65536));
        assert_eq!(get(AT_SECURE), Some(1));
        assert_eq!(get(AT_RANDOM), None);
        unsafe {
            errno::set(0);
            assert_eq!(super::getauxval(AT_RANDOM), 0);
            assert_eq!(errno::get(), ENOENT);
        }
        // forget it again so the other tests read the real vector
        STATE.store(0, core::sync::atomic::Ordering::Release);
        assert_eq!(get(AT_PAGESZ), Some(4096));
    }
}
