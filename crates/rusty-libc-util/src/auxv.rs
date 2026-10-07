use rusty_libc_core::{errno, syscall};

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

const HWCAP_X86_64: u64 = 1 << 1;
const HWCAP_X86_AVX512_1: u64 = 1 << 2;

static mut VEC: [u64; MAX_PAIRS * 2] = [0; MAX_PAIRS * 2];
static STATE: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

fn cpuid(leaf: u32, sub: u32) -> (u32, u32, u32, u32) {
    let r = core::arch::x86_64::__cpuid_count(leaf, sub);
    (r.eax, r.ebx, r.ecx, r.edx)
}

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

unsafe fn load() {
    use core::sync::atomic::Ordering::{Acquire, Release};
    unsafe {
        match STATE.compare_exchange(0, 1, Acquire, Acquire) {
            Ok(_) => {}
            Err(_) => {
                while STATE.load(Acquire) != 2 {
                    core::hint::spin_loop();
                }
                return;
            }
        }
        read_vector();
        STATE.store(2, Release);
    }
}

unsafe fn read_vector() {
    unsafe {
        let path = b"/proc/self/auxv\0";
        let fd = syscall::syscall3(syscall::SYS_OPEN, path.as_ptr() as usize, 0o2000000, 0);
        if syscall::check(fd).is_err() {
            return;
        }
        let base = core::ptr::addr_of_mut!(VEC) as *mut u8;
        let cap = MAX_PAIRS * 16;
        let mut got = 0usize;
        while got < cap {
            let r = syscall::syscall3(syscall::SYS_READ, fd, base.add(got) as usize, cap - got);
            match syscall::check(r) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) if e.0 == rusty_libc_core::errno::EINTR => {}
                Err(_) => break,
            }
        }
        syscall::syscall1(syscall::SYS_CLOSE, fd);
    }
}

pub fn get(kind: u64) -> Option<u64> {
    if kind == AT_HWCAP {
        return Some(hwcap());
    }
    unsafe {
        load();
        let v = core::ptr::addr_of!(VEC) as *const u64;
        for i in 0..MAX_PAIRS {
            let t = *v.add(i * 2);
            if t == AT_NULL {
                break;
            }
            if t == kind {
                return Some(*v.add(i * 2 + 1));
            }
        }
    }
    if kind == AT_HWCAP2 { Some(0) } else { None }
}

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

pub unsafe extern "C" fn getauxval(kind: u64) -> u64 {
    match get(kind) {
        Some(v) => v,
        None => {
            errno::set(ENOENT);
            0
        }
    }
}

pub unsafe fn init_vector(auxv: *const u64) {
    use core::sync::atomic::Ordering::Release;
    unsafe {
        let v = core::ptr::addr_of_mut!(VEC) as *mut u64;
        let mut n = 0;
        while n < MAX_PAIRS - 1 && *auxv.add(n * 2) != AT_NULL {
            *v.add(n * 2) = *auxv.add(n * 2);
            *v.add(n * 2 + 1) = *auxv.add(n * 2 + 1);
            n += 1;
        }
        *v.add(n * 2) = AT_NULL;
        *v.add(n * 2 + 1) = 0;
        STATE.store(2, Release);
    }
}

pub unsafe extern "C" fn __init_auxv(auxv: *const u64) {
    unsafe { init_vector(auxv) }
}

pub unsafe extern "C" fn __getauxval(kind: u64) -> u64 {
    unsafe { getauxval(kind) }
}

