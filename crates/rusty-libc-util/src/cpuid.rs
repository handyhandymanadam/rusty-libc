use crate::auxv;
use core::arch::asm;
use core::sync::atomic::{AtomicU8, Ordering};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuidFeature {
    pub cpuid_array: [u32; 4],
    pub active_array: [u32; 4],
}

const ZERO: CpuidFeature = CpuidFeature { cpuid_array: [0; 4], active_array: [0; 4] };
const LEAVES: usize = 10;

type Masks = [[u32; 4]; LEAVES];

const ALWAYS: Masks = [
    [0x00000000, 0x00000000, 0x4ad82203, 0x17888110],
    [0x00000000, 0x218c0318, 0x1a400131, 0x00014810],
    [0x00000000, 0x00000000, 0x00200161, 0x08000000],
    [0x00000000, 0x00000000, 0x00000000, 0x00000000],
    [0x00000000, 0x00000000, 0x00000000, 0x00000000],
    [0x00000000, 0x00000200, 0x00000000, 0x00000000],
    [0x00001c00, 0x00000000, 0x00000000, 0x00000000],
    [0x00000000, 0x00000000, 0x00000000, 0x00000000],
    [0x00000000, 0x00000010, 0x00000000, 0x00000000],
    [0x00000000, 0x00000000, 0x00000000, 0x00000000],
];
const AVX_STATE: Masks = [
    [0x00000000, 0x00000000, 0x30001000, 0x00000000],
    [0x00000000, 0x00000020, 0x00000600, 0x00000000],
    [0x00000000, 0x00000000, 0x00010800, 0x00000000],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000010, 0x00000000, 0x00000000, 0x00000000],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
];
const AVX512_STATE: Masks = [
    [0x00000000; 4],
    [0x00000000, 0xdc230000, 0x00005842, 0x0080010c],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000020, 0x00000000, 0x00000000, 0x00000000],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
];
const AMX_STATE: Masks = [
    [0x00000000; 4],
    [0x00000000, 0x00000000, 0x00000000, 0x03400000],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00200000, 0x00000000, 0x00000000, 0x00000100],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
];
const XSAVE_STATE: Masks = [
    [0x00000000, 0x00000000, 0x04000000, 0x00000000],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000017, 0x00000000, 0x00000000, 0x00000000],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
    [0x00000000; 4],
];

const FSGSBASE: u32 = 1 << 0;
const PKU: u32 = 1 << 3;
const OSPKE: u32 = 1 << 4;
const KL: u32 = 1 << 23;
const RTM: u32 = 1 << 11;
const RTM_ALWAYS_ABORT: u32 = 1 << 11;
const APX_F: u32 = 1 << 21;
const AESKLE: u32 = 1 << 0;
const WIDE_KL: u32 = 1 << 2;

const HWCAP2_FSGSBASE: u64 = 2;
const XCR0_SSE: u32 = 1 << 1;
const XCR0_AVX: u32 = 1 << 2;
const XCR0_AVX512: u32 = (1 << 5) | (1 << 6) | (1 << 7);
const XCR0_AMX: u32 = (1 << 17) | (1 << 18);
const XCR0_APX: u32 = 1 << 19;
const AT_HWCAP2: u64 = 26;

fn cpuid(leaf: u32, sub: u32) -> [u32; 4] {
    let (a, b, c, d): (u32, u32, u32, u32);
    unsafe {
        asm!("mov {tmp:r}, rbx", "cpuid", "xchg {tmp:r}, rbx", tmp = out(reg) b, inout("eax") leaf => a, inout("ecx") sub => c, out("edx") d, options(nostack, preserves_flags));
    }
    [a, b, c, d]
}

fn xgetbv0() -> u32 {
    let lo: u32;
    unsafe {
        asm!("xgetbv", in("ecx") 0u32, out("eax") lo, out("edx") _, options(nostack, preserves_flags, nomem));
    }
    lo
}

fn add(active: &mut Masks, m: &Masks, t: &[CpuidFeature; LEAVES]) {
    for i in 0..LEAVES {
        for r in 0..4 {
            active[i][r] |= t[i].cpuid_array[r] & m[i][r];
        }
    }
}

fn compute() -> [CpuidFeature; LEAVES] {
    let mut t = [ZERO; LEAVES];
    let max_basic = cpuid(0, 0)[0];
    let max_ext = cpuid(0x8000_0000, 0)[0];
    const SPEC: [(u32, u32); LEAVES] = [(1, 0), (7, 0), (0x8000_0001, 0), (0xd, 1), (0x8000_0007, 0), (0x8000_0008, 0), (7, 1), (0x19, 0), (0x14, 0), (0x24, 0)];
    for (i, &(leaf, sub)) in SPEC.iter().enumerate() {
        let ok = if leaf & 0x8000_0000 != 0 { max_ext >= leaf } else { max_basic >= leaf };
        if ok {
            t[i].cpuid_array = cpuid(leaf, sub);
        }
    }
    let mut active: Masks = [[0u32; 4]; LEAVES];
    add(&mut active, &ALWAYS, &t);
    if t[1].cpuid_array[3] & RTM_ALWAYS_ABORT == 0 {
        active[1][1] |= t[1].cpuid_array[1] & RTM;
    }
    let osxsave = t[0].cpuid_array[2] & (1 << 27) != 0;
    if osxsave {
        let xcr0 = xgetbv0();
        let avx = xcr0 & (XCR0_SSE | XCR0_AVX) == (XCR0_SSE | XCR0_AVX);
        if avx {
            add(&mut active, &AVX_STATE, &t);
            if xcr0 & XCR0_AVX512 == XCR0_AVX512 && t[1].cpuid_array[1] & (1 << 16) != 0 {
                add(&mut active, &AVX512_STATE, &t);
                active[1][1] |= t[1].cpuid_array[1] & (1 << 16);
            }
        }
        if xcr0 & XCR0_AMX == XCR0_AMX {
            add(&mut active, &AMX_STATE, &t);
        }
        if xcr0 & XCR0_APX != 0 {
            active[6][3] |= t[6].cpuid_array[3] & APX_F;
        }
        add(&mut active, &XSAVE_STATE, &t);
    }
    if t[1].cpuid_array[2] & OSPKE != 0 {
        active[1][2] |= t[1].cpuid_array[2] & PKU;
    }
    if t[7].cpuid_array[1] & AESKLE != 0 {
        active[7][1] |= AESKLE;
        active[1][2] |= t[1].cpuid_array[2] & KL;
        active[7][1] |= t[7].cpuid_array[1] & WIDE_KL;
    }
    if t[1].cpuid_array[1] & FSGSBASE != 0 && auxv::get(AT_HWCAP2).unwrap_or(0) & HWCAP2_FSGSBASE != 0 {
        active[1][1] |= FSGSBASE;
    }
    for i in 0..LEAVES {
        t[i].active_array = active[i];
    }
    t
}

static STATE: AtomicU8 = AtomicU8::new(0);
static mut TABLE: [CpuidFeature; LEAVES] = [ZERO; LEAVES];

fn table() -> &'static [CpuidFeature; LEAVES] {
    loop {
        match STATE.load(Ordering::Acquire) {
            2 => break,
            0 => {
                if STATE.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                    unsafe { *core::ptr::addr_of_mut!(TABLE) = compute() };
                    STATE.store(2, Ordering::Release);
                    break;
                }
            }
            _ => core::hint::spin_loop(),
        }
    }
    unsafe { &*core::ptr::addr_of!(TABLE) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __x86_get_cpuid_feature_leaf(leaf: u32) -> *const CpuidFeature {
    if (leaf as usize) < LEAVES { &table()[leaf as usize] } else { &ZERO }
}

