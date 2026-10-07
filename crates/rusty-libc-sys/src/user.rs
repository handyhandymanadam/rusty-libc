use core::mem::{offset_of, size_of};

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UserRegsStruct {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserFpregsStruct {
    pub cwd: u16,
    pub swd: u16,
    pub ftw: u16,
    pub fop: u16,
    pub rip: u64,
    pub rdp: u64,
    pub mxcsr: u32,
    pub mxcr_mask: u32,
    pub st_space: [u32; 32],
    pub xmm_space: [u32; 64],
    pub padding: [u32; 24],
}

impl Default for UserFpregsStruct {
    fn default() -> Self {
        UserFpregsStruct { cwd: 0, swd: 0, ftw: 0, fop: 0, rip: 0, rdp: 0, mxcsr: 0, mxcr_mask: 0, st_space: [0; 32], xmm_space: [0; 64], padding: [0; 24] }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct User {
    pub regs: UserRegsStruct,
    pub u_fpvalid: i32,
    pub i387: UserFpregsStruct,
    pub u_tsize: u64,
    pub u_dsize: u64,
    pub u_ssize: u64,
    pub start_code: u64,
    pub start_stack: u64,
    pub signal: i64,
    pub reserved: i32,
    pub u_ar0: u64,
    pub u_fpstate: u64,
    pub magic: u64,
    pub u_comm: [u8; 32],
    pub u_debugreg: [u64; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ElfSiginfo {
    pub si_signo: i32,
    pub si_code: i32,
    pub si_errno: i32,
}

pub const ELF_NGREG: usize = size_of::<UserRegsStruct>() / size_of::<u64>();
pub type ElfGregset = [u64; ELF_NGREG];

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ElfPrstatus {
    pub pr_info: ElfSiginfo,
    pub pr_cursig: i16,
    pub pr_sigpend: u64,
    pub pr_sighold: u64,
    pub pr_pid: i32,
    pub pr_ppid: i32,
    pub pr_pgrp: i32,
    pub pr_sid: i32,
    pub pr_utime: Timeval,
    pub pr_stime: Timeval,
    pub pr_cutime: Timeval,
    pub pr_cstime: Timeval,
    pub pr_reg: ElfGregset,
    pub pr_fpvalid: i32,
}

pub const ELF_PRARGSZ: usize = 80;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ElfPrpsinfo {
    pub pr_state: i8,
    pub pr_sname: i8,
    pub pr_zomb: i8,
    pub pr_nice: i8,
    pub pr_flag: u64,
    pub pr_uid: u32,
    pub pr_gid: u32,
    pub pr_pid: i32,
    pub pr_ppid: i32,
    pub pr_pgrp: i32,
    pub pr_sid: i32,
    pub pr_fname: [u8; 16],
    pub pr_psargs: [u8; ELF_PRARGSZ],
}

impl Default for ElfPrpsinfo {
    fn default() -> Self {
        ElfPrpsinfo { pr_state: 0, pr_sname: 0, pr_zomb: 0, pr_nice: 0, pr_flag: 0, pr_uid: 0, pr_gid: 0, pr_pid: 0, pr_ppid: 0, pr_pgrp: 0, pr_sid: 0, pr_fname: [0; 16], pr_psargs: [0; ELF_PRARGSZ] }
    }
}

const _: () = {
    assert!(size_of::<UserRegsStruct>() == 216);
    assert!(offset_of!(UserRegsStruct, rip) == 128);
    assert!(offset_of!(UserRegsStruct, fs_base) == 168);
    assert!(size_of::<UserFpregsStruct>() == 512);
    assert!(offset_of!(UserFpregsStruct, mxcsr) == 24);
    assert!(offset_of!(UserFpregsStruct, xmm_space) == 160);
    assert!(size_of::<User>() == 912);
    assert!(offset_of!(User, i387) == 224);
    assert!(offset_of!(User, u_ar0) == 792);
    assert!(offset_of!(User, magic) == 808);
    assert!(offset_of!(User, u_comm) == 816);
    assert!(offset_of!(User, u_debugreg) == 848);
    assert!(ELF_NGREG == 27);
    assert!(size_of::<ElfSiginfo>() == 12);
    assert!(size_of::<ElfPrstatus>() == 336);
    assert!(offset_of!(ElfPrstatus, pr_pid) == 32);
    assert!(offset_of!(ElfPrstatus, pr_utime) == 48);
    assert!(offset_of!(ElfPrstatus, pr_reg) == 112);
    assert!(offset_of!(ElfPrstatus, pr_fpvalid) == 328);
    assert!(size_of::<ElfPrpsinfo>() == 136);
    assert!(offset_of!(ElfPrpsinfo, pr_flag) == 8);
    assert!(offset_of!(ElfPrpsinfo, pr_uid) == 16);
    assert!(offset_of!(ElfPrpsinfo, pr_pid) == 24);
    assert!(offset_of!(ElfPrpsinfo, pr_fname) == 40);
    assert!(offset_of!(ElfPrpsinfo, pr_psargs) == 56);
};

