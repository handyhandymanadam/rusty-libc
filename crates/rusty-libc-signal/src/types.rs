use core::ffi::c_void;

pub type Sighandler = usize;
pub type PidT = i32;
pub type UidT = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Sigset {
    pub val: [u64; 16],
}

impl Sigset {
    pub const EMPTY: Sigset = Sigset { val: [0; 16] };
    pub const fn from_mask(m: u64) -> Sigset {
        let mut s = Sigset::EMPTY;
        s.val[0] = m;
        s
    }
    pub const fn mask(&self) -> u64 {
        self.val[0]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Sigaction {
    pub sa_handler: Sighandler,
    pub sa_mask: Sigset,
    pub sa_flags: i32,
    pub sa_restorer: usize,
}

impl Sigaction {
    pub const ZERO: Sigaction = Sigaction { sa_handler: 0, sa_mask: Sigset::EMPTY, sa_flags: 0, sa_restorer: 0 };
}

#[derive(Clone, Copy)]
#[repr(C)]
pub union Sigval {
    pub sival_int: i32,
    pub sival_ptr: *mut c_void,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Siginfo {
    pub si_signo: i32,
    pub si_errno: i32,
    pub si_code: i32,
    pub pad0: i32,
    pub fields: [u64; 14],
}

impl Siginfo {
    pub const ZERO: Siginfo = Siginfo { si_signo: 0, si_errno: 0, si_code: 0, pad0: 0, fields: [0; 14] };

    pub fn si_pid(&self) -> i32 {
        self.fields[0] as u32 as i32
    }
    pub fn si_uid(&self) -> u32 {
        (self.fields[0] >> 32) as u32
    }
    pub fn set_pid_uid(&mut self, pid: i32, uid: u32) {
        self.fields[0] = u64::from(pid as u32) | (u64::from(uid) << 32);
    }
    pub fn si_value(&self) -> Sigval {
        Sigval { sival_ptr: self.fields[1] as usize as *mut c_void }
    }
    pub fn set_value(&mut self, v: Sigval) {
        self.fields[1] = unsafe { v.sival_ptr } as usize as u64;
    }
    pub fn si_status(&self) -> i32 {
        self.fields[1] as u32 as i32
    }
    pub fn si_utime(&self) -> i64 {
        self.fields[2] as i64
    }
    pub fn si_stime(&self) -> i64 {
        self.fields[3] as i64
    }
    pub fn si_addr(&self) -> *mut c_void {
        self.fields[0] as usize as *mut c_void
    }
    pub fn si_band(&self) -> i64 {
        self.fields[0] as i64
    }
    pub fn si_fd(&self) -> i32 {
        self.fields[1] as u32 as i32
    }
    pub fn si_timerid(&self) -> i32 {
        self.fields[0] as u32 as i32
    }
    pub fn si_overrun(&self) -> i32 {
        (self.fields[0] >> 32) as u32 as i32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct StackT {
    pub ss_sp: *mut c_void,
    pub ss_flags: i32,
    pub ss_size: usize,
}

impl StackT {
    pub const ZERO: StackT = StackT { ss_sp: core::ptr::null_mut(), ss_flags: 0, ss_size: 0 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Sigstack {
    pub ss_sp: *mut c_void,
    pub ss_onstack: i32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
pub struct Sigcontext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub cs: u16,
    pub gs: u16,
    pub fs: u16,
    pub pad0: u16,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    pub fpstate: u64,
    pub reserved1: [u64; 8],
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct FpState {
    pub cwd: u16,
    pub swd: u16,
    pub ftw: u16,
    pub fop: u16,
    pub rip: u64,
    pub rdp: u64,
    pub mxcsr: u32,
    pub mxcr_mask: u32,
    pub st: [[u16; 8]; 8],
    pub xmm: [[u32; 4]; 16],
    pub reserved1: [u32; 24],
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct MContext {
    pub gregs: [i64; 23],
    pub fpregs: *mut FpState,
    pub reserved1: [u64; 8],
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct UContext {
    pub uc_flags: u64,
    pub uc_link: *mut UContext,
    pub uc_stack: StackT,
    pub uc_mcontext: MContext,
    pub uc_sigmask: Sigset,
    pub fpregs_mem: FpState,
    pub ssp: [u64; 4],
}

#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct JmpBufTag {
    pub jmpbuf: [i64; 8],
    pub mask_was_saved: i32,
    pub saved_mask: Sigset,
}

impl JmpBufTag {
    pub const ZERO: JmpBufTag = JmpBufTag { jmpbuf: [0; 8], mask_was_saved: 0, saved_mask: Sigset::EMPTY };
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<Sigset>() == 128);
    assert!(size_of::<Sigaction>() == 152);
    assert!(offset_of!(Sigaction, sa_mask) == 8);
    assert!(offset_of!(Sigaction, sa_flags) == 136);
    assert!(offset_of!(Sigaction, sa_restorer) == 144);
    assert!(size_of::<Siginfo>() == 128);
    assert!(offset_of!(Siginfo, fields) == 16);
    assert!(size_of::<StackT>() == 24);
    assert!(size_of::<Sigstack>() == 16);
    assert!(size_of::<Sigval>() == 8);
    assert!(size_of::<Sigcontext>() == 256);
    assert!(size_of::<FpState>() == 512);
    assert!(size_of::<MContext>() == 256);
    assert!(offset_of!(UContext, uc_mcontext) == 40);
    assert!(offset_of!(UContext, uc_sigmask) == 296);
    assert!(offset_of!(UContext, fpregs_mem) == 424);
    assert!(offset_of!(UContext, ssp) == 936);
    assert!(size_of::<UContext>() == 968);
    assert!(size_of::<JmpBufTag>() == 200);
    assert!(offset_of!(JmpBufTag, mask_was_saved) == 64);
    assert!(offset_of!(JmpBufTag, saved_mask) == 72);
};
