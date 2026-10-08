use crate::consts::EINVAL;
use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};
use rusty_libc_core::syscall::{self, syscall1, syscall3};

pub const RTLD_LAZY: c_int = 0x00001;
pub const RTLD_NOW: c_int = 0x00002;
pub const RTLD_BINDING_MASK: c_int = 0x3;
pub const RTLD_NOLOAD: c_int = 0x00004;
pub const RTLD_DEEPBIND: c_int = 0x00008;
pub const RTLD_GLOBAL: c_int = 0x00100;
pub const RTLD_LOCAL: c_int = 0;
pub const RTLD_NODELETE: c_int = 0x01000;
const SPROF: c_int = 0x40000000;

pub const RTLD_DL_SYMENT: c_int = 1;
pub const RTLD_DL_LINKMAP: c_int = 2;

pub const RTLD_DI_LMID: c_int = 1;
pub const RTLD_DI_LINKMAP: c_int = 2;
pub const RTLD_DI_CONFIGADDR: c_int = 3;
pub const RTLD_DI_SERINFO: c_int = 4;
pub const RTLD_DI_SERINFOSIZE: c_int = 5;
pub const RTLD_DI_ORIGIN: c_int = 6;
pub const RTLD_DI_PROFILENAME: c_int = 7;
pub const RTLD_DI_PROFILEOUT: c_int = 8;
pub const RTLD_DI_TLS_MODID: c_int = 9;
pub const RTLD_DI_TLS_DATA: c_int = 10;

const ENOENT_: c_int = 2;

#[repr(C)]
pub struct DlInfo {
    pub dli_fname: *const c_char,
    pub dli_fbase: *mut c_void,
    pub dli_sname: *const c_char,
    pub dli_saddr: *mut c_void,
}

#[repr(C)]
pub struct LinkMap {
    pub l_addr: u64,
    pub l_name: *const c_char,
    pub l_ld: *mut c_void,
    pub l_next: *mut LinkMap,
    pub l_prev: *mut LinkMap,
}

static mut MAIN_MAP: LinkMap = LinkMap { l_addr: 0, l_name: c"".as_ptr(), l_ld: null_mut(), l_next: null_mut(), l_prev: null_mut() };

fn main_handle() -> *mut c_void {
    (&raw mut MAIN_MAP).cast()
}

const STUB_NAMES: [&[u8]; 8] =
    [b"libc.so.6", b"libm.so.6", b"libpthread.so.0", b"libdl.so.2", b"librt.so.1", b"libutil.so.1", b"libanl.so.1", b"libresolv.so.2"];

const fn stub_map(name: &'static core::ffi::CStr) -> LinkMap {
    LinkMap { l_addr: 0, l_name: name.as_ptr(), l_ld: null_mut(), l_next: null_mut(), l_prev: null_mut() }
}

static mut STUB_MAPS: [LinkMap; 8] = [
    stub_map(c"libc.so.6"),
    stub_map(c"libm.so.6"),
    stub_map(c"libpthread.so.0"),
    stub_map(c"libdl.so.2"),
    stub_map(c"librt.so.1"),
    stub_map(c"libutil.so.1"),
    stub_map(c"libanl.so.1"),
    stub_map(c"libresolv.so.2"),
];

static STUB_OPEN: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];

fn stub_handle(i: usize) -> *mut c_void {
    (&raw mut STUB_MAPS).cast::<LinkMap>().wrapping_add(i).cast()
}

fn stub_index(handle: *mut c_void) -> Option<usize> {
    (0..STUB_NAMES.len()).find(|&i| stub_handle(i) == handle)
}

#[derive(Clone, Copy, PartialEq)]
enum State {
    None,
    Pending,
    Delivered,
}

struct DlError {
    state: State,
    errcode: c_int,
    objname: [u8; 300],
    errstring: [u8; 100],
    message: [u8; 560],
}

#[thread_local]
static mut ERR: DlError = DlError { state: State::None, errcode: 0, objname: [0; 300], errstring: [0; 100], message: [0; 560] };

fn copy_into(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
}

fn fail(objname: &[u8], errstring: &str, errcode: c_int) {
    unsafe {
        #[allow(clippy::deref_addrof)]
        let e = &mut *(&raw mut ERR);
        copy_into(&mut e.objname, objname);
        copy_into(&mut e.errstring, errstring.as_bytes());
        e.errcode = errcode;
        e.state = State::Pending;
    }
}

fn succeed() {
    unsafe {
        #[allow(clippy::deref_addrof)]
        let e = &mut *(&raw mut ERR);
        e.state = State::None;
    }
}

fn begin() {
    unsafe {
        #[allow(clippy::deref_addrof)]
        let e = &mut *(&raw mut ERR);
        if e.state == State::Pending {
            e.state = State::None;
        }
    }
}

fn argv0() -> &'static [u8] {
    let p = program_name();
    if p.is_null() { b"<main program>" } else { unsafe { CStr::from_ptr(p) }.to_bytes() }
}

#[cfg(feature = "export")]
unsafe extern "C" {
    static program_invocation_name: *const c_char;
}

#[cfg(feature = "export")]
fn program_name() -> *const c_char {
    unsafe { program_invocation_name }
}

#[cfg(not(feature = "export"))]
fn program_name() -> *const c_char {
    let addr: usize;
    unsafe {
        core::arch::asm!(
            ".weak program_invocation_name",
            "mov {0}, qword ptr [rip + program_invocation_name@GOTPCREL]",
            out(reg) addr,
            options(nostack, readonly, preserves_flags)
        );
        if addr == 0 { core::ptr::null() } else { *(addr as *const *const c_char) }
    }
}

pub(crate) fn program_name_ptr() -> *const c_char {
    program_name()
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub extern "C" fn dlerror() -> *mut c_char {
    unsafe {
        #[allow(clippy::deref_addrof)]
        let e = &mut *(&raw mut ERR);
        match e.state {
            State::None => core::ptr::null_mut(),
            State::Delivered => {
                e.state = State::None;
                core::ptr::null_mut()
            }
            State::Pending => {
                let obj = &e.objname[..e.objname.iter().position(|&c| c == 0).unwrap_or(0)];
                let txt = &e.errstring[..e.errstring.iter().position(|&c| c == 0).unwrap_or(0)];
                let mut n = 0;
                let mut put = |s: &[u8], msg: &mut [u8; 560]| {
                    for &c in s {
                        if n < 559 {
                            msg[n] = c;
                            n += 1;
                        }
                    }
                };
                put(obj, &mut e.message);
                if !obj.is_empty() {
                    put(b": ", &mut e.message);
                }
                put(txt, &mut e.message);
                if e.errcode != 0 {
                    put(b": ", &mut e.message);
                    let s: &[u8] = match rusty_libc_core::messages::error_message(e.errcode) {
                        Some(c) => c.to_bytes(),
                        None => b"Unknown error",
                    };
                    put(s, &mut e.message);
                }
                e.message[n] = 0;
                e.state = State::Delivered;
                e.message.as_mut_ptr() as *mut c_char
            }
        }
    }
}

unsafe fn cbytes<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(p as *const u8, rusty_libc_mem::strlen(p)) }
}

unsafe fn open_impl(file: *const c_char, mode: c_int) -> *mut c_void {
    unsafe {
        begin();
        if mode & !(RTLD_BINDING_MASK | RTLD_NOLOAD | RTLD_DEEPBIND | RTLD_GLOBAL | RTLD_LOCAL | RTLD_NODELETE | SPROF) != 0 {
            fail(b"", "invalid mode parameter", 0);
            return null_mut();
        }
        let name: &[u8] = if file.is_null() { b"" } else { cbytes(file) };
        if mode & RTLD_BINDING_MASK == 0 {
            fail(name, "invalid mode for dlopen()", EINVAL);
            return null_mut();
        }
        if name.is_empty() {
            succeed();
            return main_handle();
        }
        if let Some(i) = STUB_NAMES.iter().position(|n| *n == name) {
            if mode & RTLD_NOLOAD != 0 {
                succeed();
                return null_mut();
            }
            STUB_OPEN[i].fetch_add(1, Ordering::Relaxed);
            succeed();
            return stub_handle(i);
        }
        if !name.contains(&b'/') {
            fail(name, "cannot open shared object file", ENOENT_);
            return null_mut();
        }
        let fd = syscall3(syscall::SYS_OPEN, file as usize, 0o2000000, 0);
        let e = sys_err(fd);
        if e != 0 {
            fail(name, "cannot open shared object file", e);
            return null_mut();
        }
        let fd = fd as c_int;
        let mut hdr = [0u8; 64];
        let n = syscall3(syscall::SYS_READ, fd as usize, hdr.as_mut_ptr() as usize, 64);
        syscall1(syscall::SYS_CLOSE, fd as usize);
        let e = sys_err(n);
        if e != 0 {
            fail(name, "cannot read file data", e);
            return null_mut();
        }
        if n < 64 {
            fail(name, "file too short", 0);
            return null_mut();
        }
        if &hdr[..4] != b"\x7fELF" || hdr[4] != 2 || hdr[5] != 1 || hdr[6] != 1 {
            fail(name, "invalid ELF header", 0);
            return null_mut();
        }
        if hdr[16] == 2 {
            fail(name, "cannot dynamically load executable", 0);
            return null_mut();
        }
        if mode & RTLD_NOLOAD != 0 {
            succeed();
            return null_mut();
        }
        fail(name, "static binaries cannot load shared objects", 0);
        null_mut()
    }
}

fn sys_err(r: usize) -> c_int {
    if r > usize::MAX - 4095 { (r as isize).wrapping_neg() as c_int } else { 0 }
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void {
    unsafe { open_impl(file, mode) }
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlmopen(_nsid: c_long, file: *const c_char, mode: c_int) -> *mut c_void {
    unsafe { open_impl(file, mode) }
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    begin();
    if handle == main_handle() {
        succeed();
        0
    } else if let Some(i) = stub_index(handle)
        && STUB_OPEN[i].try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1)).is_ok()
    {
        succeed();
        0
    } else {
        fail(b"", "shared object not open", 0);
        -1
    }
}

fn lookup_fail(handle: *mut c_void, name: &[u8], version: Option<&[u8]>) -> *mut c_void {
    let _ = handle;
    let mut text = [0u8; 100];
    let mut n = 0;
    let mut add = |s: &[u8]| {
        for &c in s {
            if n < 99 {
                text[n] = c;
                n += 1;
            }
        }
    };
    add(b"undefined symbol: ");
    add(&name[..name.len().min(40)]);
    if let Some(v) = version {
        add(b", version ");
        add(&v[..v.len().min(20)]);
    }
    let s = core::str::from_utf8(&text[..n]).unwrap_or("undefined symbol");
    fail(argv0(), s, 0);
    null_mut()
}

unsafe fn sym_impl(handle: *mut c_void, name: *const c_char, version: Option<*const c_char>) -> *mut c_void {
    unsafe {
        begin();
        if handle as isize == -1 {
            fail(b"", "RTLD_NEXT used in code not dynamically loaded", 0);
            return null_mut();
        }
        if !handle.is_null() && handle != main_handle() && stub_index(handle).is_none() {
            fail(b"", "invalid handle", 0);
            return null_mut();
        }
        lookup_fail(handle, cbytes(name), version.map(|v| cbytes(v)))
    }
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    unsafe { sym_impl(handle, name, None) }
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlvsym(handle: *mut c_void, name: *const c_char, version: *const c_char) -> *mut c_void {
    unsafe { sym_impl(handle, name, Some(version)) }
}

const PT_LOAD: u32 = 1;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const AT_PHDR: u64 = 3;
const AT_PHNUM: u64 = 5;

#[repr(C)]
struct Phdr {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

fn phdrs() -> (*const Phdr, usize) {
    unsafe {
        let p = rusty_libc_util::auxv::getauxval(AT_PHDR) as *const Phdr;
        let n = rusty_libc_util::auxv::getauxval(AT_PHNUM) as usize;
        if p.is_null() { (core::ptr::null(), 0) } else { (p, n) }
    }
}

pub(crate) fn image() -> Option<(u64, u64, u64)> {
    let (p, n) = phdrs();
    if p.is_null() {
        return None;
    }
    let hs = unsafe { core::slice::from_raw_parts(p, n) };
    let mut bias = 0u64;
    for h in hs {
        if h.p_type == PT_PHDR {
            bias = (p as u64).wrapping_sub(h.p_vaddr);
        }
    }
    let (mut lo, mut hi) = (u64::MAX, 0u64);
    for h in hs.iter().filter(|h| h.p_type == PT_LOAD) {
        lo = lo.min(h.p_vaddr & !0xfff);
        hi = hi.max((h.p_vaddr + h.p_memsz + 0xfff) & !0xfff);
    }
    if lo > hi {
        return None;
    }
    Some((bias, lo.wrapping_add(bias), hi.wrapping_add(bias)))
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int {
    unsafe {
        match image() {
            Some((_bias, start, end)) if (addr as u64) >= start && (addr as u64) < end => {
                let name = program_name();
                (*info).dli_fname = if name.is_null() { c"".as_ptr() } else { name };
                (*info).dli_fbase = start as *mut c_void;
                (*info).dli_sname = core::ptr::null();
                (*info).dli_saddr = null_mut();
                1
            }
            _ => 0,
        }
    }
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr1(addr: *const c_void, info: *mut DlInfo, extra: *mut *mut c_void, flags: c_int) -> c_int {
    unsafe {
        let r = dladdr(addr, info);
        if r != 0 {
            match flags {
                RTLD_DL_SYMENT => *extra = null_mut(),
                RTLD_DL_LINKMAP => *extra = main_handle(),
                _ => {}
            }
        }
        r
    }
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlinfo(handle: *mut c_void, request: c_int, arg: *mut c_void) -> c_int {
    unsafe {
        begin();
        let stub = stub_index(handle);
        if handle != main_handle() && stub.is_none() {
            fail(b"", "invalid handle", 0);
            return -1;
        }
        if stub.is_some() && request != RTLD_DI_LMID && request != RTLD_DI_LINKMAP {
            fail(b"", "unsupported dlinfo request", 0);
            return -1;
        }
        match request {
            RTLD_DI_LMID => {
                *(arg as *mut c_long) = 0;
            }
            RTLD_DI_LINKMAP => {
                *(arg as *mut *mut LinkMap) = handle.cast();
            }
            RTLD_DI_ORIGIN => {
                let mut buf = [0u8; 4096];
                let r = syscall3(SYS_READLINK_NR, c"/proc/self/exe".as_ptr() as usize, buf.as_mut_ptr() as usize, buf.len() - 1);
                let e = sys_err(r);
                if e != 0 {
                    fail(b"", "cannot determine the origin", e);
                    return -1;
                }
                let n = r;
                let slash = buf[..n].iter().rposition(|&c| c == b'/').unwrap_or(0);
                let dst = arg as *mut u8;
                core::ptr::copy_nonoverlapping(buf.as_ptr(), dst, slash);
                *dst.add(slash) = 0;
            }
            RTLD_DI_SERINFOSIZE | RTLD_DI_SERINFO => {
                let p = arg as *mut usize;
                if request == RTLD_DI_SERINFOSIZE {
                    *p = 16;
                }
                *(p.add(1) as *mut u32) = 0;
            }
            RTLD_DI_TLS_MODID => {
                let (p, n) = phdrs();
                let has_tls = !p.is_null() && core::slice::from_raw_parts(p, n).iter().any(|h| h.p_type == PT_TLS);
                *(arg as *mut usize) = has_tls as usize;
            }
            _ => {
                fail(b"", "unsupported dlinfo request", 0);
                return -1;
            }
        }
        succeed();
        0
    }
}

const SYS_READLINK_NR: usize = 89;

#[repr(C)]
pub struct DlPhdrInfo {
    pub dlpi_addr: u64,
    pub dlpi_name: *const c_char,
    pub dlpi_phdr: *const c_void,
    pub dlpi_phnum: u16,
    pub dlpi_adds: u64,
    pub dlpi_subs: u64,
    pub dlpi_tls_modid: usize,
    pub dlpi_tls_data: *mut c_void,
}

const _: () = assert!(size_of::<DlPhdrInfo>() == 64);

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dl_iterate_phdr(callback: Option<unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int>, data: *mut c_void) -> c_int {
    unsafe {
        let (p, n) = phdrs();
        let Some(cb) = callback else { return 0 };
        let bias = image().map_or(0, |(b, _, _)| b);
        let has_tls = !p.is_null() && core::slice::from_raw_parts(p, n).iter().any(|h| h.p_type == PT_TLS);
        let mut info = DlPhdrInfo { dlpi_addr: bias, dlpi_name: c"".as_ptr(), dlpi_phdr: p.cast(), dlpi_phnum: n as u16, dlpi_adds: 1, dlpi_subs: 0, dlpi_tls_modid: has_tls as usize, dlpi_tls_data: null_mut() };
        cb(&mut info, size_of::<DlPhdrInfo>(), data)
    }
}

#[repr(C)]
pub struct DlFindObject {
    pub dlfo_flags: u64,
    pub dlfo_map_start: *mut c_void,
    pub dlfo_map_end: *mut c_void,
    pub dlfo_link_map: *mut LinkMap,
    pub dlfo_eh_frame: *mut c_void,
    pub reserved: [u64; 7],
}

const _: () = assert!(size_of::<DlFindObject>() == 96);

const PT_GNU_EH_FRAME_TYPE: u32 = 0x6474e550;

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn _dl_find_object(pc: *mut c_void, result: *mut DlFindObject) -> c_int {
    unsafe {
        let Some((bias, lo, hi)) = image() else { return -1 };
        let a = pc as u64;
        if a < lo || a >= hi {
            return -1;
        }
        let (p, n) = phdrs();
        let mut eh = 0u64;
        for h in core::slice::from_raw_parts(p, n) {
            if h.p_type == PT_GNU_EH_FRAME_TYPE {
                eh = h.p_vaddr.wrapping_add(bias);
            }
        }
        *result = DlFindObject {
            dlfo_flags: 0,
            dlfo_map_start: lo as *mut c_void,
            dlfo_map_end: hi as *mut c_void,
            dlfo_link_map: (&raw mut MAIN_MAP).cast(),
            dlfo_eh_frame: eh as *mut c_void,
            reserved: [0; 7],
        };
        0
    }
}
