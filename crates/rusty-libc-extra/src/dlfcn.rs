#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::consts::EINVAL;
use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU32, Ordering};
use rusty_libc_core::ffi;
use rusty_libc_core::sync_cell::SyncCell;

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

static MAIN_MAP: SyncCell<LinkMap> =
    SyncCell::new(LinkMap { l_addr: 0, l_name: c"".as_ptr(), l_ld: null_mut(), l_next: null_mut(), l_prev: null_mut() });

fn main_handle() -> *mut c_void {
    MAIN_MAP.as_ptr().cast()
}

const STUB_NAMES: [&[u8]; 8] =
    [b"libc.so.6", b"libm.so.6", b"libpthread.so.0", b"libdl.so.2", b"librt.so.1", b"libutil.so.1", b"libanl.so.1", b"libresolv.so.2"];

const fn stub_map(name: &'static core::ffi::CStr) -> LinkMap {
    LinkMap { l_addr: 0, l_name: name.as_ptr(), l_ld: null_mut(), l_next: null_mut(), l_prev: null_mut() }
}

static STUB_MAPS: SyncCell<[LinkMap; 8]> = SyncCell::new([
    stub_map(c"libc.so.6"),
    stub_map(c"libm.so.6"),
    stub_map(c"libpthread.so.0"),
    stub_map(c"libdl.so.2"),
    stub_map(c"librt.so.1"),
    stub_map(c"libutil.so.1"),
    stub_map(c"libanl.so.1"),
    stub_map(c"libresolv.so.2"),
]);

static STUB_OPEN: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];

fn stub_handle(i: usize) -> *mut c_void {
    STUB_MAPS.as_ptr().cast::<LinkMap>().wrapping_add(i).cast()
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
static ERR: SyncCell<*mut DlError> = SyncCell::new(null_mut());

unsafe extern "C" fn release_err(obj: *mut c_void) {
    let slot = obj.cast::<*mut DlError>();
    let p = unsafe { slot.replace(null_mut()) };
    if !p.is_null() {
        unsafe { rusty_libc_malloc::free(p.cast()) };
    }
}

fn with_err<R>(create: bool, f: impl FnOnce(&mut DlError) -> R) -> Option<R> {
    let mut p = unsafe { ERR.read() };
    if p.is_null() {
        if !create {
            return None;
        }
        let q = unsafe { rusty_libc_malloc::malloc(size_of::<DlError>()) }.cast::<DlError>();
        if q.is_null() {
            return None;
        }
        unsafe { core::ptr::write_bytes(q, 0, 1) };
        if !rusty_libc_core::tls::register_thread_dtor(release_err, ERR.as_ptr().cast(), 0) {
            unsafe { rusty_libc_malloc::free(q.cast()) };
            return None;
        }
        unsafe { ERR.write(q) };
        p = q;
    }
    Some(f(unsafe { &mut *p }))
}

fn copy_into(dst: &mut [u8], src: &[u8]) {
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
}

fn fail(objname: &[u8], errstring: &str, errcode: c_int) {
    with_err(true, |e| {
        copy_into(&mut e.objname, objname);
        copy_into(&mut e.errstring, errstring.as_bytes());
        e.errcode = errcode;
        e.state = State::Pending;
    });
}

fn succeed() {
    with_err(false, |e| e.state = State::None);
}

fn begin() {
    with_err(false, |e| {
        if e.state == State::Pending {
            e.state = State::None;
        }
    });
}

fn argv0() -> &'static [u8] {
    unsafe { ffi::cstr(program_name()) }.map_or(b"<main program>", CStr::to_bytes)
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
    }
    if addr == 0 {
        return core::ptr::null();
    }
    unsafe { *(addr as *const *const c_char) }
}

fn compose_message<R>(obj: &[u8], msg: &CStr, code: c_int, out: impl FnOnce(&[&[u8]]) -> R) -> R {
    let txt: &[u8] = if msg.is_empty() || !rusty_libc_core::i18n::active() {
        msg.to_bytes()
    } else {
        let t = unsafe { rusty_libc_core::i18n::tr_ptr(msg.as_ptr()) };
        unsafe { ffi::cstr_bytes(t) }
    };
    let sep: &[u8] = if obj.is_empty() { b"" } else { b": " };
    let mut tmp = [0u8; 128];
    let r = if code != 0 {
        let s = rusty_libc_core::messages::strerror_r_text(code, &mut tmp);
        out(&[obj, sep, txt, b": ", s])
    } else {
        out(&[obj, sep, txt])
    };
    if code != 0 {
        rusty_libc_core::errno::set(code);
    }
    r
}

fn until_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub extern "C" fn dlerror() -> *mut c_char {
    with_err(false, |e| match e.state {
        State::None => core::ptr::null_mut(),
        State::Delivered => {
            e.state = State::None;
            core::ptr::null_mut()
        }
        State::Pending => {
            let txt = CStr::from_bytes_until_nul(&e.errstring).unwrap_or(c"");
            let msg = &mut e.message;
            compose_message(until_nul(&e.objname), txt, e.errcode, |parts| {
                let mut n = 0;
                for p in parts {
                    for &c in *p {
                        if n < msg.len() - 1 {
                            msg[n] = c;
                            n += 1;
                        }
                    }
                }
                msg[n] = 0;
            });
            e.state = State::Delivered;
            e.message.as_mut_ptr().cast::<c_char>()
        }
    })
    .unwrap_or(core::ptr::null_mut())
}

#[cfg(all(feature = "export", feature = "shared"))]
#[unsafe(export_name = "dlerror")]
pub extern "C" fn dlerror_shared() -> *mut c_char {
    type RecordFn = unsafe extern "C" fn(*mut *const c_char, *mut *const c_char, *mut c_int) -> c_int;
    type ComposeFn = unsafe extern "C" fn(*const (*const u8, usize), usize) -> *const c_char;
    let (r, c): (usize, usize);
    unsafe {
        core::arch::asm!(
            ".weak __libc_ldso_dlerror_record",
            ".weak __libc_ldso_dlerror_compose",
            "mov {0}, qword ptr [rip + __libc_ldso_dlerror_record@GOTPCREL]",
            "mov {1}, qword ptr [rip + __libc_ldso_dlerror_compose@GOTPCREL]",
            out(reg) r,
            out(reg) c,
            options(nostack, readonly, preserves_flags)
        );
    }
    if r == 0 || c == 0 {
        return core::ptr::null_mut();
    }
    let record = unsafe { core::mem::transmute::<usize, RecordFn>(r) };
    let compose = unsafe { core::mem::transmute::<usize, ComposeFn>(c) };
    let (mut obj, mut msg, mut code) = (core::ptr::null(), core::ptr::null(), 0);
    if unsafe { record(&mut obj, &mut msg, &mut code) } == 0 {
        return core::ptr::null_mut();
    }
    let obj = unsafe { ffi::cstr(obj) }.map_or(&b""[..], CStr::to_bytes);
    let msg = unsafe { ffi::cstr(msg) }.unwrap_or(c"");
    compose_message(obj, msg, code, |parts| {
        let mut v: [(*const u8, usize); 5] = [(core::ptr::null(), 0); 5];
        for (i, p) in parts.iter().enumerate() {
            v[i] = (p.as_ptr(), p.len());
        }
        unsafe { compose(v.as_ptr(), parts.len()) }
    }) as *mut c_char
}

fn check_file(path: &CStr) -> Result<[u8; 64], (&'static str, c_int)> {
    let fd = unsafe { rusty_libc_core::unistd::open(path.as_ptr(), 0o2000000, 0) }.map_err(|e| ("cannot open shared object file", e.0))?;
    let mut hdr = [0u8; 64];
    let n = rusty_libc_core::unistd::read_nocancel(fd, &mut hdr);
    let _ = rusty_libc_core::unistd::close(fd);
    let n = n.map_err(|e| ("cannot read file data", e.0))?;
    if n < 64 {
        return Err(("file too short", 0));
    }
    Ok(hdr)
}

pub fn open_r(file: Option<&CStr>, mode: c_int) -> *mut c_void {
    begin();
    if mode & !(RTLD_BINDING_MASK | RTLD_NOLOAD | RTLD_DEEPBIND | RTLD_GLOBAL | RTLD_LOCAL | RTLD_NODELETE | SPROF) != 0 {
        fail(b"", "invalid mode parameter", 0);
        return null_mut();
    }
    let name: &[u8] = file.map_or(b"", CStr::to_bytes);
    if mode & RTLD_BINDING_MASK == 0 {
        fail(name, "invalid mode for dlopen()", EINVAL);
        return null_mut();
    }
    let Some(file) = file.filter(|_| !name.is_empty()) else {
        succeed();
        return main_handle();
    };
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
    let hdr = match check_file(file) {
        Ok(h) => h,
        Err((text, e)) => {
            fail(name, text, e);
            return null_mut();
        }
    };
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

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlopen(file: *const c_char, mode: c_int) -> *mut c_void {
    open_r(unsafe { ffi::cstr(file) }, mode)
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlmopen(_nsid: c_long, file: *const c_char, mode: c_int) -> *mut c_void {
    open_r(unsafe { ffi::cstr(file) }, mode)
}

pub fn close_r(handle: *mut c_void) -> c_int {
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

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlclose(handle: *mut c_void) -> c_int {
    close_r(handle)
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

pub fn sym_r(handle: *mut c_void, name: &[u8], version: Option<&[u8]>) -> *mut c_void {
    begin();
    if handle as isize == -1 {
        fail(b"", "RTLD_NEXT used in code not dynamically loaded", 0);
        return null_mut();
    }
    if !handle.is_null() && handle != main_handle() && stub_index(handle).is_none() {
        fail(b"", "invalid handle", 0);
        return null_mut();
    }
    lookup_fail(handle, name, version)
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void {
    sym_r(handle, unsafe { ffi::cstr_bytes(name) }, None)
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlvsym(handle: *mut c_void, name: *const c_char, version: *const c_char) -> *mut c_void {
    let name = unsafe { ffi::cstr_bytes(name) };
    sym_r(handle, name, Some(unsafe { ffi::cstr_bytes(version) }))
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
    let p = unsafe { rusty_libc_util::auxv::getauxval(AT_PHDR) } as *const Phdr;
    let n = unsafe { rusty_libc_util::auxv::getauxval(AT_PHNUM) } as usize;
    if p.is_null() { (core::ptr::null(), 0) } else { (p, n) }
}

fn phdr_slice() -> &'static [Phdr] {
    let (p, n) = phdrs();
    if p.is_null() {
        return &[];
    }
    unsafe { ffi::slice(p, n) }
}

fn has_tls() -> bool {
    phdr_slice().iter().any(|h| h.p_type == PT_TLS)
}

pub(crate) fn image() -> Option<(u64, u64, u64)> {
    let (p, _) = phdrs();
    if p.is_null() {
        return None;
    }
    image_of(p, phdr_slice())
}

fn image_of(p: *const Phdr, hs: &[Phdr]) -> Option<(u64, u64, u64)> {
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

fn image_start_of(addr: *const c_void) -> Option<u64> {
    match image() {
        Some((_bias, start, end)) if (addr as u64) >= start && (addr as u64) < end => Some(start),
        _ => None,
    }
}

fn fill_info(info: &mut DlInfo, start: u64) {
    let name = program_name();
    info.dli_fname = if name.is_null() { c"".as_ptr() } else { name };
    info.dli_fbase = start as *mut c_void;
    info.dli_sname = core::ptr::null();
    info.dli_saddr = null_mut();
}

pub fn addr_r(addr: *const c_void, info: &mut DlInfo) -> c_int {
    match image_start_of(addr) {
        Some(start) => {
            fill_info(info, start);
            1
        }
        None => 0,
    }
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr(addr: *const c_void, info: *mut DlInfo) -> c_int {
    let Some(start) = image_start_of(addr) else { return 0 };
    fill_info(unsafe { &mut *info }, start);
    1
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dladdr1(addr: *const c_void, info: *mut DlInfo, extra: *mut *mut c_void, flags: c_int) -> c_int {
    let r = unsafe { dladdr(addr, info) };
    if r != 0 {
        let v = match flags {
            RTLD_DL_SYMENT => null_mut(),
            RTLD_DL_LINKMAP => main_handle(),
            _ => return r,
        };
        unsafe { extra.write(v) };
    }
    r
}

fn origin(buf: &mut [u8; 4096]) -> Result<usize, c_int> {
    let r = unsafe {
        rusty_libc_core::syscall::syscall3(SYS_READLINK_NR, c"/proc/self/exe".as_ptr() as usize, buf.as_mut_ptr() as usize, buf.len() - 1)
    };
    let n = rusty_libc_core::syscall::check(r).map_err(|e| e.0)?;
    Ok(buf[..n].iter().rposition(|&c| c == b'/').unwrap_or(0))
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dlinfo(handle: *mut c_void, request: c_int, arg: *mut c_void) -> c_int {
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
        RTLD_DI_LMID => unsafe { arg.cast::<c_long>().write(0) },
        RTLD_DI_LINKMAP => unsafe { arg.cast::<*mut LinkMap>().write(handle.cast()) },
        RTLD_DI_ORIGIN => {
            let mut buf = [0u8; 4096];
            let slash = match origin(&mut buf) {
                Ok(s) => s,
                Err(e) => {
                    fail(b"", "cannot determine the origin", e);
                    return -1;
                }
            };
            let dst = unsafe { ffi::bytes_mut(arg.cast::<u8>(), slash + 1) };
            dst[..slash].copy_from_slice(&buf[..slash]);
            dst[slash] = 0;
        }
        RTLD_DI_SERINFOSIZE | RTLD_DI_SERINFO => {
            let p = arg.cast::<usize>();
            if request == RTLD_DI_SERINFOSIZE {
                unsafe { p.write(16) };
            }
            unsafe { p.wrapping_add(1).cast::<u32>().write(0) };
        }
        RTLD_DI_TLS_MODID => unsafe { arg.cast::<usize>().write(has_tls() as usize) },
        _ => {
            fail(b"", "unsupported dlinfo request", 0);
            return -1;
        }
    }
    succeed();
    0
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

pub fn program_phdr_info() -> DlPhdrInfo {
    let (p, n) = phdrs();
    let hs: &[Phdr] = if p.is_null() {
        &[]
    } else {
        unsafe { ffi::slice(p, n) }
    };
    let bias = if p.is_null() { 0 } else { image_of(p, hs).map_or(0, |(b, _, _)| b) };
    let tls = hs.iter().any(|h| h.p_type == PT_TLS);
    DlPhdrInfo { dlpi_addr: bias, dlpi_name: c"".as_ptr(), dlpi_phdr: p.cast(), dlpi_phnum: n as u16, dlpi_adds: 1, dlpi_subs: 0, dlpi_tls_modid: tls as usize, dlpi_tls_data: null_mut() }
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn dl_iterate_phdr(callback: Option<unsafe extern "C" fn(*mut DlPhdrInfo, usize, *mut c_void) -> c_int>, data: *mut c_void) -> c_int {
    let Some(cb) = callback else { return 0 };
    let mut info = program_phdr_info();
    unsafe { cb(&mut info, size_of::<DlPhdrInfo>(), data) }
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

pub fn find_object_r(pc: *mut c_void) -> Option<DlFindObject> {
    let (bias, lo, hi) = image()?;
    let a = pc as u64;
    if a < lo || a >= hi {
        return None;
    }
    let mut eh = 0u64;
    for h in phdr_slice() {
        if h.p_type == PT_GNU_EH_FRAME_TYPE {
            eh = h.p_vaddr.wrapping_add(bias);
        }
    }
    Some(DlFindObject {
        dlfo_flags: 0,
        dlfo_map_start: lo as *mut c_void,
        dlfo_map_end: hi as *mut c_void,
        dlfo_link_map: MAIN_MAP.as_ptr(),
        dlfo_eh_frame: eh as *mut c_void,
        reserved: [0; 7],
    })
}

#[cfg_attr(all(feature = "export", not(feature = "shared")), unsafe(no_mangle))]
pub unsafe extern "C" fn _dl_find_object(pc: *mut c_void, result: *mut DlFindObject) -> c_int {
    match find_object_r(pc) {
        Some(r) => {
            unsafe { result.write(r) };
            0
        }
        None => -1,
    }
}
