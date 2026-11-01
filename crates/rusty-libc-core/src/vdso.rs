//! Finding the kernel's vDSO and the functions in it (time functions and getcpu). Lives in rusty-libc-core so every
//! crate can read the clocks the way glibc does (through the vDSO, not the clock_gettime system call).
//!
//! The kernel maps a small shared object into every process and passes its address in the
//! auxiliary vector (`AT_SYSINFO_EHDR`). Its dynamic symbol table exports `__vdso_clock_gettime`,
//! `__vdso_gettimeofday`, `__vdso_time` and `__vdso_clock_getres` (version `LINUX_2.6` on x86-64):
//! the same calls as the system calls, but answered from a shared page in user space without a
//! kernel entry. We read the auxiliary vector from `/proc/self/auxv` the first time a clock is
//! read (the startup code does not keep it; `init_with` lets it hand the address over later),
//! parse the object in memory (no dlopen, no allocation) and keep the four addresses. When there
//! is no vDSO (or no /proc) every caller falls back to the real system call.
//!
//! The vDSO functions return `0` or `-errno` in `eax` (they do the system call themselves when
//! they cannot answer), the convention `clock.rs` expects.
//!
//! What stays unsafe: making the image a byte slice (the kernel's mapping, trusted to be a well-formed ELF object) and
//! calling the vDSO functions through the addresses found (their C signatures, raw output pointers). The ELF parsing
//! itself is safe code over that slice.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use crate::syscall;

/// Auxiliary vector tags.
const AT_NULL: u64 = 0;
const AT_SYSINFO_EHDR: u64 = 33;

const O_RDONLY_CLOEXEC: usize = 0o2000000;

// ELF constants.
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const DT_NULL: i64 = 0;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERDEF: i64 = 0x6fff_fffc;
const STT_NOTYPE: u8 = 0;
const STT_FUNC: u8 = 2;
const STB_GLOBAL: u8 = 1;
const STB_WEAK: u8 = 2;
const SHN_UNDEF: u16 = 0;

/// Signature of `__vdso_clock_gettime` and `__vdso_clock_getres`.
pub type ClockFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
/// Signature of `__vdso_gettimeofday`.
pub type GettimeofdayFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
/// Signature of `__vdso_getcpu` (cpu, node, unused cache).
pub type GetcpuFn = unsafe extern "C" fn(*mut u32, *mut u32, *mut c_void) -> c_int;
/// Signature of `__vdso_time`.
pub type TimeFn = unsafe extern "C" fn(*mut i64) -> i64;

static STATE: AtomicU8 = AtomicU8::new(0); // 0 = not looked for yet, 1 = done
static CLOCK_GETTIME: AtomicUsize = AtomicUsize::new(0);
static GETTIMEOFDAY: AtomicUsize = AtomicUsize::new(0);
static TIME: AtomicUsize = AtomicUsize::new(0);
static CLOCK_GETRES: AtomicUsize = AtomicUsize::new(0);
static GETCPU: AtomicUsize = AtomicUsize::new(0);
static BASE: AtomicUsize = AtomicUsize::new(0);

// ------------------------------------------------------------------ auxiliary vector

/// Value of auxiliary vector entry `tag` (0 if the entry is missing): from the vector the startup code saved, else
/// (before startup, host tests) from `/proc/self/auxv`, the kernel's copy of the vector the process started with.
pub fn auxv_entry(tag: u64) -> u64 {
    // the vector the startup code saved (as glibc, which never opens /proc/self/auxv); the file only before that
    #[cfg(feature = "start")]
    {
        let mut p = crate::start::auxv();
        if !p.is_null() {
            loop {
                // SAFETY: `p` is at a (tag, value) pair of the kernel's vector, which the startup code saved and which lives
                // on the initial stack for the life of the process; the walk stops at AT_NULL.
                let [t, v] = unsafe { *(p as *const [usize; 2]) };
                if t == AT_NULL as usize {
                    return 0;
                }
                if t as u64 == tag {
                    return v as u64;
                }
                p = p.wrapping_add(2);
            }
        }
    }
    // the same system calls as always: openat(AT_FDCWD, path, O_RDONLY|O_CLOEXEC, 0), read until full or end, close
    let mut buf = [0u8; 2048];
    // SAFETY: a NUL-terminated literal.
    let Ok(fd) = (unsafe { crate::unistd::open(c"/proc/self/auxv".as_ptr(), O_RDONLY_CLOEXEC as i32, 0) }) else {
        return 0;
    };
    let mut len = 0usize;
    loop {
        match crate::unistd::read_nocancel(fd, &mut buf[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if len == buf.len() {
                    break;
                }
            }
            Err(e) if e.0 == crate::errno::EINTR => continue,
            Err(_) => break,
        }
    }
    let _ = crate::unistd::close(fd);
    for pair in buf[..len].as_chunks::<16>().0 {
        let t = u64::from_ne_bytes(pair[..8].try_into().unwrap_or_default());
        if t == tag {
            return u64::from_ne_bytes(pair[8..].try_into().unwrap_or_default());
        }
        if t == AT_NULL {
            break;
        }
    }
    0
}

// ------------------------------------------------------------------ ELF parsing

/// A little-endian ELF image in memory, read with bounds checks: a read outside it is `None`.
struct Image<'a>(&'a [u8]);

impl Image<'_> {
    fn bytes<const N: usize>(&self, off: usize) -> Option<[u8; N]> {
        self.0.get(off..off.checked_add(N)?)?.try_into().ok()
    }
    fn u8(&self, off: usize) -> Option<u8> {
        self.0.get(off).copied()
    }
    fn u16(&self, off: usize) -> Option<u16> {
        self.bytes(off).map(u16::from_le_bytes)
    }
    fn u32(&self, off: usize) -> Option<u32> {
        self.bytes(off).map(u32::from_le_bytes)
    }
    fn u64(&self, off: usize) -> Option<u64> {
        self.bytes(off).map(u64::from_le_bytes)
    }
    /// The NUL-terminated string at `off` equals `name`.
    fn cstr_eq(&self, off: usize, name: &[u8]) -> Option<bool> {
        let s = self.0.get(off..)?;
        Some(s.len() > name.len() && &s[..name.len()] == name && s[name.len()] == 0)
    }
}

/// How many bytes of the object at `base` are mapped: the end of its furthest loadable segment's file contents (and at least
/// the headers). Reads the ELF header and the program header table only.
///
/// # Safety
/// As [`lookup`].
unsafe fn mapped_size(base: usize) -> Option<usize> {
    // SAFETY: a mapped ELF64 object starts with its 64-byte header (caller's contract).
    let ehdr = Image(unsafe { crate::ffi::bytes(base as *const u8, 64) });
    if ehdr.bytes::<4>(0)? != *b"\x7fELF" || ehdr.u8(4)? != 2 {
        return None;
    }
    let phoff = ehdr.u64(0x20)? as usize;
    let phentsize = ehdr.u16(0x36)? as usize;
    let phnum = ehdr.u16(0x38)? as usize;
    let table_end = phoff.checked_add(phnum.checked_mul(phentsize)?)?;
    // SAFETY: the program header table is part of the mapped object (caller's contract: well-formed).
    let all = Image(unsafe { crate::ffi::bytes(base as *const u8, table_end) });
    let mut end = table_end;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        if all.u32(ph)? == PT_LOAD {
            let file_end = (all.u64(ph + 8)? as usize).checked_add(all.u64(ph + 32)? as usize)?;
            end = end.max(file_end);
        }
    }
    Some(end)
}

/// Look up the function `name` with symbol version `version` in the ELF shared object mapped at
/// `base` (its ELF header). Returns its address. Used for the vDSO; a symbol without version
/// information is accepted when the object has none.
///
/// # Safety
/// `base` must be the address of a mapped, well-formed ELF64 shared object whose loadable segments' file contents are
/// mapped contiguously from `base` (the vDSO: one image).
pub unsafe fn lookup(base: usize, name: &[u8], version: &[u8]) -> Option<usize> {
    // SAFETY: forwarded contract.
    let size = unsafe { mapped_size(base) }?;
    // SAFETY: `size` bytes from `base` are the mapped image (caller's contract, `mapped_size`); it is never unmapped.
    let image = unsafe { crate::ffi::bytes(base as *const u8, size) };
    lookup_in(image, name, version).map(|off| base.wrapping_add(off))
}

/// [`lookup`] on an image in memory: the symbol's offset from the image start (its address less the load address).
fn lookup_in(img: &[u8], name: &[u8], version: &[u8]) -> Option<usize> {
    let img = Image(img);
    if img.bytes::<4>(0)? != *b"\x7fELF" || img.u8(4)? != 2 {
        return None;
    }
    let phoff = img.u64(0x20)? as usize;
    let phentsize = img.u16(0x36)? as usize;
    let phnum = img.u16(0x38)? as usize;
    // (vaddr - offset) of the first loadable segment: an address `a` in the object is image offset `a - bias`
    let mut bias: Option<usize> = None;
    let mut dynamic: Option<usize> = None;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        let p_type = img.u32(ph)?;
        let p_offset = img.u64(ph + 8)? as usize;
        let p_vaddr = img.u64(ph + 16)? as usize;
        if p_type == PT_LOAD && bias.is_none() {
            bias = Some(p_vaddr.wrapping_sub(p_offset));
        } else if p_type == PT_DYNAMIC {
            dynamic = Some(p_offset);
        }
    }
    let bias = bias?;
    let dynamic = dynamic?;
    let (mut strtab, mut symtab, mut hash, mut gnu_hash, mut versym, mut verdef) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut d = dynamic;
    loop {
        let tag = img.u64(d)? as i64;
        let p = (img.u64(d + 8)? as usize).wrapping_sub(bias);
        match tag {
            DT_NULL => break,
            DT_STRTAB => strtab = p,
            DT_SYMTAB => symtab = p,
            DT_HASH => hash = p,
            DT_GNU_HASH => gnu_hash = p,
            DT_VERSYM => versym = p,
            DT_VERDEF => verdef = p,
            _ => {}
        }
        d += 16;
    }
    // (the tables' offsets are never 0: the ELF header is there)
    if strtab == 0 || symtab == 0 {
        return None;
    }
    // Number of symbols: DT_HASH has it directly; with only DT_GNU_HASH, walk the chains.
    let nsyms: usize = if hash != 0 {
        img.u32(hash + 4)? as usize
    } else if gnu_hash != 0 {
        let nbuckets = img.u32(gnu_hash)?;
        let symoffset = img.u32(gnu_hash + 4)?;
        let bloom_size = img.u32(gnu_hash + 8)?;
        let buckets = gnu_hash + 16 + bloom_size as usize * 8;
        let chains = buckets + nbuckets as usize * 4;
        let mut last = 0u32;
        for b in 0..nbuckets as usize {
            last = last.max(img.u32(buckets + b * 4)?);
        }
        if last < symoffset {
            symoffset as usize
        } else {
            while img.u32(chains + (last - symoffset) as usize * 4)? & 1 == 0 {
                last += 1;
            }
            last as usize + 1
        }
    } else {
        return None;
    };
    for i in 0..nsyms {
        let sym = symtab + i * 24;
        let st_name = img.u32(sym)?;
        let st_info = img.u8(sym + 4)?;
        let st_shndx = img.u16(sym + 6)?;
        let st_value = img.u64(sym + 8)?;
        let typ = st_info & 0xf;
        let bind = st_info >> 4;
        if st_shndx == SHN_UNDEF || (typ != STT_FUNC && typ != STT_NOTYPE) || (bind != STB_GLOBAL && bind != STB_WEAK) {
            continue;
        }
        if !img.cstr_eq(strtab + st_name as usize, name)? {
            continue;
        }
        if versym != 0 && verdef != 0 {
            let ndx = img.u16(versym + i * 2)? & 0x7fff;
            if !version_matches(&img, verdef, ndx, strtab, version)? {
                continue;
            }
        }
        return Some((st_value as usize).wrapping_sub(bias));
    }
    None
}

/// Is version index `ndx` named `version` in the version-definition chain at `verdef`?
fn version_matches(img: &Image<'_>, verdef: usize, ndx: u16, strtab: usize, version: &[u8]) -> Option<bool> {
    let mut v = verdef;
    loop {
        let vd_ndx = img.u16(v + 4)?;
        let vd_aux = img.u32(v + 12)?;
        let vd_next = img.u32(v + 16)?;
        if vd_ndx == ndx {
            let name = img.u32(v + vd_aux as usize)?;
            return img.cstr_eq(strtab + name as usize, version);
        }
        if vd_next == 0 {
            return Some(false);
        }
        v += vd_next as usize;
    }
}

// ------------------------------------------------------------------ the four functions

/// Parse the vDSO at `base` (0 = none) and remember its functions.
///
/// # Safety
/// `base` must be 0 or the address of the kernel's vDSO image.
pub unsafe fn init_with(base: usize) {
    {
        BASE.store(base, Ordering::Relaxed);
        if base != 0 {
            // SAFETY: `base` is the kernel's vDSO image (caller's contract).
            let find = |n: &[u8]| unsafe { lookup(base, n, b"LINUX_2.6") }.unwrap_or(0);
            CLOCK_GETTIME.store(find(b"__vdso_clock_gettime"), Ordering::Relaxed);
            GETTIMEOFDAY.store(find(b"__vdso_gettimeofday"), Ordering::Relaxed);
            TIME.store(find(b"__vdso_time"), Ordering::Relaxed);
            CLOCK_GETRES.store(find(b"__vdso_clock_getres"), Ordering::Relaxed);
            GETCPU.store(find(b"__vdso_getcpu"), Ordering::Relaxed);
        }
        STATE.store(1, Ordering::Release);
    }
}

#[inline]
fn ensure() {
    if STATE.load(Ordering::Acquire) == 0 {
        // The runtime's startup code saved the address from the auxiliary vector already.
        #[cfg(feature = "start")]
        {
            let b = crate::start::sysinfo_ehdr();
            if b != 0 {
                // SAFETY: the kernel's AT_SYSINFO_EHDR, the address of its vDSO image.
                unsafe { init_with(b) };
                return;
            }
        }
        // Another path may have set the state while we read the file; both give the same answer.
        // SAFETY: AT_SYSINFO_EHDR from the kernel's auxiliary vector (0 when there is no vDSO).
        unsafe { init_with(auxv_entry(AT_SYSINFO_EHDR) as usize) };
    }
}

/// Address of the vDSO image (0 if there is none).
pub fn base() -> usize {
    ensure();
    BASE.load(Ordering::Relaxed)
}

/// `__vdso_clock_gettime`, if the kernel has it.
#[inline]
pub fn clock_gettime() -> Option<ClockFn> {
    ensure();
    let p = CLOCK_GETTIME.load(Ordering::Relaxed);
    // SAFETY: a non-zero word is the address of the vDSO function of that name and version, whose C signature `ClockFn` is.
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, ClockFn>(p) }) }
}

/// `__vdso_clock_getres`, if the kernel has it.
#[inline]
pub fn clock_getres() -> Option<ClockFn> {
    ensure();
    let p = CLOCK_GETRES.load(Ordering::Relaxed);
    // SAFETY: a non-zero word is the address of the vDSO function of that name and version, whose C signature `ClockFn` is.
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, ClockFn>(p) }) }
}

/// `__vdso_gettimeofday`, if the kernel has it.
#[inline]
pub fn gettimeofday() -> Option<GettimeofdayFn> {
    ensure();
    let p = GETTIMEOFDAY.load(Ordering::Relaxed);
    // SAFETY: a non-zero word is the address of the vDSO function of that name and version, whose C signature `GettimeofdayFn` is.
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, GettimeofdayFn>(p) }) }
}

/// `__vdso_time`, if the kernel has it.
#[inline]
pub fn time() -> Option<TimeFn> {
    ensure();
    let p = TIME.load(Ordering::Relaxed);
    // SAFETY: a non-zero word is the address of the vDSO function of that name and version, whose C signature `TimeFn` is.
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, TimeFn>(p) }) }
}

/// `__vdso_getcpu`, if the kernel has it (glibc's getcpu and sched_getcpu call it rather than the system call).
#[inline]
pub fn getcpu() -> Option<GetcpuFn> {
    ensure();
    let p = GETCPU.load(Ordering::Relaxed);
    // SAFETY: a non-zero word is the address of the vDSO function of that name and version, whose C signature `GetcpuFn` is.
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, GetcpuFn>(p) }) }
}

const SYS_CLOCK_GETTIME: usize = 228;
const SYS_GETCPU: usize = 309;

/// clock_gettime as glibc reads clocks: through the vDSO, the system call only when there is none. Returns 0 or the
/// kernel's `-errno` as `usize` (the raw system-call convention).
///
/// # Safety
/// `ts` must point to a writable `struct timespec`.
pub unsafe fn clock_gettime_raw(clock: c_int, ts: *mut c_void) -> usize {
    match clock_gettime() {
        // SAFETY: the vDSO function writes one timespec to `ts` (caller's contract).
        Some(f) => unsafe { f(clock, ts) as isize as usize },
        // SAFETY: as above, the system call.
        None => unsafe { syscall::syscall2(SYS_CLOCK_GETTIME, clock as isize as usize, ts as usize) },
    }
}

/// getcpu through the vDSO (the system call when there is none): 0 or `-errno` as `usize`.
///
/// # Safety
/// `cpu` and `node` must be null or writable.
pub unsafe fn getcpu_raw(cpu: *mut u32, node: *mut u32) -> usize {
    match getcpu() {
        // SAFETY: `cpu` and `node` are NULL or writable (caller's contract).
        Some(f) => unsafe { f(cpu, node, core::ptr::null_mut()) as isize as usize },
        // SAFETY: as above, the system call.
        None => unsafe { syscall::syscall3(SYS_GETCPU, cpu as usize, node as usize, 0) },
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
    use super::*;

    #[test]
    fn finds_and_calls_the_kernel_functions() {
        let b = base();
        assert_ne!(b, 0, "no vDSO on this machine");
        let f = clock_gettime().expect("__vdso_clock_gettime");
        let mut ts = [0i64; 2];
        assert_eq!(unsafe { f(1 /* CLOCK_MONOTONIC */, ts.as_mut_ptr().cast()) }, 0);
        assert!(ts[0] > 0 || ts[1] > 0);
        assert!(gettimeofday().is_some() && time().is_some() && clock_getres().is_some() && getcpu().is_some());
        let mut cpu = u32::MAX;
        assert_eq!(unsafe { getcpu_raw(&mut cpu, core::ptr::null_mut()) }, 0);
        assert!(cpu < 4096);
        // the same answer through the safe parser on the image, and none for a name or version that is not there
        let size = unsafe { mapped_size(b) }.unwrap();
        let image = unsafe { core::slice::from_raw_parts(b as *const u8, size) };
        assert_eq!(lookup_in(image, b"__vdso_clock_gettime", b"LINUX_2.6").map(|o| b + o), Some(CLOCK_GETTIME.load(Ordering::Relaxed)));
        assert_eq!(lookup_in(image, b"__vdso_clock_gettim", b"LINUX_2.6"), None);
        assert_eq!(lookup_in(image, b"__vdso_clock_gettime", b"LINUX_2.5"), None);
        // a cut-off image is never read past its end: the bounds checks give no answer or (when the tables needed all lie
        // before the cut) the right one, never another
        let right = lookup_in(image, b"__vdso_clock_gettime", b"LINUX_2.6");
        for cut in 0..size {
            let r = lookup_in(&image[..cut], b"__vdso_clock_gettime", b"LINUX_2.6");
            assert!(r.is_none() || r == right, "cut at {cut}");
        }
        assert_eq!(lookup_in(&image[..64], b"__vdso_clock_gettime", b"LINUX_2.6"), None);
    }

    #[test]
    fn auxv_from_proc() {
        assert_eq!(auxv_entry(6 /* AT_PAGESZ */), 4096);
        assert_eq!(auxv_entry(12345), 0);
    }
}
