#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use crate::syscall;

const AT_NULL: u64 = 0;
const AT_SYSINFO_EHDR: u64 = 33;

const O_RDONLY_CLOEXEC: usize = 0o2000000;

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

pub type ClockFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
pub type GettimeofdayFn = unsafe extern "C" fn(*mut c_void, *mut c_void) -> c_int;
pub type GetcpuFn = unsafe extern "C" fn(*mut u32, *mut u32, *mut c_void) -> c_int;
pub type TimeFn = unsafe extern "C" fn(*mut i64) -> i64;

static STATE: AtomicU8 = AtomicU8::new(0);
static CLOCK_GETTIME: AtomicUsize = AtomicUsize::new(0);
static GETTIMEOFDAY: AtomicUsize = AtomicUsize::new(0);
static TIME: AtomicUsize = AtomicUsize::new(0);
static CLOCK_GETRES: AtomicUsize = AtomicUsize::new(0);
static GETCPU: AtomicUsize = AtomicUsize::new(0);
static BASE: AtomicUsize = AtomicUsize::new(0);

pub fn auxv_entry(tag: u64) -> u64 {
    #[cfg(feature = "start")]
    {
        let mut p = crate::start::auxv();
        if !p.is_null() {
            loop {
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
    let mut buf = [0u8; 2048];
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
    fn cstr_eq(&self, off: usize, name: &[u8]) -> Option<bool> {
        let s = self.0.get(off..)?;
        Some(s.len() > name.len() && &s[..name.len()] == name && s[name.len()] == 0)
    }
}

unsafe fn mapped_size(base: usize) -> Option<usize> {
    let ehdr = Image(unsafe { crate::ffi::bytes(base as *const u8, 64) });
    if ehdr.bytes::<4>(0)? != *b"\x7fELF" || ehdr.u8(4)? != 2 {
        return None;
    }
    let phoff = ehdr.u64(0x20)? as usize;
    let phentsize = ehdr.u16(0x36)? as usize;
    let phnum = ehdr.u16(0x38)? as usize;
    let table_end = phoff.checked_add(phnum.checked_mul(phentsize)?)?;
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

pub unsafe fn lookup(base: usize, name: &[u8], version: &[u8]) -> Option<usize> {
    let size = unsafe { mapped_size(base) }?;
    let image = unsafe { crate::ffi::bytes(base as *const u8, size) };
    lookup_in(image, name, version).map(|off| base.wrapping_add(off))
}

fn lookup_in(img: &[u8], name: &[u8], version: &[u8]) -> Option<usize> {
    let img = Image(img);
    if img.bytes::<4>(0)? != *b"\x7fELF" || img.u8(4)? != 2 {
        return None;
    }
    let phoff = img.u64(0x20)? as usize;
    let phentsize = img.u16(0x36)? as usize;
    let phnum = img.u16(0x38)? as usize;
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
    if strtab == 0 || symtab == 0 {
        return None;
    }
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

pub unsafe fn init_with(base: usize) {
    {
        BASE.store(base, Ordering::Relaxed);
        if base != 0 {
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
        #[cfg(feature = "start")]
        {
            let b = crate::start::sysinfo_ehdr();
            if b != 0 {
                unsafe { init_with(b) };
                return;
            }
        }
        unsafe { init_with(auxv_entry(AT_SYSINFO_EHDR) as usize) };
    }
}

pub fn base() -> usize {
    ensure();
    BASE.load(Ordering::Relaxed)
}

#[inline]
pub fn clock_gettime() -> Option<ClockFn> {
    ensure();
    let p = CLOCK_GETTIME.load(Ordering::Relaxed);
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, ClockFn>(p) }) }
}

#[inline]
pub fn clock_getres() -> Option<ClockFn> {
    ensure();
    let p = CLOCK_GETRES.load(Ordering::Relaxed);
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, ClockFn>(p) }) }
}

#[inline]
pub fn gettimeofday() -> Option<GettimeofdayFn> {
    ensure();
    let p = GETTIMEOFDAY.load(Ordering::Relaxed);
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, GettimeofdayFn>(p) }) }
}

#[inline]
pub fn time() -> Option<TimeFn> {
    ensure();
    let p = TIME.load(Ordering::Relaxed);
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, TimeFn>(p) }) }
}

#[inline]
pub fn getcpu() -> Option<GetcpuFn> {
    ensure();
    let p = GETCPU.load(Ordering::Relaxed);
    if p == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, GetcpuFn>(p) }) }
}

const SYS_CLOCK_GETTIME: usize = 228;
const SYS_GETCPU: usize = 309;

pub unsafe fn clock_gettime_raw(clock: c_int, ts: *mut c_void) -> usize {
    match clock_gettime() {
        Some(f) => unsafe { f(clock, ts) as isize as usize },
        None => unsafe { syscall::syscall2(SYS_CLOCK_GETTIME, clock as isize as usize, ts as usize) },
    }
}

pub unsafe fn getcpu_raw(cpu: *mut u32, node: *mut u32) -> usize {
    match getcpu() {
        Some(f) => unsafe { f(cpu, node, core::ptr::null_mut()) as isize as usize },
        None => unsafe { syscall::syscall3(SYS_GETCPU, cpu as usize, node as usize, 0) },
    }
}

