use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use rusty_libc_core::syscall;

const AT_NULL: u64 = 0;
const AT_SYSINFO_EHDR: u64 = 33;

const SYS_OPENAT: usize = 257;
const SYS_READ: usize = 0;
const SYS_CLOSE: usize = 3;
const AT_FDCWD: usize = -100isize as usize;
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
pub type TimeFn = unsafe extern "C" fn(*mut i64) -> i64;

static STATE: AtomicU8 = AtomicU8::new(0);
static CLOCK_GETTIME: AtomicUsize = AtomicUsize::new(0);
static GETTIMEOFDAY: AtomicUsize = AtomicUsize::new(0);
static TIME: AtomicUsize = AtomicUsize::new(0);
static CLOCK_GETRES: AtomicUsize = AtomicUsize::new(0);
static BASE: AtomicUsize = AtomicUsize::new(0);

pub fn auxv_entry(tag: u64) -> u64 {
    let mut buf = [0u64; 256];
    unsafe {
        let r = syscall::syscall4(
            SYS_OPENAT,
            AT_FDCWD,
            c"/proc/self/auxv".as_ptr() as usize,
            O_RDONLY_CLOEXEC,
            0,
        );
        if syscall::check(r).is_err() {
            return 0;
        }
        let fd = r;
        let mut len = 0usize;
        let bytes = core::mem::size_of_val(&buf);
        loop {
            let n = syscall::syscall3(SYS_READ, fd, buf.as_mut_ptr().cast::<u8>().add(len) as usize, bytes - len);
            match syscall::check(n) {
                Ok(0) => break,
                Ok(n) => {
                    len += n;
                    if len == bytes {
                        break;
                    }
                }
                Err(e) if e.0 == rusty_libc_core::errno::EINTR => continue,
                Err(_) => break,
            }
        }
        syscall::syscall1(SYS_CLOSE, fd);
        let words = len / 16 * 2;
        let mut i = 0;
        while i + 1 < words {
            if buf[i] == tag {
                return buf[i + 1];
            }
            if buf[i] == AT_NULL {
                break;
            }
            i += 2;
        }
    }
    0
}

unsafe fn rd<T: Copy>(addr: usize) -> T {
    unsafe { core::ptr::read_unaligned(addr as *const T) }
}

unsafe fn cstr_eq(addr: usize, name: &[u8]) -> bool {
    unsafe {
        for (i, &c) in name.iter().enumerate() {
            if rd::<u8>(addr + i) != c {
                return false;
            }
        }
        rd::<u8>(addr + name.len()) == 0
    }
}

pub unsafe fn lookup(base: usize, name: &[u8], version: &[u8]) -> Option<usize> {
    unsafe {
        if rd::<[u8; 4]>(base) != *b"\x7fELF" || rd::<u8>(base + 4) != 2 {
            return None;
        }
        let phoff: u64 = rd(base + 0x20);
        let phentsize: u16 = rd(base + 0x36);
        let phnum: u16 = rd(base + 0x38);
        let mut load_offset: Option<usize> = None;
        let mut dynamic: usize = 0;
        for i in 0..phnum as usize {
            let ph = base + phoff as usize + i * phentsize as usize;
            let p_type: u32 = rd(ph);
            let p_offset: u64 = rd(ph + 8);
            let p_vaddr: u64 = rd(ph + 16);
            if p_type == PT_LOAD && load_offset.is_none() {
                load_offset = Some(base.wrapping_add(p_offset as usize).wrapping_sub(p_vaddr as usize));
            } else if p_type == PT_DYNAMIC {
                dynamic = base + p_offset as usize;
            }
        }
        let load_offset = load_offset?;
        if dynamic == 0 {
            return None;
        }
        let (mut strtab, mut symtab, mut hash, mut gnu_hash, mut versym, mut verdef) = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
        let mut d = dynamic;
        loop {
            let tag: i64 = rd(d);
            let val: u64 = rd(d + 8);
            let p = load_offset.wrapping_add(val as usize);
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
            rd::<u32>(hash + 4) as usize
        } else if gnu_hash != 0 {
            let nbuckets: u32 = rd(gnu_hash);
            let symoffset: u32 = rd(gnu_hash + 4);
            let bloom_size: u32 = rd(gnu_hash + 8);
            let buckets = gnu_hash + 16 + bloom_size as usize * 8;
            let chains = buckets + nbuckets as usize * 4;
            let mut last = 0u32;
            for b in 0..nbuckets as usize {
                let v: u32 = rd(buckets + b * 4);
                if v > last {
                    last = v;
                }
            }
            if last < symoffset {
                symoffset as usize
            } else {
                loop {
                    let h: u32 = rd(chains + (last - symoffset) as usize * 4);
                    if h & 1 != 0 {
                        break;
                    }
                    last += 1;
                }
                last as usize + 1
            }
        } else {
            return None;
        };
        for i in 0..nsyms {
            let sym = symtab + i * 24;
            let st_name: u32 = rd(sym);
            let st_info: u8 = rd(sym + 4);
            let st_shndx: u16 = rd(sym + 6);
            let st_value: u64 = rd(sym + 8);
            let typ = st_info & 0xf;
            let bind = st_info >> 4;
            if st_shndx == SHN_UNDEF || (typ != STT_FUNC && typ != STT_NOTYPE) || (bind != STB_GLOBAL && bind != STB_WEAK) {
                continue;
            }
            if !cstr_eq(strtab + st_name as usize, name) {
                continue;
            }
            if versym != 0 && verdef != 0 {
                let ndx = rd::<u16>(versym + i * 2) & 0x7fff;
                if !version_matches(verdef, ndx, strtab, version) {
                    continue;
                }
            }
            return Some(load_offset.wrapping_add(st_value as usize));
        }
        None
    }
}

unsafe fn version_matches(verdef: usize, ndx: u16, strtab: usize, version: &[u8]) -> bool {
    unsafe {
        let mut v = verdef;
        loop {
            let vd_ndx: u16 = rd(v + 4);
            let vd_aux: u32 = rd(v + 12);
            let vd_next: u32 = rd(v + 16);
            if vd_ndx == ndx {
                let name: u32 = rd(v + vd_aux as usize);
                return cstr_eq(strtab + name as usize, version);
            }
            if vd_next == 0 {
                return false;
            }
            v += vd_next as usize;
        }
    }
}

pub unsafe fn init_with(base: usize) {
    unsafe {
        BASE.store(base, Ordering::Relaxed);
        if base != 0 {
            let find = |n: &[u8]| lookup(base, n, b"LINUX_2.6").unwrap_or(0);
            CLOCK_GETTIME.store(find(b"__vdso_clock_gettime"), Ordering::Relaxed);
            GETTIMEOFDAY.store(find(b"__vdso_gettimeofday"), Ordering::Relaxed);
            TIME.store(find(b"__vdso_time"), Ordering::Relaxed);
            CLOCK_GETRES.store(find(b"__vdso_clock_getres"), Ordering::Relaxed);
        }
        STATE.store(1, Ordering::Release);
    }
}

#[inline]
fn ensure() {
    if STATE.load(Ordering::Acquire) == 0 {
        #[cfg(feature = "start")]
        {
            let b = rusty_libc_core::start::sysinfo_ehdr();
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

