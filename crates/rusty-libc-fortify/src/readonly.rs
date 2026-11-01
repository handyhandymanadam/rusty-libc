//! Is a memory area read-only? Used for `%n` in fortified printf: glibc lets `%n` through only
//! when the format string itself lives in read-only memory. Like glibc it asks the ELF segments of
//! the object that holds the area first (`dl_iterate_phdr`: no file is opened, so it works when the
//! process has no free file descriptor) and only if they give no verdict reads the mappings in
//! /proc/self/maps (the same walk as glibc's `__readonly_area_fallback`).
//!
//! `dl_iterate_phdr` is a weak reference: a program that links this crate without the C runtime (the Rust test program
//! `tests/rust-fortify`) has none. It is a statically linked program then, with one object: its own program headers, found
//! through the linker's `__ehdr_start`, are the whole list (what glibc's static `dl_iterate_phdr` reports as well).
use core::ffi::{c_char, c_int, c_void};
use rusty_libc_core::ffi;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Area {
    /// the whole area is mapped readable and not writable
    ReadOnly,
    /// some of it is writable, or not mapped
    Writable,
    /// /proc/self/maps does not exist or is not accessible: no verdict, let the call through
    Inaccessible,
    /// /proc/self/maps could not be opened for another reason (too many open files, ...)
    OpenFail,
}

fn hex(b: &[u8]) -> Option<(usize, usize)> {
    let mut v = 0usize;
    let mut i = 0;
    while i < b.len() {
        let d = match b[i] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => break,
        };
        v = (v << 4) | d as usize;
        i += 1;
    }
    if i == 0 { None } else { Some((v, i)) }
}

/// Fold one maps line into the remaining size; returns false to stop (answer: writable).
fn line(l: &[u8], ptr: usize, end: usize, size: &mut usize) -> Result<bool, ()> {
    let Some((from, a)) = hex(l) else { return Err(()) };
    if l.get(a) != Some(&b'-') {
        return Err(());
    }
    let Some((to, b)) = hex(&l[a + 1..]) else { return Err(()) };
    if l.get(a + 1 + b) != Some(&b' ') {
        return Err(());
    }
    if from < end && to > ptr {
        let perms = &l[a + b + 2..];
        if perms.first() != Some(&b'r') || perms.get(1) != Some(&b'-') {
            return Err(());
        }
        if from <= ptr && to >= end {
            *size = 0;
            return Ok(false);
        } else if from <= ptr {
            *size -= to - ptr;
        } else if to >= end {
            *size -= end - from;
        } else {
            *size -= to - from;
        }
        if *size == 0 {
            return Ok(false);
        }
    }
    Ok(true)
}

#[repr(C)]
struct PhdrInfo {
    addr: usize,
    name: *const c_char,
    phdr: *const Phdr,
    phnum: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
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

type PhdrCallback = unsafe extern "C" fn(*mut PhdrInfo, usize, *mut c_void) -> c_int;

unsafe extern "C" {
    #[linkage = "extern_weak"]
    static dl_iterate_phdr: Option<unsafe extern "C" fn(Option<PhdrCallback>, *mut c_void) -> c_int>;
    #[linkage = "extern_weak"]
    static __ehdr_start: *const u8;
}

const PT_LOAD: u32 = 1;
const PT_GNU_RELRO: u32 = 0x6474e552;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const PAGE: usize = 4096;

/// What the ELF segments say about an area.
#[derive(PartialEq, Eq)]
pub(crate) enum Seg {
    ReadOnly,
    Writable,
    /// not inside any object, or not covered by its segments: ask /proc/self/maps
    NoVerdict,
}

pub(crate) struct Query {
    pub(crate) ptr: usize,
    pub(crate) end: usize,
    pub(crate) verdict: Seg,
}

/// glibc's `_dl_readonly_area` for the object loaded at `addr` with program headers `hs` (once the area is known to lie
/// inside it).
fn judge(addr: usize, hs: &[Phdr], q: &mut Query) {
    let mut size = q.end.wrapping_sub(q.ptr);
    for h in hs.iter().filter(|h| h.p_type == PT_LOAD) {
        let from = addr.wrapping_add(h.p_vaddr as usize & !(PAGE - 1));
        let to = addr.wrapping_add((h.p_vaddr as usize).wrapping_add(h.p_filesz as usize).wrapping_add(PAGE - 1) & !(PAGE - 1));
        if from < q.end && to > q.ptr {
            if h.p_flags & PF_W != 0 {
                // a writable segment: only its RELRO part (made read-only after relocation) counts as read-only
                q.verdict = Seg::Writable;
                if let Some(r) = hs.iter().find(|r| r.p_type == PT_GNU_RELRO) {
                    let rs = addr.wrapping_add(r.p_vaddr as usize) & !(PAGE - 1);
                    let re = addr.wrapping_add((r.p_vaddr as usize).wrapping_add(r.p_memsz as usize)) & !(PAGE - 1);
                    if rs <= q.ptr && q.end <= re {
                        q.verdict = Seg::ReadOnly;
                    }
                }
                return;
            }
            if h.p_flags & PF_R == 0 {
                q.verdict = Seg::Writable;
                return;
            }
            if from <= q.ptr && to >= q.end {
                q.verdict = Seg::ReadOnly;
                return;
            } else if from <= q.ptr {
                size -= to - q.ptr;
            } else if to >= q.end {
                size -= q.end - from;
            } else {
                size -= to - from;
            }
            if size == 0 {
                break;
            }
        }
    }
    q.verdict = if size == 0 { Seg::ReadOnly } else { Seg::NoVerdict };
}

/// One object of the process: decide when it holds the area (1 stops the walk).
fn object(addr: usize, hs: &[Phdr], q: &mut Query) -> c_int {
    // the object whose mapping holds the pointer (glibc: `_dl_find_object`)
    let (mut lo, mut hi) = (usize::MAX, 0usize);
    for h in hs.iter().filter(|h| h.p_type == PT_LOAD) {
        lo = lo.min(addr.wrapping_add(h.p_vaddr as usize & !(PAGE - 1)));
        hi = hi.max(addr.wrapping_add((h.p_vaddr as usize).wrapping_add(h.p_memsz as usize).wrapping_add(PAGE - 1) & !(PAGE - 1)));
    }
    if lo <= q.ptr && q.ptr < hi {
        judge(addr, hs, q);
        return 1;
    }
    0
}

/// The `dl_iterate_phdr` callback: `data` is the `Query`.
///
/// # Safety
/// `info` points to a valid `dl_phdr_info` whose `phdr` (if not NULL) holds `phnum` program headers; `data` is the
/// `&mut Query` that `iterate_objects` or `program_object` passed, not otherwise used during the call.
unsafe extern "C" fn each_object(info: *mut PhdrInfo, _size: usize, data: *mut c_void) -> c_int {
    // SAFETY: the caller's contract (`info` valid for the call).
    let info = unsafe { &*info };
    // SAFETY: the caller's contract (`data` is our exclusive `Query`).
    let q = unsafe { &mut *data.cast::<Query>() };
    if info.phdr.is_null() {
        return 0;
    }
    // SAFETY: a non-NULL `phdr` holds `phnum` program headers, mapped while the object is (the caller's contract).
    let hs = unsafe { ffi::slice(info.phdr, info.phnum as usize) };
    object(info.addr, hs, q)
}

/// Offer every object of the process to `each_object`: through `dl_iterate_phdr` when the runtime has it, else the program itself.
fn iterate_objects(q: &mut Query) {
    // SAFETY: reads a weak symbol's address (NULL, so `None`, when the runtime has no `dl_iterate_phdr`).
    if let Some(iterate) = unsafe { dl_iterate_phdr } {
        // SAFETY: `each_object` keeps the callback contract; `q` is exclusive for the call.
        unsafe { iterate(Some(each_object), (q as *mut Query).cast()) };
    } else {
        program_object(q);
    }
}

/// The program's own headers, read from the ELF header the linker places at `__ehdr_start` (a position-independent program is
/// loaded at that address; a fixed-address one at 0).
pub(crate) fn program_object(q: &mut Query) {
    // SAFETY: reads a weak symbol's address (NULL when the linker defined none).
    let ehdr = unsafe { __ehdr_start };
    if ehdr.is_null() {
        return;
    }
    // SAFETY: the linker places the program's 64-byte ELF header at `__ehdr_start`, mapped read-only for the process's life.
    let header = unsafe { ffi::bytes(ehdr, 64) };
    let rd16 = |off: usize| u16::from_le_bytes([header[off], header[off + 1]]);
    let phoff = u64::from_le_bytes(header[32..40].try_into().unwrap_or([0; 8])) as usize;
    let phnum = rd16(56);
    let phdr = ehdr.wrapping_add(phoff).cast::<Phdr>();
    // SAFETY: the program headers sit at `e_phoff` inside the first mapped page of the program (as the kernel and the
    // loader also read them: AT_PHDR), aligned for `Phdr`.
    let hs = unsafe { ffi::slice(phdr, usize::from(phnum)) };
    let addr = if rd16(16) == 3 /* ET_DYN */ { ehdr as usize } else { 0 };
    object(addr, hs, q);
}

/// The verdict for `[ptr, ptr + size)`.
pub fn readonly_area(ptr: *const u8, size: usize) -> Area {
    let start = ptr as usize;
    let end = start.wrapping_add(size);
    let mut q = Query { ptr: start, end, verdict: Seg::NoVerdict };
    iterate_objects(&mut q);
    match q.verdict {
        Seg::ReadOnly => return Area::ReadOnly,
        Seg::Writable => return Area::Writable,
        Seg::NoVerdict => {}
    }
    // SAFETY: the path is a NUL-terminated literal.
    let fd = match unsafe { rusty_libc_core::unistd::open(c"/proc/self/maps".as_ptr(), 0o2000000 /* O_RDONLY|O_CLOEXEC */, 0) } {
        Ok(fd) => fd,
        Err(e) if e.0 == 2 || e.0 == 13 => return Area::Inaccessible,
        Err(_) => return Area::OpenFail,
    };
    let mut remaining = size;
    let mut chunk = [0u8; 1024];
    let mut cur = [0u8; 96]; // the first bytes of the current line: address range and permissions
    let mut cur_len = 0usize;
    let mut skipping = false; // inside the tail of a long line
    let mut stop = false;
    'read: loop {
        let n = match rusty_libc_core::unistd::read(fd, &mut chunk) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.0 == 4 => continue,
            Err(_) => break,
        };
        for &c in &chunk[..n] {
            if c == b'\n' {
                match line(&cur[..cur_len], start, end, &mut remaining) {
                    Ok(true) => {}
                    Ok(false) | Err(()) => {
                        stop = true;
                        break 'read;
                    }
                }
                cur_len = 0;
                skipping = false;
            } else if !skipping {
                if cur_len < cur.len() {
                    cur[cur_len] = c;
                    cur_len += 1;
                } else {
                    skipping = true;
                }
            }
        }
    }
    let _ = stop;
    let _ = rusty_libc_core::unistd::close(fd);
    if remaining == 0 { Area::ReadOnly } else { Area::Writable }
}
