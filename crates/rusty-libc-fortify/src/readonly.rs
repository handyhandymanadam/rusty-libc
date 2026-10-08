use core::ffi::{c_char, c_int, c_void};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Area {
    ReadOnly,
    Writable,
    Inaccessible,
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

#[derive(PartialEq, Eq)]
pub(crate) enum Seg {
    ReadOnly,
    Writable,
    NoVerdict,
}

pub(crate) struct Query {
    pub(crate) ptr: usize,
    pub(crate) end: usize,
    pub(crate) verdict: Seg,
}

unsafe fn judge(info: &PhdrInfo, q: &mut Query) {
    let hs = unsafe { core::slice::from_raw_parts(info.phdr, info.phnum as usize) };
    let mut size = q.end.wrapping_sub(q.ptr);
    for h in hs.iter().filter(|h| h.p_type == PT_LOAD) {
        let from = info.addr.wrapping_add(h.p_vaddr as usize & !(PAGE - 1));
        let to = info.addr.wrapping_add((h.p_vaddr as usize).wrapping_add(h.p_filesz as usize).wrapping_add(PAGE - 1) & !(PAGE - 1));
        if from < q.end && to > q.ptr {
            if h.p_flags & PF_W != 0 {
                q.verdict = Seg::Writable;
                if let Some(r) = hs.iter().find(|r| r.p_type == PT_GNU_RELRO) {
                    let rs = info.addr.wrapping_add(r.p_vaddr as usize) & !(PAGE - 1);
                    let re = info.addr.wrapping_add((r.p_vaddr as usize).wrapping_add(r.p_memsz as usize)) & !(PAGE - 1);
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

unsafe extern "C" fn each_object(info: *mut PhdrInfo, _size: usize, data: *mut c_void) -> c_int {
    unsafe {
        let (info, q) = (&*info, &mut *(data as *mut Query));
        if info.phdr.is_null() {
            return 0;
        }
        let hs = core::slice::from_raw_parts(info.phdr, info.phnum as usize);
        let (mut lo, mut hi) = (usize::MAX, 0usize);
        for h in hs.iter().filter(|h| h.p_type == PT_LOAD) {
            lo = lo.min(info.addr.wrapping_add(h.p_vaddr as usize & !(PAGE - 1)));
            hi = hi.max(info.addr.wrapping_add((h.p_vaddr as usize).wrapping_add(h.p_memsz as usize).wrapping_add(PAGE - 1) & !(PAGE - 1)));
        }
        if lo <= q.ptr && q.ptr < hi {
            judge(info, q);
            return 1;
        }
        0
    }
}

unsafe fn iterate_objects(q: &mut Query) {
    unsafe {
        if let Some(iterate) = dl_iterate_phdr {
            iterate(Some(each_object), (q as *mut Query).cast());
        } else {
            program_object(q);
        }
    }
}

pub(crate) unsafe fn program_object(q: &mut Query) {
    unsafe {
        let ehdr = __ehdr_start;
        if ehdr.is_null() {
            return;
        }
        let rd16 = |off: usize| ehdr.add(off).cast::<u16>().read_unaligned();
        let phoff = ehdr.add(32).cast::<u64>().read_unaligned() as usize;
        let mut info = PhdrInfo {
            addr: if rd16(16) == 3  { ehdr as usize } else { 0 },
            name: core::ptr::null(),
            phdr: ehdr.add(phoff).cast(),
            phnum: rd16(56),
        };
        each_object(&mut info, size_of::<PhdrInfo>(), (q as *mut Query).cast());
    }
}

pub fn readonly_area(ptr: *const u8, size: usize) -> Area {
    let start = ptr as usize;
    let end = start.wrapping_add(size);
    let mut q = Query { ptr: start, end, verdict: Seg::NoVerdict };
    unsafe { iterate_objects(&mut q) };
    match q.verdict {
        Seg::ReadOnly => return Area::ReadOnly,
        Seg::Writable => return Area::Writable,
        Seg::NoVerdict => {}
    }
    let fd = match unsafe { rusty_libc_core::unistd::open(c"/proc/self/maps".as_ptr(), 0o2000000 , 0) } {
        Ok(fd) => fd,
        Err(e) if e.0 == 2 || e.0 == 13 => return Area::Inaccessible,
        Err(_) => return Area::OpenFail,
    };
    let mut remaining = size;
    let mut chunk = [0u8; 1024];
    let mut cur = [0u8; 96];
    let mut cur_len = 0usize;
    let mut skipping = false;
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
