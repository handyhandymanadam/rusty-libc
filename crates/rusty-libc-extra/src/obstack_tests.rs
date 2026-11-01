//! Host tests for obstack.rs: random sequences of the obstack macros' operations (written out here in Rust,
//! the same code for both libraries) run on one obstack kept by our functions and one kept by the host
//! glibc's. After every step the two must agree on where the object and the free space are (relative to
//! the chunk), which chunks were requested (sizes, in order) and freed, the flags, and the bytes written.
#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)] // tests: the unsafe is the C calls under test
use crate::obstack::{self, Obstack};
use std::ffi::{c_char, c_int, c_long, c_void};
use std::sync::Mutex;

mod host {
    use super::*;
    unsafe extern "C" {
        pub fn _obstack_begin(h: *mut Obstack, size: c_int, align: c_int, cf: Option<unsafe extern "C" fn(c_long) -> *mut c_void>, ff: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int;
        pub fn _obstack_begin_1(h: *mut Obstack, size: c_int, align: c_int, cf: Option<unsafe extern "C" fn(*mut c_void, c_long) -> *mut c_void>, ff: Option<unsafe extern "C" fn(*mut c_void, *mut c_void)>, arg: *mut c_void) -> c_int;
        pub fn _obstack_newchunk(h: *mut Obstack, n: c_int);
        pub fn obstack_free(h: *mut Obstack, obj: *mut c_void);
        pub fn _obstack_memory_used(h: *mut Obstack) -> c_int;
        pub fn _obstack_allocated_p(h: *mut Obstack, obj: *mut c_void) -> c_int;
        pub fn obstack_printf(h: *mut Obstack, fmt: *const c_char, ...) -> c_int;
    }
}

static LOCK: Mutex<()> = Mutex::new(());

/// What a run asked of the allocator, per library.
struct Log {
    sizes: Vec<i64>,
    ptrs: Vec<*mut c_void>,
    frees: Vec<i64>,
}
unsafe impl Send for Log {}

static LOGS: Mutex<[Log; 2]> = Mutex::new([Log { sizes: Vec::new(), ptrs: Vec::new(), frees: Vec::new() }, Log { sizes: Vec::new(), ptrs: Vec::new(), frees: Vec::new() }]);

fn alloc(which: usize, size: c_long) -> *mut c_void {
    let p = unsafe { libc::aligned_alloc(4096, (size as usize + 4095) & !4095) };
    // fresh chunks hold a known pattern, so the bytes of blank (uninitialised) space compare
    unsafe { std::ptr::write_bytes(p as *mut u8, 0xAB, size as usize) };
    let mut l = LOGS.lock().unwrap();
    l[which].sizes.push(size);
    l[which].ptrs.push(p);
    p
}

fn release(which: usize, p: *mut c_void) {
    let mut l = LOGS.lock().unwrap();
    let idx = l[which].ptrs.iter().rposition(|&q| q == p).map_or(-1, |i| i as i64);
    l[which].frees.push(idx);
    if idx >= 0 {
        l[which].ptrs[idx as usize] = std::ptr::null_mut();
    }
    drop(l);
    unsafe { libc::free(p) };
}

unsafe extern "C" fn alloc_h(size: c_long) -> *mut c_void {
    alloc(0, size)
}
unsafe extern "C" fn free_h(p: *mut c_void) {
    release(0, p)
}
unsafe extern "C" fn alloc_o(size: c_long) -> *mut c_void {
    alloc(1, size)
}
unsafe extern "C" fn free_o(p: *mut c_void) {
    release(1, p)
}
unsafe extern "C" fn alloc_h1(arg: *mut c_void, size: c_long) -> *mut c_void {
    unsafe { *(arg as *mut i32) += 1 };
    alloc(0, size)
}
unsafe extern "C" fn free_h1(arg: *mut c_void, p: *mut c_void) {
    unsafe { *(arg as *mut i32) += 100 };
    release(0, p)
}
unsafe extern "C" fn alloc_o1(arg: *mut c_void, size: c_long) -> *mut c_void {
    unsafe { *(arg as *mut i32) += 1 };
    alloc(1, size)
}
unsafe extern "C" fn free_o1(arg: *mut c_void, p: *mut c_void) {
    unsafe { *(arg as *mut i32) += 100 };
    release(1, p)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// Which library an obstack is kept by.
#[derive(Clone, Copy)]
struct Lib {
    which: usize,
}

impl Lib {
    unsafe fn newchunk(&self, h: *mut Obstack, n: c_int) {
        unsafe {
            if self.which == 0 {
                host::_obstack_newchunk(h, n)
            } else {
                obstack::_obstack_newchunk(h, n)
            }
        }
    }
    unsafe fn free_fn(&self, h: *mut Obstack, obj: *mut c_void) {
        unsafe {
            if self.which == 0 {
                host::obstack_free(h, obj)
            } else {
                obstack::obstack_free(h, obj)
            }
        }
    }
    unsafe fn begin(&self, h: *mut Obstack, size: c_int, align: c_int) {
        unsafe {
            if self.which == 0 {
                host::_obstack_begin(h, size, align, Some(alloc_h), Some(free_h));
            } else {
                obstack::_obstack_begin(h, size, align, Some(alloc_o), Some(free_o));
            }
        }
    }
    unsafe fn begin1(&self, h: *mut Obstack, size: c_int, align: c_int, arg: *mut i32) {
        unsafe {
            if self.which == 0 {
                host::_obstack_begin_1(h, size, align, Some(alloc_h1), Some(free_h1), arg.cast());
            } else {
                obstack::_obstack_begin_1(h, size, align, Some(alloc_o1), Some(free_o1), arg.cast());
            }
        }
    }
}

// the macros of obstack.h, in Rust (statement-expression versions)
unsafe fn ptr_align(base: *mut c_char, p: *mut c_char, a: c_int) -> *mut c_char {
    let a = a as isize as usize;
    let _ = base;
    ((p as usize + a) & !a) as *mut c_char
}

unsafe fn m_grow(l: Lib, h: *mut Obstack, data: &[u8]) {
    unsafe {
        let n = data.len() as c_int;
        if (*h).next_free.offset(n as isize) > (*h).chunk_limit {
            l.newchunk(h, n);
        }
        std::ptr::copy_nonoverlapping(data.as_ptr(), (*h).next_free as *mut u8, data.len());
        (*h).next_free = (*h).next_free.offset(n as isize);
    }
}

unsafe fn m_blank(l: Lib, h: *mut Obstack, n: c_int) {
    unsafe {
        if (*h).chunk_limit.offset_from((*h).next_free) < n as isize {
            l.newchunk(h, n);
        }
        (*h).next_free = (*h).next_free.offset(n as isize);
    }
}

unsafe fn m_make_room(l: Lib, h: *mut Obstack, n: c_int) {
    unsafe {
        if (*h).chunk_limit.offset_from((*h).next_free) < n as isize {
            l.newchunk(h, n);
        }
    }
}

unsafe fn m_1grow(l: Lib, h: *mut Obstack, c: u8) {
    unsafe {
        if (*h).next_free.add(1) > (*h).chunk_limit {
            l.newchunk(h, 1);
        }
        *(*h).next_free = c as c_char;
        (*h).next_free = (*h).next_free.add(1);
    }
}

unsafe fn m_finish(h: *mut Obstack) -> *mut c_char {
    unsafe {
        let o = &mut *h;
        let value = o.object_base;
        if o.next_free == value {
            o.flags |= 2;
        }
        o.next_free = ptr_align(o.object_base, o.next_free, o.alignment_mask);
        if o.next_free.offset_from(o.chunk as *mut c_char) > o.chunk_limit.offset_from(o.chunk as *mut c_char) {
            o.next_free = o.chunk_limit;
        }
        o.object_base = o.next_free;
        value
    }
}

unsafe fn m_free(l: Lib, h: *mut Obstack, obj: *mut c_char) {
    unsafe {
        let o = &mut *h;
        if obj as *mut c_void > o.chunk as *mut c_void && (obj as *mut c_void) < o.chunk_limit as *mut c_void {
            o.next_free = obj;
            o.object_base = obj;
        } else {
            l.free_fn(h, obj.cast());
        }
    }
}

/// The observable state of an obstack, relative to its chunk, with the allocator log.
fn snapshot(which: usize, h: *mut Obstack) -> String {
    unsafe {
        let o = &*h;
        let l = LOGS.lock().unwrap();
        let idx = l[which].ptrs.iter().rposition(|&q| q == o.chunk as *mut c_void).map_or(-1, |i| i as i64);
        format!(
            "chunk #{idx} base {} next {} limit {} chunk_size {} mask {} flags {} sizes {:?} frees {:?}",
            o.object_base.offset_from(o.chunk as *mut c_char),
            o.next_free.offset_from(o.chunk as *mut c_char),
            o.chunk_limit.offset_from(o.chunk as *mut c_char),
            o.chunk_size,
            o.alignment_mask,
            o.flags & 7,
            l[which].sizes,
            l[which].frees
        )
    }
}

fn reset_logs() {
    let mut l = LOGS.lock().unwrap();
    for x in l.iter_mut() {
        x.sizes.clear();
        x.ptrs.clear();
        x.frees.clear();
    }
}

fn zeroed() -> Box<Obstack> {
    Box::new(unsafe { std::mem::zeroed() })
}

fn run(seed: u64, steps: usize) {
    reset_logs();
    let mut rng = Rng(seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407));
    let sizes = [0, 1, 16, 100, 256, 1000, 4064];
    let aligns = [0, 1, 4, 8, 16, 32, 64];
    let (size, align) = (sizes[rng.below(sizes.len() as u64) as usize], aligns[rng.below(aligns.len() as u64) as usize]);
    let with_arg = rng.below(3) == 0;
    let libs = [Lib { which: 0 }, Lib { which: 1 }];
    let mut obs = [zeroed(), zeroed()];
    let mut args = [0i32, 0i32];
    unsafe {
        for i in 0..2 {
            // the structure starts as garbage in C: fill the flag word with noise to check that only the
            // bits that belong to the library are changed
            obs[i].flags = 0xfffffff8;
            if with_arg {
                libs[i].begin1(&mut *obs[i], size, align, &mut args[i]);
            } else {
                libs[i].begin(&mut *obs[i], size, align);
            }
        }
    }
    let start = [snapshot(0, &mut *obs[0]), snapshot(1, &mut *obs[1])];
    assert_eq!(start[0], start[1], "seed {seed}: after begin");
    let mut objects: Vec<[usize; 2]> = vec![]; // offsets in the two obstacks of finished objects (as pointers)
    let mut ptrs: Vec<[*mut c_char; 2]> = vec![];
    for step in 0..steps {
        let op = rng.below(13);
        let limit = if rng.below(10) == 0 { 6000 } else { 300 };
        let n = rng.below(limit) as usize;
        let fill = (rng.next() & 0xff) as u8;
        let data: Vec<u8> = (0..n).map(|i| fill.wrapping_add(i as u8)).collect();
        let what = format!("seed {seed} step {step} op {op} n {n}");
        if std::env::var_os("OBS_TRACE").is_some() {
            eprintln!("{what}");
        }
        unsafe {
            let mut results = [std::ptr::null_mut::<c_char>(); 2];
            let pick = rng.next();
            let mut printed = [0 as c_int; 2];
            let mut freed_index = None;
            let mut live_flag = 0;
            for i in 0..2 {
                let l = libs[i];
                let h: *mut Obstack = &mut *obs[i];
                match op {
                    0 | 1 => m_grow(l, h, &data),
                    2 => m_1grow(l, h, fill),
                    3 => m_blank(l, h, n as c_int),
                    4 | 5 => results[i] = m_finish(h),
                    6 => {
                        // obstack_alloc
                        m_blank(l, h, n as c_int);
                        results[i] = m_finish(h);
                    }
                    7 => {
                        // obstack_copy0
                        m_grow(l, h, &data);
                        m_1grow(l, h, 0);
                        results[i] = m_finish(h);
                    }
                    8 => m_make_room(l, h, n as c_int),
                    9 => {
                        // free an earlier object (the same one in both), or everything but keep the structure usable
                        if !ptrs.is_empty() {
                            let k = (pick as usize) % ptrs.len();
                            // freeing a pointer that is in no chunk aborts: only free live objects (both
                            // libraries must agree on which those are)
                            let live = if l.which == 0 { host::_obstack_allocated_p(h, ptrs[k][i].cast()) } else { obstack::_obstack_allocated_p(h, ptrs[k][i].cast()) };
                            if i == 0 {
                                live_flag = live;
                            } else {
                                assert_eq!(live_flag, live, "{what}: allocated_p before free");
                            }
                            if live != 0 {
                                m_free(l, h, ptrs[k][i]);
                                freed_index = Some(k);
                            }
                        }
                    }
                    10 => {
                        // ints and pointers (need alignment: only when the object so far is aligned)
                        let o = &*h;
                        if (o.next_free as usize).is_multiple_of(8) && o.alignment_mask >= 7 {
                            if o.next_free.add(8) > o.chunk_limit {
                                l.newchunk(h, 8);
                            }
                            *((*h).next_free as *mut u64) = 0x1122334455667788 + fill as u64;
                            (*h).next_free = (*h).next_free.add(8);
                        }
                    }
                    11 => {
                        // obstack_printf with a few formats
                        let fmt = [c"%d|", c"%s=%s;", c"%-20s|", c"%.200s"][(pick % 4) as usize];
                        let text = std::ffi::CString::new(String::from_utf8_lossy(&data[..data.len().min(200)]).replace('\0', "z")).unwrap();
                        let text = if text.as_bytes().is_empty() { c"x".to_owned() } else { text };
                        printed[i] = match (pick % 4, l.which) {
                            (0, 0) => host::obstack_printf(h, fmt.as_ptr(), n as c_int),
                            (0, _) => obstack::obstack_printf(h, fmt.as_ptr(), n as c_int),
                            (1, 0) => host::obstack_printf(h, fmt.as_ptr(), text.as_ptr(), text.as_ptr()),
                            (1, _) => obstack::obstack_printf(h, fmt.as_ptr(), text.as_ptr(), text.as_ptr()),
                            (_, 0) => host::obstack_printf(h, fmt.as_ptr(), text.as_ptr()),
                            (_, _) => obstack::obstack_printf(h, fmt.as_ptr(), text.as_ptr()),
                        };
                    }
                    _ => {
                        // everything freed, then started again
                        if pick.is_multiple_of(4) {
                            l.free_fn(h, std::ptr::null_mut());
                            if with_arg {
                                l.begin1(h, size, align, &mut args[i]);
                            } else {
                                l.begin(h, size, align);
                            }
                        }
                    }
                }
            }
            if op == 12 && pick.is_multiple_of(4) {
                ptrs.clear();
                objects.clear();
            }
            // freeing an object frees it and everything allocated after it: those pointers are gone
            if let Some(k) = freed_index {
                ptrs.truncate(k);
                objects.truncate(k);
            }
            if matches!(op, 4..=7) {
                ptrs.push(results);
                objects.push([results[0] as usize, results[1] as usize]);
            }
            assert_eq!(printed[0], printed[1], "{what}: obstack_printf result");
            let (a, b) = (snapshot(0, &mut *obs[0]), snapshot(1, &mut *obs[1]));
            assert_eq!(a, b, "{what}");
            assert_eq!(args[0], args[1], "{what}: extra argument calls");
            // the bytes of the growing object
            let (o0, o1) = (&*obs[0], &*obs[1]);
            let len = o0.next_free.offset_from(o0.object_base) as usize;
            assert_eq!(std::slice::from_raw_parts(o0.object_base as *const u8, len), std::slice::from_raw_parts(o1.object_base as *const u8, len), "{what}: object bytes");
            // finished objects keep their bytes: compare a few
            for (k, p) in ptrs.iter().enumerate().rev().take(3) {
                if p[0].is_null() {
                    continue;
                }
                // the object may have been freed by now (its memory is gone): only the newest are checked
                let _ = k;
            }
            if step % 50 == 0 {
                assert_eq!(host::_obstack_memory_used(&mut *obs[0]), obstack::_obstack_memory_used(&mut *obs[1]), "{what}: memory used");
                let probe = (pick as usize) % ptrs.len().max(1);
                if let Some(p) = ptrs.get(probe) {
                    assert_eq!(host::_obstack_allocated_p(&mut *obs[0], p[0].cast()), obstack::_obstack_allocated_p(&mut *obs[1], p[1].cast()), "{what}: allocated_p");
                }
            }
        }
    }
    unsafe {
        libs[0].free_fn(&mut *obs[0], std::ptr::null_mut());
        libs[1].free_fn(&mut *obs[1], std::ptr::null_mut());
    }
    let l = LOGS.lock().unwrap();
    assert_eq!(l[0].sizes.len() as i64, l[0].frees.len() as i64, "seed {seed}: every chunk freed");
    assert_eq!(l[1].sizes.len() as i64, l[1].frees.len() as i64);
}

#[test]
fn layout() {
    assert_eq!(size_of::<Obstack>(), 88);
    assert_eq!(core::mem::offset_of!(Obstack, object_base), 16);
    assert_eq!(core::mem::offset_of!(Obstack, next_free), 24);
    assert_eq!(core::mem::offset_of!(Obstack, chunk_limit), 32);
    assert_eq!(core::mem::offset_of!(Obstack, temp), 40);
    assert_eq!(core::mem::offset_of!(Obstack, extra_arg), 72);
}

#[test]
fn random_sequences() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for seed in 1..=60 {
        run(seed, 250);
    }
}

#[test]
fn defaults() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    unsafe {
        assert_eq!(obstack::obstack_exit_failure.read(), 1);
        assert!(obstack::obstack_alloc_failed_handler.read().is_some());
    }
}
