#![allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
//! Tests: behaviour next to the host glibc (usable sizes, alignment, argument rules), and stress
//! with a shadow table that checks every live block still holds its pattern.
use crate::*;
use core::ffi::c_void;
use std::sync::Mutex;

/// The tests below look at the main heap's layout (top chunk, fences, thresholds), so they take turns and every one runs on
/// the main arena (the test harness's threads would each get an arena of their own).
static LOCK: Mutex<()> = Mutex::new(());

fn guard() -> std::sync::MutexGuard<'static, ()> {
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    crate::heap::bind_main_arena();
    g
}

mod g {
    use core::ffi::c_void;
    unsafe extern "C" {
        pub fn malloc(n: usize) -> *mut c_void;
        pub fn free(p: *mut c_void);
        pub fn malloc_usable_size(p: *mut c_void) -> usize;
        pub fn posix_memalign(m: *mut *mut c_void, a: usize, n: usize) -> i32;
        pub fn mallopt(p: i32, v: i32) -> i32;
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 11) as usize % n
    }
}

fn fill(p: *mut u8, n: usize, seed: u8) {
    for i in 0..n {
        unsafe { *p.add(i) = seed.wrapping_add(i as u8).wrapping_mul(31) };
    }
}
fn check(p: *const u8, n: usize, seed: u8) -> bool {
    (0..n).all(|i| unsafe { *p.add(i) } == seed.wrapping_add(i as u8).wrapping_mul(31))
}
fn errno() -> i32 {
    rusty_libc_core::errno::get()
}

#[test]
fn edge_cases_match_glibc() {
    let _g = guard();
    unsafe {
        let p = malloc(0);
        let q = malloc(0);
        assert!(!p.is_null() && !q.is_null() && p != q, "malloc(0) gives distinct non-null blocks");
        assert!(realloc(p, 0).is_null(), "realloc(p, 0) frees and returns NULL");
        free(q);
        free(core::ptr::null_mut());
        let a = realloc(core::ptr::null_mut(), 10);
        assert!(!a.is_null());
        free(a);
        rusty_libc_core::errno::set(0);
        assert!(malloc(usize::MAX).is_null());
        assert_eq!(errno(), 12);
        rusty_libc_core::errno::set(0);
        assert!(calloc(1 << 62, 8).is_null());
        assert_eq!(errno(), 12);
        rusty_libc_core::errno::set(0);
        assert!(reallocarray(core::ptr::null_mut(), 1 << 62, 8).is_null());
        assert_eq!(errno(), 12);
        let mut m: *mut c_void = core::ptr::null_mut();
        assert_eq!(posix_memalign(&mut m, 3, 100), 22);
        assert_eq!(g::posix_memalign(&mut m, 3, 100), 22);
        assert_eq!(posix_memalign(&mut m, 8, 100), 0);
        free(m);
        assert_eq!(posix_memalign(&mut m, 64, 100), 0);
        assert_eq!(m as usize % 64, 0);
        free(m);
        assert_eq!(posix_memalign(&mut m, 32, 0), 0);
        assert!(!m.is_null());
        free(m);
        rusty_libc_core::errno::set(0);
        assert!(aligned_alloc(3, 100).is_null());
        assert_eq!(errno(), 22);
        rusty_libc_core::errno::set(0);
        assert!(aligned_alloc(0, 100).is_null());
        assert_eq!(errno(), 22);
        rusty_libc_core::errno::set(0);
        let al = aligned_alloc(64, 100);
        assert!(!al.is_null() && (al as usize).is_multiple_of(64) && errno() == 0);
        free(al);
        let ml = memalign(0, 100);
        assert!(!ml.is_null());
        free(ml);
        let ml = memalign(24, 100);
        assert!(!ml.is_null() && (ml as usize).is_multiple_of(32), "memalign rounds the alignment up to a power of two");
        free(ml);
        let v = valloc(10);
        assert_eq!(v as usize % 4096, 0);
        assert_eq!(malloc_usable_size(v), 24);
        free(v);
        let pv = pvalloc(10);
        assert_eq!(pv as usize % 4096, 0);
        assert_eq!(malloc_usable_size(pv), 4104);
        free(pv);
    }
}

#[test]
fn usable_sizes_and_alignment_match_glibc() {
    let _g = guard();
    unsafe {
        for n in (0..=3000usize).chain([4096, 8000, 65536, 100_000]) {
            let (a, b) = (malloc(n), g::malloc(n));
            assert!(!a.is_null());
            assert_eq!(a as usize % 16, 0, "alignment for n={n}");
            if n < 100_000 {
                // Both allocators give the minimal chunk (header 8, 16-byte steps, at least 24
                // usable) plus at most a leftover too small to split off (< 32 bytes).
                let minimal = (((n + 8 + 15) & !15).max(32)) - 8;
                let (ours, theirs) = (malloc_usable_size(a), g::malloc_usable_size(b));
                assert!(ours >= minimal && ours < minimal + 32, "usable size for n={n}: ours {ours}, minimal {minimal}");
                assert!(theirs >= minimal && theirs < minimal + 32, "glibc usable size for n={n}: {theirs}, minimal {minimal}");
            }
            assert!(malloc_usable_size(a) >= n);
            free(a);
            g::free(b);
        }
    }
}

#[test]
fn calloc_and_realloc_keep_contents() {
    let _g = guard();
    unsafe {
        for n in [1usize, 7, 24, 25, 100, 1000, 5000, 70_000, 300_000, 3_000_000] {
            let p = calloc(n, 1).cast::<u8>();
            assert!((0..n).all(|i| *p.add(i) == 0), "calloc zero n={n}");
            fill(p, n, 5);
            let mut cur = p;
            let mut size = n;
            for grow in [1usize, 17, 200, 4000, 100_000] {
                let new = size + grow;
                cur = realloc(cur.cast(), new).cast();
                assert!(!cur.is_null());
                assert!(check(cur, size, 5), "realloc grow kept data n={n} grow={grow}");
                fill(cur, new, 5);
                size = new;
            }
            for shrink in [3usize, 90, 5000] {
                if size > shrink + 1 {
                    let new = size - shrink;
                    cur = realloc(cur.cast(), new).cast();
                    assert!(check(cur, new, 5), "realloc shrink kept data");
                    size = new;
                }
            }
            free(cur.cast());
        }
    }
}

#[test]
fn memalign_sizes() {
    let _g = guard();
    unsafe {
        let mut live = Vec::new();
        for shift in 4..=20 {
            let a = 1usize << shift;
            for n in [0usize, 1, 24, 100, 5000, 200_000] {
                let p = memalign(a, n);
                assert!(!p.is_null(), "memalign({a},{n})");
                assert_eq!(p as usize % a, 0, "memalign({a},{n}) misaligned");
                assert!(malloc_usable_size(p) >= n);
                fill(p.cast(), n.min(malloc_usable_size(p)), 9);
                live.push((p, n));
            }
        }
        for (p, n) in live {
            assert!(check(p.cast(), n.min(malloc_usable_size(p)), 9));
            free(p);
        }
    }
}

#[test]
fn stress_random_operations() {
    let _g = guard();
    let mut rng = Rng(0x5eed_0001_dead_beef);
    let mut live: Vec<(*mut u8, usize, u8)> = Vec::new();
    unsafe {
        for round in 0..200_000usize {
            match rng.below(10) {
                0..=4 => {
                    let n = match rng.below(20) {
                        0 => rng.below(300_000),
                        1..=3 => rng.below(5000),
                        _ => rng.below(300),
                    };
                    let seed = rng.below(256) as u8;
                    let p = malloc(n).cast::<u8>();
                    assert!(!p.is_null());
                    assert_eq!(p as usize % 16, 0);
                    fill(p, n, seed);
                    live.push((p, n, seed));
                }
                5..=6 if !live.is_empty() => {
                    let i = rng.below(live.len());
                    let (p, n, seed) = live.swap_remove(i);
                    assert!(check(p, n, seed), "block corrupted before free (round {round})");
                    free(p.cast());
                }
                7..=8 if !live.is_empty() => {
                    let i = rng.below(live.len());
                    let (p, n, seed) = live[i];
                    assert!(check(p, n, seed), "block corrupted before realloc (round {round})");
                    let new = match rng.below(10) {
                        0 => rng.below(200_000),
                        1..=4 => n + rng.below(2000),
                        _ => rng.below(n + 1),
                    };
                    let q = realloc(p.cast(), new.max(1)).cast::<u8>();
                    assert!(!q.is_null());
                    let keep = n.min(new.max(1));
                    assert!(check(q, keep, seed), "realloc lost data (round {round})");
                    let seed2 = rng.below(256) as u8;
                    fill(q, new.max(1), seed2);
                    live[i] = (q, new.max(1), seed2);
                }
                _ => {
                    let a = 16usize << rng.below(8);
                    let n = rng.below(2000);
                    let p = memalign(a, n).cast::<u8>();
                    assert!(!p.is_null());
                    assert_eq!(p as usize % a, 0);
                    fill(p, n, 3);
                    live.push((p, n, 3));
                }
            }
            if round % 20_000 == 0 {
                for &(p, n, seed) in &live {
                    assert!(check(p, n, seed), "live block corrupted (round {round})");
                }
            }
        }
        for (p, n, seed) in live {
            assert!(check(p, n, seed));
            free(p.cast());
        }
    }
    let info = mallinfo2();
    assert!(info.fordblks >= info.keepcost, "free bytes include the top chunk");
}

#[test]
fn small_blocks_are_reused_and_memory_is_returned() {
    let _g = guard();
    unsafe {
        // The block that comes back must be the one just freed (the per-thread cache or the per-size list, last in first out). It
        // is asked for by its own usable size: malloc(100) may get a 128-byte chunk (a best-fit split whose remainder is too small
        // to stand alone, as in glibc), which free files under 128 while a second malloc(100) looks under 112. Whether that
        // happens depends on the heap the tests that ran before left behind, so asking for 100 again failed now and then.
        let p = malloc(100);
        let n = malloc_usable_size(p);
        free(p);
        assert_eq!(malloc(n), p, "a just-freed small block is handed out again");
        free(p);
        let before = mallinfo2();
        let big = malloc(10 * 1024 * 1024);
        let mid = mallinfo2();
        assert_eq!(mid.hblks, before.hblks + 1);
        assert!(mid.hblkhd >= before.hblkhd + 10 * 1024 * 1024);
        free(big);
        assert_eq!(mallinfo2().hblks, before.hblks);
        malloc_trim(0);
    }
}

#[test]
fn mallopt_results_match_glibc() {
    let _g = guard();
    unsafe {
        // Only parameters whose effect does not change later behaviour of the host allocator are
        // compared here; the C differential test covers the rest.
        for param in [1, -1, -2, -3, -4, -5, -6, -7, -8, -9, -10, -11, -12, 0, 2, 999] {
            for value in [0, 1, -1, -5, 100, 160, 161, 1000, 1 << 20, 1 << 25, (1 << 25) + 1, 1 << 26, 1 << 30, i32::MAX] {
                let (a, b) = (mallopt(param, value), g::mallopt(param, value));
                assert_eq!(a, b, "mallopt({param},{value})");
                mallopt(-3, 128 * 1024);
                g::mallopt(-3, 128 * 1024);
                mallopt(-1, 128 * 1024);
                g::mallopt(-1, 128 * 1024);
                mallopt(-2, 128 * 1024);
                g::mallopt(-2, 128 * 1024);
                mallopt(-4, 65536);
                g::mallopt(-4, 65536);
            }
        }
        // The loop above leaves M_PERTURB at 0xff and M_CHECK_ACTION at i32::MAX: put every
        // parameter back so later tests (which share this one heap) see the defaults.
        mallopt(-3, 128 * 1024);
        mallopt(-6, 0);
        mallopt(-5, 3);
        mallopt(1, 128);
    }
}

#[test]
fn double_free_aborts() {
    let _g = guard();
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            let p = malloc(100);
            free(p);
            free(p);
            libc::_exit(0);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        assert!(libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGABRT, "double free must raise SIGABRT, status={status}");
    }
}

/// Run `f` in a forked child; true if the child died of SIGABRT.
unsafe fn child_aborts(f: impl FnOnce()) -> bool {
    unsafe {
        let pid = libc::fork();
        if pid == 0 {
            f();
            libc::_exit(0);
        }
        let mut status = 0;
        libc::waitpid(pid, &mut status, 0);
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGABRT
    }
}

/// Root cause of the old order-dependent failure: `mallopt_results_match_glibc` left M_PERTURB set
/// to 0xff, and `free` overwrote the double-free mark with the perturb fill, so a later
/// `double_free_aborts` saw no SIGABRT. glibc detects a double free while perturbing, so we must too.
#[test]
fn double_free_aborts_with_perturb() {
    let _g = guard();
    unsafe {
        mallopt(-6, 0xff);
        let small = child_aborts(|| {
            let p = malloc(100);
            free(p);
            free(p);
        });
        let big = child_aborts(|| {
            let p = malloc(5000);
            let q = malloc(5000);
            free(p);
            free(p);
            free(q);
        });
        mallopt(-6, 0);
        assert!(small, "small double free must abort under M_PERTURB");
        assert!(big, "large double free must abort under M_PERTURB");
    }
}

/// The failing order found by `--shuffle-seed 1`: the mallopt grid, then double free, then
/// memalign up to 1 MiB. Each step must behave the same as when run alone.
#[test]
fn order_mallopt_then_double_free_then_memalign() {
    mallopt_results_match_glibc();
    double_free_aborts();
    memalign_sizes();
    assert_eq!(mallopt(-6, 0), 1);
}

/// Second root cause: when `mmap_threshold` had been raised (the mallopt grid and freeing big
/// mmapped blocks both do that), a request of 1 MiB or more was served from the heap, and when the
/// top chunk was too small `grow` mapped a fresh 1 MiB top that could not hold it, so `malloc` and
/// `memalign` returned NULL with gigabytes free. Every request must succeed.
#[test]
fn big_requests_succeed_when_top_is_small_and_threshold_is_high() {
    let _g = guard();
    unsafe {
        mallopt(-3, 32 * 1024 * 1024);
        let mut live = Vec::new();
        for k in 0..64usize {
            let small = malloc(k * 16 * 1024 + 1);
            assert!(!small.is_null());
            let big = malloc((1 << 20) + k * 4096);
            assert!(!big.is_null(), "malloc(1 MiB + {k} pages)");
            let al = memalign(1 << 20, k * 4096);
            assert!(!al.is_null(), "memalign(1 MiB, {k} pages)");
            assert_eq!(al as usize % (1 << 20), 0);
            live.push((small, big, al));
        }
        for (a, b, c) in live {
            free(a);
            free(b);
            free(c);
        }
        mallopt(-3, 128 * 1024);
    }
}

/// The failing order found by `--shuffle-seed 1` (first run) and `--shuffle-seed 11`: freeing a
/// big mmapped block raises the mmap threshold, then 1 MiB aligned requests must still work.
#[test]
fn order_calloc_realloc_then_memalign() {
    calloc_and_realloc_keep_contents();
    memalign_sizes();
}

/// Third root cause (rare segfault in `stress_random_operations`, depending on what ASLR put in the
/// page after a heap region): when the heap moved to a fresh mapping while the old top chunk was
/// under 64 bytes, the old top got no fence, so freeing the chunk before it read the header past
/// the end of the region. The old top must now end in a fence: an in-use 16-byte chunk, then a header.
#[test]
fn small_old_top_gets_a_fence_when_heap_moves() {
    let _g = guard();
    unsafe {
        mallopt(-3, 32 * 1024 * 1024);
        let mut keep = vec![malloc(24)]; // makes sure the heap exists, so it has a top
        while mallinfo2().keepcost >= 64 || mallinfo2().keepcost == 0 {
            keep.push(malloc(24));
        }
        let old = crate::heap::main_top();
        let before = mallinfo2().keepcost;
        assert!((32..64).contains(&before), "top is {before}");
        let big = malloc(4 << 20);
        assert!(!big.is_null());
        assert_ne!(crate::heap::main_top(), old, "the heap must have moved to a new mapping");
        let w = old.cast::<usize>();
        assert_eq!(*w.add(1), 16 | 1, "fence chunk header");
        assert_eq!(*w.add(3), 1, "header after the fence");
        // freeing the chunk just before the old top must not walk off the region
        let last = keep.pop().unwrap();
        free(last);
        free(big);
        for p in keep {
            free(p);
        }
        mallopt(-3, 128 * 1024);
    }
}

/// Threads get arenas of their own; blocks freed by another thread go back to the arena they came from; the counts of
/// mallinfo2 cover every arena; a thread that ends gives its cache and arena back.
#[test]
fn threads_use_arenas_of_their_own() {
    let _g = guard();
    unsafe {
        const N: usize = 4;
        let before = crate::heap::narenas();
        let blocks: Vec<Vec<usize>> = (0..N)
            .map(|t| {
                std::thread::spawn(move || {
                    let v: Vec<usize> = (0..3000)
                        .map(|i| {
                            let p = malloc(16 + (i * 7 % 600)) as *mut u8;
                            *p = t as u8;
                            p as usize
                        })
                        .collect();
                    crate::heap::thread_shutdown();
                    v
                })
            })
            .map(|h| h.join().unwrap())
            .collect();
        assert!(crate::heap::narenas() > before, "no arena was made");
        // every thread frees the blocks of the next one (no arena is that thread's own)
        let hs: Vec<_> = (0..N)
            .map(|t| {
                let v = blocks[(t + 1) % N].clone();
                std::thread::spawn(move || {
                    for &p in &v {
                        assert_eq!(*(p as *const u8), ((t + 1) % N) as u8);
                        free(p as *mut c_void);
                    }
                    crate::heap::thread_shutdown();
                })
            })
            .collect();
        for h in hs {
            h.join().unwrap();
        }
        let m = mallinfo2();
        assert!(m.uordblks + m.fordblks <= m.arena, "{} + {} > {}", m.uordblks, m.fordblks, m.arena);
    }
}
