//! Thread-safety tests for the stream locks, on the host with std threads (`multithreaded()` reads
//! glibc's own flag here, which std sets when it spawns the first thread). Each test takes `LOCK`
//! because the open-stream list and the standard streams are global.
use crate::LOCK;
use crate::file::{self, File};
use crate::file_api::{clearerr, fclose, fflush, fgets, flockfile, fopen, fputs, fread, ftrylockfile, funlockfile, fwrite, getc, ungetc};
use crate::file_extra::{feof_unlocked, fputs_unlocked, getc_unlocked, putc_unlocked};
use crate::flock::FLock;
use core::ffi::{c_char, c_int};
use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy)]
struct Sp(*mut File);
unsafe impl Send for Sp {}
unsafe impl Sync for Sp {}
impl Sp {
    fn get(self) -> *mut File {
        self.0
    }
}

fn tmp(name: &str) -> CString {
    let dir = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
    CString::new(format!("{dir}/libc-stdio-thread-{}-{name}", std::process::id())).unwrap()
}

fn line(t: usize, s: usize) -> String {
    let len = 5 + (s * 7 + t * 13) % 120;
    let filler: String = (0..len).map(|i| (b'a' + ((t + s + i) % 26) as u8) as char).collect();
    format!("T{t} S{s} {filler} E\n")
}

#[test]
fn recursive_lock_basics() {
    let l = FLock::new();
    l.lock();
    l.lock();
    assert!(l.try_lock());
    assert!(l.held_by_me());
    // another thread cannot take it, however deep we are
    let lp = &l as *const FLock as usize;
    let other = || std::thread::spawn(move || unsafe { (*(lp as *const FLock)).try_lock() }).join().unwrap();
    assert!(!other());
    assert!(l.unlock());
    assert!(l.unlock());
    assert!(!other());
    assert!(l.unlock());
    assert!(!l.held_by_me());
    assert!(other());
    // a stray unlock by a thread that does not own it does nothing
    assert!(!l.unlock());
}

#[test]
fn lines_from_many_threads_are_whole_and_ordered() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmp("lines");
    let f = unsafe { fopen(path.as_ptr(), c"w".as_ptr()) };
    assert!(!f.is_null());
    let sp = Sp(f);
    const NT: usize = 6;
    const N: usize = 3000;
    let hs: Vec<_> = (0..NT)
        .map(|t| {
            std::thread::spawn(move || {
                let f = sp.get();
                for s in 0..N {
                    let l = line(t, s);
                    let c = CString::new(l.clone()).unwrap();
                    unsafe {
                        match s % 4 {
                            0 => {
                                fputs(c.as_ptr(), f);
                            }
                            1 => {
                                fwrite(l.as_ptr().cast(), 1, l.len(), f);
                            }
                            2 => {
                                flockfile(f);
                                for b in l.bytes() {
                                    crate::file_api::putc(c_int::from(b), f);
                                }
                                funlockfile(f);
                            }
                            _ => {
                                flockfile(f);
                                for b in l.bytes() {
                                    putc_unlocked(c_int::from(b), f);
                                }
                                funlockfile(f);
                            }
                        }
                    }
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(unsafe { fclose(f) }, 0);
    let text = std::fs::read_to_string(path.to_str().unwrap()).unwrap();
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
    let mut next = [0usize; NT];
    let mut total = 0;
    for l in text.lines() {
        total += 1;
        let mut it = l.split(' ');
        let t: usize = it.next().unwrap()[1..].parse().unwrap();
        let s: usize = it.next().unwrap()[1..].parse().unwrap();
        assert_eq!(format!("{l}\n"), line(t, s), "torn line");
        assert_eq!(s, next[t], "thread {t} out of order or lost");
        next[t] += 1;
    }
    assert_eq!(total, NT * N);
}

#[test]
fn single_bytes_are_never_lost() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmp("bytes");
    let f = unsafe { fopen(path.as_ptr(), c"w".as_ptr()) };
    let sp = Sp(f);
    let hs: Vec<_> = (0..8u8)
        .map(|t| {
            std::thread::spawn(move || {
                for _ in 0..50_000 {
                    unsafe { crate::file_api::putc(c_int::from(b'A' + t), sp.get()) };
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    unsafe { fclose(f) };
    let data = std::fs::read(path.to_str().unwrap()).unwrap();
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
    assert_eq!(data.len(), 8 * 50_000);
    for t in 0..8u8 {
        assert_eq!(data.iter().filter(|&&b| b == b'A' + t).count(), 50_000);
    }
}

#[test]
fn readers_consume_each_byte_once() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmp("readers");
    let mut x = 7u32;
    let data: Vec<u8> = (0..400_000)
        .map(|_| {
            x = x.wrapping_mul(1103515245).wrapping_add(12345);
            if (x >> 8).is_multiple_of(40) { b'\n' } else { 1 + ((x >> 16) % 255) as u8 }
        })
        .collect();
    std::fs::write(path.to_str().unwrap(), &data).unwrap();
    let want: u64 = data.iter().map(|&b| u64::from(b)).sum();
    let f = unsafe { fopen(path.as_ptr(), c"r".as_ptr()) };
    let sp = Sp(f);
    let sum = AtomicU64::new(0);
    let count = AtomicU64::new(0);
    std::thread::scope(|s| {
        for _ in 0..4 {
            s.spawn(|| {
                let f = sp.get();
                let mut buf = [0u8; 4096];
                let mut n = 0u64;
                loop {
                    unsafe {
                        match n % 3 {
                            0 => {
                                let c = getc(f);
                                if c < 0 {
                                    return;
                                }
                                sum.fetch_add(c as u64, Ordering::Relaxed);
                                count.fetch_add(1, Ordering::Relaxed);
                            }
                            1 => {
                                if fgets(buf.as_mut_ptr().cast::<c_char>(), 100, f).is_null() {
                                    return;
                                }
                                let k = buf.iter().position(|&c| c == 0).unwrap();
                                sum.fetch_add(buf[..k].iter().map(|&c| u64::from(c)).sum(), Ordering::Relaxed);
                                count.fetch_add(k as u64, Ordering::Relaxed);
                            }
                            _ => {
                                let k = fread(buf.as_mut_ptr().cast(), 1, 1 + (n as usize) % 3000, f);
                                sum.fetch_add(buf[..k].iter().map(|&c| u64::from(c)).sum(), Ordering::Relaxed);
                                count.fetch_add(k as u64, Ordering::Relaxed);
                                if k == 0 {
                                    return;
                                }
                            }
                        }
                    }
                    n += 1;
                }
            });
        }
    });
    unsafe { fclose(f) };
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
    assert_eq!(count.load(Ordering::Relaxed), data.len() as u64);
    assert_eq!(sum.load(Ordering::Relaxed), want);
}

#[test]
fn flockfile_family_and_unlocked_functions() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmp("flock");
    let f = unsafe { fopen(path.as_ptr(), c"w+".as_ptr()) };
    let sp = Sp(f);
    let try_from_thread = move || std::thread::spawn(move || unsafe {
        let r = ftrylockfile(sp.get());
        if r == 0 {
            funlockfile(sp.get());
        }
        r
    })
    .join()
    .unwrap();
    unsafe {
        flockfile(f);
        flockfile(f);
        assert_eq!(ftrylockfile(f), 0, "owner re-locks");
        assert_ne!(try_from_thread(), 0);
        funlockfile(f);
        funlockfile(f);
        assert_ne!(try_from_thread(), 0, "one level still held");
        funlockfile(f);
        assert_eq!(try_from_thread(), 0);
        // held by another thread: the _unlocked functions must not wait for it
        let release = AtomicBool::new(false);
        let ready = AtomicBool::new(false);
        std::thread::scope(|s| {
            s.spawn(|| {
                flockfile(sp.get());
                ready.store(true, Ordering::SeqCst);
                while !release.load(Ordering::SeqCst) {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                funlockfile(sp.get());
            });
            while !ready.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            assert_ne!(ftrylockfile(f), 0);
            putc_unlocked(c_int::from(b'x'), f);
            fputs_unlocked(c"yz".as_ptr(), f);
            assert_eq!(feof_unlocked(f), 0);
            let _ = getc_unlocked(f);
            release.store(true, Ordering::SeqCst);
        });
        assert_eq!(ftrylockfile(f), 0);
        funlockfile(f);
        clearerr(f);
        let _ = ungetc(c_int::from(b'q'), f);
        fflush(f);
        fclose(f);
    }
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
}

#[test]
fn fopen_fclose_churn_with_fflush_null() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stop = AtomicBool::new(false);
    std::thread::scope(|s| {
        let flushers: Vec<_> = (0..2)
            .map(|_| {
                s.spawn(|| {
                    while !stop.load(Ordering::Relaxed) {
                        unsafe { fflush(core::ptr::null_mut()) };
                    }
                })
            })
            .collect();
        let churners: Vec<_> = (0..6)
            .map(|t| {
                s.spawn(move || {
                    let path = tmp(&format!("churn{t}"));
                    for i in 0..800 {
                        unsafe {
                            let f = fopen(path.as_ptr(), c"w".as_ptr());
                            assert!(!f.is_null());
                            fputs(c"churn\n".as_ptr(), f);
                            if i % 3 == 0 {
                                fflush(f);
                            }
                            assert_eq!(fclose(f), 0);
                        }
                    }
                    std::fs::remove_file(path.to_str().unwrap()).unwrap();
                })
            })
            .collect();
        for c in churners {
            c.join().unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        for f in flushers {
            f.join().unwrap();
        }
    });
    // the list is whole: a new stream works and fflush(NULL) succeeds
    let path = tmp("after");
    unsafe {
        let f = fopen(path.as_ptr(), c"w".as_ptr());
        fputs(c"x".as_ptr(), f);
        assert_eq!(fflush(core::ptr::null_mut()), 0);
        assert_eq!(fclose(f), 0);
    }
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
}

#[test]
fn fork_handlers_take_and_release_every_stream_lock() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmp("fork");
    let f = unsafe { fopen(path.as_ptr(), c"w".as_ptr()) }; // registers the handlers
    let sp = Sp(f);
    let try_from_thread = move || std::thread::spawn(move || unsafe {
        let r = ftrylockfile(sp.get());
        if r == 0 {
            funlockfile(sp.get());
        }
        r
    })
    .join()
    .unwrap();
    assert_eq!(try_from_thread(), 0);
    unsafe {
        rusty_libc_core::process::run_fork_prepare();
        // between prepare and the fork nobody else can use the stream
        assert_ne!(try_from_thread(), 0, "stream lock held by the forking thread");
        rusty_libc_core::process::run_fork_parent();
    }
    assert_eq!(try_from_thread(), 0, "released in the parent");
    // the child path: the forking thread unlocks the same way
    unsafe {
        rusty_libc_core::process::run_fork_prepare();
        rusty_libc_core::process::run_fork_child();
    }
    assert_eq!(try_from_thread(), 0, "released in the child");
    unsafe { fclose(f) };
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
}

#[test]
fn fork_handler_visiting_a_stream_twice_releases_it() {
    // the prepare walk restarts from the head when a stream is closed under it, so a stream can be grabbed twice;
    // the parent handler must still leave it unlocked (malloc/tst-malloc-fork-deadlock hung on such a stream)
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmp("forktwice");
    let f = unsafe { fopen(path.as_ptr(), c"w".as_ptr()) };
    let sp = Sp(f);
    let try_from_thread = move || std::thread::spawn(move || unsafe {
        let r = ftrylockfile(sp.get());
        if r == 0 {
            funlockfile(sp.get());
        }
        r
    })
    .join()
    .unwrap();
    unsafe {
        rusty_libc_core::process::run_fork_prepare();
        crate::file::fork_grab(f); // the second visit
        rusty_libc_core::process::run_fork_parent();
    }
    assert_eq!(try_from_thread(), 0, "released in the parent after a second visit");
    unsafe { fclose(f) };
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
}

#[test]
fn fork_handler_does_not_wait_for_a_stream_held_by_a_blocked_thread() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmp("forkhold");
    let f = unsafe { fopen(path.as_ptr(), c"w".as_ptr()) };
    let sp = Sp(f);
    let release = AtomicBool::new(false);
    let ready = AtomicBool::new(false);
    std::thread::scope(|s| {
        s.spawn(|| unsafe {
            flockfile(sp.get());
            ready.store(true, Ordering::SeqCst);
            while !release.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            funlockfile(sp.get());
        });
        while !ready.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let t0 = std::time::Instant::now();
        unsafe {
            rusty_libc_core::process::run_fork_prepare(); // gives up on the held stream after about 50 ms
            rusty_libc_core::process::run_fork_child(); // "child": the dead owner's lock is reset
        }
        assert!(t0.elapsed() < std::time::Duration::from_secs(5), "fork handler waited too long");
        // the stream is usable by this thread now (as in a child whose owner thread is gone)
        unsafe {
            assert_eq!(ftrylockfile(f), 0);
            funlockfile(f);
        }
        release.store(true, Ordering::SeqCst);
    });
    unsafe {
        // the former holder's late funlockfile did nothing (it no longer owns the lock)
        assert_eq!(ftrylockfile(f), 0);
        funlockfile(f);
        fclose(f);
    }
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
}

#[test]
fn exit_flush_does_not_wait_for_a_held_stream() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let path = tmp("exitflush");
    let f = unsafe { fopen(path.as_ptr(), c"w".as_ptr()) };
    unsafe { fputs(c"pending\n".as_ptr(), f) };
    let sp = Sp(f);
    let release = AtomicBool::new(false);
    let ready = AtomicBool::new(false);
    std::thread::scope(|s| {
        s.spawn(|| unsafe {
            flockfile(sp.get());
            ready.store(true, Ordering::SeqCst);
            while !release.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            funlockfile(sp.get());
        });
        while !ready.load(Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        // what exit runs: bounded wait for the held stream, then flush anyway
        file::flush_at_exit_for_tests();
        let text = std::fs::read_to_string(path.to_str().unwrap()).unwrap();
        assert_eq!(text, "pending\n", "exit flush must write the data even though the lock is held");
        release.store(true, Ordering::SeqCst);
    });
    unsafe { fclose(f) };
    std::fs::remove_file(path.to_str().unwrap()).unwrap();
}
