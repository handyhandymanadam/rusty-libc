//! The text of RPC errors (`clnt_sperror`, `clnt_sperrno`, `clnt_spcreateerror`) against glibc.
use super::*;
use core::ffi::CStr;

unsafe extern "C" fn fake_geterr(cl: *mut CLIENT, e: *mut rpc_err) {
    unsafe { *e = *((*cl).cl_private as *const rpc_err) };
}

static FAKE_OPS: clnt_ops = clnt_ops { cl_call: None, cl_abort: None, cl_geterr: Some(fake_geterr), cl_freeres: None, cl_destroy: None, cl_control: None };

fn text(p: *mut c_char) -> Option<String> {
    if p.is_null() { None } else { Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned()) }
}

#[test]
fn sperrno_all_codes() {
    let _g = lock();
    let apis = both();
    for stat in -3..60 {
        let t: Vec<_> = apis.iter().map(|(_, a)| text(unsafe { (a.clnt_sperrno)(stat) })).collect();
        assert_eq!(t[0], t[1], "status {stat}");
        assert!(t[0].is_some());
    }
}

#[test]
fn sperror_texts() {
    let _g = lock();
    let apis = both();
    let msgs = [c"msg", c"", c"a longer message: with colon", c"percent %s %d"];
    let mut n = 0;
    for stat in 0..30 {
        for msg in msgs {
            for variant in 0..12 {
                let mut e = rpc_err::zeroed();
                e.re_status = stat;
                match variant {
                    0 => {}
                    1 => e.ru.RE_errno = 2,
                    2 => e.ru.RE_errno = 111,
                    3 => e.ru.RE_errno = 0,
                    4 => e.ru.RE_errno = 1000,
                    5 => e.ru.RE_errno = -1,
                    6 => e.ru.RE_vers = rpc_vers { low: 2, high: 4 },
                    7 => e.ru.RE_vers = rpc_vers { low: 0, high: u64::MAX },
                    8 => e.ru.RE_why = AUTH_TOOWEAK,
                    9 => e.ru.RE_why = 42,
                    10 => e.ru.RE_why = AUTH_OK,
                    _ => e.ru.RE_lb = rpc_lb { s1: -5, s2: 77 },
                }
                let mut why_variants = vec![e];
                if stat == RPC_AUTHERROR {
                    for w in 0..10 {
                        let mut e2 = e;
                        e2.ru.RE_why = w;
                        why_variants.push(e2);
                    }
                }
                for e in why_variants {
                    let mut er = e;
                    let mut cl = CLIENT { cl_auth: core::ptr::null_mut(), cl_ops: &FAKE_OPS, cl_private: (&mut er as *mut rpc_err).cast() };
                    let t: Vec<_> = apis.iter().map(|(_, a)| text(unsafe { (a.clnt_sperror)(&mut cl, msg.as_ptr()) })).collect();
                    assert_eq!(t[0], t[1], "status {stat} variant {variant} msg {msg:?}");
                    n += 1;
                }
            }
        }
    }
    assert!(n > 1000);
}

#[test]
fn sperror_texts_for_every_errno() {
    let _g = lock();
    let apis = both();
    for errno in -2..200 {
        for stat in [RPC_CANTSEND, RPC_CANTRECV] {
            let mut e = rpc_err::zeroed();
            e.re_status = stat;
            e.ru.RE_errno = errno;
            let mut cl = CLIENT { cl_auth: core::ptr::null_mut(), cl_ops: &FAKE_OPS, cl_private: (&mut e as *mut rpc_err).cast() };
            let t: Vec<_> = apis.iter().map(|(_, a)| text(unsafe { (a.clnt_sperror)(&mut cl, c"x".as_ptr()) })).collect();
            assert_eq!(t[0], t[1], "errno {errno}");
        }
    }
}

#[test]
fn spcreateerror_texts() {
    let _g = lock();
    let apis = both();
    for stat in 0..30 {
        for errno in [0, 2, 98, 1234] {
            for status in [0, RPC_TIMEDOUT, 99] {
                let t: Vec<_> = apis
                    .iter()
                    .map(|(_, a)| unsafe {
                        let ce = (a.__rpc_thread_createerr)();
                        (*ce).cf_stat = stat;
                        (*ce).cf_error = rpc_err::zeroed();
                        if stat == RPC_PMAPFAILURE {
                            (*ce).cf_error.re_status = status;
                        } else {
                            (*ce).cf_error.ru.RE_errno = errno;
                        }
                        text((a.clnt_spcreateerror)(c"clnt_create".as_ptr()))
                    })
                    .collect();
                assert_eq!(t[0], t[1], "cf_stat {stat} errno {errno} status {status}");
            }
        }
    }
}

#[test]
fn thread_variables_are_per_thread() {
    let _g = lock();
    // the per-thread accessors give each thread its own object; the first thread to ask gets the
    // exported compatibility variables
    for (name, a) in both() {
        let main_ce = unsafe { (a.__rpc_thread_createerr)() } as usize;
        let main_ce2 = unsafe { (a.__rpc_thread_createerr)() } as usize;
        assert_eq!(main_ce, main_ce2, "{name}: stable within a thread");
        let other = std::thread::spawn(move || unsafe { (a.__rpc_thread_createerr)() } as usize).join().unwrap();
        assert_ne!(other, main_ce, "{name}");
        let fds = unsafe { (a.__rpc_thread_svc_fdset)() } as usize;
        let other = std::thread::spawn(move || unsafe { (a.__rpc_thread_svc_fdset)() } as usize).join().unwrap();
        assert_ne!(fds, other, "{name}");
        assert!(unsafe { (a._rpc_dtablesize)() } >= 3);
    }
}
