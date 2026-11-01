//! Enumeration through the name service switch: `setpwent`/`getpwent_r`/`endpwent` and the other set/get/end triples.
//!
//! glibc walks the sources of a database (`passwd: files systemd`) one after the other: it reads every entry of the first
//! source (`files`: the file; any other name: the functions `_nss_NAME_setpwent`, `_nss_NAME_getpwent_r`, `_nss_NAME_endpwent`
//! of `libnss_NAME.so.2`), and when that one reports the end (NOTFOUND) it moves on to the next one as the `[STATUS=ACTION]`
//! list allows, calling that source's `set` function first. A source that lacks the function is skipped unless its UNAVAIL
//! action says to stop. The state (`nip`, `startp`, `last_nip` in glibc) is kept per database between the calls.
//! The engine here follows that algorithm (nss/getnssent_r.c and nss/nsswitch.c of glibc 2.43, read, not copied); a database
//! supplies [`EntOps`]: how to ask a source whether it has a function, and how to call it.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::SyncCell;
use crate::lock::RawMutex;
use crate::nssmod::{self, Order, Source, ACT_CONTINUE, ACT_MERGE, ACT_RETURN, NSS_NOTFOUND, NSS_SUCCESS, NSS_TRYAGAIN, NSS_UNAVAIL};

// ---------------------------------------------------------------- run-time configuration (__nss_configure_lookup)

const CONF_DBS: usize = 16;
type Slot = ([u8; 12], u8, Order, bool);
struct Overrides {
    lock: RawMutex,
    /// Only touched with `lock` held (`lock_always`: also before any thread exists, and in test binaries whose std
    /// threads do not mark the process multi-threaded).
    e: SyncCell<[Slot; CONF_DBS]>,
}
static OVERRIDES: Overrides = Overrides { lock: RawMutex::new(), e: SyncCell::new([([0; 12], 0, Order::EMPTY, false); CONF_DBS]) };

/// `__nss_configure_lookup`: from now on database `db` uses the sources of `spec` (an nsswitch.conf line without the `db:`),
/// whatever the file says. False when the line is invalid (glibc: -1 with EINVAL), the table is full or the name too long.
pub fn configure(db: &[u8], spec: &[u8]) -> bool {
    let Some(o) = nssmod::parse_sources(spec) else { return false };
    if db.len() > 12 {
        return false;
    }
    OVERRIDES.lock.lock_always();
    // SAFETY: the lock is held (the rule of `e`).
    let ok = unsafe {
        OVERRIDES.e.with_unsync(|tab| {
            let idx = tab.iter().position(|c| c.3 && &c.0[..c.1 as usize] == db).or_else(|| tab.iter().position(|c| !c.3));
            if let Some(i) = idx {
                tab[i].0[..db.len()].copy_from_slice(db);
                tab[i].1 = db.len() as u8;
                tab[i].2 = o;
                tab[i].3 = true;
                true
            } else {
                false
            }
        })
    };
    OVERRIDES.lock.unlock_always();
    ok
}

/// The sources set by [`configure`] for `db`, if any.
pub fn overridden(db: &[u8]) -> Option<Order> {
    OVERRIDES.lock.lock_always();
    // SAFETY: the lock is held (the rule of `e`).
    let r = unsafe { OVERRIDES.e.with_unsync(|tab| tab.iter().find(|c| c.3 && &c.0[..c.1 as usize] == db).map(|c| c.2)) };
    OVERRIDES.lock.unlock_always();
    r
}

// ---------------------------------------------------------------- the engine

/// The three entry points of a source for an enumeration.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fn3 {
    Set,
    Get,
    End,
}

/// What a database supplies: whether a source has a function, and calling it. `files` and `compat` are answered by the
/// database's own file reader, every other source by its plug-in module; `dns` has no enumeration functions.
pub trait EntOps {
    fn has(&mut self, src: &Source, f: Fn3) -> bool;
    fn call_set(&mut self, src: &Source, stayopen: i32) -> i32;
    /// The status of the next entry (the entry itself goes to the caller's buffers); `errno` is the real one.
    fn call_get(&mut self, src: &Source) -> i32;
    fn call_end(&mut self, src: &Source);
}

/// The state glibc keeps per database between the calls (`nip`, `startp`, `last_nip`).
pub struct EntState {
    /// 0: not used yet, 1: started, 2: the database has no source with the function
    started: u8,
    ord: Order,
    nip: Option<usize>,
    start_idx: usize,
    last: Option<usize>,
    stay_tmp: i32,
    pub lock: RawMutex,
}

impl EntState {
    pub const fn new() -> EntState {
        EntState { started: 0, ord: Order::EMPTY, nip: None, start_idx: 0, last: None, stay_tmp: 0, lock: RawMutex::new() }
    }
    pub fn is_started(&self) -> bool {
        self.started != 0
    }
}

impl Default for EntState {
    fn default() -> Self {
        Self::new()
    }
}

/// glibc's `__nss_lookup`: from `*nip` on, the first source that has `f`. 0 found, 1 no source left, -1 stopped by an action.
pub fn lookup(ord: &Order, nip: &mut usize, f: Fn3, ops: &mut dyn EntOps) -> i32 {
    let mut ok = ops.has(&ord.e[*nip], f);
    while !ok && ord.e[*nip].action(NSS_UNAVAIL) == ACT_CONTINUE && *nip + 1 < ord.n {
        *nip += 1;
        ok = ops.has(&ord.e[*nip], f);
    }
    if ok {
        0
    } else if *nip + 1 >= ord.n {
        1
    } else {
        -1
    }
}

/// glibc's `__nss_next2`: 0 moved to the next source that has `f`, 1 the action for `status` says stop, -1 no further source.
pub fn next2(ord: &Order, nip: &mut usize, f: Fn3, status: i32, all_values: bool, ops: &mut dyn EntOps) -> i32 {
    let cur = &ord.e[*nip];
    if all_values {
        if [NSS_TRYAGAIN, NSS_UNAVAIL, NSS_NOTFOUND, NSS_SUCCESS].iter().all(|&s| cur.action(s) == ACT_RETURN) {
            return 1;
        }
    } else if cur.action(status) == ACT_RETURN {
        return 1;
    }
    if *nip + 1 >= ord.n {
        return -1;
    }
    let mut ok;
    loop {
        *nip += 1;
        ok = ops.has(&ord.e[*nip], f);
        if ok || ord.e[*nip].action(NSS_UNAVAIL) != ACT_CONTINUE || *nip + 1 >= ord.n {
            break;
        }
    }
    if ok { 0 } else { -1 }
}

const ERANGE: i32 = 34;
const EAGAIN: i32 = 11;
const ENOENT: i32 = 2;

impl EntState {
    /// glibc's `setup`: position on the first source with `f` (`all`: from the top, reading the configuration afresh).
    fn setup(&mut self, db: &[u8], f: Fn3, all: bool, ops: &mut dyn EntOps) -> i32 {
        if self.started == 0 || all {
            // (a database without a line gets glibc's default list; an empty list stays empty)
            let o = nssmod::order(db);
            self.ord = o;
            if o.n == 0 {
                // no sources at all
                self.nip = None;
                self.started = 2;
                return 1;
            }
            let mut i = 0usize;
            let r = lookup(&self.ord, &mut i, f, ops);
            self.nip = Some(i);
            self.started = if r != 0 { 2 } else { 1 };
            self.start_idx = i;
            r
        } else if self.started == 2 {
            1
        } else {
            let mut i = self.nip.unwrap_or(self.start_idx);
            let r = lookup(&self.ord, &mut i, f, ops);
            self.nip = Some(i);
            r
        }
    }

    /// `setXXent`. `has_stay`: the database takes a `stayopen` argument that is remembered for later set calls.
    pub fn setent(&mut self, db: &[u8], stayopen: i32, ops: &mut dyn EntOps, has_stay: bool) {
        let mut no_more = self.setup(db, Fn3::Set, true, ops);
        while no_more == 0 {
            let mut i = self.nip.unwrap_or(0);
            let is_last = Some(i) == self.last;
            let st = ops.call_set(&self.ord.e[i], if has_stay { self.stay_tmp } else { 0 });
            // [SUCCESS=merge]: SUCCESS means "start the enumeration here"
            no_more = if self.ord.e[i].action(st) == ACT_MERGE { 1 } else { next2(&self.ord, &mut i, Fn3::Set, st, false, ops) };
            self.nip = Some(i);
            if is_last {
                self.last = Some(i);
            }
        }
        if has_stay {
            self.stay_tmp = stayopen;
        }
    }

    /// `endXXent`: nothing for a database never used.
    pub fn endent(&mut self, db: &[u8], ops: &mut dyn EntOps) {
        if self.started == 0 {
            return;
        }
        let mut no_more = self.setup(db, Fn3::End, true, ops);
        while no_more == 0 {
            let mut i = self.nip.unwrap_or(0);
            ops.call_end(&self.ord.e[i]);
            if Some(i) == self.last {
                break;
            }
            no_more = next2(&self.ord, &mut i, Fn3::End, 0, true, ops);
            self.nip = Some(i);
        }
        self.last = None;
        self.nip = None;
    }

    /// glibc's `__nss_getent_r`: 0 and an entry in the caller's buffers, or ENOENT at the end, or what TRYAGAIN means
    /// (the module's errno, ERANGE for a small buffer; EAGAIN when `h_internal()` says the error is not the internal one).
    pub fn getent(&mut self, db: &[u8], ops: &mut dyn EntOps, has_stay: bool, h_internal: &dyn Fn() -> bool) -> i32 {
        let mut status = NSS_NOTFOUND;
        let mut no_more = self.setup(db, Fn3::Get, false, ops);
        while no_more == 0 {
            let mut i = self.nip.unwrap_or(0);
            let is_last = Some(i) == self.last;
            status = ops.call_get(&self.ord.e[i]);
            // a buffer that is too small goes back to the caller whatever the TRYAGAIN action says
            if status == NSS_TRYAGAIN && h_internal() && crate::errno::get() == ERANGE {
                break;
            }
            loop {
                // [SUCCESS=merge]: SUCCESS means "return this entry"
                no_more = if status == NSS_SUCCESS && self.ord.e[i].action(status) == ACT_MERGE { 1 } else { next2(&self.ord, &mut i, Fn3::Get, status, false, ops) };
                self.nip = Some(i);
                if is_last {
                    self.last = Some(i);
                }
                if no_more == 0 {
                    // the next source's set function was not called yet
                    no_more = lookup(&self.ord, &mut i, Fn3::Set, ops);
                    self.nip = Some(i);
                    status = if no_more == 0 { ops.call_set(&self.ord.e[i], if has_stay { self.stay_tmp } else { 0 }) } else { NSS_NOTFOUND };
                }
                if !(no_more == 0 && status != NSS_SUCCESS) {
                    break;
                }
            }
        }
        match status {
            NSS_SUCCESS => 0,
            NSS_TRYAGAIN => {
                if h_internal() {
                    crate::errno::get()
                } else {
                    EAGAIN
                }
            }
            _ => ENOENT,
        }
    }
}

/// What a database that can merge the answers of two sources supplies (glibc's DEEPCOPY_FN and MERGE_FN: only `group`
/// has them). Each returns 0 or an errno value (ERANGE when the buffer is too small).
pub trait MergeOps {
    /// Keep a copy of the result the last source produced.
    fn save(&mut self) -> i32;
    /// Merge the saved copy with the result of the source just asked, leaving the merged entry as the result.
    fn merge(&mut self) -> i32;
    /// The source just asked found nothing: put the saved copy back as the result.
    fn restore(&mut self) -> i32;
}

/// A by-key lookup (`getpwnam_r`, `getservbyname_r`, ...) over the sources of `db`, like glibc's `getXXbyYY_r` loop
/// (nss/getXXbyYY_r.c): `files` (and `compat`) is answered by `files()`, every other name by the module function
/// `_nss_NAME_<func>` that `call` runs (it gets the function address and a place for the module's errno), and `dns` has no
/// such function. The status of each source decides, through its [STATUS=ACTION] list, whether the next one is asked
/// (SUCCESS with `continue` or `merge` goes on: the last source asked decides, its answer replaces the earlier one unless
/// they are merged). A source whose module cannot be loaded, or lacks the function, is skipped as far as its UNAVAIL action
/// allows and leaves the status of the one before it. A database with no source at all answers UNAVAIL: an empty list, or a
/// configuration glibc cannot parse, makes every lookup fail. `merge` is None for databases that cannot merge: `merge`
/// after a SUCCESS then fails with EINVAL, as in glibc.
///
/// (`files` and `call` are generic, not `&dyn`: each closure turned into a trait object costs a vtable of function pointers
/// in .data.rel.ro, which the loader relocates, and so writes, at every start of every process.)
pub fn dispatch(db: &[u8], func: &[u8], files: &impl Fn() -> i32, call: &impl Fn(usize, *mut i32) -> i32, merge: Option<&mut dyn MergeOps>) -> i32 {
    dispatch_all(db, func, files, call, merge, NO_DNS, 0)
}

/// No `dns` source function.
const NO_DNS: Option<&fn(*mut i32) -> i32> = None;

/// [`dispatch`] for the databases the `compat` source serves (passwd, group, shadow): a `compat` source runs `compat_fn` (the
/// address of `_nss_compat_<func>`, called through `call` like a module function) instead of the files reader; 0 keeps the
/// files reader for it.
pub fn dispatch_compat(db: &[u8], func: &[u8], files: &impl Fn() -> i32, call: &impl Fn(usize, *mut i32) -> i32, merge: Option<&mut dyn MergeOps>, compat_fn: usize) -> i32 {
    dispatch_all(db, func, files, call, merge, NO_DNS, compat_fn)
}

/// [`dispatch`] for a database the built-in `dns` source answers (`networks`): `dns` runs `dns` (it gets a place for the errno
/// of the lookup, like a module function) instead of being skipped as a source without the function.
pub fn dispatch_dns(db: &[u8], func: &[u8], files: &impl Fn() -> i32, call: &impl Fn(usize, *mut i32) -> i32, merge: Option<&mut dyn MergeOps>, dns: Option<&impl Fn(*mut i32) -> i32>) -> i32 {
    dispatch_all(db, func, files, call, merge, dns, 0)
}

fn dispatch_all(db: &[u8], func: &[u8], files: &impl Fn() -> i32, call: &impl Fn(usize, *mut i32) -> i32, mut merge: Option<&mut dyn MergeOps>, dns: Option<&impl Fn(*mut i32) -> i32>, compat_fn: usize) -> i32 {
    let order = nssmod::order(db);
    let mut status = NSS_UNAVAIL;
    let mut do_merge = false;
    for src in &order.e[..order.n] {
        let compat = compat_fn != 0 && src.is(b"compat");
        if is_files(src) && !compat {
            status = files();
        } else {
            let is_dns = src.is(b"dns");
            let f = if compat {
                compat_fn
            } else if is_dns {
                0
            } else {
                nssmod::function(src.name(), func)
            };
            if f == 0 && !(is_dns && dns.is_some()) {
                if src.action(NSS_UNAVAIL) != ACT_CONTINUE {
                    break;
                }
                continue;
            }
            let mut e: i32 = 0;
            status = match dns {
                Some(d) if is_dns => d(&mut e),
                _ => call(f, &mut e),
            };
            if !(-2..=1).contains(&status) {
                status = NSS_UNAVAIL;
            }
            if status != NSS_SUCCESS && status != NSS_NOTFOUND && e != 0 {
                crate::errno::set(e);
            }
        }
        // a buffer that is too small goes back to the caller whatever the TRYAGAIN action says (glibc looks at errno)
        if status == NSS_TRYAGAIN && crate::errno::get() == ERANGE {
            break;
        }
        // CHECK_MERGE: an error of the merge machinery ends the lookup
        macro_rules! check_merge {
            ($err:expr) => {{
                let err: i32 = $err;
                if err != 0 {
                    crate::errno::set(err);
                    status = if err == ERANGE { NSS_TRYAGAIN } else { NSS_UNAVAIL };
                    break;
                }
            }};
        }
        if do_merge {
            if status == NSS_SUCCESS {
                // the previous source's answer was saved: merge it with this one
                check_merge!(match merge.as_deref_mut() {
                    Some(m) => m.merge(),
                    None => 22,
                });
                do_merge = false;
            } else {
                // nothing here: the saved answer goes back and counts as this source's SUCCESS
                check_merge!(match merge.as_deref_mut() {
                    Some(m) => m.restore(),
                    None => 22,
                });
                status = NSS_SUCCESS;
            }
        }
        if src.action(status) == ACT_MERGE && status == NSS_SUCCESS {
            check_merge!(match merge.as_deref_mut() {
                Some(m) => m.save(),
                None => 22,
            });
            do_merge = true;
        }
        if src.action(status) == ACT_RETURN {
            break;
        }
    }
    status
}

/// The compat/files/dns split every database shares: which sources the built-in reader answers.
pub fn is_files(src: &Source) -> bool {
    src.is(b"files") || src.is(b"compat")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::vec::Vec;

    /// A scripted database: each source has a list of entry statuses for `get`, a status for `set`, and functions it has.
    struct Script {
        names: Vec<&'static [u8]>,
        sets: Vec<i32>,
        gets: Vec<Vec<i32>>,
        pos: Vec<usize>,
        has_set: Vec<bool>,
        has_get: Vec<bool>,
        log: RefCell<Vec<std::string::String>>,
    }
    impl Script {
        fn idx(&self, s: &Source) -> usize {
            self.names.iter().position(|n| s.name() == *n).unwrap()
        }
    }
    impl EntOps for Script {
        fn has(&mut self, s: &Source, f: Fn3) -> bool {
            let i = self.idx(s);
            match f {
                Fn3::Set => self.has_set[i],
                Fn3::Get => self.has_get[i],
                Fn3::End => true,
            }
        }
        fn call_set(&mut self, s: &Source, _st: i32) -> i32 {
            let i = self.idx(s);
            self.pos[i] = 0;
            self.log.borrow_mut().push(std::format!("set {}", i));
            self.sets[i]
        }
        fn call_get(&mut self, s: &Source) -> i32 {
            let i = self.idx(s);
            let p = self.pos[i];
            self.pos[i] += 1;
            self.log.borrow_mut().push(std::format!("get {}", i));
            let st = self.gets[i].get(p).copied().unwrap_or(NSS_NOTFOUND);
            if st == NSS_TRYAGAIN {
                crate::errno::set(11);
            }
            st
        }
        fn call_end(&mut self, s: &Source) {
            let i = self.idx(s);
            self.log.borrow_mut().push(std::format!("end {}", i));
        }
    }

    fn script(gets: Vec<Vec<i32>>) -> Script {
        let n = gets.len();
        let names: Vec<&'static [u8]> = [&b"a"[..], b"b", b"c"][..n].to_vec();
        Script { names, sets: std::vec![NSS_SUCCESS; n], gets, pos: std::vec![0; n], has_set: std::vec![true; n], has_get: std::vec![true; n], log: RefCell::new(Vec::new()) }
    }

    fn drain(db: &[u8], conf: &[u8], sc: &mut Script) -> Vec<(usize, i32)> {
        configure(db, conf);
        let mut st = EntState::new();
        let mut out = Vec::new();
        for _ in 0..20 {
            let rc = st.getent(db, sc, false, &|| true);
            if rc != 0 {
                break;
            }
            out.push((0, 0));
        }
        out
    }

    #[test]
    fn walks_sources_in_order_and_calls_set_on_the_next() {
        let mut sc = script(std::vec![std::vec![NSS_SUCCESS, NSS_SUCCESS], std::vec![NSS_SUCCESS]]);
        let out = drain(b"t1", b"a b", &mut sc);
        assert_eq!(out.len(), 3);
        let log = sc.log.borrow().join(",");
        // first source read to its end, then set and read on the second; no set on the first (not started)
        assert_eq!(log, "get 0,get 0,get 0,set 1,get 1,get 1");
    }

    #[test]
    fn notfound_return_stops_after_the_first_source() {
        let mut sc = script(std::vec![std::vec![NSS_SUCCESS], std::vec![NSS_SUCCESS]]);
        let out = drain(b"t2", b"a [NOTFOUND=return] b", &mut sc);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn success_merge_still_enumerates_all() {
        let mut sc = script(std::vec![std::vec![NSS_SUCCESS], std::vec![NSS_SUCCESS]]);
        let out = drain(b"t3", b"a [SUCCESS=merge] b", &mut sc);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn success_continue_moves_on_after_every_entry() {
        let mut sc = script(std::vec![std::vec![NSS_SUCCESS, NSS_SUCCESS], std::vec![NSS_SUCCESS, NSS_SUCCESS]]);
        let out = drain(b"t4", b"a [SUCCESS=continue] b", &mut sc);
        // glibc: after a's entry the action says continue: the call moves on to b at once and a's entry is dropped
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn source_without_set_is_skipped_when_unavail_continues() {
        let mut sc = script(std::vec![std::vec![], std::vec![NSS_SUCCESS], std::vec![NSS_SUCCESS]]);
        sc.has_set[1] = false;
        let out = drain(b"t5", b"a b c", &mut sc);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn tryagain_continues_by_default_and_stops_when_told() {
        // glibc 2.43: every status but SUCCESS continues unless the list says otherwise
        let mut sc = script(std::vec![std::vec![NSS_TRYAGAIN], std::vec![NSS_SUCCESS]]);
        assert_eq!(drain(b"t6", b"a b", &mut sc).len(), 1);
        let mut sc = script(std::vec![std::vec![NSS_TRYAGAIN], std::vec![NSS_SUCCESS]]);
        let n = drain(b"t6b", b"a [TRYAGAIN=return] b", &mut sc).len();
        assert_eq!(n, 0);
    }

    #[test]
    fn empty_list_enumerates_nothing_and_missing_line_means_files() {
        let mut sc = script(std::vec![std::vec![NSS_SUCCESS]]);
        assert_eq!(drain(b"t8", b"", &mut sc).len(), 0);
    }

    #[test]
    fn end_calls_every_source_with_the_function() {
        let mut sc = script(std::vec![std::vec![NSS_SUCCESS], std::vec![NSS_SUCCESS]]);
        configure(b"t7", b"a b");
        let mut st = EntState::new();
        assert_eq!(st.getent(b"t7", &mut sc, false, &|| true), 0);
        sc.log.borrow_mut().clear();
        st.endent(b"t7", &mut sc);
        assert_eq!(sc.log.borrow().join(","), "end 0,end 1");
    }
}
