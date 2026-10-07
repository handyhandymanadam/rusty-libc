use crate::lock::RawMutex;
use crate::nssmod::{self, Order, Source, ACT_CONTINUE, ACT_MERGE, ACT_RETURN, NSS_NOTFOUND, NSS_SUCCESS, NSS_TRYAGAIN, NSS_UNAVAIL};

const CONF_DBS: usize = 16;
type Slot = ([u8; 12], u8, Order, bool);
struct Overrides {
    lock: RawMutex,
    e: core::cell::UnsafeCell<[Slot; CONF_DBS]>,
}
unsafe impl Sync for Overrides {}
static OVERRIDES: Overrides = Overrides { lock: RawMutex::new(), e: core::cell::UnsafeCell::new([([0; 12], 0, Order::EMPTY, false); CONF_DBS]) };

pub fn configure(db: &[u8], spec: &[u8]) -> bool {
    let Some(o) = nssmod::parse_sources(spec) else { return false };
    if db.len() > 12 {
        return false;
    }
    OVERRIDES.lock.lock_always();
    let tab = unsafe { &mut *OVERRIDES.e.get() };
    let idx = tab.iter().position(|c| c.3 && &c.0[..c.1 as usize] == db).or_else(|| tab.iter().position(|c| !c.3));
    let ok = if let Some(i) = idx {
        tab[i].0[..db.len()].copy_from_slice(db);
        tab[i].1 = db.len() as u8;
        tab[i].2 = o;
        tab[i].3 = true;
        true
    } else {
        false
    };
    OVERRIDES.lock.unlock_always();
    ok
}

pub fn overridden(db: &[u8]) -> Option<Order> {
    OVERRIDES.lock.lock_always();
    let tab = unsafe { &*OVERRIDES.e.get() };
    let r = tab.iter().find(|c| c.3 && &c.0[..c.1 as usize] == db).map(|c| c.2);
    OVERRIDES.lock.unlock_always();
    r
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fn3 {
    Set,
    Get,
    End,
}

pub trait EntOps {
    fn has(&mut self, src: &Source, f: Fn3) -> bool;
    fn call_set(&mut self, src: &Source, stayopen: i32) -> i32;
    fn call_get(&mut self, src: &Source) -> i32;
    fn call_end(&mut self, src: &Source);
}

pub struct EntState {
    started: u8,
    ord: Order,
    nip: Option<usize>,
    start_idx: usize,
    last: Option<usize>,
    stay_tmp: i32,
    pub lock: RawMutex,
}

unsafe impl Sync for EntState {}

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
    fn setup(&mut self, db: &[u8], f: Fn3, all: bool, ops: &mut dyn EntOps) -> i32 {
        if self.started == 0 || all {
            let o = nssmod::order(db);
            self.ord = o;
            if o.n == 0 {
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

    pub fn setent(&mut self, db: &[u8], stayopen: i32, ops: &mut dyn EntOps, has_stay: bool) {
        let mut no_more = self.setup(db, Fn3::Set, true, ops);
        while no_more == 0 {
            let mut i = self.nip.unwrap_or(0);
            let is_last = Some(i) == self.last;
            let st = ops.call_set(&self.ord.e[i], if has_stay { self.stay_tmp } else { 0 });
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

    pub fn getent(&mut self, db: &[u8], ops: &mut dyn EntOps, has_stay: bool, h_internal: &dyn Fn() -> bool) -> i32 {
        let mut status = NSS_NOTFOUND;
        let mut no_more = self.setup(db, Fn3::Get, false, ops);
        while no_more == 0 {
            let mut i = self.nip.unwrap_or(0);
            let is_last = Some(i) == self.last;
            status = ops.call_get(&self.ord.e[i]);
            if status == NSS_TRYAGAIN && h_internal() && crate::errno::get() == ERANGE {
                break;
            }
            loop {
                no_more = if status == NSS_SUCCESS && self.ord.e[i].action(status) == ACT_MERGE { 1 } else { next2(&self.ord, &mut i, Fn3::Get, status, false, ops) };
                self.nip = Some(i);
                if is_last {
                    self.last = Some(i);
                }
                if no_more == 0 {
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

pub trait MergeOps {
    fn save(&mut self) -> i32;
    fn merge(&mut self) -> i32;
    fn restore(&mut self) -> i32;
}

pub fn dispatch(db: &[u8], func: &[u8], files: &dyn Fn() -> i32, call: &dyn Fn(usize, *mut i32) -> i32, mut merge: Option<&mut dyn MergeOps>) -> i32 {
    let order = nssmod::order(db);
    let mut status = NSS_UNAVAIL;
    let mut do_merge = false;
    for src in &order.e[..order.n] {
        if is_files(src) {
            status = files();
        } else {
            let f = if src.is(b"dns") { 0 } else { nssmod::function(src.name(), func) };
            if f == 0 {
                if src.action(NSS_UNAVAIL) != ACT_CONTINUE {
                    break;
                }
                continue;
            }
            let mut e: i32 = 0;
            status = call(f, &mut e);
            if !(-2..=1).contains(&status) {
                status = NSS_UNAVAIL;
            }
            if status != NSS_SUCCESS && status != NSS_NOTFOUND && e != 0 {
                crate::errno::set(e);
            }
        }
        if status == NSS_TRYAGAIN && crate::errno::get() == ERANGE {
            break;
        }
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
                check_merge!(match merge.as_deref_mut() {
                    Some(m) => m.merge(),
                    None => 22,
                });
                do_merge = false;
            } else {
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

pub fn is_files(src: &Source) -> bool {
    src.is(b"files") || src.is(b"compat")
}

