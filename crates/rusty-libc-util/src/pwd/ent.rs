use super::*;

pub(crate) struct EntDb {
    pub(crate) st: nssent::EntState,
    pub(crate) slot: Option<FdStream>,
}

impl EntDb {
    pub(crate) const fn new() -> EntDb {
        EntDb { st: nssent::EntState::new(), slot: None }
    }
}

pub(crate) static mut PW_DB: EntDb = EntDb::new();
pub(crate) static mut GR_DB: EntDb = EntDb::new();
pub(crate) static mut SP_DB: EntDb = EntDb::new();

pub(crate) struct EntNames {
    pub db: &'static [u8],
    pub set: &'static [u8],
    pub get: &'static [u8],
    pub end: &'static [u8],
}

pub(crate) const PW_NAMES: EntNames = EntNames { db: b"passwd", set: b"setpwent", get: b"getpwent_r", end: b"endpwent" };
pub(crate) const GR_NAMES: EntNames = EntNames { db: b"group", set: b"setgrent", get: b"getgrent_r", end: b"endgrent" };
pub(crate) const SP_NAMES: EntNames = EntNames { db: b"shadow", set: b"setspent", get: b"getspent_r", end: b"endspent" };

unsafe fn setent<E: Entry>(slot: &mut Option<FdStream>) -> i32 {
    unsafe {
        match slot {
            Some(s) => {
                s.rewind();
                ST_SUCCESS
            }
            None => match FdStream::open(E::PATH.as_ptr()) {
                Ok(s) => {
                    *slot = Some(s);
                    ST_SUCCESS
                }
                Err(e) => {
                    errno::set(e);
                    if e == EAGAIN { ST_TRYAGAIN } else { ST_UNAVAIL }
                }
            },
        }
    }
}

fn endent(slot: &mut Option<FdStream>) {
    if let Some(mut s) = slot.take() {
        s.close();
    }
}

struct PwOps<'a, E: Entry> {
    slot: &'a mut Option<FdStream>,
    res: *mut E,
    buf: *mut u8,
    len: usize,
    names: &'static EntNames,
}

impl<E: Entry> nssent::EntOps for PwOps<'_, E> {
    fn has(&mut self, src: &nssmod::Source, f: nssent::Fn3) -> bool {
        if nssent::is_files(src) {
            return true;
        }
        if src.is(b"dns") {
            return false;
        }
        let n = match f {
            nssent::Fn3::Set => self.names.set,
            nssent::Fn3::Get => self.names.get,
            nssent::Fn3::End => self.names.end,
        };
        nssmod::function(src.name(), n) != 0
    }
    fn call_set(&mut self, src: &nssmod::Source, stay: i32) -> i32 {
        unsafe {
            if nssent::is_files(src) {
                return setent::<E>(self.slot);
            }
            let f = nssmod::function(src.name(), self.names.set);
            if f == 0 {
                return ST_UNAVAIL;
            }
            let f: unsafe extern "C" fn(c_int) -> c_int = core::mem::transmute(f);
            f(stay)
        }
    }
    fn call_get(&mut self, src: &nssmod::Source) -> i32 {
        unsafe {
            if nssent::is_files(src) {
                if self.slot.is_none() {
                    let saved = errno::get();
                    let st = setent::<E>(self.slot);
                    errno::set(saved);
                    if st != ST_SUCCESS {
                        return st;
                    }
                }
                return internal_getent::<E, _>(self.slot.as_mut().unwrap(), self.res, self.buf, self.len);
            }
            let f = nssmod::function(src.name(), self.names.get);
            if f == 0 {
                return ST_UNAVAIL;
            }
            let f: unsafe extern "C" fn(*mut E, *mut u8, usize, *mut c_int) -> c_int = core::mem::transmute(f);
            let st = f(self.res, self.buf, self.len, errno::location());
            if (-2..=1).contains(&st) { st } else { ST_UNAVAIL }
        }
    }
    fn call_end(&mut self, src: &nssmod::Source) {
        unsafe {
            if nssent::is_files(src) {
                endent(self.slot);
                return;
            }
            let f = nssmod::function(src.name(), self.names.end);
            if f != 0 {
                let f: unsafe extern "C" fn() -> c_int = core::mem::transmute(f);
                f();
            }
        }
    }
}

pub(crate) unsafe fn db_setent<E: Entry>(db: *mut EntDb, names: &'static EntNames) {
    unsafe {
        let db = &mut *db;
        db.st.lock.lock_always();
        let mut ops = PwOps::<E> { slot: &mut db.slot, res: null_mut(), buf: null_mut(), len: 0, names };
        db.st.setent(names.db, 0, &mut ops, false);
        db.st.lock.unlock_always();
    }
}

pub(crate) unsafe fn db_endent<E: Entry>(db: *mut EntDb, names: &'static EntNames) {
    unsafe {
        let db = &mut *db;
        if !db.st.is_started() {
            return;
        }
        db.st.lock.lock_always();
        let mut ops = PwOps::<E> { slot: &mut db.slot, res: null_mut(), buf: null_mut(), len: 0, names };
        db.st.endent(names.db, &mut ops);
        db.st.lock.unlock_always();
    }
}

pub(crate) unsafe fn db_getent_r<E: Entry>(db: *mut EntDb, names: &'static EntNames, resbuf: *mut E, buffer: *mut u8, buflen: usize, result: *mut *mut E) -> c_int {
    unsafe {
        let db = &mut *db;
        db.st.lock.lock_always();
        let mut ops = PwOps::<E> { slot: &mut db.slot, res: resbuf, buf: buffer, len: buflen, names };
        let rc = db.st.getent(names.db, &mut ops, false, &|| true);
        db.st.lock.unlock_always();
        *result = if rc == 0 { resbuf } else { null_mut() };
        rc
    }
}
