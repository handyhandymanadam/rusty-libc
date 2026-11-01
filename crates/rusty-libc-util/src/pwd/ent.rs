//! Enumeration of passwd, group and shadow through the name service switch (see rusty-libc-core nssent).
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use super::*;
use rusty_libc_core::lock::RawMutex;

/// The engine's state (`nip`, `startp`, `last_nip` of glibc) and the stream the `files` source reads.
pub(crate) struct EntInner {
    st: nssent::EntState,
    slot: Option<FdStream>,
}

/// One enumerable database: its state under its own lock (always taken, as glibc's `__libc_lock_lock (lock)` in
/// getXXent.c and setXXent.c). The lock inside `EntState` is not used: the whole state sits behind this one.
pub(crate) struct EntDb {
    lock: RawMutex,
    inner: SyncCell<EntInner>,
}

impl EntDb {
    pub(crate) const fn new() -> EntDb {
        EntDb { lock: RawMutex::new(), inner: SyncCell::new(EntInner { st: nssent::EntState::new(), slot: None }) }
    }
    /// Run `f` on the state with the lock held.
    fn with<R>(&self, f: impl FnOnce(&mut EntInner) -> R) -> R {
        self.lock.lock_always();
        // SAFETY: `inner` is only reached here, with `lock` held, so this is the only access.
        let r = f(unsafe { &mut *self.inner.as_ptr() });
        self.lock.unlock_always();
        r
    }
}

pub(crate) static PW_DB: EntDb = EntDb::new();
pub(crate) static GR_DB: EntDb = EntDb::new();
pub(crate) static SP_DB: EntDb = EntDb::new();

/// The names a database goes by in nsswitch.conf and in its modules' functions.
pub(crate) struct EntNames {
    pub db: &'static [u8],
    pub set: &'static [u8],
    pub get: &'static [u8],
    pub end: &'static [u8],
}

pub(crate) const PW_NAMES: EntNames = EntNames { db: b"passwd", set: b"setpwent", get: b"getpwent_r", end: b"endpwent" };
pub(crate) const GR_NAMES: EntNames = EntNames { db: b"group", set: b"setgrent", get: b"getgrent_r", end: b"endgrent" };
pub(crate) const SP_NAMES: EntNames = EntNames { db: b"shadow", set: b"setspent", get: b"getspent_r", end: b"endspent" };

/// `setent` of the `files` source: open the file, or rewind it when already open.
fn setent<E: Entry>(slot: &mut Option<FdStream>) -> i32 {
    match slot {
        Some(s) => {
            s.rewind();
            ST_SUCCESS
        }
        None => match FdStream::open(E::PATH) {
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

fn endent(slot: &mut Option<FdStream>) {
    if let Some(mut s) = slot.take() {
        s.close();
    }
}

/// The sources of an enumeration: the built-in file reader for `files` and `compat`, plug-in modules for the rest.
struct PwOps<'a, 'o, 'b, E: Entry> {
    slot: &'a mut Option<FdStream>,
    out: Option<&'o mut Out<'b, E>>,
    names: &'static EntNames,
}

/// Is `src` answered by the file reader? (`files`, and `compat` where the compat module has no such function.)
fn reads_files(src: &nssmod::Source, func: &[u8]) -> bool {
    nssent::is_files(src) && !(src.is(b"compat") && compat_fn(func) != 0)
}

/// The function `func` of the module `src` names (`compat`: rusty-libc-net's compat module).
fn source_fn(src: &nssmod::Source, func: &[u8]) -> usize {
    if src.is(b"compat") { compat_fn(func) } else { nssmod::function(src.name(), func) }
}

impl<E: Entry> nssent::EntOps for PwOps<'_, '_, '_, E> {
    fn has(&mut self, src: &nssmod::Source, f: nssent::Fn3) -> bool {
        let n = match f {
            nssent::Fn3::Set => self.names.set,
            nssent::Fn3::Get => self.names.get,
            nssent::Fn3::End => self.names.end,
        };
        if reads_files(src, n) {
            return true;
        }
        if src.is(b"dns") {
            return false;
        }
        source_fn(src, n) != 0
    }
    fn call_set(&mut self, src: &nssmod::Source, stay: i32) -> i32 {
        if reads_files(src, self.names.set) {
            return setent::<E>(self.slot);
        }
        let f = source_fn(src, self.names.set);
        if f == 0 {
            return ST_UNAVAIL;
        }
        // SAFETY: `f` is a module's `_nss_*_setXXent`, whose C type is this one.
        let f: unsafe extern "C" fn(c_int) -> c_int = unsafe { core::mem::transmute(f) };
        // SAFETY: a plain value argument.
        unsafe { f(stay) }
    }
    fn call_get(&mut self, src: &nssmod::Source) -> i32 {
        let Some(out) = self.out.as_mut() else { return ST_UNAVAIL };
        if reads_files(src, self.names.get) {
            if self.slot.is_none() {
                let saved = errno::get();
                let st = setent::<E>(self.slot);
                errno::set(saved); // glibc: __nss_files_data_open restores errno after the implicit open
                if st != ST_SUCCESS {
                    return st;
                }
            }
            let Some(slot) = self.slot.as_mut() else { return ST_UNAVAIL };
            return internal_getent::<E, _>(slot, &mut *out.res, &mut *out.buf);
        }
        let f = source_fn(src, self.names.get);
        if f == 0 {
            return ST_UNAVAIL;
        }
        // SAFETY: `f` is a module's `_nss_*_getXXent_r`, whose C type is this one.
        let f: unsafe extern "C" fn(*mut E, *mut u8, usize, *mut c_int) -> c_int = unsafe { core::mem::transmute(f) };
        // SAFETY: the caller's result and buffer (valid for the call) and the thread's errno.
        let st = unsafe { f(&raw mut *out.res, out.buf.as_mut_ptr(), out.buf.len(), errno::location()) };
        if (-2..=1).contains(&st) { st } else { ST_UNAVAIL }
    }
    fn call_end(&mut self, src: &nssmod::Source) {
        if reads_files(src, self.names.end) {
            endent(self.slot);
            return;
        }
        let f = source_fn(src, self.names.end);
        if f != 0 {
            // SAFETY: `f` is a module's `_nss_*_endXXent`, whose C type is this one.
            let f: unsafe extern "C" fn() -> c_int = unsafe { core::mem::transmute(f) };
            // SAFETY: no arguments.
            unsafe { f() };
        }
    }
}

/// `setXXent` for a database of this file.
pub(crate) fn db_setent<E: Entry>(db: &EntDb, names: &'static EntNames) {
    db.with(|d| {
        let mut ops = PwOps::<E> { slot: &mut d.slot, out: None, names };
        d.st.setent(names.db, 0, &mut ops, false);
    })
}

/// `endXXent`
pub(crate) fn db_endent<E: Entry>(db: &EntDb, names: &'static EntNames) {
    db.with(|d| {
        if !d.st.is_started() {
            return;
        }
        let mut ops = PwOps::<E> { slot: &mut d.slot, out: None, names };
        d.st.endent(names.db, &mut ops);
    })
}

/// `getXXent_r`: 0 with the entry in `out` (and its result pointer set), ENOENT at the end, ERANGE or the module's errno.
pub(crate) fn db_getent<E: Entry>(db: &EntDb, names: &'static EntNames, out: &mut Out<E>) -> c_int {
    let rc = db.with(|d| {
        let mut ops = PwOps::<E> { slot: &mut d.slot, out: Some(&mut *out), names };
        d.st.getent(names.db, &mut ops, false, &|| true)
    });
    out.finish(rc == 0);
    rc
}
