use crate::netgrp::PrivNetgr;
use core::ffi::{c_char, c_int};
use core::ptr::null_mut;
use rusty_libc_core::errno;
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::nssmod;
use rusty_libc_util::pwd::{CompatFile, Gid, Group, Passwd, Spwd, Uid};

const TRYAGAIN: c_int = -2;
const UNAVAIL: c_int = -1;
const NOTFOUND: c_int = 0;
const SUCCESS: c_int = 1;
const RETURN: c_int = 2;
const ERANGE: c_int = 34;
const EAGAIN: c_int = 11;
const ENOMEM: c_int = 12;

unsafe fn slen(p: *const c_char) -> usize {
    unsafe { rusty_libc_mem::strlen(p) }
}

unsafe fn bytes<'a>(p: *const c_char) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(p as *const u8, slen(p)) }
}

unsafe fn live_eq(a: *const c_char, b: *const c_char) -> bool {
    unsafe {
        let mut i = 0;
        loop {
            let (x, y) = (*a.add(i), *b.add(i));
            if x != y {
                return false;
            }
            if x == 0 {
                return true;
            }
            i += 1;
        }
    }
}

unsafe fn strdup(p: *const c_char) -> *mut c_char {
    unsafe {
        let n = slen(p) + 1;
        let d = rusty_libc_malloc::malloc(n) as *mut c_char;
        if !d.is_null() {
            core::ptr::copy_nonoverlapping(p, d, n);
        }
        d
    }
}

unsafe fn free(p: *mut c_char) {
    unsafe { rusty_libc_malloc::free(p.cast()) }
}

struct Name(*mut c_char);
impl Name {
    unsafe fn of(p: *const c_char) -> Name {
        unsafe { Name(strdup(p)) }
    }
}
impl Drop for Name {
    fn drop(&mut self) {
        unsafe { free(self.0) }
    }
}

const DEFAULT_DOMAIN: &[u8] = b"";

struct Blacklist {
    data: *mut u8,
    current: usize,
    size: usize,
}

impl Blacklist {
    const fn new() -> Blacklist {
        Blacklist { data: null_mut(), current: 0, size: 0 }
    }
    unsafe fn reset(&mut self) {
        unsafe {
            if !self.data.is_null() {
                self.current = 1;
                *self.data = b'|';
                *self.data.add(1) = 0;
            } else {
                self.current = 0;
            }
        }
    }
    unsafe fn contains(&self, name: &[u8]) -> bool {
        unsafe {
            if self.data.is_null() {
                return false;
            }
            let hay = core::slice::from_raw_parts(self.data, self.current);
            let n = name.len() + 2;
            hay.windows(n).any(|w| w[0] == b'|' && w[n - 1] == b'|' && &w[1..n - 1] == name)
        }
    }
    unsafe fn store(&mut self, name: &[u8]) {
        unsafe {
            let n = name.len();
            if self.size == 0 {
                self.size = 512.max(2 * n);
                self.data = rusty_libc_malloc::malloc(self.size) as *mut u8;
                if self.data.is_null() {
                    return;
                }
                *self.data = b'|';
                *self.data.add(1) = 0;
                self.current = 1;
            } else {
                if self.contains(name) {
                    return;
                }
                if self.current + n + 1 >= self.size {
                    self.size += 256.max(2 * n);
                    let t = rusty_libc_malloc::realloc(self.data.cast(), self.size) as *mut u8;
                    if t.is_null() {
                        rusty_libc_malloc::free(self.data.cast());
                        self.data = null_mut();
                        self.size = 0;
                        return;
                    }
                    self.data = t;
                }
            }
            let at = self.data.add(self.current);
            core::ptr::copy_nonoverlapping(name.as_ptr(), at, n);
            *at.add(n) = b'|';
            *at.add(n + 1) = 0;
            self.current += n + 1;
        }
    }
    unsafe fn free(&mut self) {
        unsafe { rusty_libc_malloc::free(self.data.cast()) };
        *self = Blacklist::new();
    }
}

#[derive(Clone, Copy)]
enum Back {
    None,
    Files,
    Module(nssmod::Source),
}

fn backend(db: &[u8]) -> Back {
    let o = nssmod::order(db);
    if o.n == 0 {
        return Back::None;
    }
    let s = o.e[0];
    if s.is(b"files") {
        Back::Files
    } else if s.is_builtin() {
        Back::None
    } else {
        Back::Module(s)
    }
}

impl Back {
    fn module_fn(&self, func: &[u8]) -> usize {
        match self {
            Back::Module(s) => nssmod::function(s.name(), func),
            _ => 0,
        }
    }
}

type GetNam<E> = unsafe extern "C" fn(*const c_char, *mut E, *mut c_char, usize, *mut c_int) -> c_int;
type GetId<E> = unsafe extern "C" fn(u32, *mut E, *mut c_char, usize, *mut c_int) -> c_int;
type GetEnt<E> = unsafe extern "C" fn(*mut E, *mut c_char, usize, *mut c_int) -> c_int;
type SetEnt = unsafe extern "C" fn(c_int) -> c_int;
type EndEnt = unsafe extern "C" fn() -> c_int;

trait Kind: Sized + 'static {
    const DB: &'static [u8];
    const FILE: &'static [u8];
    const SET: &'static [u8];
    const GETNAM: &'static [u8];
    const GETENT: &'static [u8];
    const END: &'static [u8];
    fn zero() -> Self;
    fn name(&self) -> *const c_char;
    unsafe fn next(f: &mut CompatFile, r: *mut Self, buf: *mut u8, len: usize) -> c_int;
    fn files_slot() -> *mut Option<CompatFile>;
}

impl Kind for Passwd {
    const DB: &'static [u8] = b"passwd_compat";
    const FILE: &'static [u8] = rusty_libc_util::pwd::PASSWD_FILE;
    const SET: &'static [u8] = b"setpwent";
    const GETNAM: &'static [u8] = b"getpwnam_r";
    const GETENT: &'static [u8] = b"getpwent_r";
    const END: &'static [u8] = b"endpwent";
    fn zero() -> Passwd {
        Passwd { pw_name: null_mut(), pw_passwd: null_mut(), pw_uid: 0, pw_gid: 0, pw_gecos: null_mut(), pw_dir: null_mut(), pw_shell: null_mut() }
    }
    fn name(&self) -> *const c_char {
        self.pw_name
    }
    unsafe fn next(f: &mut CompatFile, r: *mut Passwd, buf: *mut u8, len: usize) -> c_int {
        unsafe { f.next_passwd(r, buf, len) }
    }
    fn files_slot() -> *mut Option<CompatFile> {
        static mut S: Option<CompatFile> = None;
        &raw mut S
    }
}

impl Kind for Group {
    const DB: &'static [u8] = b"group_compat";
    const FILE: &'static [u8] = rusty_libc_util::pwd::GROUP_FILE;
    const SET: &'static [u8] = b"setgrent";
    const GETNAM: &'static [u8] = b"getgrnam_r";
    const GETENT: &'static [u8] = b"getgrent_r";
    const END: &'static [u8] = b"endgrent";
    fn zero() -> Group {
        Group { gr_name: null_mut(), gr_passwd: null_mut(), gr_gid: 0, gr_mem: null_mut() }
    }
    fn name(&self) -> *const c_char {
        self.gr_name
    }
    unsafe fn next(f: &mut CompatFile, r: *mut Group, buf: *mut u8, len: usize) -> c_int {
        unsafe { f.next_group(r, buf, len) }
    }
    fn files_slot() -> *mut Option<CompatFile> {
        static mut S: Option<CompatFile> = None;
        &raw mut S
    }
}

impl Kind for Spwd {
    const DB: &'static [u8] = b"shadow_compat";
    const FILE: &'static [u8] = rusty_libc_util::pwd::SHADOW_FILE;
    const SET: &'static [u8] = b"setspent";
    const GETNAM: &'static [u8] = b"getspnam_r";
    const GETENT: &'static [u8] = b"getspent_r";
    const END: &'static [u8] = b"endspent";
    fn zero() -> Spwd {
        Spwd { sp_namp: null_mut(), sp_pwdp: null_mut(), sp_lstchg: 0, sp_min: 0, sp_max: 0, sp_warn: -1, sp_inact: -1, sp_expire: -1, sp_flag: !0 }
    }
    fn name(&self) -> *const c_char {
        self.sp_namp
    }
    unsafe fn next(f: &mut CompatFile, r: *mut Spwd, buf: *mut u8, len: usize) -> c_int {
        unsafe { f.next_spwd(r, buf, len) }
    }
    fn files_slot() -> *mut Option<CompatFile> {
        static mut S: Option<CompatFile> = None;
        &raw mut S
    }
}

static FILES_LOCK: RawMutex = RawMutex::new();

fn fail_open(e: c_int) -> c_int {
    errno::set(e);
    if e == EAGAIN { TRYAGAIN } else { UNAVAIL }
}

unsafe fn files_lookup<E: Kind>(res: *mut E, buf: *mut c_char, len: usize, errnop: *mut c_int, matches: &dyn Fn(&E) -> bool) -> c_int {
    unsafe {
        let mut f = match CompatFile::open(E::FILE) {
            Ok(f) => f,
            Err(e) => {
                *errnop = e;
                return fail_open(e);
            }
        };
        let st = loop {
            let st = E::next(&mut f, res, buf.cast(), len);
            if st != SUCCESS || matches(&*res) {
                break st;
            }
        };
        f.close();
        if st == TRYAGAIN || st == UNAVAIL {
            *errnop = errno::get();
        }
        st
    }
}

struct Impl<E: Kind> {
    back: Back,
    _e: core::marker::PhantomData<E>,
}

impl<E: Kind> Impl<E> {
    fn get() -> Impl<E> {
        Impl { back: backend(E::DB), _e: core::marker::PhantomData }
    }
    fn has(&self, func: &[u8]) -> bool {
        match self.back {
            Back::None => false,
            Back::Files => true,
            Back::Module(_) => self.back.module_fn(func) != 0,
        }
    }
    unsafe fn set(&self, stay: c_int) -> Option<c_int> {
        unsafe {
            match self.back {
                Back::None => None,
                Back::Files => {
                    FILES_LOCK.lock_always();
                    let slot = &mut *E::files_slot();
                    let st = match slot {
                        Some(f) => {
                            f.rewind();
                            SUCCESS
                        }
                        None => match CompatFile::open(E::FILE) {
                            Ok(f) => {
                                *slot = Some(f);
                                SUCCESS
                            }
                            Err(e) => fail_open(e),
                        },
                    };
                    FILES_LOCK.unlock_always();
                    Some(st)
                }
                Back::Module(_) => {
                    let f = self.back.module_fn(E::SET);
                    if f == 0 {
                        return None;
                    }
                    Some(core::mem::transmute::<usize, SetEnt>(f)(stay))
                }
            }
        }
    }
    unsafe fn end(&self) -> bool {
        unsafe {
            match self.back {
                Back::None => false,
                Back::Files => {
                    FILES_LOCK.lock_always();
                    if let Some(f) = (*E::files_slot()).take() {
                        f.close();
                    }
                    FILES_LOCK.unlock_always();
                    true
                }
                Back::Module(_) => {
                    let f = self.back.module_fn(E::END);
                    if f == 0 {
                        return false;
                    }
                    core::mem::transmute::<usize, EndEnt>(f)();
                    true
                }
            }
        }
    }
    unsafe fn getnam(&self, name: *const c_char, res: *mut E, buf: *mut c_char, len: usize, errnop: *mut c_int) -> c_int {
        unsafe {
            match self.back {
                Back::None => UNAVAIL,
                Back::Files => files_lookup::<E>(res, buf, len, errnop, &|e| !matches!(*name as u8, b'+' | b'-') && live_eq(name, e.name())),
                Back::Module(_) => match self.back.module_fn(E::GETNAM) {
                    0 => UNAVAIL,
                    f => core::mem::transmute::<usize, GetNam<E>>(f)(name, res, buf, len, errnop),
                },
            }
        }
    }
    unsafe fn getid(&self, func: &[u8], id: u32, res: *mut E, buf: *mut c_char, len: usize, errnop: *mut c_int, id_of: fn(&E) -> u32) -> c_int {
        unsafe {
            match self.back {
                Back::None => UNAVAIL,
                Back::Files => files_lookup::<E>(res, buf, len, errnop, &|e| id_of(e) == id && !matches!(*e.name() as u8, b'+' | b'-')),
                Back::Module(_) => match self.back.module_fn(func) {
                    0 => UNAVAIL,
                    f => core::mem::transmute::<usize, GetId<E>>(f)(id, res, buf, len, errnop),
                },
            }
        }
    }
    unsafe fn getent(&self, res: *mut E, buf: *mut c_char, len: usize, errnop: *mut c_int) -> c_int {
        unsafe {
            match self.back {
                Back::None => UNAVAIL,
                Back::Files => {
                    FILES_LOCK.lock_always();
                    let slot = &mut *E::files_slot();
                    if slot.is_none() {
                        match CompatFile::open(E::FILE) {
                            Ok(f) => *slot = Some(f),
                            Err(e) => {
                                FILES_LOCK.unlock_always();
                                *errnop = e;
                                return fail_open(e);
                            }
                        }
                    }
                    let st = E::next(slot.as_mut().unwrap(), res, buf.cast(), len);
                    FILES_LOCK.unlock_always();
                    if st == TRYAGAIN || st == UNAVAIL {
                        *errnop = errno::get();
                    }
                    st
                }
                Back::Module(_) => match self.back.module_fn(E::GETENT) {
                    0 => UNAVAIL,
                    f => core::mem::transmute::<usize, GetEnt<E>>(f)(res, buf, len, errnop),
                },
            }
        }
    }
}

trait Changes: Kind {
    const SHADOW: bool;
    unsafe fn need(&self) -> usize;
    unsafe fn copy_from(&mut self, src: &Self, buf: *mut c_char);
    unsafe fn free_strings(&mut self);
}

unsafe fn copy_field(dest: &mut *mut c_char, src: *const c_char, buf: &mut *mut c_char) {
    unsafe {
        if src.is_null() || *src == 0 {
            return;
        }
        let n = slen(src);
        if buf.is_null() {
            let old = *dest;
            *dest = strdup(src);
            let _ = old;
        } else if !dest.is_null() && slen(*dest) >= n {
            core::ptr::copy_nonoverlapping(src, *dest, n + 1);
        } else {
            *dest = *buf;
            core::ptr::copy_nonoverlapping(src, *dest, n + 1);
            *buf = buf.add(n + 1);
        }
    }
}

unsafe fn need_of(p: *const c_char) -> usize {
    if p.is_null() { 0 } else { unsafe { slen(p) + 1 } }
}

impl Changes for Passwd {
    const SHADOW: bool = false;
    unsafe fn need(&self) -> usize {
        unsafe { need_of(self.pw_passwd) + need_of(self.pw_gecos) + need_of(self.pw_dir) + need_of(self.pw_shell) }
    }
    unsafe fn copy_from(&mut self, src: &Passwd, buf: *mut c_char) {
        unsafe {
            let mut b = buf;
            copy_field(&mut self.pw_passwd, src.pw_passwd, &mut b);
            copy_field(&mut self.pw_gecos, src.pw_gecos, &mut b);
            copy_field(&mut self.pw_dir, src.pw_dir, &mut b);
            copy_field(&mut self.pw_shell, src.pw_shell, &mut b);
        }
    }
    unsafe fn free_strings(&mut self) {
        unsafe {
            free(self.pw_name);
            free(self.pw_passwd);
            free(self.pw_gecos);
            free(self.pw_dir);
            free(self.pw_shell);
        }
        *self = Passwd::zero();
    }
}

impl Changes for Spwd {
    const SHADOW: bool = true;
    unsafe fn need(&self) -> usize {
        unsafe { need_of(self.sp_pwdp) }
    }
    unsafe fn copy_from(&mut self, src: &Spwd, buf: *mut c_char) {
        unsafe {
            let mut b = buf;
            copy_field(&mut self.sp_pwdp, src.sp_pwdp, &mut b);
        }
        if src.sp_lstchg != 0 {
            self.sp_lstchg = src.sp_lstchg;
        }
        if src.sp_min != 0 {
            self.sp_min = src.sp_min;
        }
        if src.sp_max != 0 {
            self.sp_max = src.sp_max;
        }
        if src.sp_warn != -1 {
            self.sp_warn = src.sp_warn;
        }
        if src.sp_inact != -1 {
            self.sp_inact = src.sp_inact;
        }
        if src.sp_expire != -1 {
            self.sp_expire = src.sp_expire;
        }
        if src.sp_flag != !0 {
            self.sp_flag = src.sp_flag;
        }
    }
    unsafe fn free_strings(&mut self) {
        unsafe {
            free(self.sp_namp);
            free(self.sp_pwdp);
        }
        *self = Spwd::zero();
    }
}

struct PwEnt<E: Changes> {
    netgroup: bool,
    first: bool,
    files: bool,
    setent_status: c_int,
    stream: Option<CompatFile>,
    bl: Blacklist,
    pwd: E,
    ng: PrivNetgr,
}

impl<E: Changes> PwEnt<E> {
    fn new() -> PwEnt<E> {
        PwEnt { netgroup: false, first: false, files: true, setent_status: SUCCESS, stream: None, bl: Blacklist::new(), pwd: E::zero(), ng: PrivNetgr::new() }
    }
}

unsafe fn internal_setent<E: Changes>(ent: &mut PwEnt<E>, im: &Impl<E>, stayopen: c_int, needent: bool) -> c_int {
    unsafe {
        let mut status = SUCCESS;
        if ent.netgroup {
            ent.ng.end();
        }
        ent.first = false;
        ent.netgroup = false;
        ent.files = true;
        ent.setent_status = SUCCESS;
        ent.bl.reset();
        match &mut ent.stream {
            Some(f) => f.rewind(),
            None => match CompatFile::open(E::FILE) {
                Ok(f) => ent.stream = Some(f),
                Err(e) => status = fail_open(e),
            },
        }
        ent.pwd.free_strings();
        if needent && status == SUCCESS && let Some(st) = im.set(stayopen) {
            ent.setent_status = st;
        }
        status
    }
}

unsafe fn internal_endent<E: Changes>(ent: &mut PwEnt<E>) {
    unsafe {
        if let Some(f) = ent.stream.take() {
            f.close();
        }
        if ent.netgroup {
            ent.ng.end();
        }
        ent.first = false;
        ent.netgroup = false;
        ent.bl.reset();
        ent.pwd.free_strings();
    }
}

unsafe fn end_local<E: Changes>(ent: &mut PwEnt<E>) {
    unsafe {
        let saved = errno::get();
        internal_endent(ent);
        ent.bl.free();
        errno::set(saved);
    }
}

unsafe fn next_netgr<E: Changes>(name: Option<&[u8]>, result: *mut E, ent: &mut PwEnt<E>, im: &Impl<E>, group: *const c_char, buffer: *mut c_char, mut buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        if !im.has(E::GETNAM) {
            return UNAVAIL;
        }
        if E::SHADOW && ent.setent_status != SUCCESS {
            return ent.setent_status;
        }
        if ent.first {
            ent.ng = PrivNetgr::new();
            ent.ng.set(group as *const u8);
            ent.first = false;
        }
        loop {
            let (mut host, mut user, mut domain) = (null_mut(), null_mut(), null_mut());
            if ent.ng.get(&mut host, &mut user, &mut domain, buffer.cast(), buflen) != 1 {
                ent.ng.end();
                ent.netgroup = false;
                ent.pwd.free_strings();
                return RETURN;
            }
            if user.is_null() || *user as u8 == b'-' {
                continue;
            }
            if !domain.is_null() && bytes(domain) != DEFAULT_DOMAIN {
                continue;
            }
            if let Some(n) = name
                && bytes(user) != n
            {
                continue;
            }
            let p2len = ent.pwd.need();
            if p2len > buflen {
                *errnop = ERANGE;
                return TRYAGAIN;
            }
            let p2 = buffer.add(buflen - p2len);
            buflen -= p2len;
            if im.getnam(user, result, buffer, buflen, errnop) != SUCCESS {
                continue;
            }
            let rn = bytes((*result).name());
            if !ent.bl.contains(rn) {
                ent.bl.store(rn);
                (*result).copy_from(&ent.pwd, p2);
                break;
            }
        }
        SUCCESS
    }
}

unsafe fn next_nss<E: Changes>(result: *mut E, ent: &mut PwEnt<E>, im: &Impl<E>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        if !im.has(E::GETENT) {
            return UNAVAIL;
        }
        if !E::SHADOW && ent.setent_status != SUCCESS {
            return ent.setent_status;
        }
        let p2len = ent.pwd.need();
        if p2len > buflen {
            *errnop = ERANGE;
            return TRYAGAIN;
        }
        let p2 = buffer.add(buflen - p2len);
        let buflen = buflen - p2len;
        if !E::SHADOW {
            ent.first = false;
        }
        loop {
            let st = im.getent(result, buffer, buflen, errnop);
            if st != SUCCESS {
                return st;
            }
            if !ent.bl.contains(bytes((*result).name())) {
                break;
            }
        }
        (*result).copy_from(&ent.pwd, p2);
        SUCCESS
    }
}

unsafe fn nam_plususer<E: Changes>(name: *const c_char, result: *mut E, ent: &PwEnt<E>, im: &Impl<E>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        if !im.has(E::GETNAM) {
            return UNAVAIL;
        }
        let mut pwd = E::zero();
        pwd.copy_from(&*result, null_mut());
        let plen = pwd.need();
        if plen > buflen {
            pwd.free_strings();
            *errnop = ERANGE;
            return TRYAGAIN;
        }
        let p = buffer.add(buflen - plen);
        let st = im.getnam(name, result, buffer, buflen - plen, errnop);
        if st != SUCCESS {
            pwd.free_strings();
            return st;
        }
        if ent.bl.contains(bytes((*result).name())) {
            pwd.free_strings();
            return NOTFOUND;
        }
        (*result).copy_from(&pwd, p);
        pwd.free_strings();
        SUCCESS
    }
}

unsafe fn next_file<E: Changes>(result: *mut E, ent: &mut PwEnt<E>, im: &Impl<E>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        loop {
            let Some(stream) = ent.stream.as_mut() else { return UNAVAIL };
            let pos = stream.tell();
            let st = E::next(stream, result, buffer.cast(), buflen);
            if st == NOTFOUND {
                return NOTFOUND;
            }
            if st != SUCCESS {
                *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
                return st;
            }
            let nm = bytes((*result).name());
            match nm {
                [b'+' | b'-', ..] => {}
                _ => break,
            }
            match nm {
                [b'-', b'@', _, ..] => {
                    let mut buf2 = [0u8; 1024];
                    let mut ng = PrivNetgr::new();
                    ng.set(nm[2..].as_ptr());
                    let (mut host, mut user, mut domain) = (null_mut(), null_mut(), null_mut());
                    while ng.get(&mut host, &mut user, &mut domain, buf2.as_mut_ptr(), buf2.len()) != 0 {
                        if !user.is_null() && *user as u8 != b'-' {
                            ent.bl.store(bytes(user));
                        }
                    }
                    ng.end();
                }
                [b'+', b'@', _, ..] => {
                    ent.netgroup = true;
                    ent.first = true;
                    ent.pwd.free_strings();
                    ent.pwd.copy_from(&*result, null_mut());
                    let g = Name::of((*result).name().add(2));
                    let st = next_netgr(None, result, ent, im, g.0, buffer, buflen, errnop);
                    if st == RETURN {
                        continue;
                    }
                    return st;
                }
                [b'-', c, ..] if *c != b'@' => ent.bl.store(&nm[1..]),
                [b'+', c, ..] if *c != b'@' => {
                    let n = Name::of((*result).name().add(1));
                    let st = nam_plususer((*result).name().add(1), result, ent, im, buffer, buflen, errnop);
                    ent.bl.store(bytes(n.0));
                    if st == SUCCESS {
                        break;
                    } else if st == RETURN || st == NOTFOUND {
                        continue;
                    } else {
                        if st == TRYAGAIN {
                            stream_seek(ent, pos);
                            *errnop = ERANGE;
                        }
                        return st;
                    }
                }
                [b'+'] => {
                    ent.files = false;
                    ent.first = true;
                    ent.pwd.free_strings();
                    ent.pwd.copy_from(&*result, null_mut());
                    return next_nss(result, ent, im, buffer, buflen, errnop);
                }
                _ => {}
            }
        }
        SUCCESS
    }
}

fn stream_seek<E: Changes>(ent: &mut PwEnt<E>, pos: i64) {
    if let Some(s) = ent.stream.as_mut() {
        s.seek(pos);
    }
}

unsafe fn internal_getent<E: Changes>(pw: *mut E, ent: &mut PwEnt<E>, im: &Impl<E>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        if ent.netgroup {
            let st = next_netgr(None, pw, ent, im, core::ptr::null(), buffer, buflen, errnop);
            if st == RETURN { next_file(pw, ent, im, buffer, buflen, errnop) } else { st }
        } else if ent.files {
            next_file(pw, ent, im, buffer, buflen, errnop)
        } else {
            next_nss(pw, ent, im, buffer, buflen, errnop)
        }
    }
}

unsafe fn internal_getnam<E: Changes>(name: *const c_char, result: *mut E, ent: &mut PwEnt<E>, im: &Impl<E>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        let key = bytes(name);
        loop {
            let Some(stream) = ent.stream.as_mut() else { return UNAVAIL };
            let st = E::next(stream, result, buffer.cast(), buflen);
            if st == NOTFOUND {
                return NOTFOUND;
            }
            if st != SUCCESS {
                *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
                return st;
            }
            let nm = bytes((*result).name());
            match nm {
                [b'+' | b'-', ..] => {}
                _ => {
                    if nm == key {
                        return SUCCESS;
                    }
                    continue;
                }
            }
            match nm {
                [b'-', b'@', _, ..] => {
                    let g = Name::of((*result).name().add(2));
                    if crate::netgrp::innetgr(g.0, core::ptr::null(), name, core::ptr::null()) != 0 {
                        return NOTFOUND;
                    }
                    continue;
                }
                [b'+', b'@', _, ..] => {
                    let g = Name::of((*result).name().add(2));
                    if crate::netgrp::innetgr(g.0, core::ptr::null(), name, core::ptr::null()) != 0 {
                        let st = nam_plususer(name, result, ent, im, buffer, buflen, errnop);
                        if st == RETURN {
                            continue;
                        }
                        return st;
                    }
                    continue;
                }
                [b'-', c, ..] if *c != b'@' => {
                    if &nm[1..] == key {
                        return NOTFOUND;
                    }
                    continue;
                }
                [b'+', c, ..] if *c != b'@' => {
                    if key == &nm[1..] {
                        let st = nam_plususer(name, result, ent, im, buffer, buflen, errnop);
                        return if st == RETURN { NOTFOUND } else { st };
                    }
                }
                [b'+'] => {
                    let st = nam_plususer(name, result, ent, im, buffer, buflen, errnop);
                    if st == SUCCESS {
                        break;
                    }
                    return if st == RETURN { NOTFOUND } else { st };
                }
                _ => {}
            }
        }
        SUCCESS
    }
}

struct Global<E: Changes> {
    lock: RawMutex,
    ent: core::cell::UnsafeCell<Option<PwEnt<E>>>,
}
unsafe impl<E: Changes> Sync for Global<E> {}

static PW_EXT: Global<Passwd> = Global { lock: RawMutex::new(), ent: core::cell::UnsafeCell::new(None) };
static SP_EXT: Global<Spwd> = Global { lock: RawMutex::new(), ent: core::cell::UnsafeCell::new(None) };

impl<E: Changes> Global<E> {
    unsafe fn with<R>(&self, f: impl FnOnce(&mut PwEnt<E>) -> R) -> R {
        unsafe {
            self.lock.lock_always();
            let e = (*self.ent.get()).get_or_insert_with(PwEnt::new);
            let r = f(e);
            self.lock.unlock_always();
            r
        }
    }
}

unsafe fn compat_setent<E: Changes>(g: &Global<E>, stayopen: c_int) -> c_int {
    unsafe {
        let im = Impl::<E>::get();
        g.with(|e| internal_setent(e, &im, stayopen, true))
    }
}

unsafe fn compat_endent<E: Changes>(g: &Global<E>) -> c_int {
    unsafe {
        let im = Impl::<E>::get();
        g.with(|e| {
            if im.has(E::END) {
                im.end();
            }
            internal_endent(e);
            SUCCESS
        })
    }
}

unsafe fn compat_getent<E: Changes>(g: &Global<E>, res: *mut E, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        let im = Impl::<E>::get();
        g.with(|e| {
            let mut st = SUCCESS;
            if e.stream.is_none() {
                st = internal_setent(e, &im, 1, true);
            }
            if st == SUCCESS {
                st = internal_getent(res, e, &im, buffer, buflen, errnop);
            }
            st
        })
    }
}

unsafe fn compat_getnam<E: Changes>(name: *const c_char, res: *mut E, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        if matches!(*name as u8, b'-' | b'+') {
            return NOTFOUND;
        }
        let im = Impl::<E>::get();
        let mut ent = PwEnt::<E>::new();
        let mut st = internal_setent(&mut ent, &im, 0, false);
        if st == SUCCESS {
            st = internal_getnam(name, res, &mut ent, &im, buffer, buflen, errnop);
        }
        end_local(&mut ent);
        st
    }
}

unsafe fn uid_plususer(uid: Uid, result: *mut Passwd, im: &Impl<Passwd>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        if !im.has(b"getpwuid_r") {
            return UNAVAIL;
        }
        let mut pwd = Passwd::zero();
        pwd.copy_from(&*result, null_mut());
        let plen = pwd.need();
        if plen > buflen {
            pwd.free_strings();
            *errnop = ERANGE;
            return TRYAGAIN;
        }
        let p = buffer.add(buflen - plen);
        let st = im.getid(b"getpwuid_r", uid, result, buffer, buflen - plen, errnop, |e| e.pw_uid);
        if st == SUCCESS {
            (*result).copy_from(&pwd, p);
            pwd.free_strings();
            return SUCCESS;
        }
        pwd.free_strings();
        RETURN
    }
}

unsafe fn internal_getpwuid(uid: Uid, result: *mut Passwd, ent: &mut PwEnt<Passwd>, im: &Impl<Passwd>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        let innetgr_user = |g: &Name, result: *mut Passwd| crate::netgrp::innetgr(g.0, core::ptr::null(), (*result).pw_name, core::ptr::null()) != 0;
        loop {
            let Some(stream) = ent.stream.as_mut() else { return UNAVAIL };
            let st = stream.next_passwd(result, buffer.cast(), buflen);
            if st == NOTFOUND {
                return NOTFOUND;
            }
            if st != SUCCESS {
                *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
                return st;
            }
            let nm = bytes((*result).pw_name);
            match nm {
                [b'+' | b'-', ..] => {}
                _ => {
                    if (*result).pw_uid == uid {
                        return SUCCESS;
                    }
                    continue;
                }
            }
            match nm {
                [b'-', b'@', _, ..] => {
                    let g = Name::of((*result).pw_name.add(2));
                    let st = uid_plususer(uid, result, im, buffer, buflen, errnop);
                    if st == SUCCESS && innetgr_user(&g, result) {
                        return NOTFOUND;
                    }
                    continue;
                }
                [b'+', b'@', _, ..] => {
                    let g = Name::of((*result).pw_name.add(2));
                    let st = uid_plususer(uid, result, im, buffer, buflen, errnop);
                    if st == RETURN {
                        continue;
                    }
                    if st == SUCCESS {
                        if innetgr_user(&g, result) {
                            return SUCCESS;
                        }
                    } else {
                        return st;
                    }
                    continue;
                }
                [b'-', c, ..] if *c != b'@' => {
                    let g = Name::of((*result).pw_name.add(1));
                    let st = uid_plususer(uid, result, im, buffer, buflen, errnop);
                    if st == SUCCESS && innetgr_user(&g, result) {
                        return NOTFOUND;
                    }
                    continue;
                }
                [b'+', c, ..] if *c != b'@' => {
                    let n = Name::of((*result).pw_name.add(1));
                    let st = uid_plususer(uid, result, im, buffer, buflen, errnop);
                    if st == RETURN {
                        continue;
                    }
                    if st == SUCCESS {
                        if bytes(n.0) == bytes((*result).pw_name) {
                            return SUCCESS;
                        }
                    } else {
                        return st;
                    }
                    continue;
                }
                [b'+'] => {
                    let st = uid_plususer(uid, result, im, buffer, buflen, errnop);
                    if st == SUCCESS {
                        break;
                    }
                    return if st == RETURN { NOTFOUND } else { st };
                }
                _ => {}
            }
        }
        SUCCESS
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_setpwent(stayopen: c_int) -> c_int {
    unsafe { compat_setent(&PW_EXT, stayopen) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_endpwent() -> c_int {
    unsafe { compat_endent(&PW_EXT) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getpwent_r(pwd: *mut Passwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe { compat_getent(&PW_EXT, pwd, buffer, buflen, errnop) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getpwnam_r(name: *const c_char, pwd: *mut Passwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe { compat_getnam(name, pwd, buffer, buflen, errnop) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getpwuid_r(uid: Uid, pwd: *mut Passwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        let im = Impl::<Passwd>::get();
        let mut ent = PwEnt::<Passwd>::new();
        let mut st = internal_setent(&mut ent, &im, 0, false);
        if st == SUCCESS {
            st = internal_getpwuid(uid, pwd, &mut ent, &im, buffer, buflen, errnop);
        }
        end_local(&mut ent);
        st
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_setspent(stayopen: c_int) -> c_int {
    unsafe { compat_setent(&SP_EXT, stayopen) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_endspent() -> c_int {
    unsafe { compat_endent(&SP_EXT) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getspent_r(sp: *mut Spwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe { compat_getent(&SP_EXT, sp, buffer, buflen, errnop) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getspnam_r(name: *const c_char, sp: *mut Spwd, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe { compat_getnam(name, sp, buffer, buflen, errnop) }
}

struct GrEnt {
    files: bool,
    setent_status: c_int,
    stream: Option<CompatFile>,
    bl: Blacklist,
}

impl GrEnt {
    const fn new() -> GrEnt {
        GrEnt { files: true, setent_status: SUCCESS, stream: None, bl: Blacklist::new() }
    }
}

unsafe fn gr_setent(ent: &mut GrEnt, im: &Impl<Group>, stayopen: c_int, needent: bool) -> c_int {
    unsafe {
        let mut status = SUCCESS;
        ent.files = true;
        ent.bl.reset();
        match &mut ent.stream {
            Some(f) => f.rewind(),
            None => match CompatFile::open(Group::FILE) {
                Ok(f) => ent.stream = Some(f),
                Err(e) => status = fail_open(e),
            },
        }
        if needent && status == SUCCESS && let Some(st) = im.set(stayopen) {
            ent.setent_status = st;
        }
        status
    }
}

unsafe fn gr_endent(ent: &mut GrEnt) {
    unsafe {
        if let Some(f) = ent.stream.take() {
            f.close();
        }
        ent.bl.reset();
    }
}

unsafe fn gr_end_local(ent: &mut GrEnt) {
    unsafe {
        let saved = errno::get();
        gr_endent(ent);
        ent.bl.free();
        errno::set(saved);
    }
}

unsafe fn gr_next_nss(result: *mut Group, ent: &mut GrEnt, im: &Impl<Group>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        if !im.has(Group::GETENT) {
            return UNAVAIL;
        }
        if ent.setent_status != SUCCESS {
            return ent.setent_status;
        }
        loop {
            let st = im.getent(result, buffer, buflen, errnop);
            if st != SUCCESS {
                return st;
            }
            if !ent.bl.contains(bytes((*result).gr_name)) {
                return SUCCESS;
            }
        }
    }
}

unsafe fn plusgroup(name: *const c_char, result: *mut Group, bl: &Blacklist, im: &Impl<Group>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        if !im.has(Group::GETNAM) {
            return UNAVAIL;
        }
        let st = im.getnam(name, result, buffer, buflen, errnop);
        if st != SUCCESS {
            return st;
        }
        if bl.contains(bytes((*result).gr_name)) {
            return NOTFOUND;
        }
        SUCCESS
    }
}

unsafe fn gr_line(ent: &mut GrEnt, result: *mut Group, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> (c_int, i64) {
    unsafe {
        let Some(stream) = ent.stream.as_mut() else { return (UNAVAIL, 0) };
        let pos = stream.tell();
        let st = stream.next_group(result, buffer.cast(), buflen);
        if st != SUCCESS && st != NOTFOUND {
            *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
        }
        (st, pos)
    }
}

unsafe fn gr_next_file(result: *mut Group, ent: &mut GrEnt, im: &Impl<Group>, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        loop {
            let (st, pos) = gr_line(ent, result, buffer, buflen, errnop);
            if st != SUCCESS {
                return st;
            }
            let nm = bytes((*result).gr_name);
            match nm {
                [b'+' | b'-', ..] => {}
                _ => return SUCCESS,
            }
            match nm {
                [b'-', c, ..] if *c != b'@' => ent.bl.store(&nm[1..]),
                [b'+', c, ..] if *c != b'@' => {
                    let n = Name::of((*result).gr_name.add(1));
                    let st = plusgroup((*result).gr_name.add(1), result, &ent.bl, im, buffer, buflen, errnop);
                    ent.bl.store(bytes(n.0));
                    if st == SUCCESS {
                        return SUCCESS;
                    } else if st == RETURN || st == NOTFOUND {
                        continue;
                    } else {
                        if st == TRYAGAIN {
                            if let Some(s) = ent.stream.as_mut() {
                                s.seek(pos);
                            }
                            *errnop = ERANGE;
                            return TRYAGAIN;
                        }
                        return st;
                    }
                }
                [b'+'] => {
                    ent.files = false;
                    return gr_next_nss(result, ent, im, buffer, buflen, errnop);
                }
                _ => {}
            }
        }
    }
}

struct GrGlobal {
    lock: RawMutex,
    ent: core::cell::UnsafeCell<GrEnt>,
}
unsafe impl Sync for GrGlobal {}
static GR_EXT: GrGlobal = GrGlobal { lock: RawMutex::new(), ent: core::cell::UnsafeCell::new(GrEnt::new()) };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_setgrent(stayopen: c_int) -> c_int {
    unsafe {
        let im = Impl::<Group>::get();
        GR_EXT.lock.lock_always();
        let r = gr_setent(&mut *GR_EXT.ent.get(), &im, stayopen, true);
        GR_EXT.lock.unlock_always();
        r
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_endgrent() -> c_int {
    unsafe {
        let im = Impl::<Group>::get();
        GR_EXT.lock.lock_always();
        if im.has(Group::END) {
            im.end();
        }
        gr_endent(&mut *GR_EXT.ent.get());
        GR_EXT.lock.unlock_always();
        SUCCESS
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getgrent_r(grp: *mut Group, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        let im = Impl::<Group>::get();
        GR_EXT.lock.lock_always();
        let ent = &mut *GR_EXT.ent.get();
        let mut st = SUCCESS;
        if ent.stream.is_none() {
            st = gr_setent(ent, &im, 1, true);
        }
        if st == SUCCESS {
            st = if ent.files { gr_next_file(grp, ent, &im, buffer, buflen, errnop) } else { gr_next_nss(grp, ent, &im, buffer, buflen, errnop) };
        }
        GR_EXT.lock.unlock_always();
        st
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getgrnam_r(name: *const c_char, grp: *mut Group, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        if matches!(*name as u8, b'-' | b'+') {
            return NOTFOUND;
        }
        let key = bytes(name);
        let im = Impl::<Group>::get();
        let mut ent = GrEnt::new();
        let mut st = gr_setent(&mut ent, &im, 0, false);
        if st == SUCCESS {
            st = loop {
                let (s, _) = gr_line(&mut ent, grp, buffer, buflen, errnop);
                if s != SUCCESS {
                    break s;
                }
                let nm = bytes((*grp).gr_name);
                match nm {
                    [b'+' | b'-', ..] => {}
                    _ => {
                        if nm == key {
                            break SUCCESS;
                        }
                        continue;
                    }
                }
                match nm {
                    [b'-', _, ..] => {
                        if &nm[1..] == key {
                            break NOTFOUND;
                        }
                    }
                    [b'+', _, ..] => {
                        if key == &nm[1..] {
                            let s = plusgroup(name, grp, &ent.bl, &im, buffer, buflen, errnop);
                            if s != RETURN {
                                break s;
                            }
                        }
                    }
                    [b'+'] => {
                        let s = plusgroup(name, grp, &ent.bl, &im, buffer, buflen, errnop);
                        if s != RETURN {
                            break s;
                        }
                    }
                    _ => {}
                }
            };
        }
        gr_end_local(&mut ent);
        st
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_getgrgid_r(gid: Gid, grp: *mut Group, buffer: *mut c_char, buflen: usize, errnop: *mut c_int) -> c_int {
    unsafe {
        let im = Impl::<Group>::get();
        let mut ent = GrEnt::new();
        let mut st = gr_setent(&mut ent, &im, 0, false);
        if st == SUCCESS {
            st = loop {
                let (s, _) = gr_line(&mut ent, grp, buffer, buflen, errnop);
                if s != SUCCESS {
                    break s;
                }
                let nm = bytes((*grp).gr_name);
                match nm {
                    [b'+' | b'-', ..] => {}
                    _ => {
                        if (*grp).gr_gid == gid {
                            break SUCCESS;
                        }
                        continue;
                    }
                }
                match nm {
                    [b'-', _, ..] => ent.bl.store(&nm[1..]),
                    [b'+', _, ..] => {
                        let n = Name::of((*grp).gr_name.add(1));
                        let s = plusgroup((*grp).gr_name.add(1), grp, &ent.bl, &im, buffer, buflen, errnop);
                        ent.bl.store(bytes(n.0));
                        if s == SUCCESS && (*grp).gr_gid == gid {
                            break SUCCESS;
                        }
                    }
                    [b'+'] => {
                        if !im.has(b"getgrgid_r") {
                            break UNAVAIL;
                        }
                        let s = im.getid(b"getgrgid_r", gid, grp, buffer, buflen, errnop, |e| e.gr_gid);
                        break if s == RETURN { NOTFOUND } else { s };
                    }
                    _ => {}
                }
            };
        }
        gr_end_local(&mut ent);
        st
    }
}

struct IgEnt {
    files: bool,
    need_endgrent: bool,
    skip_initgroups_dyn: bool,
    stream: Option<CompatFile>,
    bl: Blacklist,
}

type InitgroupsDyn = unsafe extern "C" fn(*const c_char, Gid, *mut i64, *mut i64, *mut *mut Gid, i64, *mut c_int) -> c_int;

unsafe fn add_group(start: &mut i64, size: &mut i64, groups: &mut *mut Gid, limit: i64, gid: Gid) {
    unsafe {
        if *start == *size {
            if limit > 0 && *size == limit {
                return;
            }
            let newsize = if limit <= 0 { 2 * *size } else { limit.min(2 * *size) };
            let ng = rusty_libc_malloc::realloc((*groups).cast(), newsize as usize * size_of::<Gid>()) as *mut Gid;
            if ng.is_null() {
                return;
            }
            *groups = ng;
            *size = newsize;
        }
        *(*groups).add(*start as usize) = gid;
        *start += 1;
    }
}

unsafe fn check_and_add(user: *const c_char, group: Gid, start: &mut i64, size: &mut i64, groups: &mut *mut Gid, limit: i64, grp: &Group) -> bool {
    unsafe {
        if grp.gr_gid == group {
            return false;
        }
        let mut m = grp.gr_mem;
        while !(*m).is_null() {
            if bytes(*m) == bytes(user) {
                add_group(start, size, groups, limit, grp.gr_gid);
                return false;
            }
            m = m.add(1);
        }
        true
    }
}

fn ig_dyn(im: &Impl<Group>) -> Option<InitgroupsDyn> {
    match im.back {
        Back::Files => {
            unsafe extern "C" fn files_dyn(user: *const c_char, group: Gid, start: *mut i64, size: *mut i64, groups: *mut *mut Gid, limit: i64, _e: *mut c_int) -> c_int {
                unsafe { rusty_libc_util::pwd::files_initgroups_dyn(user, group, &mut *start, &mut *size, &mut *groups, limit) };
                SUCCESS
            }
            Some(files_dyn)
        }
        Back::Module(_) => {
            let f = im.back.module_fn(b"initgroups_dyn");
            if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, InitgroupsDyn>(f) }) }
        }
        Back::None => None,
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn ig_next_nss(ent: &mut IgEnt, im: &Impl<Group>, buffer: *mut c_char, buflen: usize, user: *const c_char, group: Gid, start: &mut i64, size: &mut i64, groups: &mut *mut Gid, limit: i64, errnop: *mut c_int) -> c_int {
    unsafe {
        let mut grpbuf = Group::zero();
        if !ent.skip_initgroups_dyn {
            let dynf = ig_dyn(im).expect("checked by the caller");
            let mut mystart: i64 = 0;
            let mut mysize: i64 = if limit <= 0 { *size } else { limit };
            let mut mygroups = rusty_libc_malloc::malloc(mysize as usize * size_of::<Gid>()) as *mut Gid;
            if mygroups.is_null() {
                return TRYAGAIN;
            }
            if dynf(user, group, &mut mystart, &mut mysize, &mut mygroups, limit, errnop) == SUCCESS {
                let mut status = NOTFOUND;
                let mut go_iter = false;
                if ent.bl.current <= 1 {
                    for i in 0..mystart {
                        add_group(start, size, groups, limit, *mygroups.add(i as usize));
                    }
                } else {
                    let mut tmpbuf = buffer;
                    let mut tmplen = buflen;
                    'scan: {
                        for i in 0..mystart {
                            loop {
                                status = im.getid(b"getgrgid_r", *mygroups.add(i as usize), &mut grpbuf, tmpbuf, tmplen, errnop, |e| e.gr_gid);
                                if !(status == TRYAGAIN && *errnop == ERANGE) {
                                    break;
                                }
                                if tmplen.checked_mul(2).is_none() {
                                    errno::set(ENOMEM);
                                    status = TRYAGAIN;
                                    break 'scan;
                                }
                                tmplen = (tmplen * 2).max(1024);
                                if tmpbuf != buffer {
                                    free(tmpbuf);
                                }
                                tmpbuf = rusty_libc_malloc::malloc(tmplen) as *mut c_char;
                                if tmpbuf.is_null() {
                                    status = TRYAGAIN;
                                    break 'scan;
                                }
                            }
                            if status != NOTFOUND {
                                if status != SUCCESS {
                                    break 'scan;
                                }
                                if !ent.bl.contains(bytes(grpbuf.gr_name)) && check_and_add(user, group, start, size, groups, limit, &grpbuf) {
                                    if im.set(1).is_some() {
                                        ent.need_endgrent = true;
                                    }
                                    ent.skip_initgroups_dyn = true;
                                    go_iter = true;
                                    break 'scan;
                                }
                            }
                        }
                        status = NOTFOUND;
                    }
                    if !tmpbuf.is_null() && tmpbuf != buffer {
                        free(tmpbuf);
                    }
                }
                rusty_libc_malloc::free(mygroups.cast());
                if !go_iter {
                    return status;
                }
            } else {
                rusty_libc_malloc::free(mygroups.cast());
            }
        }
        let mut status;
        loop {
            status = im.getent(&mut grpbuf, buffer, buflen, errnop);
            if status != SUCCESS {
                break;
            }
            if !ent.bl.contains(bytes(grpbuf.gr_name)) {
                break;
            }
        }
        if status == SUCCESS {
            check_and_add(user, group, start, size, groups, limit, &grpbuf);
        }
        status
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn ig_getent(ent: &mut IgEnt, im: &Impl<Group>, buffer: *mut c_char, buflen: usize, user: *const c_char, group: Gid, start: &mut i64, size: &mut i64, groups: &mut *mut Gid, limit: i64, errnop: *mut c_int) -> c_int {
    unsafe {
        if !ent.files {
            return ig_next_nss(ent, im, buffer, buflen, user, group, start, size, groups, limit, errnop);
        }
        let mut grpbuf = Group::zero();
        loop {
            let Some(stream) = ent.stream.as_mut() else { return UNAVAIL };
            let st = stream.next_group(&mut grpbuf, buffer.cast(), buflen);
            if st == NOTFOUND {
                return NOTFOUND;
            }
            if st != SUCCESS {
                *errnop = if st == TRYAGAIN { ERANGE } else { errno::get() };
                return st;
            }
            let nm = bytes(grpbuf.gr_name);
            match nm {
                [b'+' | b'-', ..] => {}
                _ => break,
            }
            match nm {
                [b'-', c, ..] if *c != b'@' => ent.bl.store(&nm[1..]),
                [b'+', c, ..] if *c != b'@' => {
                    if ent.bl.contains(&nm[1..]) {
                        continue;
                    }
                    ent.bl.store(&nm[1..]);
                    if !im.has(Group::GETNAM) {
                        return UNAVAIL;
                    }
                    if im.getnam(grpbuf.gr_name.add(1), &mut grpbuf, buffer, buflen, errnop) != SUCCESS {
                        continue;
                    }
                    check_and_add(user, group, start, size, groups, limit, &grpbuf);
                    return SUCCESS;
                }
                [b'+'] => {
                    if ig_dyn(im).is_none() || !im.has(b"getgrgid_r") {
                        if im.set(1).is_some() {
                            ent.need_endgrent = true;
                        }
                        ent.skip_initgroups_dyn = true;
                        if !im.has(Group::GETENT) {
                            return UNAVAIL;
                        }
                    }
                    ent.files = false;
                    return ig_next_nss(ent, im, buffer, buflen, user, group, start, size, groups, limit, errnop);
                }
                _ => {}
            }
        }
        check_and_add(user, group, start, size, groups, limit, &grpbuf);
        SUCCESS
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _nss_compat_initgroups_dyn(user: *const c_char, group: Gid, start: *mut i64, size: *mut i64, groups: *mut *mut Gid, limit: i64, errnop: *mut c_int) -> c_int {
    unsafe {
        let im = Impl::<Group>::get();
        let mut ent = IgEnt { files: true, need_endgrent: false, skip_initgroups_dyn: false, stream: None, bl: Blacklist::new() };
        match CompatFile::open(Group::FILE) {
            Ok(f) => ent.stream = Some(f),
            Err(e) => return fail_open(e),
        }
        let (start, size, groups) = (&mut *start, &mut *size, &mut *groups);
        let mut len = 1024usize;
        let mut buf = rusty_libc_malloc::malloc(len) as *mut c_char;
        let mut status = SUCCESS;
        if buf.is_null() {
            status = TRYAGAIN;
        } else {
            loop {
                let st = ig_getent(&mut ent, &im, buf, len, user, group, start, size, groups, limit, errnop);
                if st == TRYAGAIN && *errnop == ERANGE {
                    free(buf);
                    len *= 2;
                    buf = rusty_libc_malloc::malloc(len) as *mut c_char;
                    if buf.is_null() {
                        status = TRYAGAIN;
                        break;
                    }
                    continue;
                }
                if st != SUCCESS {
                    break;
                }
            }
            free(buf);
        }
        let saved = errno::get();
        if let Some(f) = ent.stream.take() {
            f.close();
        }
        if ent.need_endgrent {
            im.end();
        }
        ent.bl.free();
        errno::set(saved);
        status
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __rl_nss_compat_function(name: *const u8, len: usize) -> usize {
    let n = unsafe { core::slice::from_raw_parts(name, len) };
    let f: usize = match n {
        b"setpwent" => _nss_compat_setpwent as *const () as usize,
        b"getpwent_r" => _nss_compat_getpwent_r as *const () as usize,
        b"endpwent" => _nss_compat_endpwent as *const () as usize,
        b"getpwnam_r" => _nss_compat_getpwnam_r as *const () as usize,
        b"getpwuid_r" => _nss_compat_getpwuid_r as *const () as usize,
        b"setgrent" => _nss_compat_setgrent as *const () as usize,
        b"getgrent_r" => _nss_compat_getgrent_r as *const () as usize,
        b"endgrent" => _nss_compat_endgrent as *const () as usize,
        b"getgrnam_r" => _nss_compat_getgrnam_r as *const () as usize,
        b"getgrgid_r" => _nss_compat_getgrgid_r as *const () as usize,
        b"initgroups_dyn" => _nss_compat_initgroups_dyn as *const () as usize,
        b"setspent" => _nss_compat_setspent as *const () as usize,
        b"getspent_r" => _nss_compat_getspent_r as *const () as usize,
        b"endspent" => _nss_compat_endspent as *const () as usize,
        b"getspnam_r" => _nss_compat_getspnam_r as *const () as usize,
        _ => 0,
    };
    let _ = ENOMEM;
    f
}
