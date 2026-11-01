//! netdb.h: the host, service, protocol, network, rpc and alias databases.
//!
//! * hosts: the `nsswitch.conf` order of `files` (/etc/hosts) and `dns`; numeric host names are
//!   converted without a lookup like glibc's `__nss_hostname_digits_dots`.
//! * services, protocols, networks, rpc, aliases: the files backend only (a `networks` entry that
//!   would need DNS is not found).
//! * `_r` functions return 0 with `*result` set, `ENOENT` with `*result == NULL` when nothing matches,
//!   `ERANGE` when the caller's buffer is too small (the sizes needed differ slightly from glibc's).
//!   The plain functions keep one static buffer per database and return NULL when nothing matches.
//!
//! Every `_r` function is a thin C shell over a safe function of the same name without `get` (`servbyname_r`,
//! `hostbyname_r`, ...) that works on the caller's structure and buffer as references. Unsafe that stays: calling the
//! plug-in modules' functions (found by name, called through function pointers) and reading what they return, the
//! static buffers' heap blocks, the pointer-array view of the caller's buffer (util::Carve), and the C shells' pointer
//! conversions.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
use crate::dns::{self, Addr, HostData};
use crate::inet;
use crate::nssdns::{self, Outcome};
use crate::wire;
use crate::nss::{self, Action, Db, Entry, LineReader, Source, Status, ZBuf};
use crate::strerr::set_h_errno;
use crate::types::*;
use crate::util::{Buf, Carve, HeapVec, Spin, eq_nocase};
use core::cell::{Cell, RefCell};
use core::ffi::{CStr, c_char, c_int, c_void};
use rusty_libc_core::errno;
use rusty_libc_core::nscd::{self, reply::{HostLayout, ServiceLayout}};
use rusty_libc_core::ffi;

// ---------------------------------------------------------------- filling caller buffers

fn fill_servent(res: &mut servent, buf: &mut [u8], l: &nss::ServLine) -> Result<(), i32> {
    let mut f = Carve::new(buf);
    let r = (|| {
        res.s_aliases = f.string_list(nss::words(l.rest))?;
        res.s_name = f.string(l.name)?;
        res.s_proto = f.string(l.proto)?;
        res.s_port = l.port.to_be() as c_int;
        Some(())
    })();
    r.ok_or(ERANGE)
}

fn fill_protoent(res: &mut protoent, buf: &mut [u8], l: &nss::NumLine) -> Result<(), i32> {
    let mut f = Carve::new(buf);
    let r = (|| {
        res.p_aliases = f.string_list(nss::words(l.rest))?;
        res.p_name = f.string(l.name)?;
        res.p_proto = l.num;
        Some(())
    })();
    r.ok_or(ERANGE)
}

fn fill_rpcent(res: &mut rpcent, buf: &mut [u8], l: &nss::NumLine) -> Result<(), i32> {
    let mut f = Carve::new(buf);
    let r = (|| {
        res.r_aliases = f.string_list(nss::words(l.rest))?;
        res.r_name = f.string(l.name)?;
        res.r_number = l.num;
        Some(())
    })();
    r.ok_or(ERANGE)
}

fn fill_netent(res: &mut netent, buf: &mut [u8], l: &nss::NetLine) -> Result<(), i32> {
    let mut f = Carve::new(buf);
    let r = (|| {
        res.n_aliases = f.string_list(nss::words(l.rest))?;
        res.n_name = f.string(l.name)?;
        res.n_addrtype = AF_INET;
        res.n_net = l.net;
        Some(())
    })();
    r.ok_or(ERANGE)
}

/// A hostent from name, alias words (separated by NUL or white space) and addresses.
fn fill_hostent(res: &mut hostent, buf: &mut [u8], name: &[u8], aliases: &[u8], family: c_int, addrs: &[Addr]) -> Result<(), i32> {
    let mut f = Carve::new(buf);
    let alen = if family == AF_INET { 4 } else { 16 };
    let words = || aliases.split(|&c| c == 0 || c == b' ').filter(|w| !w.is_empty());
    let r = (|| {
        let na = words().count();
        let alist = f.ptr_array(na + 1)?;
        let addr_list = f.ptr_array(addrs.len() + 1)?;
        for (slot, a) in addr_list.iter_mut().zip(addrs) {
            *slot = f.bytes(&a.bytes[..alen])? as *mut c_char;
        }
        res.h_name = f.string(name)?;
        for (slot, w) in alist.iter_mut().zip(words()) {
            *slot = f.string(w)?;
        }
        res.h_aliases = alist.as_mut_ptr();
        res.h_addr_list = addr_list.as_mut_ptr();
        res.h_addrtype = family;
        res.h_length = alen as c_int;
        Some(())
    })();
    r.ok_or(ERANGE)
}

// ---------------------------------------------------------------- scanning files

/// glibc parses each line of a database file in place in the caller's buffer, so the smallest buffer a `getXXent_r` or
/// `getXXbyYY_r` call accepts depends on the lines it reads: every line read (comments and blank lines too) must fit with
/// its newline and two more bytes, and the vector of alias pointers goes after the line, aligned, with room for the
/// aliases, a null and one spare. `Fit` reproduces those decisions (nss/nss_readline.c, nss/nss_files/files-parse.c).
#[derive(Clone, Copy)]
struct Fit {
    /// Bytes of the buffer taken before the line (the parser's private data: 32 for hosts, 0 otherwise).
    base: usize,
    addr: usize,
    len: usize,
}

impl Fit {
    fn new(base: usize, buf: &[u8]) -> Fit {
        Fit { base, addr: buf.as_ptr() as usize, len: buf.len() }
    }
    /// glibc refuses before reading anything when the line buffer cannot hold even an empty line.
    fn pre_ok(&self) -> bool {
        self.len >= self.base + 3
    }
    /// `rawlen`: the line as fgets reads it, newline included; one more byte for the terminator and one that marks truncation.
    fn read_ok(&self, rawlen: usize) -> bool {
        rawlen + 2 <= self.len - self.base
    }
    /// The alias pointer vector for `k` aliases after a line of `rawlen` bytes.
    fn list_ok(&self, rawlen: usize, k: usize) -> bool {
        let start = (self.addr + self.base + rawlen + 1 + 7) & !7;
        start - self.addr + 8 * (k + 2) <= self.len
    }
}

/// What a scan of a database file came to.
enum Scan {
    /// The file cannot be opened (errno).
    Unavail(i32),
    NotFound,
    /// An entry matched (Ok) or glibc would have refused the buffer (Err(ERANGE)).
    Hit(Result<(), i32>),
}

/// Scan the file of `db` for the first entry `f` accepts. `f` gets the parsed text of each entry line and sets `*k` to the
/// number of aliases once the line parses; it answers Some for a match. A line that does not fit the buffer makes the
/// result Err(ERANGE), like glibc's.
fn scan(db: Db, fit: Fit, mut f: impl FnMut(&[u8], &mut usize) -> Option<Result<(), i32>>) -> Scan {
    let mut r = match nss::open_db(db) {
        Ok(r) => r,
        Err(e) => return Scan::Unavail(e),
    };
    if !fit.pre_ok() {
        return Scan::Hit(Err(ERANGE));
    }
    while let Some((line, rawlen)) = r.next_raw() {
        if !fit.read_ok(rawlen) {
            return Scan::Hit(Err(ERANGE));
        }
        let Some(body) = nss::entry_body(line) else { continue };
        let mut k = usize::MAX;
        let res = f(body, &mut k);
        if k != usize::MAX && !fit.list_ok(rawlen, k) {
            return Scan::Hit(Err(ERANGE));
        }
        if let Some(x) = res {
            return Scan::Hit(x);
        }
    }
    Scan::NotFound
}

const NSS_TRYAGAIN: i32 = -2;
const NSS_UNAVAIL: i32 = -1;
const NSS_NOTFOUND: i32 = 0;
const NSS_SUCCESS: i32 = 1;

/// The status glibc's `files` module would answer for a scan; `h` is the caller's `h_errnop` (networks only).
fn scan_status(h: Option<&Cell<c_int>>, r: Scan) -> i32 {
    // (the files module sets *herrnop at the end of the file and when the buffer is too small; a match leaves it alone)
    match r {
        Scan::Unavail(e) => {
            errno::set(e);
            if e == EAGAIN { NSS_TRYAGAIN } else { NSS_UNAVAIL }
        }
        Scan::NotFound => {
            if let Some(h) = h {
                h.set(HOST_NOT_FOUND);
            }
            NSS_NOTFOUND
        }
        Scan::Hit(Ok(())) => NSS_SUCCESS,
        Scan::Hit(Err(e)) => {
            errno::set(e);
            if let Some(h) = h {
                h.set(NETDB_INTERNAL);
            }
            if e == ERANGE { NSS_TRYAGAIN } else { NSS_UNAVAIL }
        }
    }
}

/// The arguments of a plug-in module's function (`_nss_NAME_...`, found by name), as a tuple of their C types.
trait ModArgs {
    /// Call the function at address `f` with these arguments; it returns an `enum nss_status` (int).
    ///
    /// # Safety
    /// `f` is the address of an `extern "C"` function whose parameters are exactly these types in this order and which
    /// returns `int` (glibc's NSS interface for the function's name), and the arguments meet that function's contract.
    unsafe fn call(self, f: usize) -> c_int;
}

macro_rules! mod_args {
    ($($t:ident $v:ident),*) => {
        impl<$($t),*> ModArgs for ($($t,)*) {
            unsafe fn call(self, f: usize) -> c_int {
                // SAFETY: a function address and a function pointer have the same size; the caller vouches for the type.
                let g = unsafe { core::mem::transmute_copy::<usize, unsafe extern "C" fn($($t),*) -> c_int>(&f) };
                let ($($v,)*) = self;
                // SAFETY: the caller's contract (the right function type and valid arguments).
                unsafe { g($($v),*) }
            }
        }
    };
}
mod_args!();
mod_args!(A a);
mod_args!(A a, B b, C c, D d, E e);
mod_args!(A a, B b, C c, D d, E e, G g);
mod_args!(A a, B b, C c, D d, E e, G g, H h);
mod_args!(A a, B b, C c, D d, E e, G g, H h, I i);
mod_args!(A a, B b, C c, D d, E e, G g, H h, I i, J j);

/// A raw argument of a C shell and what the shell converts it to ([`r_shell`] and the plain forms).
pub(crate) trait CIn<'a> {
    type Out;
    /// # Safety
    /// The pointer meets the conversion's contract (see each type) for `'a`.
    unsafe fn conv(self) -> Self::Out;
}

/// A non-NULL C string.
pub(crate) struct Str(pub(crate) *const c_char);
/// A C string or NULL.
pub(crate) struct OptStr(pub(crate) *const c_char);
/// A non-NULL pointer to a `T` the function reads and writes (h_errnop of the host functions, out-parameters).
pub(crate) struct Out<T>(pub(crate) *mut T);
/// A pointer to a `T` or NULL.
pub(crate) struct OptOut<T>(pub(crate) *mut T);
/// An `int *` or NULL, shared with the sources (h_errnop of the network functions).
pub(crate) struct OptCell(pub(crate) *mut c_int);
/// `len` readable bytes (any pointer when `len` is 0).
pub(crate) struct Bytes(pub(crate) *const u8, pub(crate) usize);

impl<'a> CIn<'a> for Str {
    type Out = &'a CStr;
    unsafe fn conv(self) -> &'a CStr {
        // SAFETY: forwarded contract (a non-NULL C string).
        unsafe { ffi::cstr_nonnull(self.0) }
    }
}
impl<'a> CIn<'a> for OptStr {
    type Out = Option<&'a CStr>;
    unsafe fn conv(self) -> Option<&'a CStr> {
        // SAFETY: forwarded contract (NULL or a C string).
        unsafe { ffi::cstr(self.0) }
    }
}
impl<'a, T: 'a> CIn<'a> for Out<T> {
    type Out = &'a mut T;
    unsafe fn conv(self) -> &'a mut T {
        // SAFETY: forwarded contract (a valid, aligned `T` nothing else accesses during the call).
        unsafe { &mut *self.0 }
    }
}
impl<'a, T: 'a> CIn<'a> for OptOut<T> {
    type Out = Option<&'a mut T>;
    unsafe fn conv(self) -> Option<&'a mut T> {
        // SAFETY: forwarded contract (NULL or as for Out).
        unsafe { ffi::out(self.0) }
    }
}
impl<'a> CIn<'a> for OptCell {
    type Out = Option<&'a Cell<c_int>>;
    unsafe fn conv(self) -> Option<&'a Cell<c_int>> {
        // SAFETY: forwarded contract (NULL or a valid int, touched only through the result during the call).
        unsafe { ffi::out(self.0) }.map(|r| Cell::from_mut(r) as &Cell<c_int>)
    }
}
impl<'a> CIn<'a> for Bytes {
    type Out = &'a [u8];
    unsafe fn conv(self) -> &'a [u8] {
        // SAFETY: forwarded contract.
        unsafe { ffi::bytes(self.0, self.1) }
    }
}
/// A `const T *` or NULL.
pub(crate) struct OptRef<T>(pub(crate) *const T);
/// `n` readable `T`s (any pointer when `n` is 0).
pub(crate) struct Slice<T>(pub(crate) *const T, pub(crate) usize);
/// `n` writable bytes, or none when the pointer is NULL or `n` is 0.
pub(crate) struct OptBytesMut(pub(crate) *mut u8, pub(crate) usize);

impl<'a, T: 'a> CIn<'a> for OptRef<T> {
    type Out = Option<&'a T>;
    unsafe fn conv(self) -> Option<&'a T> {
        // SAFETY: forwarded contract (NULL or a valid, aligned `T` not written during the call).
        unsafe { self.0.as_ref() }
    }
}
impl<'a, T: 'a> CIn<'a> for Slice<T> {
    type Out = &'a [T];
    unsafe fn conv(self) -> &'a [T] {
        // SAFETY: forwarded contract.
        unsafe { ffi::slice(self.0, self.1) }
    }
}
impl<'a> CIn<'a> for OptBytesMut {
    type Out = Option<&'a mut [u8]>;
    unsafe fn conv(self) -> Option<&'a mut [u8]> {
        if self.0.is_null() || self.1 == 0 {
            return None;
        }
        // SAFETY: forwarded contract (`n` writable bytes nothing else accesses during the call).
        Some(unsafe { ffi::bytes_mut(self.0, self.1) })
    }
}
impl CIn<'_> for () {
    type Out = ();
    unsafe fn conv(self) {}
}
impl<'a, X: CIn<'a>, Y: CIn<'a>> CIn<'a> for (X, Y) {
    type Out = (X::Out, Y::Out);
    unsafe fn conv(self) -> Self::Out {
        // SAFETY: forwarded contract.
        let x = unsafe { self.0.conv() };
        // SAFETY: forwarded contract.
        (x, unsafe { self.1.conv() })
    }
}

/// The caller's result structure and buffer of a `getXXbyYY_r` call, shared by the source closures (one runs at a time).
struct OutBufs<'a, T> {
    res: &'a mut T,
    buf: &'a mut [u8],
}

impl<T> OutBufs<'_, T> {
    /// Raw pointers for a plug-in module's function.
    fn raw(&mut self) -> (*mut T, *mut c_char, usize) {
        (self.res as *mut T, self.buf.as_mut_ptr().cast::<c_char>(), self.buf.len())
    }
}

/// glibc's `getXXbyYY_r` over the sources of `db` (nss/getXXbyYY_r.c): `files` runs `files`, a module's `_nss_NAME_<func>` is
/// called with the arguments `args` builds (given the errno slot). `h_errnop` is given for the databases that report through
/// `h_errno` (networks). Returns the value the `_r` function returns and whether `*result` is to be set (success).
///
/// Every caller in this module builds `args` with exactly the C parameter types of glibc's `_nss_NAME_<func>` and with
/// valid pointers (the caller's structure and buffer, its strings, the dispatcher's errno slot): that is what makes the
/// one module call below sound.
///
/// (The closures are generic parameters, not trait objects: a `&dyn` closure is a vtable of function pointers in
/// .data.rel.ro, relocated, and so written, at every start of every process.)
fn by_key<A: ModArgs>(db: &[u8], func: &[u8], h_errnop: Option<&Cell<c_int>>, files: &impl Fn() -> i32, args: &impl Fn(*mut c_int) -> A) -> (c_int, bool) {
    by_key_dns(db, func, h_errnop, files, args, None::<&fn(*mut c_int) -> i32>)
}

/// [`by_key`] for a database the `dns` source answers too (`dns`: its lookup, with a place for the errno it leaves).
fn by_key_dns<A: ModArgs>(db: &[u8], func: &[u8], h_errnop: Option<&Cell<c_int>>, files: &impl Fn() -> i32, args: &impl Fn(*mut c_int) -> A, dns: Option<&impl Fn(*mut c_int) -> i32>) -> (c_int, bool) {
    let any = Cell::new(false);
    let dns_any = |e: *mut c_int| {
        any.set(true);
        match dns {
            Some(d) => d(e),
            None => NSS_UNAVAIL,
        }
    };
    let status = rusty_libc_core::nssent::dispatch_dns(
        db,
        func,
        &|| {
            any.set(true);
            files()
        },
        &|f, en| {
            any.set(true);
            // SAFETY: `f` is the module's `_nss_NAME_<func>`, and `args` has its parameter types and valid pointers (see
            // by_key).
            unsafe { args(en).call(f) }
        },
        None,
        if dns.is_some() { Some(&dns_any) } else { None },
    );
    let ok = status == NSS_SUCCESS;
    if let Some(h) = h_errnop {
        if status != NSS_SUCCESS && !any.get() {
            // no source could be asked: glibc says so through h_errno (the sources' own settings are left as they are)
            h.set(if status == NSS_UNAVAIL && errno::get() != ENOENT { NETDB_INTERNAL } else { NO_RECOVERY });
        }
    }
    let rc = if status == NSS_SUCCESS || status == NSS_NOTFOUND {
        0
    } else if errno::get() == ERANGE && status != NSS_TRYAGAIN {
        EINVAL
    } else if h_errnop.is_some_and(|h| status == NSS_TRYAGAIN && h.get() != NETDB_INTERNAL) {
        EAGAIN
    } else {
        return (errno::get(), ok);
    };
    errno::set(rc);
    (rc, ok)
}

// ---------------------------------------------------------------- host lookups

/// Status of one source plus the `h_errno` it would leave.
type SrcResult = (Status, c_int);

/// The output buffer of glibc's `gethostbyname3_multi`: it reuses the caller's buffer from the alias vector of the first
/// match on, handing out addresses, strings and the final two pointer vectors; `ok` goes false when something does not fit.
struct OutBuf {
    cur: usize,
    end: usize,
    ok: bool,
}

impl OutBuf {
    fn alloc(&mut self, size: usize, align: usize) {
        if !self.ok {
            return;
        }
        let a = (self.cur + align - 1) & !(align - 1);
        if a + size > self.end {
            self.ok = false;
        } else {
            self.cur = a + size;
        }
    }
}

fn files_hosts(name: &[u8], af: c_int, v4mapped: bool, out: &mut HostData) -> SrcResult {
    let multi = nss::host_conf_multi();
    let mut r = match nss::open_db(Db::Hosts) {
        Ok(r) => r,
        Err(e) => {
            // glibc's files module: the reason stays in errno and h_errno is left as it was (nss_files internal_setent)
            errno::set(e);
            return (if e == EAGAIN { Status::TryAgain } else { Status::Unavail }, out.h);
        }
    };
    // glibc's `_nss_files_gethostbyname3_r` pads the buffer to the alignment of its parser data first
    let fit = out.fit.map(|(addr, len)| {
        let pad = (8 - addr % 8) % 8;
        Fit { base: 32, addr: addr + pad, len: len.saturating_sub(pad) }
    });
    let erange = |out: &mut HostData| {
        out.erange = true;
        (Status::TryAgain, NETDB_INTERNAL)
    };
    if let Some(f) = fit {
        if !f.pre_ok() {
            return erange(out);
        }
    }
    let mut found = false;
    // after the first match in `multi` mode: the output buffer simulation, the first name, and the counts so far
    let mut ob = OutBuf { cur: 0, end: 0, ok: true };
    let (mut naddr, mut nalias) = (0usize, 0usize);
    while let Some((line, rawlen)) = r.next_raw() {
        if !found {
            if let Some(f) = fit {
                if !f.read_ok(rawlen) {
                    return erange(out);
                }
            }
        }
        let Some(body) = nss::entry_body(line) else { continue };
        let Some(h) = nss::parse_host_line(body, af, v4mapped) else { continue };
        let k = nss::words(h.rest).count();
        if !found {
            if let Some(f) = fit {
                if !f.list_ok(rawlen, k) {
                    return erange(out);
                }
            }
        }
        let hit = eq_nocase(h.name, name) || nss::words(h.rest).any(|w| eq_nocase(w, name));
        if !hit {
            continue;
        }
        if !found {
            out.canon = Buf::from(h.name).unwrap_or_default();
            out.have_canon = true;
            if let Some(f) = fit {
                // the alias vector of this line is where the output buffer starts
                let list = (f.addr + f.base + rawlen + 1 + 7) & !7;
                ob = OutBuf { cur: list, end: f.addr + f.len, ok: true };
                naddr = 1;
                nalias = k;
            }
        } else {
            if !eq_nocase(out.canon.as_bytes(), h.name) {
                out.add_alias(h.name);
            }
            if fit.is_some() {
                // a further line: its address, aliases and, when the name differs, the name go to the output buffer
                ob.alloc(if h.family == AF_INET { 4 } else { 16 }, 4);
                naddr += 1;
                for w in nss::words(h.rest) {
                    ob.alloc(w.len() + 1, 1);
                    nalias += 1;
                }
                if h.name != out.canon.as_bytes() {
                    ob.alloc(h.name.len() + 1, 1);
                    nalias += 1;
                }
                if !ob.ok {
                    return erange(out);
                }
            }
        }
        out.push(Addr { family: h.family, bytes: h.addr, scope: 0 });
        for w in nss::words(h.rest) {
            out.add_alias(w);
        }
        found = true;
        if !multi {
            break;
        }
    }
    if !found || multi {
        // the end of the file was reached: the files source leaves HOST_NOT_FOUND behind
        out.h = HOST_NOT_FOUND;
    }
    if found && multi && fit.is_some() {
        // the two pointer vectors close the output
        ob.alloc(8 * (naddr + 1), 8);
        ob.alloc(8 * (nalias + 1), 8);
        if !ob.ok {
            return erange(out);
        }
    }
    if found { (Status::Success, NETDB_SUCCESS) } else { (Status::NotFound, HOST_NOT_FOUND) }
}

/// The `dns` source for a host name, like glibc's built-in nss_dns module: `AF_INET`/`AF_INET6` ask `gethostbyname3_r`
/// (one query, host answer parser), `AF_UNSPEC` asks `gethostbyname4_r` (A and AAAA, or only A with RES_NOAAAA, address
/// tuple parser). The status, `h_errno` and `errno` are what that module leaves behind.
pub(crate) fn dns_hosts(cfg: &dns::Config, name: &[u8], af: c_int, out: &mut HostData) -> SrcResult {
    // like glibc's nss_dns check_name: no query for a name that cannot be a host name
    if !crate::resolv::hostname_ok(name) {
        out.h = HOST_NOT_FOUND;
        return (Status::NotFound, HOST_NOT_FOUND);
    }
    let olderr = errno::get();
    let o = match af {
        AF_INET | AF_INET6 => dns_host_one(cfg, name, af, out),
        AF_UNSPEC => dns_host_pair(cfg, name, out),
        _ => Outcome { status: Status::Unavail, h_errno: Some(NO_DATA), errno: Some(EAFNOSUPPORT) },
    };
    if o.status != Status::Success {
        // nothing of a failed answer is kept
        out.n = 0;
        out.addrs.clear();
        out.aliases.clear();
        out.naliases = 0;
        out.have_canon = false;
    }
    errno::set(o.errno.unwrap_or(olderr));
    if let Some(h) = o.h_errno {
        out.h = h;
    }
    (o.status, out.h)
}

/// Fills a [`HostData`] from a host answer: the names the parser reports (the query name, then each CNAME target) become
/// the alias list, the last of them being the official name; addresses are added in order.
struct HostCollect<'a> {
    out: &'a mut HostData,
    last: Option<Buf<{ nssdns::MAXHOST + 1 }>>,
}

impl HostCollect<'_> {
    fn finish(&mut self) {
        if let Some(l) = self.last.take() {
            self.out.canon = Buf::from(l.as_bytes()).unwrap_or_default();
            self.out.have_canon = true;
        }
    }
}

fn push_addr(out: &mut HostData, a: &[u8]) {
    let mut b = [0u8; 16];
    b[..a.len()].copy_from_slice(a);
    out.push(Addr { family: if a.len() == 4 { AF_INET } else { AF_INET6 }, bytes: b, scope: 0 });
}

impl nssdns::HostSink for HostCollect<'_> {
    fn alias(&mut self, name: &[u8]) {
        if let Some(prev) = self.last.take() {
            self.out.add_alias(prev.as_bytes());
        }
        self.last = Buf::from(name);
    }
    fn addr(&mut self, a: &[u8]) {
        push_addr(self.out, a);
    }
}

/// Fills a [`HostData`] from the A+AAAA pair: addresses in order, the canonical name from the first tuple that has one.
struct TupleCollect<'a>(&'a mut HostData);

impl nssdns::TupleSink for TupleCollect<'_> {
    fn tuple(&mut self, _family: c_int, addr: &[u8], canon: Option<&[u8]>) {
        push_addr(self.0, addr);
        if let Some(c) = canon {
            self.0.canon = Buf::from(c).unwrap_or_default();
            self.0.have_canon = true;
        }
    }
}

fn keep_ttl(out: &mut HostData, ttl: i32) {
    if ttl != i32::MAX {
        out.ttl = out.ttl.min(ttl.max(0) as u32);
    }
}

fn dns_host_one(cfg: &dns::Config, name: &[u8], af: c_int, out: &mut HostData) -> Outcome {
    let qtype = if af == AF_INET { wire::T_A } else { wire::T_AAAA };
    let mut first = [0u8; 4096];
    let mut ans = dns::Answer::growable(&mut first);
    let n = match dns::search_in(cfg, name, wire::C_IN, qtype, &mut ans) {
        Ok(n) => n,
        Err(e) => return nssdns::query_failure(&e),
    };
    let mut ttl = i32::MAX;
    let mut sink = HostCollect { out, last: None };
    let o = nssdns::parse_host(ans.kept(n), qtype, &mut sink, &mut ttl);
    sink.finish();
    keep_ttl(out, ttl);
    o
}

/// The queries of `gethostbyname4_r`: A and AAAA as one pair (both go to a server at once, glibc's T_QUERY_A_AND_AAAA), or
/// only A with RES_NOAAAA. Gives the length of the first reply (in `a1`) and of the second (in `a2`; `None` when only A was
/// asked), or the failure of the lookup. The thread's resolver state keeps the switch to one query at a time.
pub(crate) fn query_a_aaaa<'a>(cfg: &dns::Config, name: &[u8], a1: &mut dns::Answer<'a>, a2: &mut dns::Answer<'a>) -> Result<(usize, Option<usize>), Outcome> {
    if cfg.options & dns::RES_NOAAAA != 0 {
        return match dns::search_in(cfg, name, wire::C_IN, wire::T_A, a1) {
            Ok(n) => Ok((n, None)),
            Err(e) => Err(nssdns::query_failure(&e)),
        };
    }
    // SAFETY: __res_state returns this thread's resolver state (the static `_res` for the main thread), valid for the
    // thread's life; nothing else in this thread holds a reference to it during the lookup.
    let flags = unsafe { &mut (*crate::resolv::__res_state()).flags };
    match dns::search_pair(cfg, name, a1, a2, flags) {
        Ok((n1, n2)) => Ok((n1, Some(n2))),
        Err(e) => Err(nssdns::query_failure(&e)),
    }
}

fn dns_host_pair(cfg: &dns::Config, name: &[u8], out: &mut HostData) -> Outcome {
    let (mut f4, mut f6) = ([0u8; 4096], [0u8; 4096]);
    let (mut a4, mut a6) = (dns::Answer::growable(&mut f4), dns::Answer::growable(&mut f6));
    let (n1, n2) = match query_a_aaaa(cfg, name, &mut a4, &mut a6) {
        Ok(l) => l,
        Err(o) => return o,
    };
    let mut ttl = i32::MAX;
    let o = nssdns::parse_a_aaaa(a4.kept(n1), n2.map(|n| a6.kept(n)), &mut TupleCollect(out), &mut ttl);
    keep_ttl(out, ttl);
    o
}

/// One source's answer for a name (used by getaddrinfo, which walks the sources itself).
pub(crate) fn src_lookup(e: &Entry, name: &[u8], af: c_int, v4mapped: bool, out: &mut HostData) -> (Status, c_int) {
    match e.src {
        Source::Files => files_hosts(name, af, v4mapped, out),
        Source::Dns => dns_hosts(&crate::resolv::current_config(), name, af, out),
        Source::Module => module_hosts(e.module_name(), name, af, out),
    }
}

// ---------------------------------------------------------------- plug-in modules (libnss_NAME.so.2)

/// glibc's `enum nss_status` values a module returns.
fn module_status(st: c_int) -> Status {
    match st {
        1 => Status::Success,
        0 => Status::NotFound,
        -2 => Status::TryAgain,
        _ => Status::Unavail,
    }
}

/// `struct gaih_addrtuple`, the answer of `_nss_NAME_gethostbyname4_r`.
#[repr(C)]
struct AddrTuple {
    next: *mut AddrTuple,
    name: *mut c_char,
    family: c_int,
    addr: [u32; 4],
    scopeid: u32,
}

/// Call `f(buffer, len)` with growing scratch buffers while it reports ERANGE (a module's buffer is too small).
fn with_scratch<R>(mut f: impl FnMut(*mut c_char, usize) -> (R, bool)) -> R {
    let mut stack = [0u8; 2048];
    let (r, retry) = f(stack.as_mut_ptr() as *mut c_char, stack.len());
    if !retry {
        return r;
    }
    let mut size = 8192usize;
    loop {
        // SAFETY: malloc has no precondition.
        let heap = unsafe { rusty_libc_malloc::malloc(size) } as *mut c_char;
        if heap.is_null() {
            return r;
        }
        let (r, retry) = f(heap, size);
        // SAFETY: `heap` came from malloc just above; the module is done with it.
        unsafe { rusty_libc_malloc::free(heap.cast()) };
        if !retry || size >= (1 << 20) {
            return r;
        }
        size *= 2;
    }
}

/// The entries of a NULL-terminated pointer array (NULL itself: none): each a C string (`len` None, without its NUL) or
/// `len` bytes.
///
/// # Safety
/// `list` is NULL or a NULL-terminated array whose entries are C strings (`len` None) or point to `len` readable bytes,
/// all valid and unchanged for `'a`.
unsafe fn c_list<'a>(list: *const *mut c_char, len: Option<usize>) -> impl Iterator<Item = &'a [u8]> {
    let mut i = 0usize;
    core::iter::from_fn(move || {
        if list.is_null() {
            return None;
        }
        // SAFETY: the array is NULL-terminated and iteration stops at the NULL, so entry `i` is inside it.
        let p = unsafe { *list.wrapping_add(i) };
        if p.is_null() {
            return None;
        }
        i += 1;
        let n = match len {
            Some(n) => n,
            // SAFETY: the entry is a C string (contract).
            None => unsafe { ffi::cstr_len(p) },
        };
        // SAFETY: the entry has `n` readable bytes valid for `'a` (contract).
        Some(unsafe { ffi::bytes(p as *const u8, n) })
    })
}

/// Copy a module's `hostent` into `out`.
///
/// # Safety
/// `h` was filled by a module's successful lookup (its pointers are valid C data); `canon` is NULL or a C string.
unsafe fn hostent_into(h: &hostent, out: &mut HostData, canon: *const c_char) {
    // SAFETY: `h_name` and `canon` are NULL or C strings (contract).
    let (name, canon) = unsafe { (OptStr(h.h_name), OptStr(canon)).conv() };
    if let Some(n) = name {
        if !out.have_canon {
            out.canon = Buf::from(n.to_bytes()).unwrap_or_default();
            out.have_canon = true;
        }
    }
    if let Some(c) = canon {
        out.canon = Buf::from(c.to_bytes()).unwrap_or_default();
        out.have_canon = true;
    }
    // SAFETY: the module's alias list (contract).
    for a in unsafe { c_list(h.h_aliases, None) } {
        out.add_alias(a);
    }
    let len = (h.h_length.max(0) as usize).min(16);
    // SAFETY: the module's address list, `h_length` bytes per address (contract).
    for b in unsafe { c_list(h.h_addr_list, Some(len)) } {
        let mut a = Addr { family: h.h_addrtype, bytes: [0; 16], scope: 0 };
        a.bytes[..len].copy_from_slice(b);
        out.push(a);
    }
}

/// One module's answer for a name. AF_UNSPEC asks `gethostbyname4_r` (both families at once, with scope ids), like getaddrinfo;
/// modules without it are asked per family through `gethostbyname3_r`/`gethostbyname2_r`.
fn module_hosts(module: &[u8], name: &[u8], af: c_int, out: &mut HostData) -> SrcResult {
    use rusty_libc_core::nssmod;
    let Some(cname) = Buf::<256>::from(name).filter(|b| b.len < 255) else { return (Status::Unavail, NO_DATA) };
    let mut cname = cname;
    cname.push(0);
    let cname_ptr = cname.b.as_ptr() as *const c_char;
    if af == AF_UNSPEC {
        let f4 = nssmod::function(module, b"gethostbyname4_r");
        if f4 != 0 {
            let mut result: (c_int, c_int) = (-1, NO_DATA);
            let mut tmp = HostData::new();
            with_scratch(|buf, len| {
                let mut pat: *mut AddrTuple = core::ptr::null_mut();
                let (mut en, mut he, mut ttl): (c_int, c_int, i32) = (0, NETDB_SUCCESS, 0);
                tmp = HostData::new();
                // SAFETY: `_nss_NAME_gethostbyname4_r` takes (const char *, struct gaih_addrtuple **, char *, size_t, int *,
                // int *, int32_t *): `cname_ptr` is a C string, `buf` has `len` writable bytes, the rest are our locals.
                let st = unsafe { (cname_ptr, &raw mut pat, buf, len, &raw mut en, &raw mut he, &raw mut ttl).call(f4) };
                let retry = st == -2 && en == ERANGE;
                if st == 1 {
                    let mut first = true;
                    let mut p = pat;
                    while !p.is_null() {
                        // SAFETY: on success the module returns a list of tuples in `buf` (or its own memory), each
                        // valid until the next call.
                        let t = unsafe { &*p };
                        if first {
                            // SAFETY: NULL or a C string set by the module.
                            if let Some(n) = unsafe { ffi::cstr(t.name) } {
                                tmp.canon = Buf::from(n.to_bytes()).unwrap_or_default();
                                tmp.have_canon = true;
                            }
                        }
                        first = false;
                        let mut a = Addr { family: t.family, bytes: [0; 16], scope: if t.family == AF_INET6 { t.scopeid } else { 0 } };
                        let n = if t.family == AF_INET { 4 } else { 16 };
                        let words = t.addr.map(u32::to_ne_bytes);
                        a.bytes[..n].copy_from_slice(&words.as_flattened()[..n]);
                        tmp.push(a);
                        p = t.next;
                    }
                }
                result = (st, he);
                ((), retry)
            });
            let st = module_status(result.0);
            if st == Status::Success {
                *out = tmp;
                return (Status::Success, NETDB_SUCCESS);
            }
            return (st, if result.1 == NETDB_SUCCESS { HOST_NOT_FOUND } else { result.1 });
        }
    }
    let fams: &[c_int] = match af {
        AF_UNSPEC => &[AF_INET6, AF_INET],
        AF_INET => &[AF_INET],
        _ => &[AF_INET6],
    };
    let mut best = (Status::Unavail, HOST_NOT_FOUND);
    let mut any = false;
    // getaddrinfo asks gethostbyname3_r (then 2_r); gethostbyname_r and gethostbyname2_r ask their own name
    let (f3, f2, f1) = match out.func {
        1 => (0, 0, nssmod::function(module, b"gethostbyname_r")),
        2 => (0, nssmod::function(module, b"gethostbyname2_r"), 0),
        _ => (nssmod::function(module, b"gethostbyname3_r"), nssmod::function(module, b"gethostbyname2_r"), 0),
    };
    if f3 == 0 && f2 == 0 && f1 == 0 {
        return (Status::Unavail, NO_DATA);
    }
    out.called = true;
    let h_in = out.h;
    for &fam in fams {
        let mut hd = HostData::new();
        let mut r: (c_int, c_int) = (-1, NO_DATA);
        with_scratch(|buf, len| {
            let mut host = HOSTENT0;
            let (mut en, mut he, mut ttl): (c_int, c_int, i32) = (0, h_in, 0);
            let mut canon: *mut c_char = core::ptr::null_mut();
            hd = HostData::new();
            let st = if f1 != 0 {
                // SAFETY: `_nss_NAME_gethostbyname_r` has glibc's signature F1. C string name, `len` writable bytes at `buf`, our own locals for the rest.
                unsafe { (cname_ptr, &raw mut host, buf, len, &raw mut en, &raw mut he).call(f1) }
            } else if f3 != 0 {
                // SAFETY: `_nss_NAME_gethostbyname3_r` has glibc's signature F3. as above.
                unsafe { (cname_ptr, fam, &raw mut host, buf, len, &raw mut en, &raw mut he, &raw mut ttl, &raw mut canon).call(f3) }
            } else {
                // SAFETY: `_nss_NAME_gethostbyname2_r` has glibc's signature F2. as above.
                unsafe { (cname_ptr, fam, &raw mut host, buf, len, &raw mut en, &raw mut he).call(f2) }
            };
            let retry = st == -2 && en == ERANGE;
            if st == 1 {
                // SAFETY: a successful lookup filled `host` (and `canon`, NULL or a C string).
                unsafe { hostent_into(&host, &mut hd, canon) };
            }
            r = (st, he);
            ((), retry)
        });
        let st = module_status(r.0);
        out.h = r.1;
        if st == Status::Success {
            any = true;
            if !out.have_canon && hd.have_canon {
                out.canon = hd.canon;
                out.have_canon = true;
            }
            for a in &hd.addrs[..hd.n] {
                out.push(*a);
            }
            for w in hd.aliases.as_bytes().split(|&c| c == 0).filter(|w| !w.is_empty()) {
                out.add_alias(w);
            }
        } else if best.0 == Status::Unavail || (st == Status::TryAgain) {
            best = (st, if r.1 == NETDB_SUCCESS { HOST_NOT_FOUND } else { r.1 });
        }
    }
    if any { (Status::Success, NETDB_SUCCESS) } else { best }
}

/// One module's answer for an address (`gethostbyaddr2_r`, or `gethostbyaddr_r` for modules without it).
fn module_addr(module: &[u8], af: c_int, addr: &[u8], h_in: c_int, name: &mut Option<Buf<256>>, aliases: &mut Buf<1024>) -> (Status, c_int, bool) {
    use rusty_libc_core::nssmod;
    let f2 = nssmod::function(module, b"gethostbyaddr2_r");
    let f1 = nssmod::function(module, b"gethostbyaddr_r");
    if f2 == 0 && f1 == 0 {
        return (Status::Unavail, h_in, false);
    }
    let mut r: (c_int, c_int) = (-1, h_in);
    let mut got: Option<(Buf<256>, Buf<1024>)> = None;
    with_scratch(|buf, len| {
        let mut host = HOSTENT0;
        let (mut en, mut he, mut ttl): (c_int, c_int, i32) = (0, h_in, 0);
        let st = if f2 != 0 {
            // SAFETY: `_nss_NAME_gethostbyaddr2_r` has glibc's signature F. `addr` is readable for its length, `len` writable bytes at `buf`, our locals for the rest.
            unsafe { (addr.as_ptr() as *const c_void, addr.len() as u32, af, &raw mut host, buf, len, &raw mut en, &raw mut he, &raw mut ttl).call(f2) }
        } else {
            // SAFETY: `_nss_NAME_gethostbyaddr_r` has glibc's signature F. as above.
            unsafe { (addr.as_ptr() as *const c_void, addr.len() as u32, af, &raw mut host, buf, len, &raw mut en, &raw mut he).call(f1) }
        };
        let retry = st == -2 && en == ERANGE;
        if st == 1 {
            // SAFETY: NULL or the C string a successful lookup set.
            if let Some(hn) = unsafe { ffi::cstr(host.h_name) } {
                let mut al = Buf::<1024>::new();
                // SAFETY: the alias list of a successful lookup.
                for a in unsafe { c_list(host.h_aliases, None) } {
                    al.push_all(a);
                    al.push(0);
                }
                got = Some((Buf::from(hn.to_bytes()).unwrap_or_default(), al));
            }
        }
        r = (st, he);
        ((), retry)
    });
    let st = module_status(r.0);
    if st == Status::Success {
        if let Some((n, al)) = got {
            *name = Some(n);
            *aliases = al;
            return (Status::Success, r.1, true);
        }
        return (Status::NotFound, r.1, true);
    }
    (st, r.1, true)
}

/// Look `name` up through the hosts sources in `nsswitch.conf` order. `af` is AF_INET or AF_INET6, or AF_UNSPEC for both.
/// Err(h_errno) on failure. Like glibc's `getXXbyYY_r` loop the last source asked decides: a later source after a SUCCESS
/// whose action is `continue` replaces the answer, a plug-in without the function is skipped, and `out.h` ends up as the
/// sources left `h_errno` (`out.any` is false when no source could be asked at all).
pub fn lookup_name(name: &[u8], af: c_int, v4mapped: bool, out: &mut HostData) -> Result<(), c_int> {
    let order = nss::hosts_order();
    let mut status = Status::Unavail;
    let mut any = false;
    for e in &order.e[..order.n] {
        let mut saved = None;
        if status == Status::Success {
            // the next source overwrites what the previous one answered
            let keep = (out.fit, out.func, out.h);
            let mut fresh = HostData::new();
            (fresh.fit, fresh.func, fresh.h) = keep;
            saved = Some(core::mem::replace(out, fresh));
        }
        out.called = e.src != Source::Module;
        let r = src_lookup(e, name, af, v4mapped, out);
        if !out.called {
            // a module without the function: skipped (the earlier answer stays), as far as its UNAVAIL action allows
            if let Some(sv) = saved {
                *out = sv;
            }
            if e.action(Status::Unavail) == Action::Return {
                break;
            }
            continue;
        }
        any = true;
        status = r.0;
        if status == Status::Success && e.action(Status::Success) == Action::Merge {
            // glibc: only groups can be merged; for hosts the merge machinery answers EINVAL
            errno::set(EINVAL);
            out.einval = true;
            break;
        }
        if out.erange {
            // the caller's buffer is too small: glibc gives that back whatever the TRYAGAIN action says
            break;
        }
        if e.action(r.0) == Action::Return {
            break;
        }
    }
    out.any = any;
    out.unavail = any && status == Status::Unavail;
    out.tryagain = any && status == Status::TryAgain;
    if out.einval {
        Err(out.h)
    } else if status == Status::Success {
        Ok(())
    } else if any {
        Err(out.h)
    } else {
        Err(NO_DATA)
    }
}

/// `__nss_hostname_digits_dots`: a numeric name needs no lookup. Ok(Some) is the answer, Ok(None) means
/// "not numeric, look it up", Err(h_errno) a name that looks numeric but is not valid.
fn digits_dots(name: &[u8], af: c_int, use_inet6: bool) -> Result<Option<(Addr, c_int)>, c_int> {
    if name.is_empty() {
        return Ok(None);
    }
    let c0 = name[0];
    if !(c0.is_ascii_digit() || c0.is_ascii_hexdigit() || c0 == b':') {
        return Ok(None);
    }
    let mut af = af;
    if af != AF_INET && af != AF_INET6 {
        af = if use_inet6 { AF_INET6 } else { AF_INET };
    }
    if c0.is_ascii_digit() {
        // all digits and dots?
        if name.iter().all(|&c| c.is_ascii_digit() || c == b'.') {
            if *name.last().unwrap() == b'.' {
                return Ok(None);
            }
            let mut a = Addr { family: af, bytes: [0; 16], scope: 0 };
            if af == AF_INET {
                let mut t = Buf::<64>::from(name).ok_or(HOST_NOT_FOUND)?;
                t.push(0);
                let mut ia = in_addr::default();
                // __inet_aton_exact: the whole string must be an address
                match inet::parse_aton(name) {
                    Some((v, end)) if end == name.len() => {
                        ia.s_addr = u32::from_ne_bytes(v);
                    }
                    _ => return Err(HOST_NOT_FOUND),
                }
                a.bytes[..4].copy_from_slice(&ia.s_addr.to_ne_bytes());
            } else {
                match inet::parse_ipv6(name) {
                    Some(v) => a.bytes = v,
                    None => return Err(HOST_NOT_FOUND),
                }
            }
            if af == AF_INET && use_inet6 {
                let v4 = [a.bytes[0], a.bytes[1], a.bytes[2], a.bytes[3]];
                a.bytes = [0; 16];
                a.bytes[10] = 0xff;
                a.bytes[11] = 0xff;
                a.bytes[12..].copy_from_slice(&v4);
                a.family = AF_INET6;
            }
            return Ok(Some((a, a.family)));
        }
    }
    if (c0.is_ascii_hexdigit() && name.contains(&b':')) || c0 == b':' {
        let af6 = match af {
            AF_INET6 => true,
            _ => return Err(HOST_NOT_FOUND),
        };
        let _ = af6;
        if name.iter().all(|&c| c.is_ascii_hexdigit() || c == b':' || c == b'.') {
            if *name.last().unwrap() == b'.' {
                return Ok(None);
            }
            return match inet::parse_ipv6(name) {
                Some(v) => Ok(Some((Addr { family: AF_INET6, bytes: v, scope: 0 }, AF_INET6))),
                None => Err(HOST_NOT_FOUND),
            };
        }
    }
    Ok(None)
}

/// glibc's exported `__nss_hostname_digits_dots` (GLIBC_2.2.5), for NSS modules and old programs: when `name` is a numeric
/// address, fill `resbuf` from a buffer laid out as glibc's (address, address list, alias list, name) and return 1; return 0
/// for any other name. With `buffer_size` NULL the buffer is the fixed `*buffer` of `buflen` bytes and the outcome goes to
/// `*status` (`enum nss_status`); otherwise `*buffer` is a malloc'd buffer grown to fit and the outcome goes to `*result`.
///
/// # Safety
/// As glibc's: valid pointers for the mode used (`status` may be NULL only with `buffer_size`, `h_errnop` may be NULL).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __nss_hostname_digits_dots(
    name: *const c_char,
    resbuf: *mut hostent,
    buffer: *mut *mut c_char,
    buffer_size: *mut usize,
    buflen: usize,
    result: *mut *mut hostent,
    status: *mut c_int,
    af: c_int,
    h_errnop: *mut c_int,
) -> c_int {
    // enum nss_status
    const NSS_TRYAGAIN: c_int = -2;
    const NSS_NOTFOUND: c_int = 0;
    const NSS_SUCCESS: c_int = 1;
    // glibc takes a resolver context first, which reads host.conf once (`_res_hconf`)
    nss::hconf_init();
    let fixed = buffer_size.is_null();
    // SAFETY: `name` is a C string, `h_errnop` NULL or valid, `buffer` and `resbuf` valid (glibc's contract, both modes).
    let ((nm, mut herr), (bufp, r)) = unsafe { ((Str(name), OptOut(h_errnop)), (Out(buffer), Out(resbuf))).conv() };
    let nm = nm.to_bytes();
    // the outcome slot (`*status` in fixed mode, `*result` and the size otherwise; glibc's contract makes them valid)
    let mut mode = if fixed {
        // SAFETY: in fixed mode `status` is valid (contract).
        Ok(unsafe { Out(status).conv() })
    } else {
        // SAFETY: in growing mode `result` and `buffer_size` are valid (contract), different objects.
        Err(unsafe { (Out(result), Out(buffer_size)).conv() })
    };
    let mut set_h = |h: c_int| {
        if let Some(e) = herr.as_deref_mut() {
            *e = h;
        }
    };
    let done = |mode: &mut Result<&mut c_int, (&mut *mut hostent, &mut usize)>, st: c_int, res: *mut hostent| match mode {
        Ok(status) => **status = st,
        Err((result, _)) => **result = res,
    };
    // like glibc, the buffer is sized for any name that may be numeric, before the parse
    let c0 = nm.first().copied().unwrap_or(0);
    if !(c0.is_ascii_hexdigit() || c0 == b':') {
        return 0;
    }
    let need = 16 + 16 + 8 + nm.len() + 1;
    match &mut mode {
        Ok(status) => {
            if buflen < need {
                **status = NSS_TRYAGAIN;
                set_h(NETDB_INTERNAL);
                errno::set(ERANGE);
                return 1;
            }
        }
        Err((result, size)) => {
            if **size < need {
                **size = need;
                // SAFETY: `*buffer` is NULL or a block from malloc (contract).
                let nb = unsafe { rusty_libc_malloc::realloc((*bufp).cast(), need) } as *mut c_char;
                if nb.is_null() {
                    let save = errno::get();
                    // SAFETY: realloc failed, so the old block is still the caller's malloc'd block (or NULL).
                    unsafe { rusty_libc_malloc::free((*bufp).cast()) };
                    *bufp = core::ptr::null_mut();
                    **size = 0;
                    errno::set(save);
                    set_h(NETDB_INTERNAL);
                    **result = core::ptr::null_mut();
                    return 1;
                }
                *bufp = nb;
            }
        }
    }
    let base = *bufp as *mut u8;
    // SAFETY: `*buffer` has at least `need` bytes (checked or grown above); nothing else touches it during the call.
    let b = unsafe { ffi::bytes_mut(base, need) };
    b.fill(0);
    let found = match digits_dots(nm, af, use_inet6()) {
        Ok(None) => return 0,
        Err(h) => {
            set_h(h);
            done(&mut mode, NSS_NOTFOUND, core::ptr::null_mut());
            return 1;
        }
        Ok(Some(a)) => a,
    };
    let (a, fam) = found;
    let len = if fam == AF_INET6 { 16 } else { 4 };
    // glibc's layout: the address at 0, the address list at 16 (the address, NULL), the alias list at 32 (NULL), the name
    // at 40. The list entries are stored as bytes (the caller's buffer need not be aligned); the NULLs are the zeroing.
    b[..len].copy_from_slice(&a.bytes[..len]);
    b[16..24].copy_from_slice(&base.expose_provenance().to_ne_bytes());
    b[40..40 + nm.len()].copy_from_slice(nm);
    let base = b.as_mut_ptr();
    r.h_name = base.wrapping_add(40).cast();
    r.h_aliases = base.wrapping_add(32).cast();
    r.h_addr_list = base.wrapping_add(16).cast();
    r.h_addrtype = fam;
    r.h_length = len as c_int;
    set_h(NETDB_SUCCESS);
    done(&mut mode, NSS_SUCCESS, resbuf);
    1
}

/// The `dns` source for an address (glibc's `_nss_dns_gethostbyaddr2_r`): one PTR query for the reverse name, then the PTR
/// parser. A failed query is NOTFOUND with the resolver's `h_errno` (glibc puts errno back before it looks at ECONNREFUSED);
/// returns the status, the `h_errno` it leaves (if it sets one) and the name.
fn dns_addr(cfg: &dns::Config, af: c_int, a: &[u8]) -> (Status, Option<c_int>, Option<Buf<256>>) {
    let olderr = errno::get();
    let rn = dns::reverse_name(af, a);
    let mut first = [0u8; 4096];
    let mut ans = dns::Answer::growable(&mut first);
    let n = match dns::query_in(cfg, rn.as_bytes(), wire::C_IN, wire::T_PTR, &mut ans) {
        Ok(n) => n,
        Err(e) => {
            errno::set(olderr);
            return (Status::NotFound, Some(e.h), None);
        }
    };
    let mut ttl = i32::MAX;
    let mut nm = Buf::<{ nssdns::MAXHOST + 1 }>::new();
    let o = nssdns::parse_ptr(ans.kept(n), &mut ttl, &mut nm);
    if let Some(e) = o.errno {
        errno::set(e);
    }
    let name = if o.status == Status::Success { Buf::from(nm.as_bytes()) } else { None };
    (o.status, o.h_errno, name)
}

/// glibc 2.43's `res_use_inet6` (resolv/resolv-internal.h): always false. RES_USE_INET6 in `_res.options` and the
/// `inet6` resolver option no longer change gethostbyname/gethostbyname_r (FIXLIST #132: they used to look up AF_INET6
/// here when RES_OPTIONS=inet6 was set).
pub(crate) fn use_inet6() -> bool {
    false
}

/// A hosts lookup with no source to ask (an empty list, or an nsswitch.conf glibc cannot parse): glibc's `getXXbyYY_r` ends
/// with status UNAVAIL, `h_errno` NETDB_INTERNAL (NO_RECOVERY when errno is ENOENT) and the current errno as the result
/// (EINVAL for ERANGE).
fn no_sources(h_errnop: &mut c_int) -> c_int {
    let e = errno::get();
    *h_errnop = if e != ENOENT { NETDB_INTERNAL } else { NO_RECOVERY };
    if e == ERANGE {
        errno::set(EINVAL);
        return EINVAL;
    }
    e
}

/// The shared body of gethostbyname_r and gethostbyname2_r. Returns the errno-style code. `func`: 1 for gethostbyname_r, 2 for
/// gethostbyname2_r (the module function plug-in sources are asked for).
/// `name` None is a NULL name. Returns the code and whether `*result` is to be set to `res`.
pub fn hostbyname_r(func: u8, name: Option<&[u8]>, af: c_int, res: &mut hostent, buf: &mut [u8], h_errnop: &mut c_int) -> (c_int, bool) {
    let errno_before = errno::get();
    let mut by_daemon = false;
    let r = hostbyname_r_body(func, name, af, res, buf, h_errnop, &mut by_daemon);
    // glibc's getXXbyYY_r ends with `__set_errno (res)`: errno is the return value, whatever the sources left behind. (An
    // answer of the name service cache daemon returns before that, and leaves errno alone when it found the host.)
    errno::set(if by_daemon && r == (0, true) { errno_before } else { r.0 });
    r
}

/// The name service cache daemon's answer to a hosts lookup as `getXXbyYY_r` returns it: the lists are in `buf` already
/// (glibc's `nscd_gethst_r`). None: use the NSS sources. A found host leaves `errno` and `h_errno` alone.
fn nscd_hostent(answer: nscd::Res<HostLayout>, res: &mut hostent, buf: &mut [u8], h_errnop: &mut c_int) -> Option<(c_int, bool)> {
    match answer {
        nscd::Res::Fallback => None,
        nscd::Res::Found(l) => {
            let base = buf.as_mut_ptr();
            let at = |off: usize| base.wrapping_add(off);
            res.h_name = at(l.name).cast();
            res.h_aliases = at(l.aliases).cast();
            res.h_addrtype = l.addrtype;
            res.h_length = l.length;
            res.h_addr_list = at(l.addr_list).cast();
            Some((0, true))
        }
        nscd::Res::NotFound(h) => {
            *h_errnop = h;
            errno::set(0);
            Some((0, false))
        }
        _ => {
            *h_errnop = NETDB_INTERNAL;
            errno::set(ERANGE);
            Some((ERANGE, false))
        }
    }
}

fn hostbyname_r_body(func: u8, name: Option<&[u8]>, af: c_int, res: &mut hostent, buf: &mut [u8], h_errnop: &mut c_int, by_daemon: &mut bool) -> (c_int, bool) {
    {
        nss::hconf_init();
        let Some(nm) = name else {
            *h_errnop = HOST_NOT_FOUND; // glibc dereferences it; be safe
            return (EINVAL, false);
        };
        let buflen = buf.len();
        let (mut name_buf, mut data) = (Buf::<1025>::from(nm).unwrap_or_default(), HostData::new());
        let _ = &mut name_buf;
        // numeric names
        match digits_dots(nm, af, use_inet6()) {
            Err(h) => {
                *h_errnop = h;
                return (0, false);
            }
            Ok(Some((a, fam))) => {
                // __nss_hostname_digits_dots: address, pointer pair, alias pointer and the name must fit
                if buflen < 16 + 16 + 8 + nm.len() + 1 {
                    *h_errnop = NETDB_INTERNAL;
                    errno::set(ERANGE);
                    return (ERANGE, false);
                }
                let r = fill_hostent(res, buf, nm, b"", fam, &[a]);
                return match r {
                    Ok(()) => {
                        *h_errnop = NETDB_SUCCESS;
                        (0, true)
                    }
                    Err(e) => {
                        *h_errnop = NETDB_INTERNAL;
                        errno::set(e);
                        (e, false)
                    }
                };
            }
            Ok(None) => {}
        }
        // the name service cache daemon next (gethostbyname2_r asks for IPv6 only when `af` is AF_INET6); the resolver state is
        // set up first, as glibc's getXXbyYY_r does with __resolv_context_get (it leaves errno as a missing resolv.conf does)
        crate::resolv::init_this_state();
        if let Some(r) = nscd_hostent(nscd::host_by_name(nm, func == 2 && af == AF_INET6, buf), res, buf, h_errnop) {
            *by_daemon = true;
            return r;
        }
        if nss::hosts_order().n == 0 {
            return (no_sources(h_errnop), false);
        }
        let want_af = if af == AF_INET || af == AF_INET6 { af } else { AF_INET };
        let v4m = want_af == AF_INET6 && use_inet6();
        data.fit = Some((buf.as_ptr() as usize, buflen));
        data.func = func;
        data.h = *h_errnop;
        match lookup_name(nm, want_af, v4m, &mut data) {
            Ok(()) => {
                let fam = if want_af == AF_INET6 { AF_INET6 } else { AF_INET };
                let addrs = &data.addrs[..data.n];
                let r = fill_hostent(res, buf, data.canon.as_bytes(), data.aliases.as_bytes(), fam, addrs);
                match r {
                    Ok(()) => {
                        // glibc: h_errno is whatever the sources left (the files source: HOST_NOT_FOUND after reading to the end)
                        *h_errnop = data.h;
                        // glibc's POSTPROCESS of gethostbyname(2)_r: host.conf's "reorder"
                        // SAFETY: fill_hostent just made `res` a valid hostent over `buf`.
                        unsafe { nss::reorder_addrs(res) };
                        (0, true)
                    }
                    Err(e) => {
                        *h_errnop = NETDB_INTERNAL;
                        errno::set(e);
                        (e, false)
                    }
                }
            }
            Err(h) => {
                if data.erange {
                    *h_errnop = NETDB_INTERNAL;
                    errno::set(ERANGE);
                    return (ERANGE, false);
                }
                if data.einval {
                    *h_errnop = data.h;
                    return (EINVAL, false);
                }
                if !data.any {
                    // no source could be asked (plug-ins without the function): UNAVAIL
                    return (no_sources(h_errnop), false);
                }
                *h_errnop = h;
                // glibc's getXXbyYY_r: NOTFOUND returns 0 (whatever h_errno says: a failed send whose errno nss_dns does
                // not know is NOTFOUND with TRY_AGAIN), TRYAGAIN EAGAIN unless h_errno is NETDB_INTERNAL, else errno
                let rc = if data.tryagain && h != NETDB_INTERNAL {
                    EAGAIN
                } else if data.unavail || data.tryagain {
                    errno::get()
                } else {
                    0
                };
                (rc, false)
            }
        }
    }
}

/// # Safety
/// glibc's contract for `gethostbyname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname_r(name: *const c_char, res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, h_errnop: *mut c_int) -> c_int {
    let af = if use_inet6() { AF_INET6 } else { AF_INET };
    // SAFETY: glibc's contract (`name` NULL or a C string, `h_errnop` valid).
    unsafe { r_shell(res, buf, buflen, result, (OptStr(name), Out(h_errnop)), |r, b, (nm, h)| hostbyname_r(1, nm.map(CStr::to_bytes), af, r, b, h)) }
}

/// # Safety
/// glibc's contract for `gethostbyname2_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname2_r(name: *const c_char, af: c_int, res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, h_errnop: *mut c_int) -> c_int {
    // SAFETY: as gethostbyname_r.
    unsafe { r_shell(res, buf, buflen, result, (OptStr(name), Out(h_errnop)), |r, b, (nm, h)| hostbyname_r(2, nm.map(CStr::to_bytes), af, r, b, h)) }
}

/// # Safety
/// glibc's contract for `gethostbyaddr_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyaddr_r(addr: *const c_void, len: u32, af: c_int, res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, h_errnop: *mut c_int) -> c_int {
    // SAFETY: glibc's contract; `addr` points to `len` readable bytes, at most the first 16 are looked at.
    unsafe { r_shell(res, buf, buflen, result, (Bytes(addr.cast(), (len as usize).min(16)), Out(h_errnop)), |r, b, (a, h)| hostbyaddr_r(a, len, af, r, b, h)) }
}

/// glibc's PREPROCESS of gethostbyaddr_r (nss/gethstbyad_r.c): a length of 16 and 16 zero bytes, whatever the family.
fn in6addr_any_skip(a: &[u8], len: u32) -> bool {
    len == 16 && a.len() == 16 && a.iter().all(|&b| b == 0)
}

/// gethostbyaddr_r on safe types: `a` is the start of the address (at most 16 bytes), `len` the length the caller gave.
pub fn hostbyaddr_r(a: &[u8], len: u32, af: c_int, res: &mut hostent, buf: &mut [u8], h_errnop: &mut c_int) -> (c_int, bool) {
    // glibc 2.43 nss/gethstbyad_r.c: the resolver state is set up first (getXXbyYY_r.c's NEED__RES, __resolv_context_get),
    // then PREPROCESS: a 16-byte address that is all zeros (in6addr_any, whatever `af` says) is not looked up: HOST_NOT_FOUND,
    // ENOENT returned, errno untouched. That is the only address it catches (a longer `len` is not caught).
    if in6addr_any_skip(a, len) {
        crate::resolv::init_this_state();
        *h_errnop = HOST_NOT_FOUND;
        return (ENOENT, false);
    }
    // the name service cache daemon first (the raw address and family; the answer needs no POSTPROCESS)
    let whole = if a.len() == len as usize { a } else { &a[..0] };
    crate::resolv::init_this_state();
    if let Some(r) = nscd_hostent(nscd::host_by_addr(whole, af, buf), res, buf, h_errnop) {
        return r;
    }
    let (rc, ok) = hostbyaddr_r_body(a, len, af, res, buf, h_errnop);
    // glibc's POSTPROCESS of gethostbyaddr_r: host.conf's "reorder" and "trim"
    if rc == 0 && ok {
        // SAFETY: on success `res` was just filled by fill_hostent over `buf` (valid lists, writable strings).
        unsafe { nss::reorder_addrs(res) };
        // SAFETY: as above.
        unsafe { nss::trim_domains(res) };
    }
    errno::set(rc);
    (rc, ok)
}

fn hostbyaddr_r_body(addr: &[u8], len: u32, af: c_int, res: &mut hostent, buf: &mut [u8], h_errnop: &mut c_int) -> (c_int, bool) {
    {
        nss::hconf_init();
        // glibc: AF_INET (and AF_UNSPEC) need 4 bytes, AF_INET6 needs 16; longer lengths use the prefix
        let af = if af == AF_UNSPEC { AF_INET } else { af };
        if !((af == AF_INET6 && len >= 16) || (af == AF_INET && len >= 4)) {
            *h_errnop = NETDB_INTERNAL;
            errno::set(EAFNOSUPPORT);
            return (EAFNOSUPPORT, false);
        }
        let len = if af == AF_INET { 4 } else { 16 };
        let a = &addr[..len];
        let (mut af, mut a) = (af, a);
        // v4-mapped and v4-compatible IPv6 addresses are looked up as IPv4
        if af == AF_INET6 && a[..10] == [0; 10] && ((a[10] == 0xff && a[11] == 0xff) || (a[10] == 0 && a[11] == 0 && (a[12] != 0 || a[13] != 0 || a[14] != 0 || a[15] > 1))) {
            a = &a[12..];
            af = AF_INET;
        }
        let order = nss::hosts_order();
        if order.n == 0 {
            return (no_sources(h_errnop), false);
        }
        let mut name: Option<Buf<256>> = None;
        let mut aliases = Buf::<1024>::new();
        // h_errno as the sources leave it: glibc hands the caller's pointer to them
        let mut h_out = *h_errnop;
        let mut range_err = false;
        let mut status = Status::Unavail;
        let mut any = false;
        for e in &order.e[..order.n] {
            let saved = if status == Status::Success { Some((name, aliases)) } else { None };
            if status == Status::Success {
                // the next source overwrites what the previous one answered
                name = None;
                aliases = Buf::<1024>::new();
            }
            let st = match e.src {
                Source::Files => {
                    let mut found = Status::NotFound;
                    let fit = Fit::new(32, buf);
                    let opened = nss::open_db(Db::Hosts);
                    if let Err(e) = &opened {
                        errno::set(*e);
                    }
                    if let Ok(mut r) = opened {
                        if !fit.pre_ok() {
                            range_err = true;
                        }
                        let mut matched = false;
                        while !range_err {
                            let Some((line, rawlen)) = r.next_raw() else { break };
                            if !fit.read_ok(rawlen) {
                                range_err = true;
                                break;
                            }
                            let Some(body) = nss::entry_body(line) else { continue };
                            let Some(h) = nss::parse_host_line(body, af, len == 16) else { continue };
                            if !fit.list_ok(rawlen, nss::words(h.rest).count()) {
                                range_err = true;
                                break;
                            }
                            let alen = if af == AF_INET { 4 } else { 16 };
                            if h.addr[..alen] == a[..alen] {
                                name = Buf::from(h.name);
                                for w in nss::words(h.rest) {
                                    aliases.push_all(w);
                                    aliases.push(0);
                                }
                                found = Status::Success;
                                matched = true;
                                break;
                            }
                        }
                        if !range_err && !matched {
                            h_out = HOST_NOT_FOUND;
                        }
                    } else {
                        found = Status::Unavail;
                    }
                    any = true;
                    found
                }
                Source::Dns => {
                    any = true;
                    let (st, h, nm) = dns_addr(&crate::resolv::current_config(), af, a);
                    if let Some(h) = h {
                        h_out = h;
                    }
                    name = nm;
                    st
                }
                Source::Module => {
                    let (st, h, asked) = module_addr(e.module_name(), af, a, h_out, &mut name, &mut aliases);
                    if !asked {
                        // no such function in this plug-in: skipped (the earlier answer stays), as far as its UNAVAIL action allows
                        if let Some((n, al)) = saved {
                            name = n;
                            aliases = al;
                        }
                        if e.action(Status::Unavail) == Action::Return {
                            break;
                        }
                        continue;
                    }
                    any = true;
                    h_out = h;
                    st
                }
            };
            if range_err {
                // glibc: a buffer that is too small is given back at once
                *h_errnop = NETDB_INTERNAL;
                errno::set(ERANGE);
                return (ERANGE, false);
            }
            status = st;
            if st == Status::Success && e.action(Status::Success) == Action::Merge {
                errno::set(EINVAL);
                *h_errnop = h_out;
                return (EINVAL, false);
            }
            if e.action(st) == Action::Return {
                break;
            }
        }
        if !any {
            return (no_sources(h_errnop), false);
        }
        match name {
            Some(n) if status == Status::Success => {
                *h_errnop = h_out;
                let ad = Addr { family: af, bytes: { let mut b = [0u8; 16]; b[..a.len()].copy_from_slice(a); b }, scope: 0 };
                match fill_hostent(res, buf, n.as_bytes(), aliases.as_bytes(), af, &[ad]) {
                    Ok(()) => (0, true),
                    Err(e) => {
                        *h_errnop = NETDB_INTERNAL;
                        errno::set(e);
                        (e, false)
                    }
                }
            }
            _ => {
                *h_errnop = h_out;
                let rc = if status == Status::TryAgain && h_out != NETDB_INTERNAL {
                    EAGAIN
                } else if status == Status::Unavail {
                    errno::get()
                } else {
                    0
                };
                (rc, false)
            }
        }
    }
}

// ---------------------------------------------------------------- the static-buffer forms

struct Static<T> {
    res: T,
    buf: ZBuf,
}

// SAFETY: the result structure holds pointers into the static's own buffer (which moves with it) and nothing else; the
// Spin lock around every Static serialises access.
unsafe impl<T> Send for Static<T> {}

impl<T> Static<T> {
    /// Get the first block (BUF0 bytes) or double it. False when memory is short (errno ENOMEM).
    fn grow(&mut self) -> bool {
        let ncap = if self.buf.is_empty() { BUF0 } else { self.buf.cap() * 2 };
        if !self.buf.grow(ncap) {
            errno::set(ENOMEM);
            return false;
        }
        true
    }

    /// The result structure and the whole buffer.
    fn parts(&mut self) -> (&mut T, &mut [u8]) {
        (&mut self.res, self.buf.as_mut_slice())
    }
}

const BUF0: usize = 1024;

macro_rules! statics {
    ($name:ident, $ty:ty, $zero:expr) => {
        static $name: Spin<Static<$ty>> = Spin::new(Static { res: $zero, buf: ZBuf::new() });
    };
}

const HOSTENT0: hostent = hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };
const SERVENT0: servent = servent { s_name: core::ptr::null_mut(), s_aliases: core::ptr::null_mut(), s_port: 0, s_proto: core::ptr::null_mut() };
const PROTOENT0: protoent = protoent { p_name: core::ptr::null_mut(), p_aliases: core::ptr::null_mut(), p_proto: 0 };
const NETENT0: netent = netent { n_name: core::ptr::null_mut(), n_aliases: core::ptr::null_mut(), n_addrtype: 0, n_net: 0 };
const RPCENT0: rpcent = rpcent { r_name: core::ptr::null_mut(), r_aliases: core::ptr::null_mut(), r_number: 0 };
const ALIASENT0: aliasent = aliasent { alias_name: core::ptr::null_mut(), alias_members_len: 0, alias_members: core::ptr::null_mut(), alias_local: 0 };

statics!(HOSTENT_S, hostent, HOSTENT0);
statics!(SERVENT_S, servent, SERVENT0);
statics!(PROTOENT_S, protoent, PROTOENT0);
statics!(NETENT_S, netent, NETENT0);
statics!(RPCENT_S, rpcent, RPCENT0);
statics!(ALIASENT_S, aliasent, ALIASENT0);

/// Call `f(result_struct, buffer)` with a buffer that grows while it returns ERANGE; `f` answers the `_r` function's code and
/// whether it succeeded. `ent`: the plain getXXent form (errno is left as the sources left it on failure, glibc's
/// `__nss_getent`); otherwise errno is the code on failure. Returns the static result structure or NULL.
fn with_static<T>(s: &Spin<Static<T>>, ent: bool, mut f: impl FnMut(&mut T, &mut [u8]) -> (c_int, bool)) -> *mut T {
    let mut g = s.lock();
    if g.buf.is_empty() && !g.grow() {
        return core::ptr::null_mut();
    }
    loop {
        let (res, buf) = g.parts();
        let (r, ok) = f(res, buf);
        if r == ERANGE {
            if !g.grow() {
                return core::ptr::null_mut();
            }
            continue;
        }
        if r == 0 {
            return if ok { &mut g.res as *mut T } else { core::ptr::null_mut() };
        }
        if !ent {
            errno::set(r);
        }
        return core::ptr::null_mut();
    }
}

/// # Safety
/// `name` is a C string. The result is valid until the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut hostent {
    // SAFETY: NULL or a C string (contract).
    let nm = unsafe { ffi::cstr(name) }.map(CStr::to_bytes);
    let mut h = 0;
    let r = with_static(&HOSTENT_S, false, |res, buf| hostbyname_r(1, nm, if use_inet6() { AF_INET6 } else { AF_INET }, res, buf, &mut h));
    if r.is_null() {
        set_h_errno(h);
    }
    r
}

/// # Safety
/// As [`gethostbyname`].
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyname2(name: *const c_char, af: c_int) -> *mut hostent {
    // SAFETY: NULL or a C string (contract).
    let nm = unsafe { ffi::cstr(name) }.map(CStr::to_bytes);
    let mut h = 0;
    let r = with_static(&HOSTENT_S, false, |res, buf| hostbyname_r(2, nm, af, res, buf, &mut h));
    if r.is_null() {
        set_h_errno(h);
    }
    r
}

/// # Safety
/// `addr` points to `len` bytes. The result is valid until the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostbyaddr(addr: *const c_void, len: u32, af: c_int) -> *mut hostent {
    // SAFETY: `len` readable bytes at `addr` (contract); at most 16 are looked at.
    let a = unsafe { ffi::bytes(addr.cast(), (len as usize).min(16)) };
    let mut h = 0;
    let olderr = errno::get();
    let r = with_static(&HOSTENT_S, false, |res, buf| hostbyaddr_r(a, len, af, res, buf, &mut h));
    if r.is_null() {
        set_h_errno(h);
        // glibc's gethostbyaddr does not set errno from the return value: in6addr_any (not looked up) leaves it as it was
        if in6addr_any_skip(a, len) {
            errno::set(olderr);
        }
    }
    r
}

// ---------------------------------------------------------------- entries by name and number

/// The C shell of a `getXXbyYY_r` function: the caller's result structure and buffer as references, `*result` set from the
/// safe function's outcome.
///
/// `extra` holds the function's other pointer arguments, converted for `f` as [`CIn`] says.
///
/// # Safety
/// `res` is a valid `T`, `buf` writable for `buflen` bytes, `result` NULL or a writable slot, `extra` meets its
/// conversion's contract; none of them overlap.
unsafe fn r_shell<'a, T: 'a, S: CIn<'a>>(res: *mut T, buf: *mut c_char, buflen: usize, result: *mut *mut T, extra: S, f: impl FnOnce(&mut T, &mut [u8], S::Out) -> (c_int, bool)) -> c_int {
    // SAFETY: the caller's structure (contract), not otherwise accessed during the call.
    let r = unsafe { &mut *res };
    // SAFETY: `buflen` writable bytes (contract).
    let b = unsafe { ffi::bytes_mut(buf.cast(), buflen) };
    // SAFETY: forwarded contract.
    let x = unsafe { extra.conv() };
    let (rc, ok) = f(r, b, x);
    // SAFETY: NULL or the caller's result slot (contract).
    if let Some(rp) = unsafe { ffi::out(result) } {
        *rp = if ok { res } else { core::ptr::null_mut() };
    }
    rc
}

/// The name service cache daemon's answer to a services lookup as `getservbyname_r` returns it (glibc's `nscd_getserv_r`):
/// the strings and the alias vector are in `buf` already. None: use the NSS sources. A found service leaves `errno` alone.
fn nscd_servent(answer: nscd::Res<ServiceLayout>, res: &mut servent, buf: &mut [u8]) -> Option<(c_int, bool)> {
    match answer {
        nscd::Res::Fallback => None,
        nscd::Res::Found(l) => {
            let base = buf.as_mut_ptr();
            let at = |off: usize| base.wrapping_add(off);
            res.s_name = at(l.name).cast();
            res.s_aliases = at(l.aliases).cast();
            res.s_proto = at(l.proto).cast();
            res.s_port = l.port;
            Some((0, true))
        }
        nscd::Res::NotFound(_) => {
            errno::set(0);
            Some((0, false))
        }
        _ => {
            errno::set(ERANGE);
            Some((ERANGE, false))
        }
    }
}

/// `getservbyname_r` on safe types (`proto` None: any protocol).
pub fn servbyname_r(name: &CStr, proto: Option<&CStr>, res: &mut servent, buf: &mut [u8]) -> (c_int, bool) {
    let nm = name.to_bytes();
    let pr = proto.map(CStr::to_bytes);
    if let Some(r) = nscd_servent(nscd::service_by_name(nm, pr, buf), res, buf) {
        return r;
    }
    let out = RefCell::new(OutBufs { res, buf });
    by_key(
        b"services",
        b"getservbyname_r",
        None,
        &|| {
            let mut o = out.borrow_mut();
            let o = &mut *o;
            scan_status(None, scan(Db::Services, Fit::new(0, o.buf), |line, k| {
                let l = nss::parse_serv_line(line)?;
                *k = nss::words(l.rest).count();
                if let Some(p) = pr {
                    if l.proto != p {
                        return None;
                    }
                }
                if l.name == nm || nss::words(l.rest).any(|w| w == nm) {
                    return Some(fill_servent(o.res, o.buf, &l));
                }
                None
            }))
        },
        &|en| {
            let (r, b, n) = out.borrow_mut().raw();
            (name.as_ptr(), proto.map_or(core::ptr::null(), CStr::as_ptr), r, b, n, en)
        },
    )
}

/// # Safety
/// glibc's contract for `getservbyname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyname_r(name: *const c_char, proto: *const c_char, res: *mut servent, buf: *mut c_char, buflen: usize, result: *mut *mut servent) -> c_int {
    // SAFETY: glibc's contract (`name` a C string, `proto` NULL or one).
    unsafe { r_shell(res, buf, buflen, result, (Str(name), OptStr(proto)), |r, b, (nm, pr)| servbyname_r(nm, pr, r, b)) }
}

/// `getservbyport_r` on safe types (`port` in network byte order).
pub fn servbyport_r(port: c_int, proto: Option<&CStr>, res: &mut servent, buf: &mut [u8]) -> (c_int, bool) {
    let pr = proto.map(CStr::to_bytes);
    if let Some(r) = nscd_servent(nscd::service_by_port(port, pr, buf), res, buf) {
        return r;
    }
    let out = RefCell::new(OutBufs { res, buf });
    by_key(
        b"services",
        b"getservbyport_r",
        None,
        &|| {
            let mut o = out.borrow_mut();
            let o = &mut *o;
            scan_status(None, scan(Db::Services, Fit::new(0, o.buf), |line, k| {
                let l = nss::parse_serv_line(line)?;
                *k = nss::words(l.rest).count();
                if (l.port.to_be() as c_int) != port {
                    return None;
                }
                if let Some(p) = pr {
                    if l.proto != p {
                        return None;
                    }
                }
                Some(fill_servent(o.res, o.buf, &l))
            }))
        },
        &|en| {
            let (r, b, n) = out.borrow_mut().raw();
            (port, proto.map_or(core::ptr::null(), CStr::as_ptr), r, b, n, en)
        },
    )
}

/// # Safety
/// glibc's contract for `getservbyport_r` (`port` in network byte order).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyport_r(port: c_int, proto: *const c_char, res: *mut servent, buf: *mut c_char, buflen: usize, result: *mut *mut servent) -> c_int {
    // SAFETY: glibc's contract (`proto` NULL or a C string).
    unsafe { r_shell(res, buf, buflen, result, OptStr(proto), |r, b, pr| servbyport_r(port, pr, r, b)) }
}

/// `getprotobyname_r` on safe types.
pub fn protobyname_r(name: &CStr, res: &mut protoent, buf: &mut [u8]) -> (c_int, bool) {
    let nm = name.to_bytes();
    let out = RefCell::new(OutBufs { res, buf });
    by_key(
        b"protocols",
        b"getprotobyname_r",
        None,
        &|| {
            let mut o = out.borrow_mut();
            let o = &mut *o;
            scan_status(None, scan(Db::Protocols, Fit::new(0, o.buf), |line, k| {
                let l = nss::parse_num_line(line)?;
                *k = nss::words(l.rest).count();
                if l.name == nm || nss::words(l.rest).any(|w| w == nm) {
                    return Some(fill_protoent(o.res, o.buf, &l));
                }
                None
            }))
        },
        &|en| {
            let (r, b, n) = out.borrow_mut().raw();
            (name.as_ptr(), r, b, n, en)
        },
    )
}

/// # Safety
/// glibc's contract for `getprotobyname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobyname_r(name: *const c_char, res: *mut protoent, buf: *mut c_char, buflen: usize, result: *mut *mut protoent) -> c_int {
    // SAFETY: glibc's contract (`name` a C string).
    unsafe { r_shell(res, buf, buflen, result, Str(name), |r, b, nm| protobyname_r(nm, r, b)) }
}

/// `getprotobynumber_r` on safe types.
pub fn protobynumber_r(proto: c_int, res: &mut protoent, buf: &mut [u8]) -> (c_int, bool) {
    let out = RefCell::new(OutBufs { res, buf });
    by_key(
        b"protocols",
        b"getprotobynumber_r",
        None,
        &|| {
            let mut o = out.borrow_mut();
            let o = &mut *o;
            scan_status(None, scan(Db::Protocols, Fit::new(0, o.buf), |line, k| {
                let l = nss::parse_num_line(line)?;
                *k = nss::words(l.rest).count();
                if l.num == proto { Some(fill_protoent(o.res, o.buf, &l)) } else { None }
            }))
        },
        &|en| {
            let (r, b, n) = out.borrow_mut().raw();
            (proto, r, b, n, en)
        },
    )
}

/// # Safety
/// glibc's contract for `getprotobynumber_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobynumber_r(proto: c_int, res: *mut protoent, buf: *mut c_char, buflen: usize, result: *mut *mut protoent) -> c_int {
    // SAFETY: glibc's contract.
    unsafe { r_shell(res, buf, buflen, result, (), |r, b, ()| protobynumber_r(proto, r, b)) }
}

/// `getnetbyname_r` on safe types (`h_errnop` None: NULL).
pub fn netbyname_r(name: &CStr, res: &mut netent, buf: &mut [u8], h_errnop: Option<&Cell<c_int>>) -> (c_int, bool) {
    let nm = name.to_bytes();
    let hp = h_errnop.map_or(core::ptr::null_mut(), Cell::as_ptr);
    let out = RefCell::new(OutBufs { res, buf });
    by_key_dns(
        b"networks",
        b"getnetbyname_r",
        h_errnop,
        &|| {
            let mut o = out.borrow_mut();
            let o = &mut *o;
            scan_status(h_errnop, scan(Db::Networks, Fit::new(0, o.buf), |line, k| {
                let l = nss::parse_net_line(line)?;
                *k = nss::words(l.rest).count();
                if eq_nocase(l.name, nm) || nss::words(l.rest).any(|w| eq_nocase(w, nm)) {
                    return Some(fill_netent(o.res, o.buf, &l));
                }
                None
            }))
        },
        &|en| {
            let (r, b, n) = out.borrow_mut().raw();
            (name.as_ptr(), r, b, n, en, hp)
        },
        // `dns` for networks: glibc's _nss_dns_getnetbyname_r (a PTR search for the name; a refused connection is UNAVAIL)
        Some(&|en| {
            let (r, b, n) = out.borrow_mut().raw();
            // SAFETY: as for a module.
            unsafe { crate::nssdns_abi::_nss_dns_getnetbyname_r(name.as_ptr(), r, b, n, en, hp) }
        }),
    )
}

/// # Safety
/// glibc's contract for `getnetbyname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyname_r(name: *const c_char, res: *mut netent, buf: *mut c_char, buflen: usize, result: *mut *mut netent, h_errnop: *mut c_int) -> c_int {
    // SAFETY: glibc's contract (`name` a C string, `h_errnop` NULL or valid).
    unsafe { r_shell(res, buf, buflen, result, (Str(name), OptCell(h_errnop)), |r, b, (nm, h)| netbyname_r(nm, r, b, h)) }
}

/// `getnetbyaddr_r` on safe types.
pub fn netbyaddr_r(net: u32, ty: c_int, res: &mut netent, buf: &mut [u8], h_errnop: Option<&Cell<c_int>>) -> (c_int, bool) {
    let hp = h_errnop.map_or(core::ptr::null_mut(), Cell::as_ptr);
    let out = RefCell::new(OutBufs { res, buf });
    by_key_dns(
        b"networks",
        b"getnetbyaddr_r",
        h_errnop,
        &|| {
            let mut o = out.borrow_mut();
            let o = &mut *o;
            scan_status(h_errnop, scan(Db::Networks, Fit::new(0, o.buf), |line, k| {
                let l = nss::parse_net_line(line)?;
                *k = nss::words(l.rest).count();
                if (ty == AF_UNSPEC || ty == AF_INET) && l.net == net { Some(fill_netent(o.res, o.buf, &l)) } else { None }
            }))
        },
        &|en| {
            let (r, b, n) = out.borrow_mut().raw();
            (net, ty, r, b, n, en, hp)
        },
        // glibc's _nss_dns_getnetbyaddr_r: a PTR query for the network's in-addr.arpa name; UNAVAIL for a type other than
        // AF_INET and for a refused connection (errno is put back as it was)
        Some(&|en| {
            let (r, b, n) = out.borrow_mut().raw();
            // SAFETY: as for a module.
            unsafe { crate::nssdns_abi::_nss_dns_getnetbyaddr_r(net, ty, r, b, n, en, hp) }
        }),
    )
}

/// # Safety
/// glibc's contract for `getnetbyaddr_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyaddr_r(net: u32, ty: c_int, res: *mut netent, buf: *mut c_char, buflen: usize, result: *mut *mut netent, h_errnop: *mut c_int) -> c_int {
    // SAFETY: glibc's contract (`h_errnop` NULL or valid).
    unsafe { r_shell(res, buf, buflen, result, OptCell(h_errnop), |r, b, h| netbyaddr_r(net, ty, r, b, h)) }
}

/// `getrpcbyname_r` on safe types.
pub fn rpcbyname_r(name: &CStr, res: &mut rpcent, buf: &mut [u8]) -> (c_int, bool) {
    let nm = name.to_bytes();
    let out = RefCell::new(OutBufs { res, buf });
    by_key(
        b"rpc",
        b"getrpcbyname_r",
        None,
        &|| {
            let mut o = out.borrow_mut();
            let o = &mut *o;
            scan_status(None, scan(Db::Rpc, Fit::new(0, o.buf), |line, k| {
                let l = nss::parse_num_line(line)?;
                *k = nss::words(l.rest).count();
                if l.name == nm || nss::words(l.rest).any(|w| w == nm) {
                    return Some(fill_rpcent(o.res, o.buf, &l));
                }
                None
            }))
        },
        &|en| {
            let (r, b, n) = out.borrow_mut().raw();
            (name.as_ptr(), r, b, n, en)
        },
    )
}

/// # Safety
/// glibc's contract for `getrpcbyname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbyname_r(name: *const c_char, res: *mut rpcent, buf: *mut c_char, buflen: usize, result: *mut *mut rpcent) -> c_int {
    // SAFETY: glibc's contract (`name` a C string).
    unsafe { r_shell(res, buf, buflen, result, Str(name), |r, b, nm| rpcbyname_r(nm, r, b)) }
}

/// `getrpcbynumber_r` on safe types.
pub fn rpcbynumber_r(number: c_int, res: &mut rpcent, buf: &mut [u8]) -> (c_int, bool) {
    let out = RefCell::new(OutBufs { res, buf });
    by_key(
        b"rpc",
        b"getrpcbynumber_r",
        None,
        &|| {
            let mut o = out.borrow_mut();
            let o = &mut *o;
            scan_status(None, scan(Db::Rpc, Fit::new(0, o.buf), |line, k| {
                let l = nss::parse_num_line(line)?;
                *k = nss::words(l.rest).count();
                if l.num == number { Some(fill_rpcent(o.res, o.buf, &l)) } else { None }
            }))
        },
        &|en| {
            let (r, b, n) = out.borrow_mut().raw();
            (number, r, b, n, en)
        },
    )
}

/// # Safety
/// glibc's contract for `getrpcbynumber_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbynumber_r(number: c_int, res: *mut rpcent, buf: *mut c_char, buflen: usize, result: *mut *mut rpcent) -> c_int {
    // SAFETY: glibc's contract.
    unsafe { r_shell(res, buf, buflen, result, (), |r, b, ()| rpcbynumber_r(number, r, b)) }
}

/// # Safety
/// Arguments as for the C function; the result is valid until the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyname(name: *const c_char, proto: *const c_char) -> *mut servent {
    // SAFETY: `name` a C string, `proto` NULL or one (contract).
    let (nm, pr) = unsafe { (Str(name), OptStr(proto)).conv() };
    with_static(&SERVENT_S, false, |res, buf| servbyname_r(nm, pr, res, buf))
}

/// # Safety
/// Arguments as for the C function; the result is valid until the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservbyport(port: c_int, proto: *const c_char) -> *mut servent {
    // SAFETY: NULL or a C string (contract).
    let pr = unsafe { ffi::cstr(proto) };
    with_static(&SERVENT_S, false, |res, buf| servbyport_r(port, pr, res, buf))
}

/// # Safety
/// Arguments as for the C function; the result is valid until the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotobyname(name: *const c_char) -> *mut protoent {
    // SAFETY: a C string (contract).
    let nm = unsafe { ffi::cstr_nonnull(name) };
    with_static(&PROTOENT_S, false, |res, buf| protobyname_r(nm, res, buf))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getprotobynumber(proto: c_int) -> *mut protoent {
    with_static(&PROTOENT_S, false, |res, buf| protobynumber_r(proto, res, buf))
}

/// # Safety
/// Arguments as for the C function; the result is valid until the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcbyname(name: *const c_char) -> *mut rpcent {
    // SAFETY: a C string (contract).
    let nm = unsafe { ffi::cstr_nonnull(name) };
    with_static(&RPCENT_S, false, |res, buf| rpcbyname_r(nm, res, buf))
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getrpcbynumber(number: c_int) -> *mut rpcent {
    with_static(&RPCENT_S, false, |res, buf| rpcbynumber_r(number, res, buf))
}

/// # Safety
/// `name` is a C string. The result is valid until the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetbyname(name: *const c_char) -> *mut netent {
    // SAFETY: a C string (contract).
    let nm = unsafe { ffi::cstr_nonnull(name) };
    let h = Cell::new(0);
    let r = with_static(&NETENT_S, false, |res, buf| netbyname_r(nm, res, buf, Some(&h)));
    // glibc's getXXbyYY.c: h_errno takes the sources' value only when one was set (the resolver's own setting stays otherwise)
    if h.get() != 0 {
        set_h_errno(h.get());
    }
    r
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getnetbyaddr(net: u32, ty: c_int) -> *mut netent {
    let h = Cell::new(0);
    let r = with_static(&NETENT_S, false, |res, buf| netbyaddr_r(net, ty, res, buf, Some(&h)));
    // glibc's getXXbyYY.c: h_errno takes the sources' value only when one was set (the resolver's own setting stays otherwise)
    if h.get() != 0 {
        set_h_errno(h.get());
    }
    r
}

// ---------------------------------------------------------------- *ent iteration
//
// setXXent / getXXent_r / endXXent walk the sources of the database through rusty_libc_core::nssent (glibc's
// __nss_setent / __nss_getent_r / __nss_endent): `files` is the file reader here, every other source a plug-in module
// (`_nss_NAME_setservent` ...), `dns` has no enumeration functions.

use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::lock::RawMutex;
use rusty_libc_core::nssent::{self, EntOps, Fn3};
use rusty_libc_core::nssmod;
use rusty_libc_core::sync_cell::SyncCell;

const ST_TRYAGAIN: i32 = -2;
const ST_UNAVAIL: i32 = -1;
const ST_NOTFOUND: i32 = 0;
const ST_SUCCESS: i32 = 1;

/// The `files` source of one database: its open file.
struct FileEnt {
    r: LineReader,
}

/// One enumerable database.
struct NetDb {
    st: nssent::EntState,
    f: FileEnt,
}

/// A database's enumeration state behind its own lock (taken always, as glibc's `__libc_lock_lock` in __nss_setent and
/// friends). `started` mirrors `st.is_started()` for endXXent's unlocked first look (glibc's `if (*startp == NULL) return`).
struct DbSlot {
    lock: RawMutex,
    started: AtomicBool,
    db: SyncCell<NetDb>,
}

impl DbSlot {
    const fn new() -> DbSlot {
        DbSlot { lock: RawMutex::new(), started: AtomicBool::new(false), db: SyncCell::new(NetDb { st: nssent::EntState::new(), f: FileEnt { r: LineReader::closed() } }) }
    }

    /// Run `f` on the database under its lock.
    fn with<R>(&self, f: impl FnOnce(&mut NetDb) -> R) -> R {
        self.lock.lock_always();
        // SAFETY: the slot's lock is held, and the value is reached only here.
        let r = unsafe {
            self.db.with_unsync(|db| {
                let r = f(db);
                self.started.store(db.st.is_started(), Ordering::Relaxed);
                r
            })
        };
        self.lock.unlock_always();
        r
    }
}

static HOST_DB: DbSlot = DbSlot::new();
static SERV_DB: DbSlot = DbSlot::new();
static PROTO_DB: DbSlot = DbSlot::new();
static NET_DB: DbSlot = DbSlot::new();
static RPC_DB: DbSlot = DbSlot::new();
static ALIAS_DB: DbSlot = DbSlot::new();

struct Names {
    db: &'static [u8],
    dbid: Db,
    set: &'static [u8],
    get: &'static [u8],
    end: &'static [u8],
    stay: bool,
    /// The functions of this database report through `h_errno` too.
    h: bool,
}

const HOST_NAMES: Names = Names { db: b"hosts", dbid: Db::Hosts, set: b"sethostent", get: b"gethostent_r", end: b"endhostent", stay: true, h: true };
const SERV_NAMES: Names = Names { db: b"services", dbid: Db::Services, set: b"setservent", get: b"getservent_r", end: b"endservent", stay: true, h: false };
const PROTO_NAMES: Names = Names { db: b"protocols", dbid: Db::Protocols, set: b"setprotoent", get: b"getprotoent_r", end: b"endprotoent", stay: true, h: false };
const NET_NAMES: Names = Names { db: b"networks", dbid: Db::Networks, set: b"setnetent", get: b"getnetent_r", end: b"endnetent", stay: true, h: true };
const RPC_NAMES: Names = Names { db: b"rpc", dbid: Db::Rpc, set: b"setrpcent", get: b"getrpcent_r", end: b"endrpcent", stay: true, h: false };
const ALIAS_NAMES: Names = Names { db: b"aliases", dbid: Db::Aliases, set: b"setaliasent", get: b"getaliasent_r", end: b"endaliasent", stay: false, h: false };

/// Reads the next entry of the `files` source into the caller's buffers: ST_SUCCESS, ST_NOTFOUND at the end, ST_TRYAGAIN with
/// errno ERANGE when the buffer is too small (the entry stays for the next call).
/// The last argument is the caller's buffer length (`buf.len()`).
type ReadFn<T> = fn(&mut FileEnt, &mut T, &mut [u8], usize) -> i32;

/// The caller's result structure and buffer of a getXXent_r call, and how the files source reads into them.
struct EntOut<'a, T> {
    res: &'a mut T,
    buf: &'a mut [u8],
    /// The caller's buffer length (`buf.len()` but for the aliases' slack).
    limit: usize,
    read: ReadFn<T>,
}

struct NetOps<'a, 'b, T> {
    f: &'a mut FileEnt,
    names: &'static Names,
    /// None for set/end.
    out: Option<EntOut<'b, T>>,
    h: *mut c_int,
}

fn is_files(src: &nssmod::Source) -> bool {
    nssent::is_files(src)
}

impl<T> EntOps for NetOps<'_, '_, T> {
    fn has(&mut self, src: &nssmod::Source, f: Fn3) -> bool {
        if is_files(src) {
            return true;
        }
        if src.is(b"dns") {
            return false;
        }
        let n = match f {
            Fn3::Set => self.names.set,
            Fn3::Get => self.names.get,
            Fn3::End => self.names.end,
        };
        nssmod::function(src.name(), n) != 0
    }
    fn call_set(&mut self, src: &nssmod::Source, stay: i32) -> i32 {
        if is_files(src) {
            return file_set(self.f, self.names.dbid);
        }
        let f = nssmod::function(src.name(), self.names.set);
        if f == 0 {
            return ST_UNAVAIL;
        }
        if self.names.stay {
            // SAFETY: a module's `_nss_NAME_setXXent` takes the stay-open flag (glibc's signature). a plain value.
            unsafe { (stay,).call(f) }
        } else {
            // SAFETY: `_nss_NAME_setaliasent` takes nothing. no arguments.
            unsafe { ().call(f) }
        }
    }
    fn call_get(&mut self, src: &nssmod::Source) -> i32 {
        let Some(out) = self.out.as_mut() else { return ST_UNAVAIL };
        if is_files(src) {
            if !self.f.r.is_open() {
                let saved = errno::get();
                let st = file_set(self.f, self.names.dbid);
                errno::set(saved); // glibc: __nss_files_data_open restores errno after the implicit open
                if st != ST_SUCCESS {
                    return st;
                }
            }
            return (out.read)(self.f, out.res, out.buf, out.limit);
        }
        let f = nssmod::function(src.name(), self.names.get);
        if f == 0 {
            return ST_UNAVAIL;
        }
        // SAFETY: a module's `_nss_NAME_getXXent_r` has glibc's signature. the caller's structure and buffer, the thread's errno, NULL or the thread's h_errno.
        let st = unsafe { (out.res as *mut T, out.buf.as_mut_ptr().cast::<c_char>(), out.limit, errno::location(), self.h).call(f) };
        if (-2..=1).contains(&st) { st } else { ST_UNAVAIL }
    }
    fn call_end(&mut self, src: &nssmod::Source) {
        if is_files(src) {
            self.f.r.close();
            return;
        }
        let f = nssmod::function(src.name(), self.names.end);
        if f != 0 {
            // SAFETY: a module's `_nss_NAME_endXXent` takes nothing. no arguments.
            unsafe { ().call(f) };
        }
    }
}

/// `setent` of the `files` source: open the file, or rewind it when already open.
fn file_set(f: &mut FileEnt, db: Db) -> i32 {
    if f.r.is_open() {
        f.r.rewind();
        return ST_SUCCESS;
    }
    match nss::open_db(db) {
        Ok(r) => {
            f.r = r;
            ST_SUCCESS
        }
        Err(e) => {
            errno::set(e);
            if e == EAGAIN { ST_TRYAGAIN } else { ST_UNAVAIL }
        }
    }
}

fn db_set<T>(slot: &DbSlot, names: &'static Names, stay: c_int) {
    slot.with(|db| {
        let mut ops = NetOps::<T> { f: &mut db.f, names, out: None, h: core::ptr::null_mut() };
        db.st.setent(names.db, stay, &mut ops, names.stay);
    })
}

fn db_end<T>(slot: &DbSlot, names: &'static Names) {
    if !slot.started.load(Ordering::Relaxed) {
        return;
    }
    slot.with(|db| {
        let mut ops = NetOps::<T> { f: &mut db.f, names, out: None, h: core::ptr::null_mut() };
        db.st.endent(names.db, &mut ops);
    })
}

/// glibc's `__nss_getent_r` for this database: 0 on success (the result is to be set), ENOENT at the end, ERANGE for a
/// small buffer.
fn db_get<T>(slot: &DbSlot, names: &'static Names, read: ReadFn<T>, res: &mut T, buf: &mut [u8], limit: usize) -> (c_int, bool) {
    // glibc passes the thread's own `h_errno` down, never the caller's h_errnop (which the get*ent_r functions ignore)
    let hp: *mut c_int = if names.h { crate::strerr::__h_errno.as_ptr() } else { core::ptr::null_mut() };
    let rc = slot.with(|db| {
        let mut ops = NetOps::<T> { f: &mut db.f, names, out: Some(EntOut { res, buf, limit, read }), h: hp };
        db.st.getent(names.db, &mut ops, names.stay, &|| !names.h || crate::strerr::h_errno() == NETDB_INTERNAL)
    });
    (rc, rc == 0)
}

/// The next entry of an open `files` source for an enumeration, with glibc's buffer rules (`Fit`). `parse` is as for `scan`.
fn read_ent(f: &mut FileEnt, fit: Fit, h: bool, mut parse: impl FnMut(&[u8], &mut usize) -> Option<Result<(), i32>>) -> i32 {
    let erange = |f: &mut FileEnt, unread: bool| {
        if unread {
            f.r.unread();
        }
        errno::set(ERANGE);
        if h {
            crate::strerr::set_h_errno(NETDB_INTERNAL);
        }
        ST_TRYAGAIN
    };
    if !fit.pre_ok() {
        return erange(f, false);
    }
    loop {
        let Some((line, rawlen)) = f.r.next_raw() else {
            if h {
                crate::strerr::set_h_errno(HOST_NOT_FOUND);
            }
            return ST_NOTFOUND;
        };
        if !fit.read_ok(rawlen) {
            return erange(f, true);
        }
        let Some(body) = nss::entry_body(line) else { continue };
        let mut k = usize::MAX;
        let r = parse(body, &mut k);
        if k != usize::MAX && !fit.list_ok(rawlen, k) {
            return erange(f, true);
        }
        match r {
            None => continue,
            Some(Ok(())) => return ST_SUCCESS,
            Some(Err(e)) => {
                f.r.unread();
                errno::set(e);
                if h {
                    crate::strerr::set_h_errno(NETDB_INTERNAL);
                }
                return if e == ERANGE { ST_TRYAGAIN } else { ST_UNAVAIL };
            }
        }
    }
}

fn read_serv(f: &mut FileEnt, res: &mut servent, buf: &mut [u8], _limit: usize) -> i32 {
    read_ent(f, Fit::new(0, buf), false, |line, k| {
        let l = nss::parse_serv_line(line)?;
        *k = nss::words(l.rest).count();
        Some(fill_servent(res, buf, &l))
    })
}
fn read_proto(f: &mut FileEnt, res: &mut protoent, buf: &mut [u8], _limit: usize) -> i32 {
    read_ent(f, Fit::new(0, buf), false, |line, k| {
        let l = nss::parse_num_line(line)?;
        *k = nss::words(l.rest).count();
        Some(fill_protoent(res, buf, &l))
    })
}
fn read_net(f: &mut FileEnt, res: &mut netent, buf: &mut [u8], _limit: usize) -> i32 {
    read_ent(f, Fit::new(0, buf), true, |line, k| {
        let l = nss::parse_net_line(line)?;
        *k = nss::words(l.rest).count();
        Some(fill_netent(res, buf, &l))
    })
}
fn read_rpc(f: &mut FileEnt, res: &mut rpcent, buf: &mut [u8], _limit: usize) -> i32 {
    read_ent(f, Fit::new(0, buf), false, |line, k| {
        let l = nss::parse_num_line(line)?;
        *k = nss::words(l.rest).count();
        Some(fill_rpcent(res, buf, &l))
    })
}
fn read_host(f: &mut FileEnt, res: &mut hostent, buf: &mut [u8], _limit: usize) -> i32 {
    // the hosts parser keeps the address and its pointers in a 32 byte area at the start of the buffer
    read_ent(f, Fit::new(32, buf), true, |line, k| {
        let h = nss::parse_host_line(line, AF_INET, false)?;
        *k = nss::words(h.rest).count();
        let a = Addr { family: h.family, bytes: h.addr, scope: 0 };
        Some(fill_hostent(res, buf, h.name, h.rest, h.family, &[a]))
    })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setservent(stay: c_int) {
    db_set::<servent>(&SERV_DB, &SERV_NAMES, stay)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endservent() {
    db_end::<servent>(&SERV_DB, &SERV_NAMES)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setprotoent(stay: c_int) {
    db_set::<protoent>(&PROTO_DB, &PROTO_NAMES, stay)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endprotoent() {
    db_end::<protoent>(&PROTO_DB, &PROTO_NAMES)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setnetent(stay: c_int) {
    db_set::<netent>(&NET_DB, &NET_NAMES, stay)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endnetent() {
    db_end::<netent>(&NET_DB, &NET_NAMES)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setrpcent(stay: c_int) {
    db_set::<rpcent>(&RPC_DB, &RPC_NAMES, stay)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endrpcent() {
    db_end::<rpcent>(&RPC_DB, &RPC_NAMES)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn sethostent(stay: c_int) {
    db_set::<hostent>(&HOST_DB, &HOST_NAMES, stay)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endhostent() {
    db_end::<hostent>(&HOST_DB, &HOST_NAMES)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn setaliasent() {
    db_set::<aliasent>(&ALIAS_DB, &ALIAS_NAMES, 0)
}
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn endaliasent() {
    db_end::<aliasent>(&ALIAS_DB, &ALIAS_NAMES)
}

/// `getservent_r` on safe types.
pub fn servent_r(res: &mut servent, buf: &mut [u8]) -> (c_int, bool) {
    {
        let n = buf.len();
        db_get(&SERV_DB, &SERV_NAMES, read_serv, res, buf, n)
    }
}
/// `getprotoent_r` on safe types.
pub fn protoent_r(res: &mut protoent, buf: &mut [u8]) -> (c_int, bool) {
    {
        let n = buf.len();
        db_get(&PROTO_DB, &PROTO_NAMES, read_proto, res, buf, n)
    }
}
/// `getnetent_r` on safe types.
pub fn netent_r(res: &mut netent, buf: &mut [u8]) -> (c_int, bool) {
    {
        let n = buf.len();
        db_get(&NET_DB, &NET_NAMES, read_net, res, buf, n)
    }
}
/// `getrpcent_r` on safe types.
pub fn rpcent_r(res: &mut rpcent, buf: &mut [u8]) -> (c_int, bool) {
    {
        let n = buf.len();
        db_get(&RPC_DB, &RPC_NAMES, read_rpc, res, buf, n)
    }
}
/// `gethostent_r` on safe types.
pub fn hostent_r(res: &mut hostent, buf: &mut [u8]) -> (c_int, bool) {
    {
        let n = buf.len();
        db_get(&HOST_DB, &HOST_NAMES, read_host, res, buf, n)
    }
}

/// # Safety
/// glibc's contract for `getservent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getservent_r(res: *mut servent, buf: *mut c_char, buflen: usize, result: *mut *mut servent) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { r_shell(res, buf, buflen, result, (), |r, b, ()| servent_r(r, b)) }
}

/// # Safety
/// glibc's contract for `getprotoent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getprotoent_r(res: *mut protoent, buf: *mut c_char, buflen: usize, result: *mut *mut protoent) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { r_shell(res, buf, buflen, result, (), |r, b, ()| protoent_r(r, b)) }
}

/// # Safety
/// glibc's contract for `getnetent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getnetent_r(res: *mut netent, buf: *mut c_char, buflen: usize, result: *mut *mut netent, _h_errnop: *mut c_int) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { r_shell(res, buf, buflen, result, (), |r, b, ()| netent_r(r, b)) }
}

/// # Safety
/// glibc's contract for `getrpcent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getrpcent_r(res: *mut rpcent, buf: *mut c_char, buflen: usize, result: *mut *mut rpcent) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { r_shell(res, buf, buflen, result, (), |r, b, ()| rpcent_r(r, b)) }
}

/// # Safety
/// glibc's contract for `gethostent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn gethostent_r(res: *mut hostent, buf: *mut c_char, buflen: usize, result: *mut *mut hostent, _h_errnop: *mut c_int) -> c_int {
    // SAFETY: forwarded contract.
    unsafe { r_shell(res, buf, buflen, result, (), |r, b, ()| hostent_r(r, b)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getservent() -> *mut servent {
    with_static(&SERVENT_S, true, servent_r)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getprotoent() -> *mut protoent {
    with_static(&PROTOENT_S, true, protoent_r)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getnetent() -> *mut netent {
    with_static(&NETENT_S, true, netent_r)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getrpcent() -> *mut rpcent {
    with_static(&RPCENT_S, true, rpcent_r)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gethostent() -> *mut hostent {
    with_static(&HOSTENT_S, true, hostent_r)
}

// ---------------------------------------------------------------- aliases (aliases.h)
//
// /etc/aliases is read the way glibc's nss_files does (nss/nss_files/files-alias.c `get_next_alias`, read as reference and
// written in Rust): on the raw stream, a line and its continuation lines compacted in place in the caller's buffer, the
// members' pointers after them. A buffer that is too small loses what was read (glibc does not seek back for aliases): the
// next call starts after it. `:include:` members are expanded from the file they name.

const ST_RETURN: i32 = 2;

fn c_isspace(c: u8) -> bool {
    matches!(c, b' ' | 9..=13)
}

/// End the text at `b[at..]` at its first `#` or newline.
fn cut_at_comment_or_newline(b: &mut [u8], at: usize) {
    let mut q = at;
    while b[q] != 0 {
        if b[q] == b'#' || b[q] == b'\n' {
            b[q] = 0;
            return;
        }
        q += 1;
    }
}

/// The NUL-terminated text at `b[at..]`, without its NUL.
fn cstr_at(b: &[u8], at: usize) -> &[u8] {
    let n = b[at..].iter().position(|&c| c == 0).unwrap_or(b.len() - at);
    &b[at..at + n]
}

/// glibc's `get_next_alias`: the next alias entry (or, with `matchname`, the next entry of that name) in `b`. The text is
/// compacted in place (indexes into `b` instead of glibc's pointers); the pointers stored in `result` point into `b`.
/// `limit` is the caller's buffer length, `b.len()`: the member pointer array is placed inside it (glibc places it after the
/// text without checking the end, up to 7 bytes past the buffer; we refuse such a buffer with ERANGE instead).
fn get_next_alias(st: &mut LineReader, matchname: Option<&[u8]>, result: &mut aliasent, b: &mut [u8], limit: usize) -> i32 {
    let buflen = limit;
    let base = b.as_mut_ptr();
    let mut status = ST_NOTFOUND;
    let mut ignore = false;
    result.alias_members_len = 0;
    let no_room = || {
        errno::set(ERANGE);
        ST_TRYAGAIN
    };
    loop {
        let entry_start = st.tell();
        let mut fu = 0usize;
        let mut room_left = buflen - (buflen % 8);
        if room_left < 2 {
            return no_room();
        }
        b[fu + room_left - 1] = 0xff;
        if !st.fgets(&mut b[fu..fu + room_left]) {
            break;
        }
        if b[fu + room_left - 1] != 0xff {
            return no_room();
        }
        let mut line = fu;
        if ignore && c_isspace(b[fu]) {
            continue;
        }
        cut_at_comment_or_newline(b, fu);
        while c_isspace(b[line]) {
            line += 1;
        }
        let name_at = fu;
        result.alias_name = base.wrapping_add(fu).cast();
        while b[line] != 0 && b[line] != b':' {
            b[fu] = b[line];
            fu += 1;
            line += 1;
        }
        if b[line] == 0 || name_at == fu {
            continue;
        }
        b[fu] = 0;
        fu += 1;
        let used = fu - name_at;
        if room_left < used {
            return no_room();
        }
        room_left -= used;
        line += 1;
        ignore = match matchname {
            Some(m) => !eq_nocase(cstr_at(b, name_at), m),
            None => false,
        };
        if !ignore {
            loop {
                while c_isspace(b[line]) {
                    line += 1;
                }
                let mut cp = fu;
                while b[line] != 0 && b[line] != b',' {
                    b[fu] = b[line];
                    fu += 1;
                    line += 1;
                }
                if fu != cp {
                    if b[line] != 0 {
                        line += 1;
                    }
                    b[fu] = 0;
                    fu += 1;
                    let is_include = b[cp..cp + 9.min(fu - cp)] == *b":include:";
                    if !is_include {
                        let n = fu - cp;
                        if room_left < n + 8 {
                            return no_room();
                        }
                        room_left -= n + 8;
                        result.alias_members_len += 1;
                    } else {
                        fu = cp;
                        let mut path = Buf::<320>::new();
                        path.push_all(cstr_at(b, cp + 9));
                        path.push(0);
                        let listfile = LineReader::open(&path).ok();
                        // the rest of the line, with its NUL (glibc's strdup)
                        let old_line = if listfile.is_some() {
                            let n = cstr_at(b, line).len();
                            let mut v = HeapVec::<u8>::new();
                            if v.extend_from(&b[line..line + n + 1]) { Some(v) } else { None }
                        } else {
                            None
                        };
                        if let (Some(mut lf), Some(old)) = (listfile, old_line) {
                            while !lf.at_eof() {
                                if room_left < 2 {
                                    return no_room();
                                }
                                b[fu + room_left - 1] = 0xff;
                                if !lf.fgets(&mut b[fu..fu + room_left]) {
                                    break;
                                }
                                line = fu;
                                if b[fu + room_left - 1] != 0xff {
                                    return no_room();
                                }
                                cut_at_comment_or_newline(b, line);
                                loop {
                                    while c_isspace(b[line]) {
                                        line += 1;
                                    }
                                    cp = fu;
                                    while b[line] != 0 && b[line] != b',' {
                                        b[fu] = b[line];
                                        fu += 1;
                                        line += 1;
                                    }
                                    if b[line] != 0 {
                                        line += 1;
                                    }
                                    if fu != cp {
                                        b[fu] = 0;
                                        fu += 1;
                                        let n = fu - cp;
                                        if room_left < n + 8 {
                                            return no_room();
                                        }
                                        room_left -= n + 8;
                                        result.alias_members_len += 1;
                                    }
                                    if b[line] == 0 {
                                        break;
                                    }
                                }
                            }
                            drop(lf);
                            // glibc: strncpy of the rest of the line back into the buffer (padding with NULs)
                            b[fu + room_left - 1] = 0;
                            let n = cstr_at(&old, 0).len().min(room_left);
                            b[fu..fu + n].copy_from_slice(&old[..n]);
                            b[fu + n..fu + room_left].fill(0);
                            line = fu;
                            if b[fu + room_left - 1] != 0 {
                                return no_room();
                            }
                        }
                    }
                }
                if b[line] == 0 {
                    // a continuation line starts with white space; anything else begins the next entry
                    let ch = st.getc();
                    if ch == -1 || ch == b'\n' as i32 || !c_isspace(ch as u8) {
                        if ch != -1 {
                            st.ungetc();
                        }
                        // the member pointers, 8-aligned after the text; each member follows the previous string
                        let at = ((base as usize + fu + 7) & !7) - base as usize;
                        // (glibc writes the array past the buffer here; ours gives the entry back and reports ERANGE)
                        let give_back = |st: &mut LineReader| {
                            if let Some(off) = entry_start {
                                st.seek(off);
                            }
                            no_room()
                        };
                        if at > b.len() {
                            return give_back(st);
                        }
                        let (text, rest) = b.split_at_mut(at);
                        let Some(members) = Carve::new(rest).ptr_array(result.alias_members_len) else { return give_back(st) };
                        let tp = text.as_mut_ptr();
                        let mut c = name_at;
                        for m in members.iter_mut() {
                            c += cstr_at(text, c).len() + 1;
                            *m = tp.wrapping_add(c).cast();
                        }
                        result.alias_members = members.as_mut_ptr();
                        status = if result.alias_members_len == 0 { ST_RETURN } else { ST_SUCCESS };
                        break;
                    }
                    b[fu + room_left - 1] = 0xff;
                    if !st.fgets(&mut b[fu..fu + room_left]) {
                        // a continuation line without data and without a newline: an empty line, then the end again
                        line = fu;
                        b[line] = 0;
                        continue;
                    }
                    line = fu;
                    if b[fu + room_left - 1] != 0xff {
                        return no_room();
                    }
                    cut_at_comment_or_newline(b, line);
                }
            }
        }
        if status != ST_NOTFOUND {
            break;
        }
    }
    status
}

// glibc's alias parser (files-alias.c `get_next_alias`) puts the member pointer array at the next 8-byte boundary after the text
// without checking it against the buffer's end, so it can write up to 7 bytes past `buflen`. Ours never writes past the buffer
// (FIXLIST #87, Adam 2026-10-31): a buffer that would need it gets ERANGE, so the smallest accepted size can be a few bytes
// larger than glibc's for some entries.

/// `getaliasent_r` on safe types.
pub fn aliasent_r(res: &mut aliasent, buf: &mut [u8]) -> (c_int, bool) {
    let n = buf.len();
    alias_ent(res, buf, n)
}

/// getaliasent_r with the caller's buffer length `limit` .
fn alias_ent(res: &mut aliasent, buf: &mut [u8], limit: usize) -> (c_int, bool) {
    db_get(&ALIAS_DB, &ALIAS_NAMES, read_aliasf, res, buf, limit)
}

/// # Safety
/// glibc's contract for `getaliasent_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasent_r(res: *mut aliasent, buf: *mut c_char, buflen: usize, result: *mut *mut aliasent) -> c_int {
    // SAFETY: glibc's contract.
    unsafe { r_shell(res, buf, buflen, result, (), |r, b, ()| alias_ent(r, b, buflen)) }
}

/// The `files` source of the aliases (`_nss_files_getaliasent_r`).
fn read_aliasf(f: &mut FileEnt, res: &mut aliasent, buf: &mut [u8], limit: usize) -> i32 {
    res.alias_local = 1;
    loop {
        let st = get_next_alias(&mut f.r, None, res, buf, limit);
        if st != ST_RETURN {
            return st;
        }
    }
}

/// `getaliasbyname_r` on safe types (the pointer array stays inside `buf`).
pub fn aliasbyname_r(name: &CStr, res: &mut aliasent, buf: &mut [u8]) -> (c_int, bool) {
    let n = buf.len();
    alias_byname(name, res, buf, n)
}

/// getaliasbyname_r with the caller's buffer length `limit` .
fn alias_byname(name: &CStr, res: &mut aliasent, buf: &mut [u8], limit: usize) -> (c_int, bool) {
    let out = RefCell::new(OutBufs { res, buf });
    by_key(
        b"aliases",
        b"getaliasbyname_r",
        None,
        &|| {
            let mut r = match nss::open_db(Db::Aliases) {
                Ok(r) => r,
                Err(e) => return scan_status(None, Scan::Unavail(e)),
            };
            let mut o = out.borrow_mut();
            let o = &mut *o;
            o.res.alias_local = 1;
            loop {
                let st = get_next_alias(&mut r, Some(name.to_bytes()), o.res, o.buf, limit);
                if st != ST_RETURN {
                    return st;
                }
            }
        },
        &|en| {
            let (r, b, _) = out.borrow_mut().raw();
            (name.as_ptr(), r, b, limit, en)
        },
    )
}

/// # Safety
/// glibc's contract for `getaliasbyname_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasbyname_r(name: *const c_char, res: *mut aliasent, buf: *mut c_char, buflen: usize, result: *mut *mut aliasent) -> c_int {
    // SAFETY: glibc's contract (`name` a C string).
    unsafe { r_shell(res, buf, buflen, result, Str(name), |r, b, nm| alias_byname(nm, r, b, buflen)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn getaliasent() -> *mut aliasent {
    with_static(&ALIASENT_S, true, aliasent_r)
}

/// # Safety
/// `name` is a C string. The result is valid until the next call.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn getaliasbyname(name: *const c_char) -> *mut aliasent {
    // SAFETY: a C string (contract).
    let nm = unsafe { ffi::cstr_nonnull(name) };
    with_static(&ALIASENT_S, false, |res, buf| aliasbyname_r(nm, res, buf))
}
