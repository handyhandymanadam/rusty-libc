#![allow(non_upper_case_globals)]
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicI32, AtomicPtr, Ordering};
use rusty_libc_core::string as cstring;
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_stdio::file::File;
use rusty_libc_stdio::fmt::Sink;
use rusty_libc_stdio::rust_api::{Arg, format_to, snprintf};
use rusty_libc_util::getopt::{COption, Data, getopt_internal_r};

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ArgpOption {
    pub name: *const c_char,
    pub key: c_int,
    pub arg: *const c_char,
    pub flags: c_int,
    pub doc: *const c_char,
    pub group: c_int,
}

pub type ArgpParser = unsafe extern "C" fn(c_int, *mut c_char, *mut ArgpState) -> c_int;
pub type HelpFilter = unsafe extern "C" fn(c_int, *const c_char, *mut c_void) -> *mut c_char;

#[repr(C)]
pub struct Argp {
    pub options: *const ArgpOption,
    pub parser: Option<ArgpParser>,
    pub args_doc: *const c_char,
    pub doc: *const c_char,
    pub children: *const ArgpChild,
    pub help_filter: Option<HelpFilter>,
    pub argp_domain: *const c_char,
}

#[repr(C)]
pub struct ArgpChild {
    pub argp: *const Argp,
    pub flags: c_int,
    pub header: *const c_char,
    pub group: c_int,
}

#[repr(C)]
pub struct ArgpState {
    pub root_argp: *const Argp,
    pub argc: c_int,
    pub argv: *mut *mut c_char,
    pub next: c_int,
    pub flags: c_uint,
    pub arg_num: c_uint,
    pub quoted: c_int,
    pub input: *mut c_void,
    pub child_inputs: *mut *mut c_void,
    pub hook: *mut c_void,
    pub name: *mut c_char,
    pub err_stream: *mut File,
    pub out_stream: *mut File,
    pub pstate: *mut c_void,
}

const _: () = assert!(size_of::<ArgpOption>() == 48);
const _: () = assert!(size_of::<Argp>() == 56);
const _: () = assert!(size_of::<ArgpChild>() == 32);
const _: () = assert!(size_of::<ArgpState>() == 96);

unsafe impl Sync for ArgpOption {}

pub const OPTION_ARG_OPTIONAL: c_int = 0x1;
pub const OPTION_HIDDEN: c_int = 0x2;
pub const OPTION_ALIAS: c_int = 0x4;
pub const OPTION_DOC: c_int = 0x8;
pub const OPTION_NO_USAGE: c_int = 0x10;

pub const ARGP_ERR_UNKNOWN: c_int = 7;
pub const ARGP_KEY_ARG: c_int = 0;
pub const ARGP_KEY_ARGS: c_int = 0x1000006;
pub const ARGP_KEY_END: c_int = 0x1000001;
pub const ARGP_KEY_NO_ARGS: c_int = 0x1000002;
pub const ARGP_KEY_INIT: c_int = 0x1000003;
pub const ARGP_KEY_FINI: c_int = 0x1000007;
pub const ARGP_KEY_SUCCESS: c_int = 0x1000004;
pub const ARGP_KEY_ERROR: c_int = 0x1000005;

pub const ARGP_KEY_HELP_PRE_DOC: c_int = 0x2000001;
pub const ARGP_KEY_HELP_POST_DOC: c_int = 0x2000002;
pub const ARGP_KEY_HELP_HEADER: c_int = 0x2000003;
pub const ARGP_KEY_HELP_EXTRA: c_int = 0x2000004;
pub const ARGP_KEY_HELP_DUP_ARGS_NOTE: c_int = 0x2000005;
pub const ARGP_KEY_HELP_ARGS_DOC: c_int = 0x2000006;

pub const ARGP_PARSE_ARGV0: c_uint = 0x01;
pub const ARGP_NO_ERRS: c_uint = 0x02;
pub const ARGP_NO_ARGS: c_uint = 0x04;
pub const ARGP_IN_ORDER: c_uint = 0x08;
pub const ARGP_NO_HELP: c_uint = 0x10;
pub const ARGP_NO_EXIT: c_uint = 0x20;
pub const ARGP_LONG_ONLY: c_uint = 0x40;
pub const ARGP_SILENT: c_uint = ARGP_NO_EXIT | ARGP_NO_ERRS | ARGP_NO_HELP;

pub const ARGP_HELP_USAGE: c_uint = 0x01;
pub const ARGP_HELP_SHORT_USAGE: c_uint = 0x02;
pub const ARGP_HELP_SEE: c_uint = 0x04;
pub const ARGP_HELP_LONG: c_uint = 0x08;
pub const ARGP_HELP_PRE_DOC: c_uint = 0x10;
pub const ARGP_HELP_POST_DOC: c_uint = 0x20;
pub const ARGP_HELP_DOC: c_uint = ARGP_HELP_PRE_DOC | ARGP_HELP_POST_DOC;
pub const ARGP_HELP_BUG_ADDR: c_uint = 0x40;
pub const ARGP_HELP_LONG_ONLY: c_uint = 0x80;
pub const ARGP_HELP_EXIT_ERR: c_uint = 0x100;
pub const ARGP_HELP_EXIT_OK: c_uint = 0x200;
pub const ARGP_HELP_STD_ERR: c_uint = ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR;
pub const ARGP_HELP_STD_USAGE: c_uint = ARGP_HELP_SHORT_USAGE | ARGP_HELP_SEE | ARGP_HELP_EXIT_ERR;
pub const ARGP_HELP_STD_HELP: c_uint = ARGP_HELP_SHORT_USAGE | ARGP_HELP_LONG | ARGP_HELP_EXIT_OK | ARGP_HELP_DOC | ARGP_HELP_BUG_ADDR;

const EBADKEY: c_int = ARGP_ERR_UNKNOWN;
const ENOMEM: c_int = 12;
const EINVAL: c_int = 22;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static argp_program_version: SyncCell<*const c_char> = SyncCell::new(null());
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static argp_program_version_hook: SyncCell<Option<unsafe extern "C" fn(*mut File, *mut ArgpState)>> = SyncCell::new(None);
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static argp_program_bug_address: SyncCell<*const c_char> = SyncCell::new(null());
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static argp_err_exit_status: SyncCell<c_int> = SyncCell::new(64);

fn program_version() -> *const c_char {
    unsafe { argp_program_version.read() }
}

fn program_version_hook() -> Option<unsafe extern "C" fn(*mut File, *mut ArgpState)> {
    unsafe { argp_program_version_hook.read() }
}

fn program_bug_address() -> Option<&'static CStr> {
    let p = unsafe { argp_program_bug_address.read() };
    unsafe { rusty_libc_core::ffi::cstr(p) }
}

fn err_exit_status() -> c_int {
    unsafe { argp_err_exit_status.read() }
}

#[cfg(feature = "export")]
unsafe extern "C" {
    static mut program_invocation_name: *mut c_char;
    static mut program_invocation_short_name: *mut c_char;
}
#[cfg(not(feature = "export"))]
use rusty_libc_util::err::{program_invocation_name, program_invocation_short_name};

fn short_program_name() -> &'static CStr {
    let p = unsafe { program_invocation_short_name };
    unsafe { rusty_libc_core::ffi::cstr(p) }.unwrap_or(c"")
}

fn set_program_names(full: *mut c_char, short: *mut c_char) {
    unsafe { program_invocation_name = full };
    unsafe { program_invocation_short_name = short };
}

fn isspace(c: u8) -> bool {
    rusty_libc_ctype::is_space(c as i32)
}

fn isalnum(c: u8) -> bool {
    rusty_libc_ctype::is_alnum(c as i32)
}

fn isprint(c: c_int) -> bool {
    rusty_libc_ctype::is_print(c)
}

fn isblank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

fn tolower(c: c_int) -> c_int {
    rusty_libc_ctype::to_lower(c)
}

fn flush_exit(status: c_int) -> ! {
    rusty_libc_core::process::exit(status)
}

fn std_err() -> *mut File {
    unsafe { rusty_libc_stdio::stderr.read() }
}

fn std_out() -> *mut File {
    unsafe { rusty_libc_stdio::stdout.read() }
}

fn oend(o: &ArgpOption) -> bool {
    o.key == 0 && o.name.is_null() && o.doc.is_null() && o.group == 0
}

fn oshort(o: &ArgpOption) -> bool {
    if o.flags & OPTION_DOC != 0 {
        false
    } else {
        let k = o.key;
        k > 0 && k <= 255 && isprint(k)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _option_is_short(opt: *const ArgpOption) -> c_int {
    oshort(unsafe { &*opt }) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _option_is_end(opt: *const ArgpOption) -> c_int {
    oend(unsafe { &*opt }) as c_int
}

mod heap {
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;

    pub(super) fn malloc(n: usize) -> *mut u8 {
        unsafe { rusty_libc_malloc::malloc(n) }.cast()
    }

    pub(super) unsafe fn free(p: *mut u8) {
        unsafe { rusty_libc_malloc::free(p.cast()) }
    }

    pub(super) fn oom() -> ! {
        rusty_libc_core::process::abort()
    }

    pub(super) struct MBox<T>(NonNull<T>);

    impl<T> MBox<T> {
        pub(super) fn uninit() -> Option<MBox<MaybeUninit<T>>> {
            const { assert!(align_of::<T>() <= 16) };
            NonNull::new(malloc(size_of::<T>()).cast::<MaybeUninit<T>>()).map(MBox)
        }

        pub(super) fn new(v: T) -> Option<MBox<T>> {
            Some(MBox::uninit()?.init(v))
        }

        pub(super) fn into_raw(self) -> NonNull<T> {
            let p = self.0;
            core::mem::forget(self);
            p
        }

        pub(super) fn consume(self, f: impl FnOnce(T)) {
            let p = self.into_raw();
            f(unsafe { p.read() });
            unsafe { free(p.as_ptr().cast()) };
        }

        pub(super) unsafe fn from_raw(p: NonNull<T>) -> MBox<T> {
            MBox(p)
        }
    }

    impl<T> MBox<MaybeUninit<T>> {
        pub(super) fn init(self, v: T) -> MBox<T> {
            let p = self.0.cast::<T>();
            core::mem::forget(self);
            unsafe { p.write(v) };
            MBox(p)
        }
    }

    impl<T> core::ops::Deref for MBox<T> {
        type Target = T;
        fn deref(&self) -> &T {
            unsafe { self.0.as_ref() }
        }
    }

    impl<T> core::ops::DerefMut for MBox<T> {
        fn deref_mut(&mut self) -> &mut T {
            unsafe { self.0.as_mut() }
        }
    }

    impl<T> Drop for MBox<T> {
        fn drop(&mut self) {
            unsafe { core::ptr::drop_in_place(self.0.as_ptr()) };
            unsafe { free(self.0.as_ptr().cast()) };
        }
    }

    pub(super) struct MVec<T: Copy> {
        p: NonNull<T>,
        len: usize,
        cap: usize,
    }

    impl<T: Copy> MVec<T> {
        pub(super) fn with_capacity(cap: usize) -> Option<MVec<T>> {
            const { assert!(align_of::<T>() <= 16) };
            let p = NonNull::new(malloc(cap.checked_mul(size_of::<T>())?).cast::<T>())?;
            Some(MVec { p, len: 0, cap })
        }

        pub(super) fn push(&mut self, v: T) {
            if self.len == self.cap {
                oom();
            }
            unsafe { self.p.as_ptr().wrapping_add(self.len).write(v) };
            self.len += 1;
        }

        pub(super) fn extend_from_slice(&mut self, s: &[T]) {
            for &v in s {
                self.push(v);
            }
        }

        pub(super) fn len(&self) -> usize {
            self.len
        }

        pub(super) fn leak(self) {
            core::mem::forget(self);
        }
    }

    impl<T: Copy> core::ops::Deref for MVec<T> {
        type Target = [T];
        fn deref(&self) -> &[T] {
            unsafe { core::slice::from_raw_parts(self.p.as_ptr(), self.len) }
        }
    }

    impl<T: Copy> core::ops::DerefMut for MVec<T> {
        fn deref_mut(&mut self) -> &mut [T] {
            unsafe { core::slice::from_raw_parts_mut(self.p.as_ptr(), self.len) }
        }
    }

    impl<T: Copy> Drop for MVec<T> {
        fn drop(&mut self) {
            unsafe { free(self.p.as_ptr().cast()) };
        }
    }

    pub(super) struct MBuf {
        p: NonNull<u8>,
        cap: usize,
    }

    impl MBuf {
        pub(super) fn zeroed(cap: usize) -> Option<MBuf> {
            let p = unsafe { rusty_libc_malloc::calloc(1, cap) }.cast::<u8>();
            NonNull::new(p).map(|p| MBuf { p, cap })
        }

        pub(super) fn copy_of(src: &[u8]) -> Option<MBuf> {
            let p = NonNull::new(malloc(src.len()))?;
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), p.as_ptr(), src.len()) };
            Some(MBuf { p, cap: src.len() })
        }

        pub(super) unsafe fn from_raw(p: NonNull<u8>, cap: usize) -> MBuf {
            MBuf { p, cap }
        }

        pub(super) fn into_raw(self) -> NonNull<u8> {
            let p = self.p;
            core::mem::forget(self);
            p
        }

        pub(super) fn fresh(cap: usize) -> Option<MBuf> {
            let p = unsafe { rusty_libc_malloc::realloc(core::ptr::null_mut(), cap) }.cast::<u8>();
            let p = NonNull::new(p)?;
            unsafe { core::ptr::write_bytes(p.as_ptr(), 0, cap) };
            Some(MBuf { p, cap })
        }

        pub(super) fn grow(&mut self, new_cap: usize) -> bool {
            let np = unsafe { rusty_libc_malloc::realloc(self.p.as_ptr().cast(), new_cap) }.cast::<u8>();
            let Some(np) = NonNull::new(np) else { return false };
            if new_cap > self.cap {
                unsafe { core::ptr::write_bytes(np.as_ptr().wrapping_add(self.cap), 0, new_cap - self.cap) };
            }
            self.p = np;
            self.cap = new_cap;
            true
        }
    }

    impl core::ops::Deref for MBuf {
        type Target = [u8];
        fn deref(&self) -> &[u8] {
            unsafe { core::slice::from_raw_parts(self.p.as_ptr(), self.cap) }
        }
    }

    impl core::ops::DerefMut for MBuf {
        fn deref_mut(&mut self) -> &mut [u8] {
            unsafe { core::slice::from_raw_parts_mut(self.p.as_ptr(), self.cap) }
        }
    }

    impl Drop for MBuf {
        fn drop(&mut self) {
            unsafe { free(self.p.as_ptr()) };
        }
    }
}

use heap::{MBox, MBuf, MVec, oom};

mod view {
    use super::*;

    #[derive(Clone, Copy)]
    pub(super) struct ArgpView<'a>(&'a Argp);

    impl<'a> ArgpView<'a> {
        pub(super) unsafe fn new(p: *const Argp) -> ArgpView<'a> {
            ArgpView(unsafe { &*p })
        }

        pub(super) fn ptr(self) -> *const Argp {
            self.0
        }

        pub(super) fn has_options(self) -> bool {
            !self.0.options.is_null()
        }

        pub(super) fn options(self) -> Opts<'a> {
            let p = self.0.options;
            if p.is_null() {
                return Opts(&[]);
            }
            let mut n = 0;
            while !oend(unsafe { &*p.wrapping_add(n) }) {
                n += 1;
            }
            Opts(unsafe { core::slice::from_raw_parts(p, n) })
        }

        pub(super) fn parser(self) -> Option<ArgpParser> {
            self.0.parser
        }

        pub(super) fn help_filter(self) -> Option<HelpFilter> {
            self.0.help_filter
        }

        pub(super) fn domain(self) -> Domain {
            Domain(self.0.argp_domain)
        }

        pub(super) fn args_doc(self) -> Option<&'a CStr> {
            unsafe { rusty_libc_core::ffi::cstr(self.0.args_doc) }
        }

        pub(super) fn doc(self) -> Option<&'a CStr> {
            unsafe { rusty_libc_core::ffi::cstr(self.0.doc) }
        }

        pub(super) fn has_children(self) -> bool {
            !self.0.children.is_null()
        }

        pub(super) fn children(self) -> &'a [ArgpChild] {
            let p = self.0.children;
            if p.is_null() {
                return &[];
            }
            let mut n = 0;
            while !unsafe { &*p.wrapping_add(n) }.argp.is_null() {
                n += 1;
            }
            unsafe { core::slice::from_raw_parts(p, n) }
        }

        pub(super) fn child_argp(self, c: &'a ArgpChild) -> ArgpView<'a> {
            debug_assert!(!c.argp.is_null());
            unsafe { ArgpView::new(c.argp) }
        }

        pub(super) fn child_header(self, c: &'a ArgpChild) -> Option<&'a CStr> {
            unsafe { rusty_libc_core::ffi::cstr(c.header) }
        }
    }

    #[derive(Clone, Copy)]
    pub(super) struct Opts<'a>(&'a [ArgpOption]);

    impl<'a> Opts<'a> {
        pub(super) fn len(self) -> usize {
            self.0.len()
        }

        pub(super) fn get(self, i: usize) -> Opt<'a> {
            Opt(&self.0[i])
        }

        pub(super) fn first(self) -> Opt<'a> {
            Opt(&self.0[0])
        }

        pub(super) fn sub(self, start: usize, n: usize) -> Opts<'a> {
            Opts(&self.0[start..start + n])
        }

        pub(super) fn iter(self) -> impl Iterator<Item = Opt<'a>> {
            self.0.iter().map(Opt)
        }
    }

    #[derive(Clone, Copy)]
    pub(super) struct Opt<'a>(&'a ArgpOption);

    impl<'a> Opt<'a> {
        pub(super) fn key(self) -> c_int {
            self.0.key
        }
        pub(super) fn flags(self) -> c_int {
            self.0.flags
        }
        pub(super) fn group(self) -> c_int {
            self.0.group
        }
        pub(super) fn has_name(self) -> bool {
            !self.0.name.is_null()
        }
        pub(super) fn has_arg(self) -> bool {
            !self.0.arg.is_null()
        }
        pub(super) fn name_ptr(self) -> *const c_char {
            self.0.name
        }
        pub(super) fn name(self) -> Option<&'a CStr> {
            unsafe { rusty_libc_core::ffi::cstr(self.0.name) }
        }
        pub(super) fn name_is(self, n: &CStr) -> bool {
            !self.0.name.is_null() && unsafe { rusty_libc_core::ffi::cstr_eq(self.0.name, n.as_ptr()) }
        }
        pub(super) fn arg(self) -> Option<&'a CStr> {
            unsafe { rusty_libc_core::ffi::cstr(self.0.arg) }
        }
        pub(super) fn doc(self) -> Option<&'a CStr> {
            unsafe { rusty_libc_core::ffi::cstr(self.0.doc) }
        }
        pub(super) fn short(self) -> bool {
            oshort(self.0)
        }
        pub(super) fn visible(self) -> bool {
            self.0.flags & OPTION_HIDDEN == 0
        }
        pub(super) fn alias(self) -> bool {
            self.0.flags & OPTION_ALIAS != 0
        }
        pub(super) fn is_doc(self) -> bool {
            self.0.flags & OPTION_DOC != 0
        }
    }

    #[derive(Clone, Copy)]
    pub(super) struct Domain(*const c_char);

    impl Domain {
        pub(super) const NONE: Domain = Domain(null());
    }

    pub(super) fn dg(domain: Domain, s: &CStr) -> &CStr {
        let t = unsafe { rusty_libc_core::i18n::dtr(domain.0, s.as_ptr()) };
        if t == s.as_ptr() {
            return s;
        }
        unsafe { CStr::from_ptr(t) }
    }

    pub(super) fn dgo(domain: Domain, s: Option<&CStr>) -> Option<&CStr> {
        s.map(|s| dg(domain, s))
    }

    #[derive(Clone, Copy)]
    pub(super) struct StateView<'a>(&'a ArgpState);

    impl<'a> StateView<'a> {
        pub(super) unsafe fn new(p: *const ArgpState) -> Option<StateView<'a>> {
            unsafe { p.as_ref() }.map(StateView)
        }

        pub(super) fn flags(self) -> c_uint {
            self.0.flags
        }

        pub(super) fn root_argp(self) -> Option<ArgpView<'a>> {
            let p = self.0.root_argp;
            if p.is_null() { None } else { Some(unsafe { ArgpView::new(p) }) }
        }

        pub(super) fn name(self) -> Option<&'a CStr> {
            unsafe { rusty_libc_core::ffi::cstr(self.0.name) }
        }

        pub(super) fn err_stream(self) -> *mut File {
            self.0.err_stream
        }

        pub(super) fn pstate(self) -> *mut c_void {
            self.0.pstate
        }
    }

    #[derive(Clone, Copy)]
    pub(super) struct Stream(*mut File);

    impl Stream {
        pub(super) unsafe fn new(f: *mut File) -> Option<Stream> {
            if f.is_null() { None } else { Some(Stream(f)) }
        }

        pub(super) fn write(self, b: &[u8]) -> usize {
            unsafe { rusty_libc_stdio::fwrite(b.as_ptr().cast(), 1, b.len(), self.0) }
        }

        pub(super) fn putc(self, c: u8) {
            unsafe { rusty_libc_stdio::putc(c as c_int, self.0) };
        }

        pub(super) fn lock(self) {
            unsafe { rusty_libc_stdio::flockfile(self.0) };
        }

        pub(super) fn unlock(self) {
            unsafe { rusty_libc_stdio::funlockfile(self.0) };
        }
    }
}

use view::{ArgpView, Domain, Opt, Opts, StateView, Stream, dg, dgo};

fn out(stream: Stream, parts: &[&[u8]]) {
    for p in parts {
        if !p.is_empty() {
            stream.write(p);
        }
    }
}

fn root_domain(state: Option<StateView>) -> Domain {
    state.and_then(|s| s.root_argp()).map_or(Domain::NONE, |a| a.domain())
}

struct Filtered<'s> {
    p: *const c_char,
    given: *const c_char,
    _text: core::marker::PhantomData<&'s CStr>,
}

impl<'s> Filtered<'s> {
    fn same(text: Option<&'s CStr>) -> Filtered<'s> {
        let p = text.map_or(null(), |t| t.as_ptr());
        Filtered { p, given: p, _text: core::marker::PhantomData }
    }

    fn get(&self) -> Option<&CStr> {
        unsafe { rusty_libc_core::ffi::cstr(self.p) }
    }
}

impl Drop for Filtered<'_> {
    fn drop(&mut self) {
        if self.p != self.given {
            unsafe { heap::free(self.p.cast_mut().cast()) };
        }
    }
}

fn call_filter<'s>(f: HelpFilter, key: c_int, text: *const c_char, input: *mut c_void) -> Filtered<'s> {
    let p = unsafe { f(key, text, input) }.cast_const();
    Filtered { p, given: text, _text: core::marker::PhantomData }
}

fn filter_doc<'s>(doc: Option<&'s CStr>, key: c_int, argp: Option<ArgpView>, state: Option<StateView>) -> Filtered<'s> {
    if let Some(argp) = argp
        && let Some(f) = argp.help_filter()
    {
        let input = argp_input(argp.ptr(), state);
        call_filter(f, key, doc.map_or(null(), |d| d.as_ptr()), input)
    } else {
        Filtered::same(doc)
    }
}

struct FmtStream {
    stream: Stream,
    lmargin: usize,
    rmargin: usize,
    wmargin: isize,
    point_offs: usize,
    point_col: isize,
    buf: MBuf,
    p: usize,
}

const INIT_BUF_SIZE: usize = 200;

static LAST_BUF: AtomicPtr<u8> = AtomicPtr::new(null_mut());

fn keep_last_buf(buf: MBuf) {
    let old = LAST_BUF.swap(buf.into_raw().as_ptr(), Ordering::AcqRel);
    if let Some(old) = core::ptr::NonNull::new(old) {
        drop(unsafe { MBuf::from_raw(old, INIT_BUF_SIZE) });
    }
}

fn take_last_buf() -> Option<MBuf> {
    let p = LAST_BUF.swap(null_mut(), Ordering::AcqRel);
    match core::ptr::NonNull::new(p) {
        Some(p) => {
            let mut b = unsafe { MBuf::from_raw(p, INIT_BUF_SIZE) };
            b[..16].fill(0);
            Some(b)
        }
        None => MBuf::zeroed(INIT_BUF_SIZE),
    }
}

const PRINTF_SIZE_GUESS: usize = 150;

impl FmtStream {
    fn new(stream: Stream, lmargin: usize, rmargin: usize, wmargin: isize) -> Option<MBox<FmtStream>> {
        let fs = MBox::<FmtStream>::uninit()?;
        let buf = take_last_buf()?;
        Some(fs.init(FmtStream { stream, lmargin, rmargin, wmargin, point_offs: 0, point_col: 0, buf, p: 0 }))
    }

    fn finish(mut fs: MBox<FmtStream>) {
        fs.update();
        if fs.p > 0 {
            out(fs.stream, &[fs.bslice(0, fs.p)]);
        }
        fs.consume(|f| {
            if f.buf.len() == INIT_BUF_SIZE {
                keep_last_buf(f.buf);
            } else {
                drop(f.buf);
            }
        });
    }

    fn byte_at(&self, i: isize) -> u8 {
        if i < 0 { 0 } else { self.buf.get(i as usize).copied().unwrap_or(0) }
    }

    fn end(&self) -> usize {
        self.buf.len()
    }

    fn bmove(&mut self, from: usize, to: usize, dst: usize) {
        let len = self.buf.len();
        if from > to || to > len || dst > len - (to - from) {
            oom();
        }
        self.buf.copy_within(from..to, dst);
    }

    fn bset(&mut self, i: usize, v: u8) {
        match self.buf.get_mut(i) {
            Some(b) => *b = v,
            None => oom(),
        }
    }

    fn bslice(&self, from: usize, to: usize) -> &[u8] {
        self.buf.get(from..to).unwrap_or_else(|| oom())
    }

    fn update(&mut self) {
        let mut b = self.point_offs;
        while b < self.p {
            if self.point_col == 0 && self.lmargin != 0 {
                let pad = self.lmargin;
                if self.p + pad < self.end() {
                    self.bmove(b, self.p, b + pad);
                    self.p += pad;
                    self.buf.get_mut(b..b + pad).unwrap_or_else(|| oom()).fill(b' ');
                    b += pad;
                } else {
                    for _ in 0..pad {
                        self.stream.putc(b' ');
                    }
                }
                self.point_col = pad as isize;
            }
            let len = self.p - b;
            let found = cstring::memchr(self.bslice(b, self.p), b'\n');
            if self.point_col < 0 {
                self.point_col = 0;
            }
            let nl: usize = match found {
                None => {
                    if (self.point_col as usize).wrapping_add(len) < self.rmargin {
                        self.point_col += len as isize;
                        break;
                    }
                    self.p
                }
                Some(i) => {
                    if self.point_col + (i as isize) < self.rmargin as isize {
                        self.point_col = 0;
                        b += i + 1;
                        continue;
                    }
                    b + i
                }
            };
            match self.wrap_long_line(b, nl, len) {
                Some(next) => b = next,
                None => break,
            }
        }
        self.point_offs = self.p;
    }

    #[inline(never)]
    fn wrap_long_line(&mut self, mut b: usize, mut nl: usize, mut len: usize) -> Option<usize> {
        let r = self.rmargin.wrapping_sub(1);
        if self.wmargin < 0 {
            if nl < self.p {
                let dst = b.wrapping_add(r.wrapping_sub(self.point_col as usize));
                self.bmove(nl, self.p, dst);
                self.p = self.p.wrapping_sub(nl.wrapping_sub(dst));
                self.point_col = 0;
                b += r + 1;
            } else {
                self.point_col += len as isize;
                self.p = self.p.wrapping_sub((self.point_col as usize).wrapping_sub(r));
                return None;
            }
        } else {
            let bi = b as isize;
            let mut q: isize = bi + (r + 1) as isize - self.point_col;
            while q >= bi && !isblank(self.byte_at(q)) {
                q -= 1;
            }
            let mut nextline: isize = q + 1;
            if nextline > bi {
                if q >= bi {
                    loop {
                        q -= 1;
                        if !(q >= bi && isblank(self.byte_at(q))) {
                            break;
                        }
                    }
                }
                nl = (q + 1) as usize;
            } else {
                q = bi + (r + 1) as isize - self.point_col;
                loop {
                    q += 1;
                    if !(q < nl as isize && !isblank(self.byte_at(q))) {
                        break;
                    }
                }
                if q == nl as isize {
                    self.point_col = 0;
                    b = nl + 1;
                    return Some(b);
                }
                nl = q as usize;
                loop {
                    q += 1;
                    if !isblank(self.byte_at(q)) {
                        break;
                    }
                }
                nextline = q;
            }
            let end = self.end() as isize;
            let wm = self.wmargin;
            let at_end = nextline == bi + len as isize + 1;
            let need_more = if at_end { end - (nl as isize) < wm + 1 } else { nextline - (nl as isize + 1) < wm };
            if need_more && self.p as isize > nextline {
                if end - self.p as isize > wm + 1 {
                    let mv = self.p - nextline as usize;
                    let to = nl + 1 + wm as usize;
                    self.bmove(nextline as usize, nextline as usize + mv, to);
                    nextline = to as isize;
                    len = to + mv - b;
                    self.bset(nl, b'\n');
                    nl += 1;
                } else {
                    if nl > 0 {
                        out(self.stream, &[self.bslice(0, nl)]);
                    }
                    self.stream.putc(b'\n');
                    len += b;
                    b = 0;
                    nl = 0;
                }
            } else {
                self.bset(nl, b'\n');
                nl += 1;
            }
            let bi = b as isize;
            let at_end2 = nextline == bi + len as isize + 1;
            if nextline - nl as isize >= wm || (at_end2 && end - nextline >= wm) {
                for _ in 0..wm {
                    self.bset(nl, b' ');
                    nl += 1;
                }
            } else {
                for _ in 0..wm {
                    self.stream.putc(b' ');
                }
            }
            let nextline = nextline as usize;
            if nl < nextline {
                self.bmove(nextline, b + len, nl);
            }
            len -= nextline - b;
            b = nl;
            self.p = nl + len;
            self.point_col = if wm != 0 { wm } else { -1 };
        }
        Some(b)
    }

    #[inline]
    fn ensure(&mut self, amount: usize) -> bool {
        self.end() - self.p >= amount || self.make_room(amount)
    }

    #[inline(never)]
    fn make_room(&mut self, amount: usize) -> bool {
        self.update();
        let n = self.p;
        let wrote = if n > 0 { self.stream.write(self.bslice(0, n)) } else { 0 };
        if wrote == n {
            self.p = 0;
            self.point_offs = 0;
        } else {
            self.p -= wrote;
            self.point_offs = self.point_offs.wrapping_sub(wrote);
            self.buf.copy_within(wrote..wrote + self.p, 0);
            return false;
        }
        if self.end() < amount {
            let old_size = self.end();
            let new_size = old_size + amount;
            let copy = if old_size == INIT_BUF_SIZE { MBuf::copy_of(&self.buf[..INIT_BUF_SIZE]) } else { None };
            if !self.buf.grow(new_size) {
                drop(copy);
                rusty_libc_core::errno::set(ENOMEM);
                return false;
            }
            if let Some(c) = copy {
                keep_last_buf(c);
            }
            self.p = 0;
        }
        true
    }

    fn write(&mut self, s: &[u8]) -> usize {
        if self.p + s.len() <= self.end() || self.ensure(s.len()) {
            self.buf[self.p..self.p + s.len()].copy_from_slice(s);
            self.p += s.len();
            s.len()
        } else {
            0
        }
    }

    fn puts(&mut self, s: &CStr) -> c_int {
        let s = s.to_bytes();
        if !s.is_empty() {
            let w = self.write(s);
            if w == s.len() { 0 } else { -1 }
        } else {
            0
        }
    }

    fn putc(&mut self, ch: u8) -> c_int {
        if self.p < self.end() || self.ensure(1) {
            self.buf[self.p] = ch;
            self.p += 1;
            ch as c_int
        } else {
            -1
        }
    }

    fn set_lmargin(&mut self, m: usize) -> usize {
        if self.p > self.point_offs {
            self.update();
        }
        core::mem::replace(&mut self.lmargin, m)
    }

    fn set_wmargin(&mut self, m: isize) -> isize {
        if self.p > self.point_offs {
            self.update();
        }
        core::mem::replace(&mut self.wmargin, m)
    }

    fn point(&mut self) -> usize {
        if self.p > self.point_offs {
            self.update();
        }
        if self.point_col >= 0 { self.point_col as usize } else { 0 }
    }

    fn printf(&mut self, fmt: &CStr, args: &[Arg]) -> isize {
        let mut size_guess = PRINTF_SIZE_GUESS;
        loop {
            if !self.ensure(size_guess) {
                return -1;
            }
            let avail = self.end() - self.p;
            let p = self.p;
            let n = snprintf(self.buf.get_mut(p..).unwrap_or_else(|| oom()), fmt, args);
            if n >= 0 && (n as usize) >= avail {
                size_guess = n as usize + 1;
                continue;
            }
            let n = n.max(0);
            self.p += n as usize;
            return n as isize;
        }
    }
}

const NUPARAMS: usize = 9;
const DUP_ARGS: usize = 0;
const DUP_ARGS_NOTE: usize = 1;
const SHORT_OPT_COL: usize = 2;
const LONG_OPT_COL: usize = 3;
const DOC_OPT_COL: usize = 4;
const OPT_DOC_COL: usize = 5;
const HEADER_COL: usize = 6;
const USAGE_INDENT: usize = 7;
const RMARGIN: usize = 8;

static UPARAMS: [AtomicI32; NUPARAMS] = [
    AtomicI32::new(0),
    AtomicI32::new(1),
    AtomicI32::new(2),
    AtomicI32::new(6),
    AtomicI32::new(2),
    AtomicI32::new(29),
    AtomicI32::new(1),
    AtomicI32::new(12),
    AtomicI32::new(79),
];

const UPARAM_NAMES: [(&[u8], bool, usize); NUPARAMS] = [
    (b"dup-args", true, DUP_ARGS),
    (b"dup-args-note", true, DUP_ARGS_NOTE),
    (b"short-opt-col", false, SHORT_OPT_COL),
    (b"long-opt-col", false, LONG_OPT_COL),
    (b"doc-opt-col", false, DOC_OPT_COL),
    (b"opt-doc-col", false, OPT_DOC_COL),
    (b"header-col", false, HEADER_COL),
    (b"usage-indent", false, USAGE_INDENT),
    (b"rmargin", false, RMARGIN),
];

fn up(i: usize) -> c_int {
    UPARAMS[i].load(Ordering::Relaxed)
}

fn failure_text(state: Option<StateView>, msg: &CStr, args: &[Arg]) {
    let mut buf = [0u8; 600];
    let n = snprintf(&mut buf, msg, args);
    let n = (n.max(0) as usize).min(buf.len() - 1);
    buf[n] = 0;
    failure_str(state, 0, 0, Some(&buf[..n]));
}

fn param_name<'t>(t: &'t mut [u8; 300], name: &[u8]) -> (usize, &'t CStr) {
    let k = name.len().min(200);
    t[..k].copy_from_slice(&name[..k]);
    (k, CStr::from_bytes_until_nul(&t[..]).unwrap_or(c""))
}

fn fill_in_uparams(state: Option<StateView>) {
    let var = unsafe { rusty_libc_stdlib::env::getenv(c"ARGP_HELP_FMT".as_ptr()) };
    let Some(cs) = (unsafe { rusty_libc_core::ffi::cstr(var) }) else { return };
    let v = cs.to_bytes_with_nul();
    let at = |k: usize| v.get(k).copied().unwrap_or(0);
    let mut i = 0usize;
    let skipws = |k: &mut usize| {
        while isspace(at(*k)) {
            *k += 1;
        }
    };
    while at(i) != 0 {
        skipws(&mut i);
        if at(i).is_ascii_alphabetic() {
            let mut unspec = false;
            let mut val: c_int = 0;
            let mut arg = i;
            while isalnum(at(arg)) || at(arg) == b'-' || at(arg) == b'_' {
                arg += 1;
            }
            let mut var_len = arg - i;
            skipws(&mut arg);
            if at(arg) == 0 || at(arg) == b',' {
                unspec = true;
            } else if at(arg) == b'=' {
                arg += 1;
                skipws(&mut arg);
            }
            if unspec {
                if at(i) == b'n' && at(i + 1) == b'o' && at(i + 2) == b'-' {
                    val = 0;
                    i += 3;
                    var_len -= 3;
                } else {
                    val = 1;
                }
            } else if at(arg).is_ascii_digit() {
                let start = cs.as_ptr().wrapping_add(arg);
                let mut ep: *mut c_char = null_mut();
                val = unsafe { rusty_libc_stdlib::num::strtol(start, &mut ep, 10) } as c_int;
                arg += ep as usize - start as usize;
                skipws(&mut arg);
            }
            let name = &v[i..i + var_len];
            let mut found = false;
            for (n, is_bool, idx) in UPARAM_NAMES {
                if n == name {
                    found = true;
                    if unspec && !is_bool {
                        let mut t = [0u8; 300];
                        let (k, s) = param_name(&mut t, name);
                        failure_text(state, dg(root_domain(state), c"%.*s: ARGP_HELP_FMT parameter requires a value"), &[Arg::Int(k as i64), Arg::Str(s)]);
                    } else {
                        UPARAMS[idx].store(val, Ordering::Relaxed);
                    }
                    break;
                }
            }
            if !found {
                let mut t = [0u8; 300];
                let (k, s) = param_name(&mut t, name);
                failure_text(state, dg(root_domain(state), c"%.*s: Unknown ARGP_HELP_FMT parameter"), &[Arg::Int(k as i64), Arg::Str(s)]);
            }
            i = arg;
            if at(i) == b',' {
                i += 1;
            }
        } else if at(i) != 0 {
            let rest = CStr::from_bytes_with_nul(&v[i..]).unwrap_or(c"");
            failure_text(state, dg(root_domain(state), c"Garbage in ARGP_HELP_FMT: %s"), &[Arg::Str(rest)]);
            break;
        }
    }
}

struct HolCluster<'a> {
    header: Option<&'a CStr>,
    index: c_int,
    group: c_int,
    parent: Option<ClPtr<'a>>,
    argp: ArgpView<'a>,
    depth: c_int,
    next: Option<ClPtr<'a>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ClPtr<'a>(core::ptr::NonNull<HolCluster<'a>>);

impl<'a> ClPtr<'a> {
    fn get(self) -> &'a HolCluster<'a> {
        unsafe { self.0.as_ref() }
    }

    fn set_next(self, next: Option<ClPtr<'a>>) {
        unsafe { (*self.0.as_ptr()).next = next };
    }
}

#[derive(Clone, Copy)]
struct HolEntry<'a> {
    opts: Opts<'a>,
    so: usize,
    group: c_int,
    cluster: Option<ClPtr<'a>>,
    argp: ArgpView<'a>,
}

struct Hol<'a> {
    entries: Option<MVec<HolEntry<'a>>>,
    short_options: Option<MVec<u8>>,
    clusters: Option<ClPtr<'a>>,
}

impl<'a> Hol<'a> {
    fn num_entries(&self) -> usize {
        self.entries.as_ref().map_or(0, |e| e.len())
    }

    fn entries(&self) -> &[HolEntry<'a>] {
        self.entries.as_deref().unwrap_or(&[])
    }

    fn short_options(&self) -> &[u8] {
        self.short_options.as_deref().unwrap_or(&[])
    }
}

impl Drop for Hol<'_> {
    fn drop(&mut self) {
        let mut cl = self.clusters.take();
        while let Some(c) = cl {
            cl = c.get().next;
            drop(unsafe { MBox::from_raw(c.0) });
        }
        if self.num_entries() > 0 {
            drop(self.entries.take());
            drop(self.short_options.take());
        } else {
            if let Some(e) = self.entries.take() {
                e.leak();
            }
            if let Some(s) = self.short_options.take() {
                s.leak();
            }
        }
    }
}

fn make_hol<'a>(argp: ArgpView<'a>, cluster: Option<ClPtr<'a>>) -> MBox<Hol<'a>> {
    let mut hol = MBox::new(Hol { entries: None, short_options: None, clusters: None }).unwrap_or_else(|| oom());
    if argp.has_options() {
        let opts = argp.options();
        let num_entries = opts.iter().filter(|o| !o.alias()).count();
        let num_short = opts.iter().filter(|o| o.short()).count();
        let mut entries = MVec::with_capacity(num_entries).unwrap_or_else(|| oom());
        let mut so = MVec::with_capacity(num_short + 1).unwrap_or_else(|| oom());
        let mut cur_group = 0;
        let mut i = 0;
        while i < opts.len() {
            let o = opts.get(i);
            cur_group = if o.group() != 0 {
                o.group()
            } else if !o.has_name() && o.key() == 0 {
                cur_group + 1
            } else {
                cur_group
            };
            let (start, so_start) = (i, so.len());
            loop {
                let o = opts.get(i);
                if o.short() && !so.contains(&(o.key() as u8)) {
                    so.push(o.key() as u8);
                }
                i += 1;
                if !(i < opts.len() && opts.get(i).alias()) {
                    break;
                }
            }
            entries.push(HolEntry { opts: opts.sub(start, i - start), so: so_start, group: cur_group, cluster, argp });
        }
        so.push(0);
        hol.entries = Some(entries);
        hol.short_options = Some(so);
    }
    hol
}

fn hol_add_cluster<'a>(hol: &mut Hol<'a>, group: c_int, header: Option<&'a CStr>, index: c_int, parent: Option<ClPtr<'a>>, argp: ArgpView<'a>) -> Option<ClPtr<'a>> {
    let depth = parent.map_or(0, |p| p.get().depth + 1);
    let cl = MBox::new(HolCluster { header, index, group, parent, argp, depth, next: hol.clusters })?;
    let cl = ClPtr(cl.into_raw());
    hol.clusters = Some(cl);
    Some(cl)
}

fn hol_entry_short_iterate<'a>(entry: &HolEntry<'a>, so: &[u8], mut func: impl FnMut(Opt<'a>, Opt<'a>) -> c_int) -> c_int {
    let mut val = 0;
    let mut real = entry.opts.first();
    let mut s = entry.so;
    for opt in entry.opts.iter() {
        if val != 0 {
            break;
        }
        if opt.short() && so[s] as c_int == opt.key() {
            if !opt.alias() {
                real = opt;
            }
            if opt.visible() {
                val = func(opt, real);
            }
            s += 1;
        }
    }
    val
}

fn hol_entry_long_iterate<'a>(entry: &HolEntry<'a>, mut func: impl FnMut(Opt<'a>, Opt<'a>) -> c_int) -> c_int {
    let mut val = 0;
    let mut real = entry.opts.first();
    for opt in entry.opts.iter() {
        if val != 0 {
            break;
        }
        if opt.has_name() {
            if !opt.alias() {
                real = opt;
            }
            if opt.visible() {
                val = func(opt, real);
            }
        }
    }
    val
}

fn hol_entry_first_short(entry: &HolEntry, so: &[u8]) -> c_int {
    hol_entry_short_iterate(entry, so, |opt, _| if opt.short() { opt.key() } else { 0 })
}

fn hol_entry_first_long_opt<'a>(entry: &HolEntry<'a>) -> Option<Opt<'a>> {
    entry.opts.iter().find(|o| o.has_name() && o.visible())
}

fn hol_set_group(hol: &mut Hol, name: &CStr, group: c_int) {
    let Some(entries) = hol.entries.as_deref_mut() else { return };
    if let Some(e) = entries.iter_mut().find(|e| e.opts.iter().any(|o| o.visible() && o.name_is(name))) {
        e.group = group;
    }
}

fn group_cmp(g1: c_int, g2: c_int) -> c_int {
    if (g1 < 0 && g2 < 0) || (g1 >= 0 && g2 >= 0) { g1.wrapping_sub(g2) } else { g2.wrapping_sub(g1) }
}

fn hol_sibling_cluster_cmp(c1: &HolCluster, c2: &HolCluster) -> c_int {
    let cmp = group_cmp(c1.group, c2.group);
    if cmp != 0 {
        return cmp;
    }
    c2.index - c1.index
}

fn hol_cousin_cluster_cmp(c1: ClPtr, c2: ClPtr) -> c_int {
    let (a, b) = (c1.get(), c2.get());
    if a.parent == b.parent {
        hol_sibling_cluster_cmp(a, b)
    } else {
        let (Some(pa), Some(pb)) = (a.parent, b.parent) else { oom() };
        let cmp = hol_cousin_cluster_cmp(pa, pb);
        if cmp != 0 {
            return cmp;
        }
        let cmp = group_cmp(a.group, b.group);
        if cmp != 0 {
            return cmp;
        }
        b.index - a.index
    }
}

fn up_to_depth(mut c: ClPtr, depth: c_int) -> ClPtr {
    loop {
        c = c.get().parent.unwrap_or_else(|| oom());
        if c.get().depth <= depth {
            return c;
        }
    }
}

fn hol_cluster_cmp(c1: ClPtr, c2: ClPtr) -> c_int {
    let (d1, d2) = (c1.get().depth, c2.get().depth);
    if d1 > d2 {
        let cmp = hol_cousin_cluster_cmp(up_to_depth(c1, d2), c2);
        if cmp != 0 { cmp } else { 1 }
    } else if d1 < d2 {
        let cmp = hol_cousin_cluster_cmp(c1, up_to_depth(c2, d1));
        if cmp != 0 { cmp } else { -1 }
    } else {
        hol_cousin_cluster_cmp(c1, c2)
    }
}

fn hol_cluster_base(mut cl: ClPtr) -> ClPtr {
    while let Some(p) = cl.get().parent {
        cl = p;
    }
    cl
}

fn canon_doc_option(name: &mut &CStr) -> bool {
    let b = name.to_bytes_with_nul();
    let mut i = 0;
    while isspace(b[i]) {
        i += 1;
    }
    let non_opt = b[i] != b'-';
    while b[i] != 0 && !isalnum(b[i]) {
        i += 1;
    }
    *name = &name[i..];
    non_opt
}

fn hol_entry_cmp(e1: &HolEntry, e2: &HolEntry, so: &[u8]) -> c_int {
    let group1 = e1.cluster.map_or(e1.group, |c| hol_cluster_base(c).get().group);
    let group2 = e2.cluster.map_or(e2.group, |c| hol_cluster_base(c).get().group);
    let mut cmp = group_cmp(group1, group2);
    if cmp != 0 {
        return cmp;
    }
    cmp = e1.cluster.is_some() as c_int - e2.cluster.is_some() as c_int;
    if cmp != 0 {
        return cmp;
    }
    if let (Some(c1), Some(c2)) = (e1.cluster, e2.cluster) {
        cmp = hol_cluster_cmp(c1, c2);
        if cmp != 0 {
            return cmp;
        }
    }
    cmp = group_cmp(e1.group, e2.group);
    if cmp != 0 {
        return cmp;
    }
    let (lo1, lo2) = (hol_entry_first_long_opt(e1), hol_entry_first_long_opt(e2));
    let (is_doc1, is_doc2) = (e1.opts.first().is_doc(), e2.opts.first().is_doc());
    let mut long1 = if is_doc1 { lo1.and_then(|o| o.name()) } else { None };
    let mut long2 = if is_doc2 { lo2.and_then(|o| o.name()) } else { None };
    let doc1 = if is_doc1 { long1.as_mut().is_some_and(canon_doc_option) as c_int } else { 0 };
    let doc2 = if is_doc2 { long2.as_mut().is_some_and(canon_doc_option) as c_int } else { 0 };
    cmp = doc1 - doc2;
    if cmp != 0 {
        return cmp;
    }
    let short1 = hol_entry_first_short(e1, so);
    let short2 = hol_entry_first_short(e2, so);
    if short1 == 0 && !is_doc1 {
        long1 = lo1.and_then(|o| o.name());
    }
    if short2 == 0 && !is_doc2 {
        long2 = lo2.and_then(|o| o.name());
    }
    let first_of = |short: c_int, long: Option<&CStr>| -> u8 {
        if short != 0 {
            short as u8
        } else {
            long.map_or(0, |l| l.to_bytes_with_nul()[0])
        }
    };
    let first1 = first_of(short1, long1);
    let first2 = first_of(short2, long2);
    cmp = tolower(first1 as c_int) - tolower(first2 as c_int);
    if cmp != 0 {
        return cmp;
    }
    cmp = first2 as c_int - first1 as c_int;
    if cmp != 0 {
        return cmp;
    }
    cmp = (short1 != 0) as c_int - (short2 != 0) as c_int;
    if cmp != 0 {
        return cmp;
    }
    if short1 == 0 {
        cmp = long1.is_some() as c_int - long2.is_some() as c_int;
        if cmp != 0 {
            return cmp;
        }
        if let (Some(l1), Some(l2)) = (long1, long2) {
            cmp = cstring::strcasecmp(l1, l2) as c_int;
            if cmp != 0 {
                return cmp;
            }
        }
    }
    0
}

fn hol_sort(hol: &mut Hol) {
    if hol.num_entries() > 0 {
        let Hol { entries, short_options, .. } = hol;
        let so = short_options.as_deref().unwrap_or(&[]);
        if let Some(entries) = entries.as_deref_mut() {
            rusty_libc_stdlib::sort::sort_by(entries, |a, b| hol_entry_cmp(a, b, so).cmp(&0));
        }
    }
}

fn hol_append<'a>(hol: &mut Hol<'a>, mut more: MBox<Hol<'a>>) {
    let more_clusters = more.clusters.take();
    match hol.clusters {
        None => hol.clusters = more_clusters,
        Some(mut c) => {
            while let Some(n) = c.get().next {
                c = n;
            }
            c.set_next(more_clusters);
        }
    }
    if more.num_entries() > 0 {
        if hol.num_entries() == 0 {
            if let Some(e) = hol.entries.take() {
                e.leak();
            }
            if let Some(s) = hol.short_options.take() {
                s.leak();
            }
            hol.entries = more.entries.take();
            hol.short_options = more.short_options.take();
        } else {
            let num_entries = hol.num_entries() + more.num_entries();
            let hol_so = hol.short_options();
            let hol_so_len = hol_so.iter().position(|&c| c == 0).unwrap_or(hol_so.len());
            let more_so = more.short_options();
            let more_so_len = more_so.iter().position(|&c| c == 0).unwrap_or(more_so.len());
            let mut entries = MVec::with_capacity(num_entries).unwrap_or_else(|| oom());
            let mut short_options = MVec::with_capacity(hol_so_len + more_so_len + 1).unwrap_or_else(|| oom());
            entries.extend_from_slice(hol.entries());
            short_options.extend_from_slice(&hol_so[..hol_so_len]);
            let mut more_s = 0;
            for e in more.entries() {
                let mut e = *e;
                e.so = short_options.len();
                for opt in e.opts.iter() {
                    let ch = more_so[more_s];
                    if opt.short() && ch as c_int == opt.key() {
                        if !short_options[..hol_so_len].contains(&ch) {
                            short_options.push(ch);
                        }
                        more_s += 1;
                    }
                }
                entries.push(e);
            }
            short_options.push(0);
            let old_entries = hol.entries.replace(entries);
            let old_so = hol.short_options.replace(short_options);
            drop(old_entries);
            drop(old_so);
        }
    }
    drop(more);
}

fn argp_hol<'a>(argp: ArgpView<'a>, cluster: Option<ClPtr<'a>>) -> MBox<Hol<'a>> {
    let mut hol = make_hol(argp, cluster);
    for (index, child) in argp.children().iter().enumerate() {
        let header = argp.child_header(child);
        let child_cluster = if child.group != 0 || header.is_some() { hol_add_cluster(&mut hol, child.group, header, index as c_int, cluster, argp) } else { cluster };
        let more = argp_hol(argp.child_argp(child), child_cluster);
        hol_append(&mut hol, more);
    }
    hol
}

fn indent_to(stream: &mut FmtStream, col: c_uint) {
    let mut needed = col as c_int - stream.point() as c_int;
    while needed > 0 {
        needed -= 1;
        stream.putc(b' ');
    }
}

fn space(stream: &mut FmtStream, ensure: usize) {
    if stream.point() + ensure >= stream.rmargin {
        stream.putc(b'\n');
    } else {
        stream.putc(b' ');
    }
}

fn arg_print(real: Opt, req_fmt: &CStr, opt_fmt: &CStr, domain: Domain, stream: &mut FmtStream) {
    if let Some(a) = real.arg() {
        let a = dg(domain, a);
        if real.flags() & OPTION_ARG_OPTIONAL != 0 {
            stream.printf(opt_fmt, &[Arg::Str(a)]);
        } else {
            stream.printf(req_fmt, &[Arg::Str(a)]);
        }
    }
}

struct HolHelpState<'a> {
    prev_entry: Option<HolEntry<'a>>,
    sep_groups: bool,
    suppressed_dup_arg: bool,
}

struct PentryState<'h, 'a> {
    entry: &'h HolEntry<'a>,
    hhstate: &'h mut HolHelpState<'a>,
    first: bool,
    state: Option<StateView<'h>>,
}

fn print_header(s: Option<&CStr>, argp: ArgpView, pest: &mut PentryState, stream: &mut FmtStream) {
    let tstr = dgo(argp.domain(), s);
    let fstr = filter_doc(tstr, ARGP_KEY_HELP_HEADER, Some(argp), pest.state);
    if let Some(f) = fstr.get() {
        if !f.is_empty() {
            if pest.hhstate.prev_entry.is_some() {
                stream.putc(b'\n');
            }
            indent_to(stream, up(HEADER_COL) as c_uint);
            stream.set_lmargin(up(HEADER_COL) as usize);
            stream.set_wmargin(up(HEADER_COL) as isize);
            stream.puts(f);
            stream.set_lmargin(0);
            stream.putc(b'\n');
        }
        pest.hhstate.sep_groups = true;
    }
}

fn hol_cluster_is_child(mut cl1: Option<ClPtr>, cl2: ClPtr) -> bool {
    while let Some(c) = cl1
        && c != cl2
    {
        cl1 = c.get().parent;
    }
    cl1 == Some(cl2)
}

fn comma(col: c_uint, pest: &mut PentryState, stream: &mut FmtStream) {
    if pest.first {
        let pe = pest.hhstate.prev_entry;
        let cl = pest.entry.cluster;
        if pest.hhstate.sep_groups
            && let Some(pe) = pe
            && pest.entry.group != pe.group
        {
            stream.putc(b'\n');
        }
        if let Some(c) = cl {
            let cg = c.get();
            if cg.header.is_some_and(|h| !h.is_empty()) && pe.is_none_or(|pe| pe.cluster != cl && !hol_cluster_is_child(pe.cluster, c)) {
                let old_wm = stream.wmargin;
                print_header(cg.header, cg.argp, pest, stream);
                stream.set_wmargin(old_wm);
            }
        }
        pest.first = false;
    } else {
        stream.puts(c", ");
    }
    indent_to(stream, col);
}

fn hol_entry_help<'h, 'a>(entry: &'h HolEntry<'a>, so_all: &[u8], state: Option<StateView<'h>>, stream: &mut FmtStream, hhstate: &'h mut HolHelpState<'a>) {
    let real = entry.opts.first();
    let mut so = entry.so;
    let old_lm = stream.set_lmargin(0);
    let old_wm = stream.wmargin;
    let have_long_opt = !real.is_doc() && entry.opts.iter().any(|o| o.has_name() && o.visible());
    let mut pest = PentryState { entry, hhstate, first: true, state };
    stream.set_wmargin(up(SHORT_OPT_COL) as isize);
    for opt in entry.opts.iter() {
        if opt.short() && opt.key() == so_all[so] as c_int {
            if opt.visible() {
                comma(up(SHORT_OPT_COL) as c_uint, &mut pest, stream);
                stream.putc(b'-');
                stream.putc(so_all[so]);
                if !have_long_opt || up(DUP_ARGS) != 0 {
                    arg_print(real, c" %s", c"[%s]", root_domain(state), stream);
                } else if real.has_arg() {
                    pest.hhstate.suppressed_dup_arg = true;
                }
            }
            so += 1;
        }
    }
    if real.is_doc() {
        stream.set_wmargin(up(DOC_OPT_COL) as isize);
        for opt in entry.opts.iter() {
            if let Some(name) = opt.name()
                && opt.visible()
            {
                comma(up(DOC_OPT_COL) as c_uint, &mut pest, stream);
                stream.puts(dg(root_domain(state), name));
            }
        }
    } else {
        stream.set_wmargin(up(LONG_OPT_COL) as isize);
        for opt in entry.opts.iter() {
            if let Some(name) = opt.name()
                && opt.visible()
            {
                comma(up(LONG_OPT_COL) as c_uint, &mut pest, stream);
                stream.printf(c"--%s", &[Arg::Str(name)]);
                arg_print(real, c"=%s", c"[=%s]", root_domain(state), stream);
            }
        }
    }
    stream.set_lmargin(0);
    if pest.first {
        if !real.short() && !real.has_name() {
            print_header(real.doc(), entry.argp, &mut pest, stream);
        } else {
            stream.set_lmargin(old_lm);
            stream.set_wmargin(old_wm);
            return;
        }
    } else {
        let tstr = dgo(root_domain(state), real.doc());
        let fstr = filter_doc(tstr, real.key(), Some(entry.argp), state);
        if let Some(f) = fstr.get()
            && !f.is_empty()
        {
            let col = stream.point() as c_uint;
            stream.set_lmargin(up(OPT_DOC_COL) as usize);
            stream.set_wmargin(up(OPT_DOC_COL) as isize);
            if col > (up(OPT_DOC_COL) + 3) as c_uint {
                stream.putc(b'\n');
            } else if col >= up(OPT_DOC_COL) as c_uint {
                stream.puts(c"   ");
            } else {
                indent_to(stream, up(OPT_DOC_COL) as c_uint);
            }
            stream.puts(f);
        }
        drop(fstr);
        stream.set_lmargin(0);
        stream.putc(b'\n');
    }
    pest.hhstate.prev_entry = Some(*entry);
    stream.set_lmargin(old_lm);
    stream.set_wmargin(old_wm);
}

fn hol_help(hol: &Hol, state: Option<StateView>, stream: &mut FmtStream) {
    let mut hhstate = HolHelpState { prev_entry: None, sep_groups: false, suppressed_dup_arg: false };
    for entry in hol.entries() {
        hol_entry_help(entry, hol.short_options(), state, stream, &mut hhstate);
    }
    if hhstate.suppressed_dup_arg && up(DUP_ARGS_NOTE) != 0 {
        let tstr = dg(root_domain(state), c"Mandatory or optional arguments to long options are also mandatory or optional for any corresponding short options.");
        let fstr = filter_doc(Some(tstr), ARGP_KEY_HELP_DUP_ARGS_NOTE, state.and_then(|s| s.root_argp()), state);
        if let Some(f) = fstr.get()
            && !f.is_empty()
        {
            stream.putc(b'\n');
            stream.puts(f);
            stream.putc(b'\n');
        }
    }
}

fn hol_usage(hol: &Hol, stream: &mut FmtStream) {
    if hol.num_entries() > 0 {
        let so = hol.short_options();
        let so_len = so.iter().position(|&c| c == 0).unwrap_or(so.len());
        let mut buf: MVec<u8> = MVec::with_capacity(so_len + 2).unwrap_or_else(|| oom());
        for entry in hol.entries() {
            hol_entry_short_iterate(entry, so, |opt, real| {
                if !(opt.has_arg() || real.has_arg()) && (opt.flags() | real.flags()) & OPTION_NO_USAGE == 0 {
                    buf.push(opt.key() as u8);
                }
                0
            });
        }
        if !buf.is_empty() {
            buf.push(0);
            stream.printf(c" [-%s]", &[Arg::Str(CStr::from_bytes_with_nul(&buf).unwrap_or(c""))]);
        }
        for entry in hol.entries() {
            let domain = entry.argp.domain();
            hol_entry_short_iterate(entry, so, |opt, real| {
                let flags = opt.flags() | real.flags();
                if let Some(arg) = opt.arg().or(real.arg())
                    && flags & OPTION_NO_USAGE == 0
                {
                    let arg = dg(domain, arg);
                    if flags & OPTION_ARG_OPTIONAL != 0 {
                        stream.printf(c" [-%c[%s]]", &[Arg::Int(i64::from(opt.key())), Arg::Str(arg)]);
                    } else {
                        space(stream, 6 + arg.count_bytes());
                        stream.printf(c"[-%c %s]", &[Arg::Int(i64::from(opt.key())), Arg::Str(arg)]);
                    }
                }
                0
            });
        }
        for entry in hol.entries() {
            let domain = entry.argp.domain();
            hol_entry_long_iterate(entry, |opt, real| {
                let flags = opt.flags() | real.flags();
                if flags & OPTION_NO_USAGE == 0 {
                    let name = Arg::Str(opt.name().unwrap_or(c""));
                    if let Some(arg) = opt.arg().or(real.arg()) {
                        let arg = dg(domain, arg);
                        if flags & OPTION_ARG_OPTIONAL != 0 {
                            stream.printf(c" [--%s[=%s]]", &[name, Arg::Str(arg)]);
                        } else {
                            stream.printf(c" [--%s=%s]", &[name, Arg::Str(arg)]);
                        }
                    } else {
                        stream.printf(c" [--%s]", &[name]);
                    }
                }
                0
            });
        }
        drop(buf);
    }
}

fn argp_args_levels(argp: ArgpView) -> usize {
    let mut levels = 0;
    if argp.args_doc().is_some_and(|d| d.to_bytes().contains(&b'\n')) {
        levels += 1;
    }
    for child in argp.children() {
        levels += argp_args_levels(argp.child_argp(child));
    }
    levels
}

fn argp_args_usage(argp: ArgpView, state: Option<StateView>, levels: &mut [u8], li: &mut usize, mut advance: bool, stream: &mut FmtStream) -> bool {
    let our_level = *li;
    let mut multiple = false;
    let mut nl_is_newline = false;
    let tdoc = dgo(argp.domain(), argp.args_doc());
    let fdoc = filter_doc(tdoc, ARGP_KEY_HELP_ARGS_DOC, Some(argp), state);
    if let Some(f) = fdoc.get() {
        let d = f.to_bytes();
        let line_end = |from: usize| d[from..].iter().position(|&c| c == b'\n').map_or(d.len(), |k| from + k);
        let mut cp = 0;
        let mut nl = line_end(cp);
        if nl < d.len() {
            multiple = true;
            for _ in 0..levels[our_level] {
                cp = nl + 1;
                nl = line_end(cp);
            }
            *li += 1;
        }
        space(stream, 1 + nl - cp);
        stream.write(&d[cp..nl]);
        nl_is_newline = nl < d.len();
    }
    drop(fdoc);
    for child in argp.children() {
        advance = !argp_args_usage(argp.child_argp(child), state, levels, li, advance, stream);
    }
    if advance && multiple {
        if nl_is_newline {
            levels[our_level] += 1;
            advance = false;
        } else if levels[our_level] > 0 {
            levels[our_level] = 0;
        }
    }
    !advance
}

fn argp_doc(argp: ArgpView, state: Option<StateView>, post: bool, pre_blank: bool, first_only: bool, stream: &mut FmtStream) -> bool {
    let mut anything = false;
    let doc = dgo(argp.domain(), argp.doc());
    let (inp_text, inp_text_limit): (Option<&CStr>, usize) = match doc {
        None => (None, 0),
        Some(d) => {
            let b = d.to_bytes_with_nul();
            let vt = b.iter().position(|&c| c == 0x0b);
            if post {
                (vt.map(|v| &d[v + 1..]), 0)
            } else {
                (Some(d), vt.unwrap_or(0))
            }
        }
    };
    let mut input: *mut c_void = null_mut();
    if let Some(f) = argp.help_filter() {
        let dup = if inp_text_limit != 0 { inp_text.and_then(|t| strndup(t, inp_text_limit)) } else { None };
        let given = match &dup {
            Some(d) => d.as_ptr(),
            None if inp_text_limit != 0 => null(),
            None => inp_text.map_or(null(), |t| t.as_ptr()),
        };
        input = argp_input(argp.ptr(), state);
        let text = call_filter(f, if post { ARGP_KEY_HELP_POST_DOC } else { ARGP_KEY_HELP_PRE_DOC }, given, input);
        if let Some(t) = text.get() {
            if pre_blank {
                stream.putc(b'\n');
            }
            stream.puts(t);
            if stream.point() > stream.lmargin {
                stream.putc(b'\n');
            }
            anything = true;
        }
        drop(text);
        drop(dup);
    } else if let Some(t) = inp_text {
        if pre_blank {
            stream.putc(b'\n');
        }
        if inp_text_limit != 0 {
            stream.write(&t.to_bytes()[..inp_text_limit]);
        } else {
            stream.puts(t);
        }
        if stream.point() > stream.lmargin {
            stream.putc(b'\n');
        }
        anything = true;
    }
    if post && let Some(f) = argp.help_filter() {
        let text = call_filter(f, ARGP_KEY_HELP_EXTRA, null(), input);
        if let Some(t) = text.get() {
            if anything || pre_blank {
                stream.putc(b'\n');
            }
            stream.puts(t);
            drop(text);
            if stream.point() > stream.lmargin {
                stream.putc(b'\n');
            }
            anything = true;
        }
    }
    for child in argp.children() {
        if first_only && anything {
            break;
        }
        anything |= argp_doc(argp.child_argp(child), state, post, anything || pre_blank, first_only, stream);
    }
    anything
}

struct MStr(core::ptr::NonNull<c_char>);

impl MStr {
    fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr()
    }
}

impl Drop for MStr {
    fn drop(&mut self) {
        unsafe { heap::free(self.0.as_ptr().cast()) };
    }
}

fn strndup(s: &CStr, n: usize) -> Option<MStr> {
    core::ptr::NonNull::new(unsafe { rusty_libc_malloc::strndup(s.as_ptr(), n) }).map(MStr)
}

fn help_inner(argp: Option<ArgpView>, state: Option<StateView>, stream: Option<Stream>, flags: c_uint, name: Option<&CStr>) {
    let mut flags = flags;
    let mut anything = false;
    let Some(stream) = stream else { return };
    let need_argp = || argp.unwrap_or_else(|| oom());
    let need_name = || name.unwrap_or_else(|| oom());
    stream.lock();
    fill_in_uparams(state);
    let Some(mut fs) = FmtStream::new(stream, 0, up(RMARGIN) as usize, 0) else {
        stream.unlock();
        return;
    };
    let mut hol: Option<MBox<Hol>> = None;
    if flags & (ARGP_HELP_USAGE | ARGP_HELP_SHORT_USAGE | ARGP_HELP_LONG) != 0 {
        let mut h = argp_hol(need_argp(), None);
        hol_set_group(&mut h, c"help", -1);
        hol_set_group(&mut h, c"version", -1);
        hol_sort(&mut h);
        hol = Some(h);
    }
    if flags & (ARGP_HELP_USAGE | ARGP_HELP_SHORT_USAGE) != 0 {
        let argp = need_argp();
        let h = hol.as_deref().unwrap_or_else(|| oom());
        let mut first_pattern = true;
        let num_pattern_levels = argp_args_levels(argp);
        let mut pattern_levels = MBuf::zeroed(num_pattern_levels.max(1)).unwrap_or_else(|| oom());
        loop {
            let old_wm = fs.set_wmargin(up(USAGE_INDENT) as isize);
            let mut li = 0;
            let label = if first_pattern { c"Usage:" } else { c"  or: " };
            fs.printf(c"%s %s", &[Arg::Str(dg(argp.domain(), label)), Arg::Str(need_name())]);
            let old_lm = fs.set_lmargin(up(USAGE_INDENT) as usize);
            if flags & ARGP_HELP_SHORT_USAGE != 0 {
                if h.num_entries() > 0 {
                    fs.puts(dg(argp.domain(), c" [OPTION...]"));
                }
            } else {
                hol_usage(h, &mut fs);
                flags |= ARGP_HELP_SHORT_USAGE;
            }
            let more_patterns = argp_args_usage(argp, state, &mut pattern_levels, &mut li, true, &mut fs);
            fs.set_wmargin(old_wm);
            fs.set_lmargin(old_lm);
            fs.putc(b'\n');
            anything = true;
            first_pattern = false;
            if !more_patterns {
                break;
            }
        }
        drop(pattern_levels);
    }
    if flags & ARGP_HELP_PRE_DOC != 0 {
        anything |= argp_doc(need_argp(), state, false, false, true, &mut fs);
    }
    if flags & ARGP_HELP_SEE != 0 {
        let n = need_name();
        fs.printf(dg(need_argp().domain(), c"Try `%s --help' or `%s --usage' for more information.\n"), &[Arg::Str(n), Arg::Str(n)]);
        anything = true;
    }
    if flags & ARGP_HELP_LONG != 0
        && let Some(h) = hol.as_deref()
        && h.num_entries() > 0
    {
        if anything {
            fs.putc(b'\n');
        }
        hol_help(h, state, &mut fs);
        anything = true;
    }
    if flags & ARGP_HELP_POST_DOC != 0 {
        anything |= argp_doc(need_argp(), state, true, anything, false, &mut fs);
    }
    if flags & ARGP_HELP_BUG_ADDR != 0
        && let Some(bug) = program_bug_address()
    {
        if anything {
            fs.putc(b'\n');
        }
        fs.printf(dg(need_argp().domain(), c"Report bugs to %s.\n"), &[Arg::Str(bug)]);
    }
    stream.unlock();
    drop(hol);
    FmtStream::finish(fs);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_help(argp: *const Argp, stream: *mut File, flags: c_uint, name: *mut c_char) {
    let argp = (!argp.is_null()).then(|| unsafe { ArgpView::new(argp) });
    let stream = unsafe { Stream::new(stream) };
    let name = unsafe { rusty_libc_core::ffi::cstr(name) };
    help_inner(argp, None, stream, flags, name)
}

fn state_help(state: Option<StateView>, stream: *mut File, flags: c_uint) {
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) && !stream.is_null() {
        let mut flags = flags;
        if state.is_some_and(|s| s.flags() & ARGP_LONG_ONLY != 0) {
            flags |= ARGP_HELP_LONG_ONLY;
        }
        let st = unsafe { Stream::new(stream) };
        let name = state.map_or(Some(short_program_name()), |s| s.name());
        help_inner(state.and_then(|s| s.root_argp()), state, st, flags, name);
        if state.is_none_or(|s| s.flags() & ARGP_NO_EXIT == 0) {
            if flags & ARGP_HELP_EXIT_ERR != 0 {
                flush_exit(err_exit_status());
            }
            if flags & ARGP_HELP_EXIT_OK != 0 {
                flush_exit(0);
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_state_help(state: *const ArgpState, stream: *mut File, flags: c_uint) {
    state_help(unsafe { StateView::new(state) }, stream, flags)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_usage(state: *const ArgpState) {
    state_help(unsafe { StateView::new(state) }, std_err(), ARGP_HELP_STD_USAGE)
}

struct Collect {
    buf: Option<MBuf>,
    len: usize,
}

impl Collect {
    fn new() -> Collect {
        Collect { buf: None, len: 0 }
    }

    fn text(&self) -> Option<&[u8]> {
        self.buf.as_deref().map(|b| &b[..self.len])
    }
}

impl Sink for Collect {
    fn put(&mut self, bytes: &[u8]) -> bool {
        let cap = self.buf.as_ref().map_or(0, |b| b.len());
        if self.len + bytes.len() + 1 > cap {
            let ncap = (self.len + bytes.len() + 1).max(cap * 2).max(128);
            match &mut self.buf {
                Some(b) => {
                    if !b.grow(ncap) {
                        return false;
                    }
                }
                None => match MBuf::fresh(ncap) {
                    Some(b) => self.buf = Some(b),
                    None => return false,
                },
            }
        }
        let Some(b) = self.buf.as_deref_mut() else { return false };
        b[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        b[self.len] = 0;
        true
    }
}

unsafe fn vformat(fmt: *const c_char, ap: &mut core::ffi::VaList) -> Option<Collect> {
    let mut c = Collect::new();
    if unsafe { rusty_libc_stdio::printf_api::run(&mut c, fmt, ap) } < 0 {
        return None;
    }
    if c.buf.is_none() {
        c.put(b"");
    }
    Some(c)
}

fn name_of<'s>(state: Option<StateView<'s>>) -> &'s CStr {
    state.map_or(short_program_name(), |s| s.name().unwrap_or_else(|| oom()))
}

fn err_stream_of(state: Option<StateView>) -> *mut File {
    state.map_or_else(std_err, |s| s.err_stream())
}

fn error_str(state: Option<StateView>, msg: &[u8]) {
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) {
        let raw = err_stream_of(state);
        if let Some(stream) = unsafe { Stream::new(raw) } {
            stream.lock();
            out(stream, &[name_of(state).to_bytes(), b": ", msg, b"\n"]);
            state_help(state, raw, ARGP_HELP_STD_ERR);
            stream.unlock();
        }
    }
}

fn error_fmt(state: Option<StateView>, fmt: &CStr, args: &[Arg]) {
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) && !err_stream_of(state).is_null() {
        let mut c = Collect::new();
        let ok = format_to(&mut c, fmt, args) >= 0;
        if ok && c.buf.is_none() {
            c.put(b"");
        }
        let msg = if ok { c.text() } else { None };
        error_str(state, msg.unwrap_or(b"(null)"));
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_error(state: *const ArgpState, fmt: *const c_char, mut args: ...) {
    let state = unsafe { StateView::new(state) };
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) && !err_stream_of(state).is_null() {
        let ap: &mut core::ffi::VaList = &mut args;
        let c = unsafe { vformat(fmt, ap) };
        let msg = c.as_ref().and_then(|c| c.text()).unwrap_or(b"(null)");
        error_str(state, msg);
    }
}

fn failure_str(state: Option<StateView>, status: c_int, errnum: c_int, msg: Option<&[u8]>) {
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) {
        if let Some(stream) = unsafe { Stream::new(err_stream_of(state)) } {
            stream.lock();
            out(stream, &[name_of(state).to_bytes()]);
            if let Some(m) = msg {
                out(stream, &[b": ", m]);
            }
            if errnum != 0 {
                let mut tmp = [0u8; 128];
                out(stream, &[b": ", rusty_libc_core::messages::strerror_r_text(errnum, &mut tmp)]);
            }
            out(stream, &[b"\n"]);
            stream.unlock();
            if status != 0 && state.is_none_or(|s| s.flags() & ARGP_NO_EXIT == 0) {
                flush_exit(status);
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_failure(state: *const ArgpState, status: c_int, errnum: c_int, fmt: *const c_char, mut args: ...) {
    let state = unsafe { StateView::new(state) };
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) && !err_stream_of(state).is_null() {
        if fmt.is_null() {
            failure_str(state, status, errnum, None);
        } else {
            let ap: &mut core::ffi::VaList = &mut args;
            let c = unsafe { vformat(fmt, ap) };
            let msg = c.as_ref().and_then(|c| c.text()).unwrap_or(b"(null)");
            failure_str(state, status, errnum, Some(msg));
        }
    }
}

const KEY_END: c_int = -1;
const KEY_ARG: c_int = 1;
const KEY_ERR: c_int = b'?' as c_int;
const GROUP_BITS: u32 = 8;
const USER_BITS: u32 = 32 - GROUP_BITS;
const USER_MASK: c_int = (1 << USER_BITS) - 1;

const OPT_PROGNAME: c_int = -2;
const OPT_USAGE: c_int = -3;
const OPT_HANG: c_int = -4;

struct SyncArr<T, const N: usize>([T; N]);
unsafe impl<T, const N: usize> Sync for SyncArr<T, N> {}

macro_rules! opt {
    ($name:expr, $key:expr, $arg:expr, $flags:expr, $doc:expr, $group:expr) => {
        ArgpOption { name: $name, key: $key, arg: $arg, flags: $flags, doc: $doc, group: $group }
    };
}

static ARGP_DEFAULT_OPTIONS: SyncArr<ArgpOption, 5> = SyncArr([
    opt!(c"help".as_ptr(), b'?' as c_int, null(), 0, c"Give this help list".as_ptr(), -1),
    opt!(c"usage".as_ptr(), OPT_USAGE, null(), 0, c"Give a short usage message".as_ptr(), 0),
    opt!(c"program-name".as_ptr(), OPT_PROGNAME, c"NAME".as_ptr(), OPTION_HIDDEN, c"Set the program name".as_ptr(), 0),
    opt!(c"HANG".as_ptr(), OPT_HANG, c"SECS".as_ptr(), OPTION_ARG_OPTIONAL | OPTION_HIDDEN, c"Hang for SECS seconds (default 3600)".as_ptr(), 0),
    opt!(null(), 0, null(), 0, null(), 0),
]);

static ARGP_VERSION_OPTIONS: SyncArr<ArgpOption, 2> = SyncArr([opt!(c"version".as_ptr(), b'V' as c_int, null(), 0, c"Print program version".as_ptr(), -1), opt!(null(), 0, null(), 0, null(), 0)]);

struct SyncArgp(Argp);
unsafe impl Sync for SyncArgp {}

static ARGP_HANG: AtomicI32 = AtomicI32::new(0);

unsafe fn atol10(s: *const c_char) -> c_int {
    unsafe { rusty_libc_stdlib::num::strtol(s, null_mut(), 10) as c_int }
}

unsafe fn state_fields(state: *mut ArgpState) -> (c_uint, *mut File, *mut *mut c_char) {
    let flags = unsafe { (*state).flags };
    let out = unsafe { (*state).out_stream };
    let argv = unsafe { (*state).argv };
    (flags, out, argv)
}

unsafe extern "C" fn argp_default_parser(key: c_int, arg: *mut c_char, state: *mut ArgpState) -> c_int {
    let (flags, out_stream, argv) = unsafe { state_fields(state) };
    match key {
        63 => state_help(unsafe { StateView::new(state) }, out_stream, ARGP_HELP_STD_HELP),
        OPT_USAGE => state_help(unsafe { StateView::new(state) }, out_stream, ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK),
        OPT_PROGNAME => {
            let name = unsafe { rusty_libc_core::ffi::cstr_bytes(arg) };
            let short = match name.iter().rposition(|&c| c == b'/') {
                Some(i) => arg.wrapping_add(i + 1),
                None => arg,
            };
            set_program_names(arg, short);
            unsafe { (*state).name = short };
            if flags & (ARGP_PARSE_ARGV0 | ARGP_NO_ERRS) == ARGP_PARSE_ARGV0 {
                unsafe { *argv = arg };
            }
        }
        OPT_HANG => {
            let secs = if arg.is_null() { 3600 } else { unsafe { atol10(arg) } };
            ARGP_HANG.store(secs, Ordering::Relaxed);
            while ARGP_HANG.load(Ordering::Relaxed) > 0 {
                ARGP_HANG.store(ARGP_HANG.load(Ordering::Relaxed) - 1, Ordering::Relaxed);
                unsafe { rusty_libc_time::clock::sleep(1) };
            }
        }
        _ => return EBADKEY,
    }
    0
}

static ARGP_DEFAULT_ARGP: SyncArgp = SyncArgp(Argp { options: ARGP_DEFAULT_OPTIONS.0.as_ptr(), parser: Some(argp_default_parser), args_doc: null(), doc: null(), children: null(), help_filter: None, argp_domain: c"libc".as_ptr() });

unsafe extern "C" fn argp_version_parser(key: c_int, _arg: *mut c_char, state: *mut ArgpState) -> c_int {
    let (flags, out_stream, _) = unsafe { state_fields(state) };
    match key {
        86 => {
            if let Some(h) = program_version_hook() {
                unsafe { h(out_stream, state) };
            } else if let Some(v) = {
                unsafe { rusty_libc_core::ffi::cstr(program_version()) }
            } {
                let st = unsafe { Stream::new(out_stream) }.unwrap_or_else(|| oom());
                out(st, &[v.to_bytes(), b"\n"]);
            } else {
                let sv = unsafe { StateView::new(state) };
                error_fmt(sv, c"%s", &[Arg::Str(dg(root_domain(sv), c"(PROGRAM ERROR) No version known!?"))]);
            }
            if flags & ARGP_NO_EXIT == 0 {
                flush_exit(0);
            }
        }
        _ => return EBADKEY,
    }
    0
}

static ARGP_VERSION_ARGP: SyncArgp = SyncArgp(Argp { options: ARGP_VERSION_OPTIONS.0.as_ptr(), parser: Some(argp_version_parser), args_doc: null(), doc: null(), children: null(), help_filter: None, argp_domain: c"libc".as_ptr() });

unsafe fn has_long_option(long_options: &[COption], name: *const c_char) -> bool {
    long_options.iter().any(|l| unsafe { rusty_libc_core::ffi::cstr_eq(l.name, name) })
}

#[derive(Clone, Copy)]
struct Group {
    parser: Option<ArgpParser>,
    argp: *const Argp,
    short_end: usize,
    args_processed: c_uint,
    parent: Option<usize>,
    parent_index: c_uint,
    input: *mut c_void,
    child_inputs: Option<usize>,
    hook: *mut c_void,
    pass_input: bool,
}

const NO_GROUP: Group = Group { parser: None, argp: null(), short_end: 0, args_processed: 0, parent: None, parent_index: 0, input: null_mut(), child_inputs: None, hook: null_mut(), pass_input: false };

const NO_LONG_OPTION: COption = COption { name: null(), has_arg: 0, flag: null_mut(), val: 0 };

struct ParserSizes {
    short_len: usize,
    long_len: usize,
    num_groups: usize,
    num_child_inputs: usize,
}

fn calc_sizes(argp: ArgpView, szs: &mut ParserSizes) {
    if argp.has_options() || argp.parser().is_some() {
        szs.num_groups += 1;
        if argp.has_options() {
            let num_opts = argp.options().len();
            szs.short_len += num_opts * 3;
            szs.long_len += num_opts;
        }
    }
    for child in argp.children() {
        calc_sizes(argp.child_argp(child), szs);
        szs.num_child_inputs += 1;
    }
}

unsafe fn argv_at(argv: *mut *mut c_char, i: usize) -> *mut c_char {
    unsafe { *argv.wrapping_add(i) }
}

struct Parser<'a> {
    argp: Option<ArgpView<'a>>,
    storage: *mut u8,
    slots: usize,
    groups: *mut Group,
    egroup: usize,
    child_inputs: *mut *mut c_void,
    num_child_inputs: usize,
    long_opts: *mut COption,
    long_cap: usize,
    short_opts: *mut u8,
    short_cap: usize,
    short_len: usize,
    long_len: usize,
    opt_data: Data,
    try_getopt: bool,
    state: ArgpState,
}

impl<'a> Parser<'a> {
    fn new() -> Parser<'a> {
        Parser {
            argp: None,
            storage: null_mut(),
            slots: 0,
            groups: null_mut(),
            egroup: 0,
            child_inputs: null_mut(),
            num_child_inputs: 0,
            long_opts: null_mut(),
            long_cap: 0,
            short_opts: null_mut(),
            short_cap: 0,
            short_len: 0,
            long_len: 0,
            opt_data: Data::new(),
            try_getopt: false,
            state: empty_state(),
        }
    }

    fn grp(&self, i: usize) -> &Group {
        assert!(i < self.slots);
        unsafe { &*self.groups.wrapping_add(i) }
    }

    fn grp_mut(&mut self, i: usize) -> &mut Group {
        assert!(i < self.slots);
        unsafe { &mut *self.groups.wrapping_add(i) }
    }

    fn child_input(&self, i: usize) -> *mut c_void {
        assert!(i < self.num_child_inputs);
        unsafe { self.child_inputs.wrapping_add(i).read() }
    }

    fn set_child_input(&mut self, i: usize, v: *mut c_void) {
        assert!(i < self.num_child_inputs);
        unsafe { self.child_inputs.wrapping_add(i).write(v) };
    }

    fn long_opts(&mut self) -> &mut [COption] {
        unsafe { core::slice::from_raw_parts_mut(self.long_opts, self.long_cap) }
    }

    fn short_opts(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.short_opts, self.short_cap) }
    }

    fn state_view(&self) -> Option<StateView<'_>> {
        unsafe { StateView::new(&self.state) }
    }

    fn convert(&mut self, argp: Option<ArgpView<'a>>, flags: c_uint) {
        let mut short_end = 0;
        if flags & ARGP_IN_ORDER != 0 {
            self.short_opts()[0] = b'-';
            short_end = 1;
        } else if flags & ARGP_NO_ARGS != 0 {
            self.short_opts()[0] = b'+';
            short_end = 1;
        }
        self.short_opts()[short_end] = 0;
        self.long_opts()[0].name = null();
        self.argp = argp;
        let mut cvt = (short_end, 0usize, 0usize);
        self.egroup = match argp {
            Some(a) => self.convert_options(a, None, 0, 0, &mut cvt),
            None => 0,
        };
        self.short_len = cvt.0;
        self.long_len = cvt.1;
    }

    fn convert_options(&mut self, argp: ArgpView<'a>, mut parent: Option<usize>, parent_index: c_uint, mut group: usize, cvt: &mut (usize, usize, usize)) -> usize {
        if argp.has_options() || argp.parser().is_some() {
            let opts = argp.options();
            if opts.len() > 0 {
                let mut real = opts.first();
                for opt in opts.iter() {
                    if !opt.alias() {
                        real = opt;
                    }
                    if real.is_doc() {
                        continue;
                    }
                    if opt.short() {
                        let so = self.short_opts();
                        so[cvt.0] = opt.key() as u8;
                        cvt.0 += 1;
                        if real.has_arg() {
                            so[cvt.0] = b':';
                            cvt.0 += 1;
                            if real.flags() & OPTION_ARG_OPTIONAL != 0 {
                                so[cvt.0] = b':';
                                cvt.0 += 1;
                            }
                        }
                        so[cvt.0] = 0;
                    }
                    let known = opt.has_name() && unsafe { has_long_option(&self.long_opts()[..cvt.1], opt.name_ptr()) };
                    if opt.has_name() && !known {
                        let has_arg = if real.has_arg() {
                            if real.flags() & OPTION_ARG_OPTIONAL != 0 { 2 } else { 1 }
                        } else {
                            0
                        };
                        let key = if opt.key() != 0 { opt.key() } else { real.key() };
                        let val = (key & USER_MASK).wrapping_add((group as c_int + 1) << USER_BITS);
                        let lo = self.long_opts();
                        lo[cvt.1] = COption { name: opt.name_ptr(), has_arg, flag: null_mut(), val };
                        cvt.1 += 1;
                        lo[cvt.1].name = null();
                    }
                }
            }
            let children = argp.children();
            let child_inputs = if argp.has_children() {
                let at = cvt.2;
                cvt.2 += children.len();
                Some(at)
            } else {
                None
            };
            let g = Group {
                parser: argp.parser(),
                argp: argp.ptr(),
                short_end: cvt.0,
                args_processed: 0,
                parent,
                parent_index,
                input: null_mut(),
                child_inputs,
                hook: null_mut(),
                pass_input: argp.parser().is_none() && !children.is_empty(),
            };
            *self.grp_mut(group) = g;
            parent = Some(group);
            group += 1;
        } else {
            parent = None;
        }
        for (index, child) in argp.children().iter().enumerate() {
            group = self.convert_options(argp.child_argp(child), parent, index as c_uint, group, cvt);
        }
        group
    }

    fn group_parse(&mut self, gi: usize, key: c_int, arg: *mut c_char) -> c_int {
        let g = *self.grp(gi);
        let Some(p) = g.parser else { return EBADKEY };
        self.state.hook = g.hook;
        self.state.input = g.input;
        self.state.child_inputs = g.child_inputs.map_or(null_mut(), |i| self.child_inputs.wrapping_add(i));
        self.state.arg_num = g.args_processed;
        let st: *mut ArgpState = &raw mut self.state;
        let err = unsafe { p(key, arg, st) };
        self.grp_mut(gi).hook = self.state.hook;
        err
    }

    fn init(&mut self, argp: Option<ArgpView<'a>>, argc: c_int, argv: *mut *mut c_char, flags: c_uint, input: *mut c_void) -> c_int {
        let mut szs = ParserSizes { short_len: if flags & ARGP_NO_ARGS != 0 { 0 } else { 1 }, long_len: 0, num_groups: 0, num_child_inputs: 0 };
        if let Some(a) = argp {
            calc_sizes(a, &mut szs);
        }
        let slots = szs.num_groups + 1;
        let glen = slots * size_of::<Group>();
        let clen = szs.num_child_inputs * size_of::<*mut c_void>();
        let llen = (szs.long_len + 1) * size_of::<COption>();
        let slen = szs.short_len + 1;
        let storage = heap::malloc(glen + clen + llen + slen);
        if storage.is_null() {
            return ENOMEM;
        }
        const { assert!(size_of::<Group>().is_multiple_of(8) && size_of::<COption>().is_multiple_of(8) && align_of::<Group>() <= 8 && align_of::<COption>() <= 8) };
        self.storage = storage;
        self.slots = slots;
        self.groups = storage.cast();
        self.child_inputs = storage.wrapping_add(glen).cast();
        self.num_child_inputs = szs.num_child_inputs;
        self.long_opts = storage.wrapping_add(glen + clen).cast();
        self.long_cap = szs.long_len + 1;
        self.short_opts = storage.wrapping_add(glen + clen + llen);
        self.short_cap = slen;
        for i in 0..slots {
            unsafe { self.groups.wrapping_add(i).write(NO_GROUP) };
        }
        const { assert!(NO_LONG_OPTION.name.is_null() && NO_LONG_OPTION.has_arg == 0 && NO_LONG_OPTION.flag.is_null() && NO_LONG_OPTION.val == 0) };
        unsafe { core::ptr::write_bytes(storage.wrapping_add(glen), 0, clen + llen + slen) };
        self.convert(argp, flags);
        self.state.root_argp = self.argp.map_or(null(), |a| a.ptr());
        self.state.argc = argc;
        self.state.argv = argv;
        self.state.flags = flags;
        self.state.err_stream = std_err();
        self.state.out_stream = std_out();
        self.state.next = 0;
        self.state.pstate = self.groups.cast();
        self.try_getopt = true;
        if self.egroup > 0 {
            self.grp_mut(0).input = input;
        }
        let mut err = 0;
        let mut gi = 0;
        while gi < self.egroup && (err == 0 || err == EBADKEY) {
            let mut g = *self.grp(gi);
            if let Some(p) = g.parent {
                let base = self.grp(p).child_inputs.unwrap_or_else(|| oom());
                g.input = self.child_input(base + g.parent_index as usize);
                self.grp_mut(gi).input = g.input;
            }
            if g.pass_input {
                self.set_child_input(g.child_inputs.unwrap_or_else(|| oom()), g.input);
            }
            err = self.group_parse(gi, ARGP_KEY_INIT, null_mut());
            gi += 1;
        }
        if err == EBADKEY {
            err = 0;
        }
        if err != 0 {
            return err;
        }
        if self.state.flags & ARGP_NO_ERRS != 0 {
            self.opt_data.opterr = 0;
            if self.state.flags & ARGP_PARSE_ARGV0 != 0 {
                self.state.argv = self.state.argv.wrapping_sub(1);
                self.state.argc += 1;
            }
        } else {
            self.opt_data.opterr = 1;
        }
        let argv0 = if self.state.argv == argv { unsafe { argv_at(argv, 0) } } else { null_mut() };
        if !argv0.is_null() {
            let name = unsafe { rusty_libc_core::ffi::cstr_bytes(argv0) };
            self.state.name = match name.iter().rposition(|&c| c == b'/') {
                Some(i) => argv0.wrapping_add(i + 1),
                None => argv0,
            };
        } else {
            self.state.name = short_program_name().as_ptr().cast_mut();
        }
        0
    }

    fn finalize(&mut self, mut err: c_int, arg_ebadkey: bool, end_index: *mut c_int) -> c_int {
        let set_end_index = |next: c_int| {
            if let Some(e) = unsafe { rusty_libc_core::ffi::out(end_index) } {
                *e = next;
            }
        };
        if err == EBADKEY && arg_ebadkey {
            err = 0;
        }
        if err == 0 {
            if self.state.next == self.state.argc {
                let mut gi = 0;
                while gi < self.egroup && (err == 0 || err == EBADKEY) {
                    if self.grp(gi).args_processed == 0 {
                        err = self.group_parse(gi, ARGP_KEY_NO_ARGS, null_mut());
                    }
                    gi += 1;
                }
                let mut gi = self.egroup;
                while gi > 0 && (err == 0 || err == EBADKEY) {
                    gi -= 1;
                    err = self.group_parse(gi, ARGP_KEY_END, null_mut());
                }
                if err == EBADKEY {
                    err = 0;
                }
                if !end_index.is_null() {
                    set_end_index(self.state.next);
                }
            } else if !end_index.is_null() {
                set_end_index(self.state.next);
            } else {
                let es = unsafe { Stream::new(self.state.err_stream) };
                if self.state.flags & ARGP_NO_ERRS == 0
                    && let Some(es) = es
                {
                    let msgid = c"%s: Too many arguments\n";
                    let f = dg(self.argp.unwrap_or_else(|| oom()).domain(), msgid);
                    let name = self.state_view().and_then(|s| s.name()).unwrap_or_else(|| oom());
                    if core::ptr::eq(f.as_ptr(), msgid.as_ptr()) {
                        out(es, &[name.to_bytes(), b": Too many arguments\n"]);
                    } else {
                        let mut buf = [0u8; 1024];
                        let n = (snprintf(&mut buf, f, &[Arg::Str(name)]).max(0) as usize).min(buf.len() - 1);
                        out(es, &[&buf[..n]]);
                    }
                }
                err = EBADKEY;
            }
        }
        if err != 0 {
            if err == EBADKEY {
                state_help(self.state_view(), self.state.err_stream, ARGP_HELP_STD_ERR);
            }
            for gi in 0..self.egroup {
                self.group_parse(gi, ARGP_KEY_ERROR, null_mut());
            }
        } else {
            let mut gi = self.egroup;
            while gi > 0 && (err == 0 || err == EBADKEY) {
                gi -= 1;
                err = self.group_parse(gi, ARGP_KEY_SUCCESS, null_mut());
            }
            if err == EBADKEY {
                err = 0;
            }
        }
        for gi in (0..self.egroup).rev() {
            self.group_parse(gi, ARGP_KEY_FINI, null_mut());
        }
        if err == EBADKEY {
            err = EINVAL;
        }
        unsafe { heap::free(self.storage) };
        self.storage = null_mut();
        err
    }

    fn parse_arg(&mut self, val: *mut c_char) -> c_int {
        self.state.next -= 1;
        let index = self.state.next;
        let mut err = EBADKEY;
        let mut key = 0;
        let mut gi = 0;
        while gi < self.egroup && err == EBADKEY {
            self.state.next += 1;
            key = ARGP_KEY_ARG;
            err = self.group_parse(gi, key, val);
            if err == EBADKEY {
                self.state.next -= 1;
                key = ARGP_KEY_ARGS;
                err = self.group_parse(gi, key, null_mut());
            }
            gi += 1;
        }
        if err == 0 {
            if key == ARGP_KEY_ARGS {
                self.state.next = self.state.argc;
            }
            if self.state.next > index {
                let n = (self.state.next - index) as c_uint;
                self.grp_mut(gi - 1).args_processed += n;
            } else {
                self.try_getopt = true;
            }
        }
        err
    }

    fn parse_opt(&mut self, opt: c_int) -> c_int {
        let group_key = opt >> USER_BITS;
        let mut err = EBADKEY;
        let optarg = self.opt_data.optarg;
        if group_key == 0 {
            let nul = self.short_len;
            let so = self.short_opts();
            if let Some(si) = so[..=nul].iter().position(|&c| c == opt as u8) {
                for gi in 0..self.egroup {
                    if self.grp(gi).short_end > si {
                        err = self.group_parse(gi, opt, optarg);
                        break;
                    }
                }
            }
        } else {
            let user_key = (if opt & (1 << (USER_BITS - 1)) != 0 { !USER_MASK } else { 0 }) | (opt & USER_MASK);
            err = self.group_parse((group_key - 1) as usize, user_key, optarg);
        }
        if err == EBADKEY {
            let bad = dg(self.argp.unwrap_or_else(|| oom()).domain(), c"(PROGRAM ERROR) Option should have been recognized!?");
            if group_key == 0 {
                error_fmt(self.state_view(), c"-%c: %s", &[Arg::Int(i64::from(opt)), Arg::Str(bad)]);
            } else {
                let lo: &[COption] = self.long_opts();
                let name = lo.iter().find(|l| l.val == opt || l.name.is_null()).map_or(null(), |l| l.name);
                let name = unsafe { rusty_libc_core::ffi::cstr(name) }.unwrap_or(c"???");
                error_fmt(self.state_view(), c"--%s: %s", &[Arg::Str(name), Arg::Str(bad)]);
            }
        }
        err
    }

    fn parse_next(&mut self, arg_ebadkey: &mut bool) -> c_int {
        let mut opt: c_int;
        if self.state.quoted != 0 && self.state.next < self.state.quoted {
            self.state.quoted = 0;
        }
        if self.try_getopt && self.state.quoted == 0 {
            self.opt_data.optind = self.state.next;
            self.opt_data.optopt = KEY_END;
            let long_only = self.state.flags & ARGP_LONG_ONLY != 0;
            opt = unsafe { getopt_internal_r(self.state.argc, self.state.argv, self.short_opts.cast(), self.long_opts, null_mut(), long_only, &mut self.opt_data, false) };
            self.state.next = self.opt_data.optind;
            if opt == KEY_END {
                self.try_getopt = false;
                if self.state.next > 1 {
                    let prev = unsafe { argv_at(self.state.argv, (self.state.next - 1) as usize) };
                    if unsafe { rusty_libc_core::ffi::cstr_eq(prev.cast_const(), c"--".as_ptr()) } {
                        self.state.quoted = self.state.next;
                    }
                }
            } else if opt == KEY_ERR && self.opt_data.optopt != KEY_END {
                *arg_ebadkey = false;
                return EBADKEY;
            }
        } else {
            opt = KEY_END;
        }
        if opt == KEY_END {
            if self.state.next >= self.state.argc || self.state.flags & ARGP_NO_ARGS != 0 {
                *arg_ebadkey = true;
                return EBADKEY;
            } else {
                opt = KEY_ARG;
                self.opt_data.optarg = unsafe { argv_at(self.state.argv, self.state.next as usize) };
                self.state.next += 1;
            }
        }
        let err = if opt == KEY_ARG { self.parse_arg(self.opt_data.optarg) } else { self.parse_opt(opt) };
        if err == EBADKEY {
            *arg_ebadkey = opt == KEY_END || opt == KEY_ARG;
        }
        err
    }
}

fn empty_state() -> ArgpState {
    ArgpState {
        root_argp: null(),
        argc: 0,
        argv: null_mut(),
        next: 0,
        flags: 0,
        arg_num: 0,
        quoted: 0,
        input: null_mut(),
        child_inputs: null_mut(),
        hook: null_mut(),
        name: null_mut(),
        err_stream: null_mut(),
        out_stream: null_mut(),
        pstate: null_mut(),
    }
}

const NO_CHILD: ArgpChild = ArgpChild { argp: null(), flags: 0, header: null(), group: 0 };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_parse(argp: *const Argp, argc: c_int, argv: *mut *mut c_char, flags: c_uint, end_index: *mut c_int, input: *mut c_void) -> c_int {
    let mut child = [NO_CHILD, NO_CHILD, NO_CHILD, NO_CHILD];
    let use_top = flags & ARGP_NO_HELP == 0;
    if use_top {
        let mut ci = 0;
        if !argp.is_null() {
            child[ci].argp = argp;
            ci += 1;
        }
        child[ci].argp = &ARGP_DEFAULT_ARGP.0;
        ci += 1;
        if !program_version().is_null() || program_version_hook().is_some() {
            child[ci].argp = &ARGP_VERSION_ARGP.0;
        }
    }
    let top_argp = Argp { options: null(), parser: None, args_doc: null(), doc: null(), children: child.as_ptr(), help_filter: None, argp_domain: null() };
    let view = if use_top {
        Some(unsafe { ArgpView::new(&top_argp) })
    } else if argp.is_null() {
        None
    } else {
        Some(unsafe { ArgpView::new(argp) })
    };
    let mut parser = Parser::new();
    let mut err = parser.init(view, argc, argv, flags, input);
    if err == 0 {
        let mut arg_ebadkey = false;
        while err == 0 {
            err = parser.parse_next(&mut arg_ebadkey);
        }
        err = parser.finalize(err, arg_ebadkey, end_index);
    }
    err
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _argp_input(argp: *const Argp, state: *const ArgpState) -> *mut c_void {
    argp_input(argp, unsafe { StateView::new(state) })
}

fn argp_input(argp: *const Argp, state: Option<StateView>) -> *mut c_void {
    if let Some(s) = state {
        let mut g = s.pstate().cast::<Group>().cast_const();
        loop {
            let gr = unsafe { g.read() };
            if gr.argp.is_null() {
                break;
            }
            if gr.argp == argp {
                return gr.input;
            }
            g = g.wrapping_add(1);
        }
    }
    null_mut()
}
