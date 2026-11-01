//! argp.h: hierarchical command line parsing layered over getopt: `argp_parse`, the help and usage output
//! (`argp_help`, `argp_state_help`, `argp_usage`), the error reporting (`argp_error`, `argp_failure`), and the
//! variables `argp_program_version`, `argp_program_version_hook`, `argp_program_bug_address` and
//! `argp_err_exit_status`.
//!
//! The parser and the help formatter (the columns, the wrapping, the option groups and aliases, `--help`,
//! `--usage`, `--version`, `-?`, the `ARGP_HELP_FMT` environment variable) behave as glibc's, message texts and
//! quirks included; the structure of the code follows glibc 2.43 argp/argp-parse.c, argp-help.c and
//! argp-fmtstream.c (read as reference and written in Rust). Texts are translated where glibc's are: the argp's own
//! texts and the user's option and argument documentation through `dgettext(argp_domain, ...)` (a NULL domain is the
//! program's current text domain), see rusty_libc_core::i18n; nothing is translated until a locale is selected.
//!
//! Unsafe (BRIEF-UNSAFE.md U2): the caller's argp tree is checked once, at the C entry points, into the views of the
//! `view` module (`ArgpView`, `Opt`, `StateView`), whose constructors are the only unsafe step; the help formatter and
//! the parser then work on those views, on malloc'd buffers owned by the small types of the `heap` module, and on indices.
//! What stays unsafe: the user's callbacks (parsers, help filters, the version hook), the FILE calls, the program's
//! `argv` array, the parser's group table (the user's code reaches it through `state->pstate` while a callback runs, so
//! it is read and written by copies, never borrowed across a callback), getopt, and the C varargs of `argp_error` and
//! `argp_failure`.
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

/// `struct argp_option` (48 bytes).
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

/// `struct argp` (56 bytes).
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

/// `struct argp_child` (32 bytes).
#[repr(C)]
pub struct ArgpChild {
    pub argp: *const Argp,
    pub flags: c_int,
    pub header: *const c_char,
    pub group: c_int,
}

/// `struct argp_state` (96 bytes).
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

// SAFETY: an option is plain data (pointers to strings the program never changes while argp uses them); the library keeps
// immutable option tables in statics, which needs Sync, and nothing writes an option through a shared reference.
unsafe impl Sync for ArgpOption {}

pub const OPTION_ARG_OPTIONAL: c_int = 0x1;
pub const OPTION_HIDDEN: c_int = 0x2;
pub const OPTION_ALIAS: c_int = 0x4;
pub const OPTION_DOC: c_int = 0x8;
pub const OPTION_NO_USAGE: c_int = 0x10;

pub const ARGP_ERR_UNKNOWN: c_int = 7; // E2BIG
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

// ------------------------------------------------------------------------------------------ the variables

/// `argp_program_version`: if set, `--version` prints it. Programs set it before parsing (glibc has no lock on it either);
/// the library only reads it.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static argp_program_version: SyncCell<*const c_char> = SyncCell::new(null());
/// `argp_program_version_hook`: if set, `--version` calls it instead. Same rule as `argp_program_version`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static argp_program_version_hook: SyncCell<Option<unsafe extern "C" fn(*mut File, *mut ArgpState)>> = SyncCell::new(None);
/// `argp_program_bug_address`: printed by the standard help after "Report bugs to". Same rule.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static argp_program_bug_address: SyncCell<*const c_char> = SyncCell::new(null());
/// `argp_err_exit_status`: the exit status after a parsing error (EX_USAGE, 64). Same rule.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static argp_err_exit_status: SyncCell<c_int> = SyncCell::new(64);

fn program_version() -> *const c_char {
    // SAFETY: the program writes the variable before it parses (the C contract of argp, as in glibc); the library never
    // writes it, so this read races with nothing.
    unsafe { argp_program_version.read() }
}

fn program_version_hook() -> Option<unsafe extern "C" fn(*mut File, *mut ArgpState)> {
    // SAFETY: as in `program_version`.
    unsafe { argp_program_version_hook.read() }
}

fn program_bug_address() -> Option<&'static CStr> {
    // SAFETY: as in `program_version`.
    let p = unsafe { argp_program_bug_address.read() };
    // SAFETY: a program that sets the variable points it at a C string that lives as long as the program.
    unsafe { rusty_libc_core::ffi::cstr(p) }
}

fn err_exit_status() -> c_int {
    // SAFETY: as in `program_version`.
    unsafe { argp_err_exit_status.read() }
}

// the program name variables of rusty-libc-util
#[cfg(feature = "export")]
unsafe extern "C" {
    static mut program_invocation_name: *mut c_char;
    static mut program_invocation_short_name: *mut c_char;
}
#[cfg(not(feature = "export"))]
use rusty_libc_util::err::{program_invocation_name, program_invocation_short_name};

/// `program_invocation_short_name`, or "" when it is not set.
fn short_program_name() -> &'static CStr {
    // SAFETY: the variable is written by the start-up code before main and by `--program-name` (glibc's argp writes it
    // the same way, unsynchronised); this is a plain pointer-sized read.
    let p = unsafe { program_invocation_short_name };
    // SAFETY: the variable is NULL or points at the program's argv[0] (or a `--program-name` argument), which lives for
    // the whole program.
    unsafe { rusty_libc_core::ffi::cstr(p) }.unwrap_or(c"")
}

/// `--program-name`: set both program name variables (as glibc's argp does).
fn set_program_names(full: *mut c_char, short: *mut c_char) {
    // SAFETY: a plain pointer store to the variable, as glibc's argp makes it (see `short_program_name`).
    unsafe { program_invocation_name = full };
    // SAFETY: as above.
    unsafe { program_invocation_short_name = short };
}

// ------------------------------------------------------------------------------------------ small helpers

fn isspace(c: u8) -> bool {
    rusty_libc_ctype::is_space(c as i32)
}

fn isalnum(c: u8) -> bool {
    rusty_libc_ctype::is_alnum(c as i32)
}

/// glibc asks the locale (an option character is a short option only when `isprint` says so in the locale in force).
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

/// `stderr` and `stdout` as they are now (a program may assign them).
fn std_err() -> *mut File {
    // SAFETY: a pointer-sized read of stdio's variable, which programs assign only from one thread (as with glibc).
    unsafe { rusty_libc_stdio::stderr.read() }
}

fn std_out() -> *mut File {
    // SAFETY: as in `std_err`.
    unsafe { rusty_libc_stdio::stdout.read() }
}

/// `__option_is_end`
fn oend(o: &ArgpOption) -> bool {
    o.key == 0 && o.name.is_null() && o.doc.is_null() && o.group == 0
}

/// `__option_is_short`
fn oshort(o: &ArgpOption) -> bool {
    if o.flags & OPTION_DOC != 0 {
        false
    } else {
        let k = o.key;
        k > 0 && k <= 255 && isprint(k)
    }
}

/// `_option_is_short`, `_option_is_end` (exported with glibc's names).
///
/// # Safety
/// `opt` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _option_is_short(opt: *const ArgpOption) -> c_int {
    // SAFETY: the caller passes a valid option (a NULL faults, as in glibc).
    oshort(unsafe { &*opt }) as c_int
}

/// # Safety
/// `opt` is valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _option_is_end(opt: *const ArgpOption) -> c_int {
    // SAFETY: as in `_option_is_short`.
    oend(unsafe { &*opt }) as c_int
}

// ------------------------------------------------------------------------------------------ owned malloc memory

/// Owners of the malloc blocks the help formatter and the parser use. The library has no global Rust allocator, and the
/// blocks are allocated with the same sizes and in the same order as before (and as glibc's argp allocates them), so
/// these are small owners over malloc rather than `Box`/`Vec`.
mod heap {
    use core::mem::MaybeUninit;
    use core::ptr::NonNull;

    /// malloc (no precondition; NULL on failure).
    pub(super) fn malloc(n: usize) -> *mut u8 {
        // SAFETY: malloc has no precondition.
        unsafe { rusty_libc_malloc::malloc(n) }.cast()
    }

    /// Give a block back.
    ///
    /// # Safety
    /// `p` is NULL or a live block from malloc/calloc/realloc that nothing uses afterwards.
    pub(super) unsafe fn free(p: *mut u8) {
        // SAFETY: the caller's contract is free's.
        unsafe { rusty_libc_malloc::free(p.cast()) }
    }

    /// Out of memory where glibc's argp does not check (it would write through NULL): stop the program.
    pub(super) fn oom() -> ! {
        rusty_libc_core::process::abort()
    }

    /// One value in its own malloc block (glibc mallocs these: the hol, its clusters, the format stream).
    pub(super) struct MBox<T>(NonNull<T>);

    impl<T> MBox<T> {
        /// An uninitialised block for a `T`, or None when malloc fails.
        pub(super) fn uninit() -> Option<MBox<MaybeUninit<T>>> {
            const { assert!(align_of::<T>() <= 16) };
            NonNull::new(malloc(size_of::<T>()).cast::<MaybeUninit<T>>()).map(MBox)
        }

        /// `v` in a new block, or None when malloc fails.
        pub(super) fn new(v: T) -> Option<MBox<T>> {
            Some(MBox::uninit()?.init(v))
        }

        /// Give up ownership: the block is now the caller's (see [`MBox::from_raw`]).
        pub(super) fn into_raw(self) -> NonNull<T> {
            let p = self.0;
            core::mem::forget(self);
            p
        }

        /// Move the value out to `f`, then free the block (after `f`, as glibc frees a struct's buffers before the
        /// struct).
        pub(super) fn consume(self, f: impl FnOnce(T)) {
            let p = self.into_raw();
            // SAFETY: the block holds an initialised `T` that we own; it is moved out once and the block is not read
            // again.
            f(unsafe { p.read() });
            // SAFETY: the block came from malloc; its value was moved out above; freed once, here.
            unsafe { free(p.as_ptr().cast()) };
        }

        /// Take back a block given away by [`MBox::into_raw`].
        ///
        /// # Safety
        /// `p` came from `into_raw` and is taken back once; no reference to the value outlives the returned box.
        pub(super) unsafe fn from_raw(p: NonNull<T>) -> MBox<T> {
            MBox(p)
        }
    }

    impl<T> MBox<MaybeUninit<T>> {
        /// Store `v` in the block.
        pub(super) fn init(self, v: T) -> MBox<T> {
            let p = self.0.cast::<T>();
            core::mem::forget(self);
            // SAFETY: the block is ours, sized and aligned for a `T` (malloc aligns to 16, checked in `uninit`), and
            // holds no value yet.
            unsafe { p.write(v) };
            MBox(p)
        }
    }

    impl<T> core::ops::Deref for MBox<T> {
        type Target = T;
        fn deref(&self) -> &T {
            // SAFETY: the block holds an initialised `T` owned by `self`.
            unsafe { self.0.as_ref() }
        }
    }

    impl<T> core::ops::DerefMut for MBox<T> {
        fn deref_mut(&mut self) -> &mut T {
            // SAFETY: as in `deref`; `&mut self` makes the borrow exclusive.
            unsafe { self.0.as_mut() }
        }
    }

    impl<T> Drop for MBox<T> {
        fn drop(&mut self) {
            // SAFETY: the value is initialised and dropped once, here.
            unsafe { core::ptr::drop_in_place(self.0.as_ptr()) };
            // SAFETY: the block came from malloc and is freed once, here.
            unsafe { free(self.0.as_ptr().cast()) };
        }
    }

    /// A fixed-capacity array in one malloc block of exactly `cap` elements, filled by `push`.
    pub(super) struct MVec<T: Copy> {
        p: NonNull<T>,
        len: usize,
        cap: usize,
    }

    impl<T: Copy> MVec<T> {
        /// Room for `cap` elements (malloc of `cap * size_of::<T>()` bytes, also for `cap == 0`), or None.
        pub(super) fn with_capacity(cap: usize) -> Option<MVec<T>> {
            const { assert!(align_of::<T>() <= 16) };
            let p = NonNull::new(malloc(cap.checked_mul(size_of::<T>())?).cast::<T>())?;
            Some(MVec { p, len: 0, cap })
        }

        /// Append `v`; past the capacity is a bug (glibc would write past its block): it stops the program.
        pub(super) fn push(&mut self, v: T) {
            if self.len == self.cap {
                oom();
            }
            // SAFETY: `len < cap`, so the slot is inside the block; it is written before it becomes part of the slice.
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

        /// Keep the block allocated forever (where glibc's argp leaks it).
        pub(super) fn leak(self) {
            core::mem::forget(self);
        }
    }

    impl<T: Copy> core::ops::Deref for MVec<T> {
        type Target = [T];
        fn deref(&self) -> &[T] {
            // SAFETY: the first `len` slots are initialised (by `push`) and owned by `self`.
            unsafe { core::slice::from_raw_parts(self.p.as_ptr(), self.len) }
        }
    }

    impl<T: Copy> core::ops::DerefMut for MVec<T> {
        fn deref_mut(&mut self) -> &mut [T] {
            // SAFETY: as in `deref`; `&mut self` makes the borrow exclusive.
            unsafe { core::slice::from_raw_parts_mut(self.p.as_ptr(), self.len) }
        }
    }

    impl<T: Copy> Drop for MVec<T> {
        fn drop(&mut self) {
            // SAFETY: the block came from malloc and is freed once, here.
            unsafe { free(self.p.as_ptr().cast()) };
        }
    }

    /// A malloc'd byte buffer whose every byte is initialised (calloc'd, copied, or zeroed when it grows).
    pub(super) struct MBuf {
        p: NonNull<u8>,
        cap: usize,
    }

    impl MBuf {
        /// `cap` zero bytes (calloc), or None.
        pub(super) fn zeroed(cap: usize) -> Option<MBuf> {
            // SAFETY: calloc has no precondition.
            let p = unsafe { rusty_libc_malloc::calloc(1, cap) }.cast::<u8>();
            NonNull::new(p).map(|p| MBuf { p, cap })
        }

        /// A malloc'd copy of `src`, or None.
        pub(super) fn copy_of(src: &[u8]) -> Option<MBuf> {
            let p = NonNull::new(malloc(src.len()))?;
            // SAFETY: a fresh block of `src.len()` bytes, distinct from `src`.
            unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), p.as_ptr(), src.len()) };
            Some(MBuf { p, cap: src.len() })
        }

        /// Take ownership of a block.
        ///
        /// # Safety
        /// `p` is a live malloc block of `cap` initialised bytes that nothing else uses or frees.
        pub(super) unsafe fn from_raw(p: NonNull<u8>, cap: usize) -> MBuf {
            MBuf { p, cap }
        }

        /// Give up ownership without freeing.
        pub(super) fn into_raw(self) -> NonNull<u8> {
            let p = self.p;
            core::mem::forget(self);
            p
        }

        /// realloc(NULL, cap) (that is, malloc, as the code it replaces called it) with the bytes zeroed, or None.
        pub(super) fn fresh(cap: usize) -> Option<MBuf> {
            // SAFETY: realloc of NULL is malloc: no precondition.
            let p = unsafe { rusty_libc_malloc::realloc(core::ptr::null_mut(), cap) }.cast::<u8>();
            let p = NonNull::new(p)?;
            // SAFETY: a fresh block of `cap` bytes.
            unsafe { core::ptr::write_bytes(p.as_ptr(), 0, cap) };
            Some(MBuf { p, cap })
        }

        /// realloc to `new_cap` bytes and zero the new part (fresh memory, as glibc's realloc into the top chunk
        /// gives). false (and the buffer unchanged) when realloc fails.
        pub(super) fn grow(&mut self, new_cap: usize) -> bool {
            // SAFETY: `p` is our live malloc block; on success the old pointer is dead and replaced below.
            let np = unsafe { rusty_libc_malloc::realloc(self.p.as_ptr().cast(), new_cap) }.cast::<u8>();
            let Some(np) = NonNull::new(np) else { return false };
            if new_cap > self.cap {
                // SAFETY: bytes `cap..new_cap` of the new block are ours and not yet initialised.
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
            // SAFETY: `cap` initialised bytes owned by `self`.
            unsafe { core::slice::from_raw_parts(self.p.as_ptr(), self.cap) }
        }
    }

    impl core::ops::DerefMut for MBuf {
        fn deref_mut(&mut self) -> &mut [u8] {
            // SAFETY: as in `deref`; `&mut self` makes the borrow exclusive.
            unsafe { core::slice::from_raw_parts_mut(self.p.as_ptr(), self.cap) }
        }
    }

    impl Drop for MBuf {
        fn drop(&mut self) {
            // SAFETY: the block came from malloc/calloc/realloc and is freed once, here.
            unsafe { free(self.p.as_ptr()) };
        }
    }
}

use heap::{MBox, MBuf, MVec, oom};

// ------------------------------------------------------------------------------------------ checked views of C data

/// The C data argp works on, checked once at the entry points. Each view's constructor is unsafe and states what the
/// caller vouches for; after that the methods are safe because the fields are private to this module.
mod view {
    use super::*;

    /// A valid `struct argp` and everything reachable from it, for `'a`: `options` is NULL or an array ended by an
    /// all-zero entry whose strings are NULL or C strings, `children` is NULL or an array ended by an entry with a NULL
    /// `argp` whose argps are valid in the same way, and the strings (`args_doc`, `doc`, `argp_domain`, headers) are NULL
    /// or C strings. All of it lives and stays unchanged for `'a`.
    #[derive(Clone, Copy)]
    pub(super) struct ArgpView<'a>(&'a Argp);

    impl<'a> ArgpView<'a> {
        /// # Safety
        /// `p` is not NULL and points to an argp that is valid for `'a` as the type describes.
        pub(super) unsafe fn new(p: *const Argp) -> ArgpView<'a> {
            // SAFETY: the caller's contract.
            ArgpView(unsafe { &*p })
        }

        /// The argp's address (its identity: `_argp_input` looks a group up by it).
        pub(super) fn ptr(self) -> *const Argp {
            self.0
        }

        pub(super) fn has_options(self) -> bool {
            !self.0.options.is_null()
        }

        /// The options before the end marker (empty when `options` is NULL) with, from the same pass, the number of options that are not aliases, the number of
        /// short options, and which of the first 64 are short (bit i for option i): make_hol's counts.
        pub(super) fn options_counted(self) -> (Opts<'a>, usize, usize, u64) {
            let p = self.0.options;
            let (mut n, mut entries, mut shorts, mut mask) = (0usize, 0usize, 0usize, 0u64);
            if p.is_null() {
                return (Opts(&[]), 0, 0, 0);
            }
            loop {
                // SAFETY: the array ends with an end entry (type invariant), so every element up to and including it is
                // readable; the loop stops at the end entry.
                let o = unsafe { &*p.wrapping_add(n) };
                if oend(o) {
                    break;
                }
                entries += usize::from(o.flags & OPTION_ALIAS == 0);
                if oshort(o) {
                    shorts += 1;
                    if n < 64 {
                        mask |= 1 << n;
                    }
                }
                n += 1;
            }
            // SAFETY: `n` initialised elements before the end entry, valid for `'a`.
            (Opts(unsafe { core::slice::from_raw_parts(p, n) }), entries, shorts, mask)
        }

        /// The options before the end marker, one by one (one pass, where `options_counted().0.iter()` measures the array first).
        pub(super) fn options_iter(self) -> OptIter<'a> {
            OptIter { p: self.0.options, _a: core::marker::PhantomData }
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
            // SAFETY: NULL or a C string valid for `'a` (type invariant).
            unsafe { rusty_libc_core::ffi::cstr(self.0.args_doc) }
        }

        pub(super) fn doc(self) -> Option<&'a CStr> {
            // SAFETY: as in `args_doc`.
            unsafe { rusty_libc_core::ffi::cstr(self.0.doc) }
        }

        pub(super) fn has_children(self) -> bool {
            !self.0.children.is_null()
        }

        /// The children before the terminating entry (empty when `children` is NULL).
        pub(super) fn children(self) -> &'a [ArgpChild] {
            let p = self.0.children;
            if p.is_null() {
                return &[];
            }
            let mut n = 0;
            // SAFETY: the array ends with an entry whose `argp` is NULL (type invariant); the loop stops there.
            while !unsafe { &*p.wrapping_add(n) }.argp.is_null() {
                n += 1;
            }
            // SAFETY: `n` initialised elements before the terminator, valid for `'a`.
            unsafe { core::slice::from_raw_parts(p, n) }
        }

        /// The argp of one of [`ArgpView::children`].
        pub(super) fn child_argp(self, c: &'a ArgpChild) -> ArgpView<'a> {
            debug_assert!(!c.argp.is_null());
            // SAFETY: `c` is one of this argp's children (callers take it from `children`), whose argp is valid for `'a`
            // (type invariant).
            unsafe { ArgpView::new(c.argp) }
        }

        /// The header of one of [`ArgpView::children`].
        pub(super) fn child_header(self, c: &'a ArgpChild) -> Option<&'a CStr> {
            // SAFETY: as in `args_doc` (a child's header is one of the tree's strings).
            unsafe { rusty_libc_core::ffi::cstr(c.header) }
        }
    }

    /// The options of a valid argp up to its end entry (see [`ArgpView::options_iter`]): `p` is NULL or points into the
    /// argp's option array at or before its end entry.
    pub(super) struct OptIter<'a> {
        p: *const ArgpOption,
        _a: core::marker::PhantomData<&'a ArgpOption>,
    }

    impl<'a> Iterator for OptIter<'a> {
        type Item = Opt<'a>;
        #[inline]
        fn next(&mut self) -> Option<Opt<'a>> {
            if self.p.is_null() {
                return None;
            }
            // SAFETY: `p` points at an element of the option array at or before its end entry (the field's invariant:
            // it starts at the array and moves on only past a non-end entry), readable and unchanged for `'a`
            // (`ArgpView` invariant).
            let o = unsafe { &*self.p };
            if oend(o) {
                return None;
            }
            self.p = self.p.wrapping_add(1);
            Some(Opt(o))
        }
    }

    /// The options of a valid argp (a run of them: a hol entry's option and its aliases).
    #[derive(Clone, Copy)]
    pub(super) struct Opts<'a>(&'a [ArgpOption]);

    impl<'a> Opts<'a> {
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

    /// One option of a valid argp: its strings are NULL or C strings valid for `'a`.
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
        /// The name as a pointer (getopt's long option table holds it).
        pub(super) fn name_ptr(self) -> *const c_char {
            self.0.name
        }
        pub(super) fn name(self) -> Option<&'a CStr> {
            // SAFETY: NULL or a C string valid for `'a` (`ArgpView` invariant).
            unsafe { rusty_libc_core::ffi::cstr(self.0.name) }
        }
        /// The option has the name `n` (strcmp, without measuring the name first).
        pub(super) fn name_is(self, n: &CStr) -> bool {
            if self.0.name.is_null() {
                return false;
            }
            // (names that differ in their first byte are different: strcmp only where they agree there)
            // SAFETY: a non-NULL name is a C string valid for `'a` (`ArgpView` invariant): its first byte is readable.
            let first = unsafe { *self.0.name };
            // SAFETY: as above; `n` is a C string.
            first == n.to_bytes_with_nul()[0] as c_char && unsafe { rusty_libc_core::ffi::cstr_eq(self.0.name, n.as_ptr()) }
        }
        pub(super) fn arg(self) -> Option<&'a CStr> {
            // SAFETY: as in `name`.
            unsafe { rusty_libc_core::ffi::cstr(self.0.arg) }
        }
        pub(super) fn doc(self) -> Option<&'a CStr> {
            // SAFETY: as in `name`.
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

    /// A text domain for `dgettext`: NULL or a C string that lives as long as the argp it came from (made only from a
    /// view, or NULL).
    #[derive(Clone, Copy)]
    pub(super) struct Domain(*const c_char);

    impl Domain {
        pub(super) const NONE: Domain = Domain(null());
    }

    /// glibc's `dgettext(domain, s)`: the translation (which lives forever) or `s` itself.
    pub(super) fn dg(domain: Domain, s: &CStr) -> &CStr {
        // SAFETY: `domain` is NULL or a C string (type invariant); `s` is a C string.
        let t = unsafe { rusty_libc_core::i18n::dtr(domain.0, s.as_ptr()) };
        if t == s.as_ptr() {
            // no translation: `s` as it is, without measuring it again
            return s;
        }
        // SAFETY: dtr returns `s` or a catalog string that lives for the whole program; either is a C string valid for 's.
        unsafe { CStr::from_ptr(t) }
    }

    /// [`dg`] of a string that may be NULL.
    pub(super) fn dgo(domain: Domain, s: Option<&CStr>) -> Option<&CStr> {
        s.map(|s| dg(domain, s))
    }

    /// A parse state the library made (`argp_parse`) or that a C caller passes: `root_argp` is NULL or a valid argp
    /// (see [`ArgpView`]), `name` NULL or a C string, the streams NULL or valid FILEs, all for `'a`.
    #[derive(Clone, Copy)]
    pub(super) struct StateView<'a>(&'a ArgpState);

    impl<'a> StateView<'a> {
        /// # Safety
        /// `p` is NULL or a state valid for `'a` as the type describes; nothing writes it while the view is used except
        /// through the same pointer chain (argp's own callbacks).
        pub(super) unsafe fn new(p: *const ArgpState) -> Option<StateView<'a>> {
            // SAFETY: the caller's contract.
            unsafe { p.as_ref() }.map(StateView)
        }

        pub(super) fn flags(self) -> c_uint {
            self.0.flags
        }

        pub(super) fn root_argp(self) -> Option<ArgpView<'a>> {
            let p = self.0.root_argp;
            // SAFETY: NULL or a valid argp (type invariant).
            if p.is_null() { None } else { Some(unsafe { ArgpView::new(p) }) }
        }

        /// The program name in the state.
        pub(super) fn name(self) -> Option<&'a CStr> {
            // SAFETY: NULL or a C string valid for `'a` (type invariant).
            unsafe { rusty_libc_core::ffi::cstr(self.0.name) }
        }

        pub(super) fn err_stream(self) -> *mut File {
            self.0.err_stream
        }

        pub(super) fn pstate(self) -> *mut c_void {
            self.0.pstate
        }
    }

    /// An open FILE that stays valid while the value is used.
    #[derive(Clone, Copy)]
    pub(super) struct Stream(*mut File);

    impl Stream {
        /// # Safety
        /// `f` is NULL or an open FILE that stays open while the returned value is used.
        pub(super) unsafe fn new(f: *mut File) -> Option<Stream> {
            if f.is_null() { None } else { Some(Stream(f)) }
        }

        /// fwrite of `b` (not called for an empty `b`, as glibc's argp does not); the count written.
        pub(super) fn write(self, b: &[u8]) -> usize {
            // SAFETY: an open FILE (type invariant) and `b.len()` readable bytes.
            unsafe { rusty_libc_stdio::fwrite(b.as_ptr().cast(), 1, b.len(), self.0) }
        }

        pub(super) fn putc(self, c: u8) {
            // SAFETY: an open FILE (type invariant).
            unsafe { rusty_libc_stdio::putc(c as c_int, self.0) };
        }

        pub(super) fn lock(self) {
            // SAFETY: an open FILE (type invariant).
            unsafe { rusty_libc_stdio::flockfile(self.0) };
        }

        pub(super) fn unlock(self) {
            // SAFETY: an open FILE (type invariant), locked by this thread.
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

/// glibc's `state == NULL ? NULL : state->root_argp->argp_domain`.
fn root_domain(state: Option<StateView>) -> Domain {
    state.and_then(|s| s.root_argp()).map_or(Domain::NONE, |a| a.domain())
}

/// The result of a user help filter: NULL, the text it was given, or a malloc'd string that is freed when this is dropped.
struct Filtered<'s> {
    p: *const c_char,
    given: *const c_char,
    _text: core::marker::PhantomData<&'s CStr>,
}

impl<'s> Filtered<'s> {
    /// No filter: the text itself.
    fn same(text: Option<&'s CStr>) -> Filtered<'s> {
        let p = text.map_or(null(), |t| t.as_ptr());
        Filtered { p, given: p, _text: core::marker::PhantomData }
    }

    fn get(&self) -> Option<&CStr> {
        // SAFETY: a help filter returns NULL, the text it was given (valid for 's) or a new malloc'd C string that `self`
        // owns until it is dropped.
        unsafe { rusty_libc_core::ffi::cstr(self.p) }
    }
}

impl Drop for Filtered<'_> {
    fn drop(&mut self) {
        if self.p != self.given {
            // SAFETY: a filter result that is not its input is a malloc'd string the caller owns (the help filter
            // contract); freed once, here.
            unsafe { heap::free(self.p.cast_mut().cast()) };
        }
    }
}

/// Call the user's help filter.
fn call_filter<'s>(f: HelpFilter, key: c_int, text: *const c_char, input: *mut c_void) -> Filtered<'s> {
    // SAFETY: the argp's help filter is a C function of this type (the argp contract); `text` is NULL or a C string that
    // lives for 's, `input` is the argp's input.
    let p = unsafe { f(key, text, input) }.cast_const();
    Filtered { p, given: text, _text: core::marker::PhantomData }
}

/// Apply a user help filter to `doc`, if the argp has one.
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

// ------------------------------------------------------------------------------------------ the format stream

/// `struct argp_fmtstream`: output that is wrapped and indented as it is written. The text is `buf[..p]`; `point_offs`
/// is how much of it has been wrapped already.
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

/// The bytes a new stream's buffer starts with. glibc's wrapping reads the byte just past the text in one case (a partial line
/// that ends exactly at the right margin: `__argp_fmtstream_update` looks at `buf[r + 1 - point_col]`, which is `fs->p`), and
/// its buffer is a plain malloc(200): the chunk the previous stream freed (malloc's tcache hands the last freed chunk of that
/// size back first), holding that stream's text except the first 16 bytes (the tcache link and key), or fresh zeroed memory.
/// So whether a line exactly as wide as the margin is kept or wrapped depends on the text the previous stream left there. This
/// cache gives a new buffer the same contents: the 200 bytes of the last buffer a stream dropped (freed at the end, or left
/// behind when it grew), with the first 16 zeroed; zeros before any stream. The pointer owns its block.
static LAST_BUF: AtomicPtr<u8> = AtomicPtr::new(null_mut());

/// Keep `buf` (INIT_BUF_SIZE bytes) as the contents the next stream starts with; frees what it replaces.
fn keep_last_buf(buf: MBuf) {
    let old = LAST_BUF.swap(buf.into_raw().as_ptr(), Ordering::AcqRel);
    if let Some(old) = core::ptr::NonNull::new(old) {
        // SAFETY: a non-NULL LAST_BUF value is an INIT_BUF_SIZE-byte malloc block that the cache owned; the swap took it
        // out, so this is its only owner.
        drop(unsafe { MBuf::from_raw(old, INIT_BUF_SIZE) });
    }
}

/// The cached buffer (see LAST_BUF) with its first 16 bytes zeroed, or a fresh zeroed one; None when calloc fails.
fn take_last_buf() -> Option<MBuf> {
    let p = LAST_BUF.swap(null_mut(), Ordering::AcqRel);
    match core::ptr::NonNull::new(p) {
        Some(p) => {
            // SAFETY: as in `keep_last_buf`: the swap made us the block's only owner.
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
        // the stream itself first, then its buffer (glibc's order)
        let fs = MBox::<FmtStream>::uninit()?;
        let buf = take_last_buf()?;
        Some(fs.init(FmtStream { stream, lmargin, rmargin, wmargin, point_offs: 0, point_col: 0, buf, p: 0 }))
    }

    /// `__argp_fmtstream_free`: flush, then keep or free the buffer, then free the stream.
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

    /// The byte at `i` of the buffer, or 0 past its end (glibc reads the heap there; see LAST_BUF for the byte just past
    /// the text, which is inside the buffer whenever the text does not fill it).
    fn byte_at(&self, i: isize) -> u8 {
        if i < 0 { 0 } else { self.buf.get(i as usize).copied().unwrap_or(0) }
    }

    fn end(&self) -> usize {
        self.buf.len()
    }

    /// `memmove(buf + dst, buf + from, to - from)`, stopping the program with SIGABRT where glibc's argp would move
    /// outside its buffer (a few ARGP_HELP_FMT settings make glibc's wrapping overrun it: heap corruption and a crash).
    fn bmove(&mut self, from: usize, to: usize, dst: usize) {
        let len = self.buf.len();
        if from > to || to > len || dst > len - (to - from) {
            oom();
        }
        self.buf.copy_within(from..to, dst);
    }

    /// `buf[i] = v`, with the overrun rule of `bmove`.
    fn bset(&mut self, i: usize, v: u8) {
        match self.buf.get_mut(i) {
            Some(b) => *b = v,
            None => oom(),
        }
    }

    /// `buf[from..to]`, with the overrun rule of `bmove`.
    fn bslice(&self, from: usize, to: usize) -> &[u8] {
        self.buf.get(from..to).unwrap_or_else(|| oom())
    }

    /// Wrap the text from `point_offs` to the end of the buffer (glibc's `__argp_fmtstream_update`). Indices are signed
    /// where glibc's pointers step back past the start of the line.
    fn update(&mut self) {
        let mut b = self.point_offs;
        while b < self.p {
            if self.point_col == 0 && self.lmargin != 0 {
                // a new line: spaces to the left margin
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
                    // the buffer ends in a partial line
                    if (self.point_col as usize).wrapping_add(len) < self.rmargin {
                        self.point_col += len as isize;
                        break;
                    }
                    self.p
                }
                Some(i) => {
                    if self.point_col + (i as isize) < self.rmargin as isize {
                        // a whole line that fits
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

    /// The part of `update` for a line too long for the margin (truncate or word wrap), from `b` with its end (the newline
    /// or the end of the text) at `nl`, `len` bytes to the end of the text: Some(where to go on) or None (stop). Kept out of
    /// line: it is rare, and inlined it made every `update` call set up its values.
    #[inline(never)]
    fn wrap_long_line(&mut self, mut b: usize, mut nl: usize, mut len: usize) -> Option<usize> {
        // this line is too long
        let r = self.rmargin.wrapping_sub(1);
        if self.wmargin < 0 {
            // truncate
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
            // word wrap: scan back from the column past the margin for the start of the word
            let bi = b as isize;
            let mut q: isize = bi + (r + 1) as isize - self.point_col;
            // back to the last blank at or before `q` (bytes past the buffer read as 0, not blank): one slice search
            if q >= bi {
                let top = q.min(self.end() as isize - 1);
                let found = if top >= bi { self.buf[bi as usize..=top as usize].iter().rposition(|&c| isblank(c)) } else { None };
                q = match found {
                    Some(i) => bi + i as isize,
                    None => bi - 1,
                };
            }
            let mut nextline: isize = q + 1;
            if nextline > bi {
                // swallow the separating blanks
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
                // a single word wider than the line: an overlong line of its own
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
            // (NEXTLINE == BUF + LEN + 1 is the case where NL happens to fall at the end of the buffer)
            let end = self.end() as isize;
            let wm = self.wmargin;
            let at_end = nextline == bi + len as isize + 1;
            let need_more = if at_end { end - (nl as isize) < wm + 1 } else { nextline - (nl as isize + 1) < wm };
            if need_more && self.p as isize > nextline {
                // the margin needs more blanks than were removed
                if end - self.p as isize > wm + 1 {
                    let mv = self.p - nextline as usize;
                    let to = nl + 1 + wm as usize;
                    self.bmove(nextline as usize, nextline as usize + mv, to);
                    nextline = to as isize;
                    len = to + mv - b;
                    self.bset(nl, b'\n');
                    nl += 1;
                } else {
                    // output the first line so the space can be used
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
                // (the margin's blanks at once; past the buffer stops the program, as `bset` does)
                if wm > 0 {
                    let w = wm as usize;
                    self.buf.get_mut(nl..nl + w).unwrap_or_else(|| oom()).fill(b' ');
                    nl += w;
                }
            } else {
                for _ in 0..wm {
                    self.stream.putc(b' ');
                }
            }
            // the tail of the original buffer goes to the current position
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

    /// Room for `amount` more bytes: flush or grow. false when that fails.
    #[inline]
    fn ensure(&mut self, amount: usize) -> bool {
        self.end() - self.p >= amount || self.make_room(amount)
    }

    /// The flush-or-grow part of [`ensure`](Self::ensure), out of line (the usual call finds room).
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
            // the first buffer, outgrown, is what glibc's realloc frees (see LAST_BUF)
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

    #[inline]
    fn write(&mut self, s: &[u8]) -> usize {
        // the usual case, room in the buffer: one bounds check
        let p = self.p;
        if let Some(d) = self.buf.get_mut(p..p.wrapping_add(s.len())) {
            d.copy_from_slice(s);
            self.p = p + s.len();
            return s.len();
        }
        self.write_slow(s)
    }

    /// [`write`](Self::write) when the buffer is full: flush or grow first.
    #[inline(never)]
    fn write_slow(&mut self, s: &[u8]) -> usize {
        if self.ensure(s.len()) {
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

    #[inline]
    fn putc(&mut self, ch: u8) -> c_int {
        // the usual case, room in the buffer: one bounds check
        if let Some(b) = self.buf.get_mut(self.p) {
            *b = ch;
            self.p += 1;
            return ch as c_int;
        }
        self.putc_slow(ch)
    }

    /// [`putc`](Self::putc) when the buffer is full: flush or grow first.
    #[inline(never)]
    fn putc_slow(&mut self, ch: u8) -> c_int {
        if self.ensure(1) {
            self.buf[self.p] = ch;
            self.p += 1;
            ch as c_int
        } else {
            -1
        }
    }

    /// `n` spaces, as `n` calls of [`putc`](Self::putc): the runs that fit in the buffer are filled at once.
    fn put_spaces(&mut self, mut n: usize) {
        while n > 0 {
            let p = self.p;
            let k = n.min(self.end() - p);
            if k == 0 {
                self.putc_slow(b' ');
                n -= 1;
                continue;
            }
            self.buf[p..p + k].fill(b' ');
            self.p = p + k;
            n -= k;
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

    /// [`printf`](Self::printf) of a format made only of literal text and `%s`/`%c` conversions, given as the pieces of
    /// its output: the same buffer effects as the formatting (the room asked for first, snprintf's truncated copy and NUL
    /// when it does not fit, the retry with the full size, the NUL after the text), without parsing a format.
    fn print_parts(&mut self, parts: &[&[u8]]) -> isize {
        let total: usize = parts.iter().map(|p| p.len()).sum();
        let mut size_guess = PRINTF_SIZE_GUESS;
        loop {
            if !self.ensure(size_guess) {
                return -1;
            }
            let p = self.p;
            let avail = self.end() - p;
            if avail > 0 {
                // snprintf's output: what fits of the text before its last byte, then the NUL
                let dst = &mut self.buf[p..];
                let keep = total.min(avail - 1);
                let mut at = 0;
                for part in parts {
                    if at >= keep {
                        break;
                    }
                    let k = part.len().min(keep - at);
                    dst[at..at + k].copy_from_slice(&part[..k]);
                    at += k;
                }
                dst[keep] = 0;
            }
            if total >= avail {
                size_guess = total + 1;
                continue;
            }
            self.p += total;
            return total as isize;
        }
    }

    /// `printf` into the stream (glibc's `__argp_fmtstream_printf`, with typed arguments).
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

// ------------------------------------------------------------------------------------------ ARGP_HELP_FMT

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

/// The formatting parameters (a global, as glibc's `uparams`: set from the environment by each help call). Relaxed
/// atomics: plain loads and stores, as glibc's unsynchronised int array, without a data race.
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

/// A failure message from the argp internals, in the `argp_failure` style with a formatted text.
fn failure_text(state: Option<StateView>, msg: &CStr, args: &[Arg]) {
    let mut buf = [0u8; 600];
    let n = snprintf(&mut buf, msg, args);
    let n = (n.max(0) as usize).min(buf.len() - 1);
    buf[n] = 0;
    failure_str(state, 0, 0, Some(&buf[..n]));
}

/// The first `name.len().min(200)` bytes of `name` as a C string in `t`.
fn param_name<'t>(t: &'t mut [u8; 300], name: &[u8]) -> (usize, &'t CStr) {
    let k = name.len().min(200);
    t[..k].copy_from_slice(&name[..k]);
    (k, CStr::from_bytes_until_nul(&t[..]).unwrap_or(c""))
}

/// Read `ARGP_HELP_FMT` from the environment.
fn fill_in_uparams(state: Option<StateView>) {
    // SAFETY: getenv has no precondition beyond a C string name.
    let var = unsafe { rusty_libc_stdlib::env::getenv(c"ARGP_HELP_FMT".as_ptr()) };
    // SAFETY: getenv returns NULL or a C string of the environment, which this help call does not change.
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
                // SAFETY: `start` points into the C string `cs` (at a digit, before its NUL); strtol reads up to the end of
                // the number and stores a pointer into the same string in `ep`.
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

// ------------------------------------------------------------------------------------------ the help option list

/// A cluster of the hol (a child argp with a group or a header). Clusters are malloc'd one by one (as glibc does), linked
/// by `next`, and point at their parent; entries point at their cluster.
struct HolCluster<'a> {
    header: Option<&'a CStr>,
    index: c_int,
    group: c_int,
    parent: Option<ClPtr<'a>>,
    argp: ArgpView<'a>,
    depth: c_int,
    next: Option<ClPtr<'a>>,
}

/// A pointer to a cluster. Invariant of this module: a cluster is made only by `hol_add_cluster`, its fields other than
/// `next` never change, it is freed only when the root hol of the help call is dropped (at the end of `help_inner`,
/// after the last use of every `ClPtr`), and a `ClPtr` never leaves the help formatting.
#[derive(Clone, Copy, PartialEq, Eq)]
struct ClPtr<'a>(core::ptr::NonNull<HolCluster<'a>>);

impl<'a> ClPtr<'a> {
    fn get(self) -> &'a HolCluster<'a> {
        // SAFETY: the cluster is alive for every use of a ClPtr (type invariant) and only `next` is ever written, through
        // `set_next`, while no reference from `get` is held.
        unsafe { self.0.as_ref() }
    }

    fn set_next(self, next: Option<ClPtr<'a>>) {
        // SAFETY: as in `get`; callers hold no reference to the cluster while they link it.
        unsafe { (*self.0.as_ptr()).next = next };
    }
}

/// `struct hol_entry`: an option and its aliases (`opts`); `so` indexes the hol's short option string.
#[derive(Clone, Copy)]
struct HolEntry<'a> {
    opts: Opts<'a>,
    so: usize,
    group: c_int,
    cluster: Option<ClPtr<'a>>,
    argp: ArgpView<'a>,
}

/// `struct hol`. glibc allocates the arrays only when the argp has options, and frees them only when there are entries
/// (an argp with an empty option list leaks its two zero-entry blocks); this keeps that.
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
        // glibc's hol_free: the clusters, then the entries and short options (only when there are entries), then the hol
        let mut cl = self.clusters.take();
        while let Some(c) = cl {
            cl = c.get().next;
            // SAFETY: the cluster came from `MBox::into_raw` in `hol_add_cluster` and is in exactly one hol's list (moved
            // by `hol_append`); this is the end of the help call (ClPtr invariant), so it is taken back and freed once.
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
        // the options, both counts and the short ones in one pass (glibc counts in one pass too)
        let (opts, num_entries, num_short, short_mask) = argp.options_counted();
        let is_short = |i: usize, o: Opt| if i < 64 { short_mask & (1 << i) != 0 } else { o.short() };
        let mut entries = MVec::with_capacity(num_entries).unwrap_or_else(|| oom());
        let mut so = MVec::with_capacity(num_short + 1).unwrap_or_else(|| oom());
        let mut cur_group = 0;
        let mut it = opts.iter().enumerate().peekable();
        while let Some((start, o)) = it.next() {
            cur_group = if o.group() != 0 {
                o.group()
            } else if !o.has_name() && o.key() == 0 {
                cur_group + 1
            } else {
                cur_group
            };
            let so_start = so.len();
            // the option and the aliases that follow it
            let (mut i, mut o) = (start, o);
            loop {
                // (a plain loop: the few short options so far, where `contains` sets up memchr)
                if is_short(i, o) && !so.iter().any(|&c| c == o.key() as u8) {
                    so.push(o.key() as u8);
                }
                match it.peek() {
                    Some(&(j, a)) if a.alias() => {
                        it.next();
                        (i, o) = (j, a);
                    }
                    _ => break,
                }
            }
            entries.push(HolEntry { opts: opts.sub(start, i + 1 - start), so: so_start, group: cur_group, cluster, argp });
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

/// Call `func(opt, real)` for each visible short option of `entry` (`real` is the last non-alias option seen) until it
/// returns non-zero.
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

fn hol_set_group(hol: &mut Hol, name: &CStr, group: c_int) {
    let Some(entries) = hol.entries.as_deref_mut() else { return };
    if let Some(e) = entries.iter_mut().find(|e| e.opts.iter().any(|o| o.visible() && o.name_is(name))) {
        e.group = group;
    }
}

/// Order by group: 0, 1, 2, ..., n, -m, ..., -2, -1.
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

/// Two clusters at the same depth (glibc dereferences the parents without checking: two clusters at the same depth have
/// parents at the same depth, so both are set or both are not, and the walk stops at the common ancestor or the roots).
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

/// The ancestor of `c` at depth `depth` (glibc's walk up; a cluster deeper than `depth` has a parent).
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

/// The tail of an OPTION_DOC name used for sorting (`name` is moved past it); true if it is to be treated as a non-option.
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
    // (i is at or before the NUL: the tail is a C string, taken without scanning it again)
    *name = &name[i..];
    non_opt
}

/// What glibc's `hol_entry_cmp` looks at in an entry, worked out once per entry before the sort (the comparison is a pure
/// function of the two entries, so the sort makes the same comparisons with the same results).
#[derive(Clone, Copy)]
struct SortKey<'a> {
    /// The group of the entry's base cluster, or its own group.
    group: c_int,
    cluster: Option<ClPtr<'a>>,
    egroup: c_int,
    /// 1 for a documentation option to be treated as a non-option (`canon_doc_option`).
    doc: c_int,
    short: c_int,
    /// The character the entry sorts by (its first short option, or the first character of its long name) and its
    /// `tolower`.
    first: u8,
    lower: c_int,
    /// The long name the comparison uses: a doc option's name after `canon_doc_option`, or with no short option the first
    /// visible long name.
    long: Option<&'a CStr>,
}

const NO_KEY: SortKey<'static> = SortKey { group: 0, cluster: None, egroup: 0, doc: 0, short: 0, first: 0, lower: 0, long: None };

fn sort_key<'a>(e: &HolEntry<'a>, so: &[u8]) -> SortKey<'a> {
    let group = e.cluster.map_or(e.group, |c| hol_cluster_base(c).get().group);
    // `hol_entry_first_short` and `hol_entry_first_long_opt` in one walk over the options
    let (mut short, mut lo) = (0, None);
    let mut si = e.so;
    for opt in e.opts.iter() {
        if short == 0 && opt.short() && so[si] as c_int == opt.key() {
            if opt.visible() {
                short = opt.key();
            }
            si += 1;
        }
        if lo.is_none() && opt.has_name() && opt.visible() {
            lo = Some(opt);
        }
        if short != 0 && lo.is_some() {
            break;
        }
    }
    let is_doc = e.opts.first().is_doc();
    let mut long = if is_doc { lo.and_then(|o| o.name()) } else { None };
    let doc = if is_doc { long.as_mut().is_some_and(canon_doc_option) as c_int } else { 0 };
    if short == 0 && !is_doc {
        long = lo.and_then(|o| o.name());
    }
    let first = if short != 0 { short as u8 } else { long.map_or(0, |l| l.to_bytes_with_nul()[0]) };
    SortKey { group, cluster: e.cluster, egroup: e.group, doc, short, first, lower: tolower(first as c_int), long }
}

/// glibc's `hol_entry_cmp` on the keys of two entries.
#[inline]
fn hol_key_cmp(k1: &SortKey, k2: &SortKey) -> c_int {
    let mut cmp = group_cmp(k1.group, k2.group);
    if cmp != 0 {
        return cmp;
    }
    cmp = k1.cluster.is_some() as c_int - k2.cluster.is_some() as c_int;
    if cmp != 0 {
        return cmp;
    }
    if let (Some(c1), Some(c2)) = (k1.cluster, k2.cluster) {
        cmp = hol_cluster_cmp(c1, c2);
        if cmp != 0 {
            return cmp;
        }
    }
    cmp = group_cmp(k1.egroup, k2.egroup);
    if cmp != 0 {
        return cmp;
    }
    cmp = k1.doc - k2.doc;
    if cmp != 0 {
        return cmp;
    }
    cmp = k1.lower - k2.lower;
    if cmp != 0 {
        return cmp;
    }
    cmp = k2.first as c_int - k1.first as c_int;
    if cmp != 0 {
        return cmp;
    }
    cmp = (k1.short != 0) as c_int - (k2.short != 0) as c_int;
    if cmp != 0 {
        return cmp;
    }
    if k1.short == 0 {
        cmp = k1.long.is_some() as c_int - k2.long.is_some() as c_int;
        if cmp != 0 {
            return cmp;
        }
        if let (Some(l1), Some(l2)) = (k1.long, k2.long) {
            cmp = cstring::strcasecmp(l1, l2) as c_int;
            if cmp != 0 {
                return cmp;
            }
        }
    }
    0
}

/// The merge sort of `rusty_libc_stdlib::sort::sort_by` (glibc's msort: halves of `n / 2` and `n - n / 2`, a merge that
/// takes from the left run while `cmp(left, right) <= 0`), on at most 16 indices with a stack buffer: the same comparisons in
/// the same order, without the general sort's set-up and copy calls.
#[inline(always)]
fn msort_idx(b: &mut [u8], tmp: &mut [u8; 16], cmp: &mut impl FnMut(u8, u8) -> c_int) {
    // (runs of 0 or 1 return here, without the call)
    if b.len() > 1 {
        msort_idx_run(b, tmp, cmp);
    }
}

/// [`msort_idx`] on a run of 2 or more.
#[inline(never)]
fn msort_idx_run(b: &mut [u8], tmp: &mut [u8; 16], cmp: &mut impl FnMut(u8, u8) -> c_int) {
    let n = b.len();
    let n1 = n / 2;
    {
        let (b1, b2) = b.split_at_mut(n1);
        msort_idx(b1, tmp, cmp);
        msort_idx(b2, tmp, cmp);
    }
    let (mut i, mut j, mut k) = (0, n1, 0);
    // both runs are open here: fewer than n are written before one closes
    loop {
        if cmp(b[i], b[j]) <= 0 {
            tmp[k] = b[i];
            k += 1;
            i += 1;
            if i == n1 {
                break;
            }
        } else {
            tmp[k] = b[j];
            k += 1;
            j += 1;
            if j == n {
                break;
            }
        }
    }
    // what is left of the left run goes after the merged part; the rest of the right run is in place already
    while i < n1 {
        tmp[k] = b[i];
        k += 1;
        i += 1;
    }
    for (d, &t) in b[..k].iter_mut().zip(&tmp[..k]) {
        *d = t;
    }
}

/// Sort the entries with qsort's algorithm (the same comparator calls, so ties come out in glibc's order). Up to
/// SORT_KEYS entries are sorted by index over their precomputed keys and then put in that order; more are sorted in place,
/// working the keys out at each comparison.
fn hol_sort(hol: &mut Hol) {
    const SORT_KEYS: usize = 16;
    if hol.num_entries() > 0 {
        let Hol { entries, short_options, .. } = hol;
        let so = short_options.as_deref().unwrap_or(&[]);
        let Some(entries) = entries.as_deref_mut() else { return };
        let n = entries.len();
        if n > SORT_KEYS {
            rusty_libc_stdlib::sort::sort_by(entries, |a, b| hol_key_cmp(&sort_key(a, so), &sort_key(b, so)).cmp(&0));
            return;
        }
        let mut keys = [NO_KEY; SORT_KEYS];
        let mut idx = [0u8; SORT_KEYS];
        for (i, e) in entries.iter().enumerate() {
            keys[i] = sort_key(e, so);
            idx[i] = i as u8;
        }
        let keys = &keys[..n];
        let idx = &mut idx[..n];
        let mut tmp = [0u8; SORT_KEYS];
        msort_idx(idx, &mut tmp, &mut |a, b| hol_key_cmp(&keys[a as usize], &keys[b as usize]));
        // put the entries in that order (new[j] = old[idx[j]]), one cycle of the permutation at a time
        let mut done = 0u32;
        for i in 0..n {
            if done & (1 << i) != 0 {
                continue;
            }
            let first = entries[i];
            let mut j = i;
            loop {
                done |= 1 << j;
                let k = idx[j] as usize;
                if k == i {
                    entries[j] = first;
                    break;
                }
                entries[j] = entries[k];
                j = k;
            }
        }
    }
}

/// Append `more` to `hol`, destroying `more`. Options in `hol` shadow those of `more` with the same name.
fn hol_append<'a>(hol: &mut Hol<'a>, mut more: MBox<Hol<'a>>) {
    // the clusters of `more` go at the end of the list
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
            // glibc takes over `more`'s arrays; `hol`'s own (zero-entry) arrays leak there
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
            // the entries of `more` get new short option positions; a short option `hol` already has is dropped
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

/// A `hol` of all the levels of options in `argp`.
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

// ------------------------------------------------------------------------------------------ printing the hol

fn indent_to(stream: &mut FmtStream, col: c_uint) {
    let needed = col as c_int - stream.point() as c_int;
    if needed > 0 {
        stream.put_spaces(needed as usize);
    }
}

fn space(stream: &mut FmtStream, ensure: usize) {
    if stream.point() + ensure >= stream.rmargin {
        stream.putc(b'\n');
    } else {
        stream.putc(b' ');
    }
}

/// If the option `real` has an argument, print it with `req_fmt` or `opt_fmt`.
/// If the option `real` has an argument, print it as `req` followed by it, or (an optional one) as `opt` followed by it and
/// `]` (glibc's formats " %s" / "[%s]" and "=%s" / "[=%s]").
fn arg_print(real: Opt, req: &[u8], opt: &[u8], domain: Domain, stream: &mut FmtStream) {
    if let Some(a) = real.arg() {
        let a = dg(domain, a).to_bytes();
        if real.flags() & OPTION_ARG_OPTIONAL != 0 {
            stream.print_parts(&[opt, a, b"]"]);
        } else {
            stream.print_parts(&[req, a]);
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
    // short options first
    stream.set_wmargin(up(SHORT_OPT_COL) as isize);
    for opt in entry.opts.iter() {
        if opt.short() && opt.key() == so_all[so] as c_int {
            if opt.visible() {
                comma(up(SHORT_OPT_COL) as c_uint, &mut pest, stream);
                stream.putc(b'-');
                stream.putc(so_all[so]);
                if !have_long_opt || up(DUP_ARGS) != 0 {
                    arg_print(real, b" ", b"[", root_domain(state), stream);
                } else if real.has_arg() {
                    pest.hhstate.suppressed_dup_arg = true;
                }
            }
            so += 1;
        }
    }
    // then the long options
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
                stream.print_parts(&[b"--", name.to_bytes()]);
                arg_print(real, b"=", b"[=", root_domain(state), stream);
            }
        }
    }
    // the documentation string
    stream.set_lmargin(0);
    if pest.first {
        if !real.short() && !real.has_name() {
            // a group header
            print_header(real.doc(), entry.argp, &mut pest, stream);
        } else {
            // a shadowed option or an empty header: nothing
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
        // the argument-less short options, as one cluster (in a stack buffer when they fit, as glibc's alloca)
        let need = so_len + 2;
        let mut stack = [0u8; 128];
        let mut heap = if need > stack.len() { Some(MBuf::zeroed(need).unwrap_or_else(|| oom())) } else { None };
        let buf: &mut [u8] = match heap.as_mut() {
            Some(h) => &mut h[..],
            None => &mut stack[..need],
        };
        let mut n = 0;
        for entry in hol.entries() {
            hol_entry_short_iterate(entry, so, |opt, real| {
                if !(opt.has_arg() || real.has_arg()) && (opt.flags() | real.flags()) & OPTION_NO_USAGE == 0 {
                    buf[n] = opt.key() as u8;
                    n += 1;
                }
                0
            });
        }
        if n > 0 {
            buf[n] = 0;
            // (" [-%s]")
            stream.print_parts(&[b" [-", &buf[..n], b"]"]);
        }
        // the short options with an argument; the cookie of the callbacks is the entry's argp domain
        for entry in hol.entries() {
            let domain = entry.argp.domain();
            hol_entry_short_iterate(entry, so, |opt, real| {
                let flags = opt.flags() | real.flags();
                if let Some(arg) = opt.arg().or_else(|| real.arg())
                    && flags & OPTION_NO_USAGE == 0
                {
                    let arg = dg(domain, arg);
                    if flags & OPTION_ARG_OPTIONAL != 0 {
                        stream.print_parts(&[b" [-", &[opt.key() as u8], b"[", arg.to_bytes(), b"]]"]);
                    } else {
                        // wrap by hand so that it (probably) does not break at the embedded space
                        space(stream, 6 + arg.count_bytes());
                        stream.print_parts(&[b"[-", &[opt.key() as u8], b" ", arg.to_bytes(), b"]"]);
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
                    let name = opt.name().unwrap_or(c"").to_bytes();
                    if let Some(arg) = opt.arg().or_else(|| real.arg()) {
                        let arg = dg(domain, arg);
                        if flags & OPTION_ARG_OPTIONAL != 0 {
                            stream.print_parts(&[b" [--", name, b"[=", arg.to_bytes(), b"]]"]);
                        } else {
                            stream.print_parts(&[b" [--", name, b"=", arg.to_bytes(), b"]"]);
                        }
                    } else {
                        stream.print_parts(&[b" [--", name, b"]"]);
                    }
                }
                0
            });
        }
        drop(heap);
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

/// Print the non-option arguments documented in `argp` (each output preceded by a space); `levels[*li..]` select the
/// pattern of a multi-line args doc and is advanced when `advance`. True while there are more patterns.
fn argp_args_usage(argp: ArgpView, state: Option<StateView>, levels: &mut [u8], li: &mut usize, mut advance: bool, stream: &mut FmtStream) -> bool {
    let our_level = *li;
    let mut multiple = false;
    // whether the pattern printed ends at a newline (glibc reads `*nl` after it freed a filtered doc; this is the value
    // it had before the free)
    let mut nl_is_newline = false;
    let tdoc = dgo(argp.domain(), argp.args_doc());
    let fdoc = filter_doc(tdoc, ARGP_KEY_HELP_ARGS_DOC, Some(argp), state);
    if let Some(f) = fdoc.get() {
        let d = f.to_bytes();
        let line_end = |from: usize| d[from..].iter().position(|&c| c == b'\n').map_or(d.len(), |k| from + k);
        let mut cp = 0;
        let mut nl = line_end(cp);
        if nl < d.len() {
            // a multi-level args doc: advance to the pattern the state in LEVELS says
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

/// Print the documentation of `argp` (before the `\v` when `post` is false, after it otherwise).
fn argp_doc(argp: ArgpView, state: Option<StateView>, post: bool, pre_blank: bool, first_only: bool, stream: &mut FmtStream) -> bool {
    let mut anything = false;
    let doc = dgo(argp.domain(), argp.doc());
    // the part of the doc before or after the vertical tab
    let (inp_text, inp_text_limit): (Option<&CStr>, usize) = match doc {
        None => (None, 0),
        Some(d) => {
            let b = d.to_bytes_with_nul();
            let vt = cstring::memchr(b, 0x0b);
            if post {
                (vt.map(|v| &d[v + 1..]), 0)
            } else {
                (Some(d), vt.unwrap_or(0))
            }
        }
    };
    let mut input: *mut c_void = null_mut();
    if let Some(f) = argp.help_filter() {
        // the filter gets the pre-doc part as its own string (glibc strndup's it)
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

/// A malloc'd copy of at most `n` bytes of `s` (strndup), freed when dropped.
struct MStr(core::ptr::NonNull<c_char>);

impl MStr {
    fn as_ptr(&self) -> *const c_char {
        self.0.as_ptr()
    }
}

impl Drop for MStr {
    fn drop(&mut self) {
        // SAFETY: the string came from strndup (malloc) and is freed once, here.
        unsafe { heap::free(self.0.as_ptr().cast()) };
    }
}

fn strndup(s: &CStr, n: usize) -> Option<MStr> {
    // SAFETY: `s` is a C string; strndup reads at most `n` bytes of it and returns a new malloc'd string or NULL.
    core::ptr::NonNull::new(unsafe { rusty_libc_malloc::strndup(s.as_ptr(), n) }).map(MStr)
}

/// Output a usage or help message for `argp` (glibc's `_help`). glibc dereferences `argp` and `name` without checking
/// wherever the flags need them; a missing one stops the program here.
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
        // if present, these options always come last
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
        // (on the stack when small, as glibc's alloca)
        let mut levels_stack = [0u8; 64];
        let mut levels_heap = if num_pattern_levels > levels_stack.len() { Some(MBuf::zeroed(num_pattern_levels).unwrap_or_else(|| oom())) } else { None };
        let pattern_levels: &mut [u8] = match levels_heap.as_mut() {
            Some(h) => &mut h[..],
            None => &mut levels_stack[..num_pattern_levels.max(1)],
        };
        loop {
            let old_wm = fs.set_wmargin(up(USAGE_INDENT) as isize);
            let mut li = 0;
            let label = if first_pattern { c"Usage:" } else { c"  or: " };
            fs.print_parts(&[dg(argp.domain(), label).to_bytes(), b" ", need_name().to_bytes()]);
            // the left margin as well, because hol_usage wraps options with newlines by hand
            let old_lm = fs.set_lmargin(up(USAGE_INDENT) as usize);
            if flags & ARGP_HELP_SHORT_USAGE != 0 {
                if h.num_entries() > 0 {
                    fs.puts(dg(argp.domain(), c" [OPTION...]"));
                }
            } else {
                hol_usage(h, &mut fs);
                flags |= ARGP_HELP_SHORT_USAGE;
            }
            let more_patterns = argp_args_usage(argp, state, pattern_levels, &mut li, true, &mut fs);
            fs.set_wmargin(old_wm);
            fs.set_lmargin(old_lm);
            fs.putc(b'\n');
            anything = true;
            first_pattern = false;
            if !more_patterns {
                break;
            }
        }
        drop(levels_heap);
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

/// `argp_help (argp, stream, flags, name)`: output a usage or help message for `argp` to `stream`.
///
/// # Safety
/// The pointers are valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_help(argp: *const Argp, stream: *mut File, flags: c_uint, name: *mut c_char) {
    // SAFETY: the caller passes a valid argp tree (or NULL), which lives for the call.
    let argp = (!argp.is_null()).then(|| unsafe { ArgpView::new(argp) });
    // SAFETY: the caller passes NULL or an open FILE.
    let stream = unsafe { Stream::new(stream) };
    // SAFETY: the caller passes NULL or a C string.
    let name = unsafe { rusty_libc_core::ffi::cstr(name) };
    help_inner(argp, None, stream, flags, name)
}

/// `argp_state_help`'s body on a checked state.
fn state_help(state: Option<StateView>, stream: *mut File, flags: c_uint) {
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) && !stream.is_null() {
        let mut flags = flags;
        if state.is_some_and(|s| s.flags() & ARGP_LONG_ONLY != 0) {
            flags |= ARGP_HELP_LONG_ONLY;
        }
        // SAFETY: a FILE given by the caller or held in the parse state (the argp contract: a valid open stream).
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

/// `argp_state_help (state, stream, flags)`: output, if appropriate, a usage or help message for `state`; may exit.
///
/// # Safety
/// `state` is NULL or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_state_help(state: *const ArgpState, stream: *mut File, flags: c_uint) {
    // SAFETY: the caller passes NULL or a valid parse state (normally the one argp gave its parser).
    state_help(unsafe { StateView::new(state) }, stream, flags)
}

/// `argp_usage (state)`: possibly output the standard usage message to standard error and exit.
///
/// # Safety
/// `state` is NULL or valid.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_usage(state: *const ArgpState) {
    // SAFETY: as in `argp_state_help`.
    state_help(unsafe { StateView::new(state) }, std_err(), ARGP_HELP_STD_USAGE)
}

/// A collected message (a growing heap buffer, NUL-terminated after the text) as a sink for the printf engine.
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

/// Format `fmt` with the arguments of `ap` into a heap string (None on failure).
///
/// # Safety
/// `fmt` and `ap` are a printf format and its arguments.
unsafe fn vformat(fmt: *const c_char, ap: &mut core::ffi::VaList) -> Option<Collect> {
    let mut c = Collect::new();
    // SAFETY: the caller's contract is printf's.
    if unsafe { rusty_libc_stdio::printf_api::run(&mut c, fmt, ap) } < 0 {
        return None;
    }
    if c.buf.is_none() {
        c.put(b"");
    }
    Some(c)
}

/// The program name for messages: the state's (glibc faults on a NULL one, so does this) or the short program name.
fn name_of<'s>(state: Option<StateView<'s>>) -> &'s CStr {
    state.map_or(short_program_name(), |s| s.name().unwrap_or_else(|| oom()))
}

/// The stream errors go to: the state's, or stderr without a state.
fn err_stream_of(state: Option<StateView>) -> *mut File {
    state.map_or_else(std_err, |s| s.err_stream())
}

/// `argp_error`'s body with an already formatted message.
fn error_str(state: Option<StateView>, msg: &[u8]) {
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) {
        let raw = err_stream_of(state);
        // SAFETY: stderr or the state's error stream: NULL or an open FILE (argp contract).
        if let Some(stream) = unsafe { Stream::new(raw) } {
            stream.lock();
            out(stream, &[name_of(state).to_bytes(), b": ", msg, b"\n"]);
            state_help(state, raw, ARGP_HELP_STD_ERR);
            stream.unlock();
        }
    }
}

/// `argp_error` with typed arguments (the library's own messages).
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

/// `argp_error (state, fmt, ...)`: print the formatted message preceded by the program name, then the "Try ..."
/// text; exits with `argp_err_exit_status` unless `ARGP_NO_EXIT`.
///
/// # Safety
/// As `printf`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_error(state: *const ArgpState, fmt: *const c_char, mut args: ...) {
    // SAFETY: the caller passes NULL or a valid parse state.
    let state = unsafe { StateView::new(state) };
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) && !err_stream_of(state).is_null() {
        let ap: &mut core::ffi::VaList = &mut args;
        // SAFETY: the caller's contract is printf's.
        let c = unsafe { vformat(fmt, ap) };
        let msg = c.as_ref().and_then(|c| c.text()).unwrap_or(b"(null)");
        error_str(state, msg);
    }
}

/// The body of `argp_failure` with an already formatted message.
fn failure_str(state: Option<StateView>, status: c_int, errnum: c_int, msg: Option<&[u8]>) {
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) {
        // SAFETY: stderr or the state's error stream: NULL or an open FILE (argp contract).
        if let Some(stream) = unsafe { Stream::new(err_stream_of(state)) } {
            stream.lock();
            out(stream, &[name_of(state).to_bytes()]);
            if let Some(m) = msg {
                out(stream, &[b": ", m]);
            }
            if errnum != 0 {
                let mut tmp = [0u8; 128];
                // glibc: __strerror_r (translated; "Unknown error N")
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

/// `argp_failure (state, status, errnum, fmt, ...)`: like `error`, but respecting `ARGP_NO_EXIT` and
/// `ARGP_NO_ERRS` and writing to the state's error stream.
///
/// # Safety
/// As `printf`; `fmt` may be NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_failure(state: *const ArgpState, status: c_int, errnum: c_int, fmt: *const c_char, mut args: ...) {
    // SAFETY: the caller passes NULL or a valid parse state.
    let state = unsafe { StateView::new(state) };
    if state.is_none_or(|s| s.flags() & ARGP_NO_ERRS == 0) && !err_stream_of(state).is_null() {
        if fmt.is_null() {
            failure_str(state, status, errnum, None);
        } else {
            let ap: &mut core::ffi::VaList = &mut args;
            // SAFETY: the caller's contract is printf's.
            let c = unsafe { vformat(fmt, ap) };
            let msg = c.as_ref().and_then(|c| c.text()).unwrap_or(b"(null)");
            failure_str(state, status, errnum, Some(msg));
        }
    }
}

// ------------------------------------------------------------------------------------------ the parser

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
// SAFETY: the arrays below are immutable statics of options whose pointers point at string literals; nothing writes them.
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
// SAFETY: as for SyncArr: immutable statics whose pointers point at other immutable statics and literals.
unsafe impl Sync for SyncArgp {}

/// glibc's `_argp_hang` (a debugging aid: `--HANG` waits until it reaches 0, and a debugger may set it). Relaxed atomic.
static ARGP_HANG: AtomicI32 = AtomicI32::new(0);

/// `strtol(s, NULL, 10)`.
///
/// # Safety
/// `s` is a C string.
unsafe fn atol10(s: *const c_char) -> c_int {
    // SAFETY: the caller's contract; no end pointer is stored.
    unsafe { rusty_libc_stdlib::num::strtol(s, null_mut(), 10) as c_int }
}

/// The `state` fields the default and version parsers read: argp calls its parsers with the state of the parse in
/// progress, and they read it through the pointer they were given.
///
/// # Safety
/// `state` is the state argp passed to the parser.
unsafe fn state_fields(state: *mut ArgpState) -> (c_uint, *mut File, *mut *mut c_char) {
    // SAFETY: the caller's contract; a plain field read (as the two below).
    let flags = unsafe { (*state).flags };
    // SAFETY: as above.
    let out = unsafe { (*state).out_stream };
    // SAFETY: as above.
    let argv = unsafe { (*state).argv };
    (flags, out, argv)
}

unsafe extern "C" fn argp_default_parser(key: c_int, arg: *mut c_char, state: *mut ArgpState) -> c_int {
    // SAFETY: argp calls its parsers with the state of the parse in progress.
    let (flags, out_stream, argv) = unsafe { state_fields(state) };
    match key {
        // SAFETY: (both arms) as above; the view is dropped before the parser returns.
        63 => state_help(unsafe { StateView::new(state) }, out_stream, ARGP_HELP_STD_HELP),
        // SAFETY: as above.
        OPT_USAGE => state_help(unsafe { StateView::new(state) }, out_stream, ARGP_HELP_USAGE | ARGP_HELP_EXIT_OK),
        OPT_PROGNAME => {
            // SAFETY: getopt gives a required argument: one of the program's argv strings.
            let name = unsafe { rusty_libc_core::ffi::cstr_bytes(arg) };
            let short = match name.iter().rposition(|&c| c == b'/') {
                Some(i) => arg.wrapping_add(i + 1),
                None => arg,
            };
            set_program_names(arg, short);
            // SAFETY: the state of the parse in progress (see above); a plain field store.
            unsafe { (*state).name = short };
            if flags & (ARGP_PARSE_ARGV0 | ARGP_NO_ERRS) == ARGP_PARSE_ARGV0 {
                // SAFETY: the program's argv (argp_parse's contract) has at least one element.
                unsafe { *argv = arg };
            }
        }
        OPT_HANG => {
            // SAFETY: NULL or the option's argument, a C string from argv.
            let secs = if arg.is_null() { 3600 } else { unsafe { atol10(arg) } };
            ARGP_HANG.store(secs, Ordering::Relaxed);
            while ARGP_HANG.load(Ordering::Relaxed) > 0 {
                ARGP_HANG.store(ARGP_HANG.load(Ordering::Relaxed) - 1, Ordering::Relaxed);
                // SAFETY: sleep has no precondition.
                unsafe { rusty_libc_time::clock::sleep(1) };
            }
        }
        _ => return EBADKEY,
    }
    0
}

static ARGP_DEFAULT_ARGP: SyncArgp = SyncArgp(Argp { options: ARGP_DEFAULT_OPTIONS.0.as_ptr(), parser: Some(argp_default_parser), args_doc: null(), doc: null(), children: null(), help_filter: None, argp_domain: c"libc".as_ptr() });

unsafe extern "C" fn argp_version_parser(key: c_int, _arg: *mut c_char, state: *mut ArgpState) -> c_int {
    // SAFETY: argp calls its parsers with the state of the parse in progress.
    let (flags, out_stream, _) = unsafe { state_fields(state) };
    match key {
        86 => {
            if let Some(h) = program_version_hook() {
                // SAFETY: the program's version hook takes the output stream and the state (the argp contract).
                unsafe { h(out_stream, state) };
            } else if let Some(v) = {
                // SAFETY: the program points the variable at a C string that lives as long as it does.
                unsafe { rusty_libc_core::ffi::cstr(program_version()) }
            } {
                // SAFETY: the state's output stream is an open FILE (glibc writes to it unchecked; NULL stops here).
                let st = unsafe { Stream::new(out_stream) }.unwrap_or_else(|| oom());
                out(st, &[v.to_bytes(), b"\n"]);
            } else {
                // SAFETY: as above; the view is dropped before the parser returns.
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

/// Whether the long option `name` is among the filled entries of the table (`long_options` holds only those: each has a
/// name).
///
/// # Safety
/// `name` is a C string (an option name from the argp views).
unsafe fn has_long_option(long_options: &[COption], name: *const c_char) -> bool {
    // SAFETY: `name` is a C string (the caller's contract): its first byte (the NUL for an empty name) is readable.
    let first = unsafe { *name };
    long_options.iter().any(|l| {
        // SAFETY: every name in the filled part of the table is an option name copied from the argp views (a C string valid
        // for the parse), so its first byte is readable.
        let lfirst = unsafe { *l.name };
        // (two names that differ in their first byte are different: strcmp only where they agree there, as most do not)
        // SAFETY: as above, both are C strings.
        lfirst == first && unsafe { rusty_libc_core::ffi::cstr_eq(l.name, name) }
    })
}

/// The state of a group during parsing: one per argp of the tree that has options or a parser. (Indices are u32: the
/// struct is 64 bytes, copied and cleared once per group.)
#[derive(Clone, Copy)]
struct Group {
    parser: Option<ArgpParser>,
    /// The argp (its identity, for `_argp_input`); NULL in the slot after the last group.
    argp: *const Argp,
    input: *mut c_void,
    hook: *mut c_void,
    /// One past this group's last character in the short option string.
    short_end: u32,
    args_processed: c_uint,
    parent: Option<u32>,
    parent_index: c_uint,
    /// This group's children's inputs: an index into the child input table.
    child_inputs: Option<u32>,
    /// No parser of its own but children: ARGP_KEY_INIT hands the input on to the first child.
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
            let num_opts = argp.options_iter().count();
            szs.short_len += num_opts * 3;
            szs.long_len += num_opts;
        }
    }
    for child in argp.children() {
        calc_sizes(argp.child_argp(child), szs);
        szs.num_child_inputs += 1;
    }
}

/// An element of the program's `argv`.
///
/// # Safety
/// `argv` is the program's argument array (argp_parse's contract: `argc` strings and a NULL) and `i` indexes it.
unsafe fn argv_at(argv: *mut *mut c_char, i: usize) -> *mut c_char {
    // SAFETY: the caller's contract.
    unsafe { *argv.wrapping_add(i) }
}

/// The parser of one `argp_parse` call. It lives on argp_parse's stack and does not move once the parsers have been
/// called (they get a pointer to `state`).
///
/// The tables are one malloc block (as in glibc): the groups (one slot more than there are groups, holding NO_GROUP), the
/// child inputs, getopt's long and short option tables. The group and child input tables are reached by the user's
/// code while its parsers run (`state->pstate` leads `_argp_input` to the groups, `state->child_inputs` points into the
/// child inputs), so the parser reads and writes them by copies through raw pointers and never holds a reference into
/// them across a call; the option tables are only touched here and by getopt.
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
    /// Where `convert` left the short option string's NUL (the string never changes afterwards).
    short_len: usize,
    /// The number of entries `convert` filled in the long option table (all with a name; the NULL-name end follows).
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

    /// Slot `i` of the group table. The reference is tied to `&self`: the table is written only through `&mut self`
    /// (`grp_mut`, `init`), and the parsers, which read it through `state->pstate`, are only called from `&mut self`
    /// methods, so no reference from here is alive while the table changes or a parser runs.
    fn grp(&self, i: usize) -> &Group {
        assert!(i < self.slots);
        // SAFETY: slot `i` of the group table (initialised in `init`); see above for why nothing writes it meanwhile.
        unsafe { &*self.groups.wrapping_add(i) }
    }

    /// Slot `i` of the group table, to change (see `grp`: user code only reads the table, and never while this lives).
    fn grp_mut(&mut self, i: usize) -> &mut Group {
        assert!(i < self.slots);
        // SAFETY: as in `grp`; `&mut self` makes the borrow exclusive within the library.
        unsafe { &mut *self.groups.wrapping_add(i) }
    }

    fn child_input(&self, i: usize) -> *mut c_void {
        assert!(i < self.num_child_inputs);
        // SAFETY: entry `i` of the child input table (zeroed in `init`); parsers write it through `state->child_inputs`
        // only while they run, never while this read happens.
        unsafe { self.child_inputs.wrapping_add(i).read() }
    }

    fn set_child_input(&mut self, i: usize, v: *mut c_void) {
        assert!(i < self.num_child_inputs);
        // SAFETY: as in `child_input`.
        unsafe { self.child_inputs.wrapping_add(i).write(v) };
    }

    fn long_opts(&mut self) -> &mut [COption] {
        // SAFETY: the long option table: `long_cap` entries of the storage block, initialised in `init`, touched only
        // through this parser (getopt gets the pointer only for the duration of its call).
        unsafe { core::slice::from_raw_parts_mut(self.long_opts, self.long_cap) }
    }

    fn short_opts(&mut self) -> &mut [u8] {
        // SAFETY: the short option string: `short_cap` zeroed bytes of the storage block, touched only through this
        // parser (and read by getopt during its call).
        unsafe { core::slice::from_raw_parts_mut(self.short_opts, self.short_cap) }
    }

    /// A view of our own state, for the help and error functions.
    fn state_view(&self) -> Option<StateView<'_>> {
        // SAFETY: our own state: root_argp is the argp tree of this parse, name a C string from argv or the program
        // name, the streams stdout/stderr or what the parsers set (the argp contract).
        unsafe { StateView::new(&self.state) }
    }

    /// Fill in the tables (glibc's `parser_convert`).
    fn convert(&mut self, argp: Option<ArgpView<'a>>, flags: c_uint) {
        // (the short option string and the long option table are all zeros from `init`: every terminator glibc writes
        // after an entry is already there)
        let mut short_end = 0;
        if flags & ARGP_IN_ORDER != 0 {
            self.short_opts()[0] = b'-';
            short_end = 1;
        } else if flags & ARGP_NO_ARGS != 0 {
            self.short_opts()[0] = b'+';
            short_end = 1;
        }
        self.argp = argp;
        let mut cvt = (short_end, 0usize, 0usize);
        self.egroup = match argp {
            Some(a) => self.convert_options(a, None, 0, 0, &mut cvt),
            None => 0,
        };
        self.short_len = cvt.0;
        self.long_len = cvt.1;
    }

    /// One argp's options into the tables (glibc's `convert_options`); `cvt` is (short end, long end, child inputs end).
    fn convert_options(&mut self, argp: ArgpView<'a>, mut parent: Option<usize>, parent_index: c_uint, mut group: usize, cvt: &mut (usize, usize, usize)) -> usize {
        let children = argp.children();
        if argp.has_options() || argp.parser().is_some() {
            {
                // `real`: the last option that is not an alias (glibc starts it at the first option)
                let mut real: Option<Opt<'a>> = None;
                for opt in argp.options_iter() {
                    if !opt.alias() || real.is_none() {
                        real = Some(opt);
                    }
                    let Some(real) = real else { continue };
                    if real.is_doc() {
                        continue;
                    }
                    if opt.short() {
                        // (the bytes after the end are zeros: no terminator to write)
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
                    }
                    // SAFETY: a non-NULL option name of a view is a C string.
                    if opt.has_name() && !unsafe { has_long_option(&self.long_opts()[..cvt.1], opt.name_ptr()) } {
                        let has_arg = if real.has_arg() {
                            if real.flags() & OPTION_ARG_OPTIONAL != 0 { 2 } else { 1 }
                        } else {
                            0
                        };
                        // a disambiguating code is added to the user's value: the group number in the high bits
                        let key = if opt.key() != 0 { opt.key() } else { real.key() };
                        let val = (key & USER_MASK).wrapping_add((group as c_int + 1) << USER_BITS);
                        // (the entries after the end are zeros: the NULL-name terminator is already there)
                        self.long_opts()[cvt.1] = COption { name: opt.name_ptr(), has_arg, flag: null_mut(), val };
                        cvt.1 += 1;
                    }
                }
            }
            let child_inputs = if argp.has_children() {
                let at = cvt.2;
                cvt.2 += children.len();
                Some(at as u32)
            } else {
                None
            };
            let g = Group {
                parser: argp.parser(),
                argp: argp.ptr(),
                short_end: cvt.0 as u32,
                args_processed: 0,
                parent: parent.map(|p| p as u32),
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
        for (index, child) in children.iter().enumerate() {
            group = self.convert_options(argp.child_argp(child), parent, index as c_uint, group, cvt);
        }
        group
    }

    /// Call group `gi`'s parser (glibc's `group_parse`): the state carries the group's hook, input and child inputs while
    /// it runs.
    ///
    /// `gi` < `slots`: every caller passes a group index below `egroup` (< `slots`) from its loop, except the long option
    /// case, which checks it first.
    fn group_parse(&mut self, gi: usize, key: c_int, arg: *mut c_char) -> c_int {
        debug_assert!(gi < self.slots);
        let gp = self.groups.wrapping_add(gi);
        // SAFETY: slot `gi` < `slots` of the group table (see above; the callers' loops are bounded by `egroup`, which
        // `convert` set to the number of groups, one less than `slots`), initialised in `init`; read by copy, no reference
        // is kept across the parser call (see `grp`). (Without `grp`'s bounds check: ~1% of argp_parse's instructions.)
        let g = unsafe { gp.read() };
        let Some(p) = g.parser else { return EBADKEY };
        let (hook, input, child_inputs, arg_num) = (g.hook, g.input, g.child_inputs, g.args_processed);
        self.state.hook = hook;
        self.state.input = input;
        self.state.child_inputs = child_inputs.map_or(null_mut(), |i| self.child_inputs.wrapping_add(i as usize));
        self.state.arg_num = arg_num;
        let st: *mut ArgpState = &raw mut self.state;
        // SAFETY: an argp parser function (the argp contract) called with our state; it may write the state and the
        // child inputs through the pointers it is given, and nothing of ours is borrowed across the call.
        let err = unsafe { p(key, arg, st) };
        // SAFETY: as above: slot `gi` of the table; a plain field store, with no reference into the table alive.
        unsafe { (*gp).hook = self.state.hook };
        err
    }

    /// glibc's `parser_init`. On an error from a parser's ARGP_KEY_INIT the tables stay allocated (glibc leaks them).
    fn init(&mut self, argp: Option<ArgpView<'a>>, argc: c_int, argv: *mut *mut c_char, flags: c_uint, input: *mut c_void) -> c_int {
        let mut szs = ParserSizes { short_len: if flags & ARGP_NO_ARGS != 0 { 0 } else { 1 }, long_len: 0, num_groups: 0, num_child_inputs: 0 };
        if let Some(a) = argp {
            calc_sizes(a, &mut szs);
        }
        let slots = szs.num_groups + 1;
        let glen = slots * size_of::<Group>();
        let clen = szs.num_child_inputs * size_of::<*mut c_void>();
        let llen = (szs.long_len + 1) * size_of::<COption>();
        // (with ARGP_NO_ARGS glibc counts no room for the '+' or '-' it puts first, so a table whose options all take optional
        // arguments has its NUL written one byte past glibc's block; one byte more here keeps that NUL inside ours)
        let slen = szs.short_len + 2;
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
        // every slot gets a value (glibc fills only what it uses; the slot after the last group must be NO_GROUP here)
        for i in 0..slots {
            // SAFETY: slot `i` of the group table, inside the block (the table is `glen` bytes at its start, aligned: malloc
            // aligns to 16 and the sizes are multiples of 8).
            unsafe { self.groups.wrapping_add(i).write(NO_GROUP) };
        }
        // the child inputs (NULL), the long options (NO_LONG_OPTION: NULL pointers and zeros) and the short option string
        // (NUL bytes) follow the groups and are all zero bytes
        const { assert!(NO_LONG_OPTION.name.is_null() && NO_LONG_OPTION.has_arg == 0 && NO_LONG_OPTION.flag.is_null() && NO_LONG_OPTION.val == 0) };
        // SAFETY: the last `clen + llen + slen` bytes of the block, after the group table; all-zero bytes are a valid NULL
        // pointer, a valid NO_LONG_OPTION entry and a NUL.
        unsafe { core::ptr::write_bytes(storage.wrapping_add(glen), 0, clen + llen + slen) };
        // (`opt_data` and `state` are still as `Parser::new` made them: glibc's zeroed state)
        self.convert(argp, flags);
        self.state.root_argp = self.argp.map_or(null(), |a| a.ptr());
        self.state.argc = argc;
        self.state.argv = argv;
        self.state.flags = flags;
        self.state.err_stream = std_err();
        self.state.out_stream = std_out();
        self.state.next = 0;
        // `_argp_input` finds the groups through this; it stops at the NO_GROUP slot
        self.state.pstate = self.groups.cast();
        self.try_getopt = true;
        // call each parser for the first time, giving it a chance to propagate values to child parsers
        if self.egroup > 0 {
            self.grp_mut(0).input = input;
        }
        let mut err = 0;
        let mut gi = 0;
        while gi < self.egroup && (err == 0 || err == EBADKEY) {
            let mut g = *self.grp(gi);
            if let Some(p) = g.parent {
                let base = self.grp(p as usize).child_inputs.unwrap_or_else(|| oom());
                g.input = self.child_input(base as usize + g.parent_index as usize);
                self.grp_mut(gi).input = g.input;
            }
            if g.pass_input {
                self.set_child_input(g.child_inputs.unwrap_or_else(|| oom()) as usize, g.input);
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
                // getopt always skips ARGV[0]: fake it out (OPTERR is 0, so it will not be accessed)
                self.state.argv = self.state.argv.wrapping_sub(1);
                self.state.argc += 1;
            }
        } else {
            self.opt_data.opterr = 1;
        }
        // SAFETY: argv[0] of the program's argv (argp_parse's contract); read only when argv was not shifted above.
        let argv0 = if self.state.argv == argv { unsafe { argv_at(argv, 0) } } else { null_mut() };
        if !argv0.is_null() {
            // SAFETY: a non-NULL element of argv is a C string.
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

    /// glibc's `parser_finalize`; frees the tables.
    fn finalize(&mut self, mut err: c_int, arg_ebadkey: bool, end_index: *mut c_int) -> c_int {
        let set_end_index = |next: c_int| {
            // SAFETY: the caller of argp_parse passes NULL or a valid int.
            if let Some(e) = unsafe { rusty_libc_core::ffi::out(end_index) } {
                *e = next;
            }
        };
        if err == EBADKEY && arg_ebadkey {
            err = 0;
        }
        if err == 0 {
            if self.state.next == self.state.argc {
                // all arguments were parsed: call all the parsers again
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
                // no way to return the remaining arguments: they must be bogus
                // SAFETY: the state's error stream: NULL or an open FILE (argp contract).
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
        // call the parsers once more for final cleanup; errors are ignored
        for gi in (0..self.egroup).rev() {
            self.group_parse(gi, ARGP_KEY_FINI, null_mut());
        }
        if err == EBADKEY {
            err = EINVAL;
        }
        // SAFETY: the tables' block from `init`, freed once, here; nothing reads the tables afterwards (a parser that
        // kept `state->pstate` past argp_parse reaches freed memory, as in glibc).
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
            // a short option: its position in SHORT_OPTS says which group it came from (strchr: the NUL matches too)
            let nul = self.short_len;
            let so = self.short_opts();
            if let Some(si) = so[..=nul].iter().position(|&c| c == opt as u8) {
                for gi in 0..self.egroup {
                    if self.grp(gi).short_end as usize > si {
                        err = self.group_parse(gi, opt, optarg);
                        break;
                    }
                }
            }
        } else {
            // a long option; keep the sign of the user key
            let user_key = (if opt & (1 << (USER_BITS - 1)) != 0 { !USER_MASK } else { 0 }) | (opt & USER_MASK);
            let gi = (group_key - 1) as usize;
            if gi >= self.slots {
                // (cannot happen: the value comes from our own long option table; `grp` stopped the program here)
                oom();
            }
            err = self.group_parse(gi, user_key, optarg);
        }
        if err == EBADKEY {
            // an option not recognized is an error in the parser: which parser deals with each option is
            // computed in advance
            let bad = dg(self.argp.unwrap_or_else(|| oom()).domain(), c"(PROGRAM ERROR) Option should have been recognized!?");
            if group_key == 0 {
                error_fmt(self.state_view(), c"-%c: %s", &[Arg::Int(i64::from(opt)), Arg::Str(bad)]);
            } else {
                let lo: &[COption] = self.long_opts();
                let name = lo.iter().find(|l| l.val == opt || l.name.is_null()).map_or(null(), |l| l.name);
                // SAFETY: NULL or an option name from the table (a C string from the argp views).
                let name = unsafe { rusty_libc_core::ffi::cstr(name) }.unwrap_or(c"???");
                error_fmt(self.state_view(), c"--%s: %s", &[Arg::Str(name), Arg::Str(bad)]);
            }
        }
        err
    }

    fn parse_next(&mut self, arg_ebadkey: &mut bool) -> c_int {
        let mut opt: c_int;
        if self.state.quoted != 0 && self.state.next < self.state.quoted {
            // the next pointer moved before the quoted region: pretend the `--' was never seen
            self.state.quoted = 0;
        }
        if self.try_getopt && self.state.quoted == 0 {
            self.opt_data.optind = self.state.next;
            self.opt_data.optopt = KEY_END;
            let long_only = self.state.flags & ARGP_LONG_ONLY != 0;
            // SAFETY: argv is the program's argument array (it may be permuted, as glibc's getopt does), the option
            // tables are ours and end with a NUL / a NULL name.
            opt = unsafe { getopt_internal_r(self.state.argc, self.state.argv, self.short_opts.cast(), self.long_opts, null_mut(), long_only, &mut self.opt_data, false) };
            self.state.next = self.opt_data.optind;
            if opt == KEY_END {
                // no more options for getopt: go on by ourselves
                self.try_getopt = false;
                if self.state.next > 1 {
                    // SAFETY: `next - 1` indexes the program's argv (getopt stopped after it).
                    let prev = unsafe { argv_at(self.state.argv, (self.state.next - 1) as usize) };
                    // SAFETY: an element of argv before argc is a C string (compared without measuring it first).
                    if unsafe { rusty_libc_core::ffi::cstr_eq(prev.cast_const(), c"--".as_ptr()) } {
                        // a `quoted' region: arguments that look like options must not be given to getopt
                        self.state.quoted = self.state.next;
                    }
                }
            } else if opt == KEY_ERR && self.opt_data.optopt != KEY_END {
                // a real error (getopt set OPTOPT to the offending character)
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
                // a non-option argument: simulate what getopt might have done
                opt = KEY_ARG;
                // SAFETY: `next < argc` indexes the program's argv.
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

/// `argp_parse (argp, argc, argv, flags, arg_index, input)`: parse the command line according to `argp` (and the
/// standard `--help`, `--usage`, `--version` options unless `ARGP_NO_HELP`). 0, `EINVAL` for an unknown option or
/// argument, or what a parser function returned; may call `exit`.
///
/// # Safety
/// `argv` has `argc` strings and a NULL; `argp` is valid; the other pointers are valid or NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn argp_parse(argp: *const Argp, argc: c_int, argv: *mut *mut c_char, flags: c_uint, end_index: *mut c_int, input: *mut c_void) -> c_int {
    // the standard options are children of a top argp of our own, with the user's argp first
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
        // SAFETY: our top argp: no options, children in `child` (ended by a NULL argp: at most three of the four are
        // used), each the caller's valid argp or one of our statics; it and `child` live until the end of this call.
        Some(unsafe { ArgpView::new(&top_argp) })
    } else if argp.is_null() {
        None
    } else {
        // SAFETY: the caller passes a valid argp tree that lives for the call.
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

/// `_argp_input (argp, state)`: the input of `argp` in the parser of `state`.
///
/// # Safety
/// `state` is NULL or a state of a parse in progress.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn _argp_input(argp: *const Argp, state: *const ArgpState) -> *mut c_void {
    // SAFETY: the caller passes NULL or the state of a parse in progress.
    argp_input(argp, unsafe { StateView::new(state) })
}

/// The input of `argp` in the parse that `state` belongs to: its group table, reached through `state->pstate`, ends with a
/// slot whose argp is NULL. A state that does not come from argp_parse (or that outlived it) reaches what its `pstate`
/// points at, as in glibc.
fn argp_input(argp: *const Argp, state: Option<StateView>) -> *mut c_void {
    if let Some(s) = state {
        let mut g = s.pstate().cast::<Group>().cast_const();
        loop {
            // SAFETY: the state of a parse in progress: `pstate` is its parser's group table (see `Parser`), read by copy
            // up to its NO_GROUP slot while the parser holds no reference into it (a parser callback or help filter runs).
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
