//! regex.h as C sees it: regcomp/regexec/regerror/regfree and the GNU re_* interface. The structs
//! have glibc's layout (regex_t is 64 bytes; the flag bits live in the byte at offset 56, from the
//! low bit: can_be_null, regs_allocated (2 bits), fastmap_accurate, no_sub, not_bol, not_eol,
//! newline_anchor).
//!
//! Thin unsafe shell, safe core (BRIEF-UNSAFE.md U2). Each exported function turns its raw arguments into Rust values
//! once: strings and buffers into slices (core's `ffi`), the caller's `regex_t` into a [`view::Pattern`] and its
//! `re_registers` into a [`view::Registers`]. Those two types (module `view`, the only code that reads the structs'
//! pointer fields) carry the regex.h contract as their invariant: `buffer` NULL or a pattern this library compiled,
//! `fastmap` and `translate` NULL or 256 bytes, the register arrays as long as `num_regs` says. Everything after the
//! conversion (the GNU search stub, the register copy-out, regerror's copy, the BSD and regexp.h interfaces) is safe code.
//! The C data objects (`re_syntax_options`, `re_max_failures`, `loc1`, `loc2`, `locs`) are atomics, which have the
//! plain C type's size and layout, so a program's direct reads and writes (and copy relocations) see the same objects;
//! the BSD interface's one global buffer is a `SyncCell` (glibc's re_comp/re_exec are not thread-safe either).
use crate::api::{self, Compiled};
use crate::consts::*;
use crate::exec::Reg;
use crate::vec::V;
use core::ffi::{CStr, c_char, c_int, c_ulong, c_void};
use core::ptr::{null, null_mut};
use core::sync::atomic::{AtomicI32, AtomicPtr, AtomicU64, Ordering};
use rusty_libc_core::ffi;
use rusty_libc_core::sync_cell::SyncCell;
use view::{Pattern, Registers};

pub type RegoffT = i32;
pub type RegMatch = Reg;

#[repr(C)]
pub struct RePatternBuffer {
    pub buffer: *mut c_void,
    pub allocated: usize,
    pub used: usize,
    pub syntax: c_ulong,
    pub fastmap: *mut c_char,
    pub translate: *mut u8,
    pub re_nsub: usize,
    /// can_be_null:1, regs_allocated:2, fastmap_accurate:1, no_sub:1, not_bol:1, not_eol:1, newline_anchor:1
    pub bits: u32,
    pub _pad: u32,
}
pub type RegexT = RePatternBuffer;

#[repr(C)]
pub struct ReRegisters {
    pub num_regs: u32,
    pub start: *mut RegoffT,
    pub end: *mut RegoffT,
}

const B_CAN_BE_NULL: u32 = 1;
const B_REGS_SHIFT: u32 = 1;
const B_FASTMAP_ACCURATE: u32 = 1 << 3;
const B_NO_SUB: u32 = 1 << 4;
const B_NOT_BOL: u32 = 1 << 5;
const B_NOT_EOL: u32 = 1 << 6;
const B_NEWLINE_ANCHOR: u32 = 1 << 7;

impl RePatternBuffer {
    /// All fields 0 / NULL (the state of a zeroed `struct re_pattern_buffer`).
    pub const ZERO: RePatternBuffer =
        RePatternBuffer { buffer: null_mut(), allocated: 0, used: 0, syntax: 0, fastmap: null_mut(), translate: null_mut(), re_nsub: 0, bits: 0, _pad: 0 };

    fn flag(&self, b: u32) -> bool {
        self.bits & b != 0
    }
    fn set_flag(&mut self, b: u32, on: bool) {
        if on {
            self.bits |= b;
        } else {
            self.bits &= !b;
        }
    }
    fn regs_allocated(&self) -> u32 {
        (self.bits >> B_REGS_SHIFT) & 3
    }
    fn set_regs_allocated(&mut self, v: u32) {
        self.bits = (self.bits & !(3 << B_REGS_SHIFT)) | ((v & 3) << B_REGS_SHIFT);
    }
}

/// `re_syntax_options`: the syntax bits re_compile_pattern and re_comp use (`reg_syntax_t`, an unsigned long). An atomic
/// with the layout of the C object: programs assign it directly.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static re_syntax_options: AtomicU64 = AtomicU64::new(0);

/// Obsolete in glibc, still exported.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static re_max_failures: AtomicI32 = AtomicI32::new(2000);

const _: () = assert!(size_of::<AtomicU64>() == size_of::<c_ulong>() && size_of::<AtomicPtr<c_char>>() == size_of::<*mut c_char>());

/// The caller's structs seen through the regex.h contract. The pointer fields are private to this module: safe code
/// outside it can read the plain fields (through `Deref`) and change the flag bits, but it cannot point `buffer`,
/// `fastmap`, `translate` or the register arrays anywhere else, so the invariants hold for every safe method (Rust for
/// Rustaceans p.233: soundness is checked at the privacy boundary).
mod view {
    use super::*;
    use core::ops::Deref;

    /// A `regex_t` (`struct re_pattern_buffer`) whose fields keep the regex.h contract:
    /// - `buffer` is NULL or points to `size_of::<Compiled>()` readable bytes (a struct that was zeroed or compiled before:
    ///   glibc follows the pointer too), whose `magic` field holds `MAGIC` exactly when they are the live `Compiled` an
    ///   earlier compile stored there (in a block of its own from malloc, `allocated` bytes long);
    /// - `fastmap` is NULL or points to 256 writable bytes; `translate` is NULL or points to 256 readable bytes;
    /// - for as long as the view lives nothing else writes the struct, the fastmap or the table (and for a `&mut Pattern`
    ///   nothing else reads them either).
    #[repr(transparent)]
    pub struct Pattern(RePatternBuffer);

    impl Deref for Pattern {
        type Target = RePatternBuffer;
        #[inline(always)]
        fn deref(&self) -> &RePatternBuffer {
            &self.0
        }
    }

    impl Pattern {
        /// A pattern with nothing compiled and no fastmap or table.
        pub const ZERO: Pattern = Pattern(RePatternBuffer::ZERO);

        /// The pattern at `p` (an argument of regexec and friends).
        ///
        /// # Safety
        /// `p` points to a `regex_t` that keeps the invariant of [`Pattern`] for `'a` (what regcomp or re_compile_pattern
        /// left there, or a struct the caller set up as `re_compile_pattern` documents), and nothing writes it meanwhile.
        #[inline(always)]
        pub unsafe fn from_ptr<'a>(p: *const RegexT) -> &'a Pattern {
            // SAFETY: the caller's contract; `Pattern` is a transparent wrapper of the struct.
            unsafe { &*p.cast::<Pattern>() }
        }

        /// As [`Pattern::from_ptr`], for exclusive use.
        ///
        /// # Safety
        /// As [`Pattern::from_ptr`], and nothing else reads or writes the struct for `'a`.
        #[inline(always)]
        pub unsafe fn from_mut_ptr<'a>(p: *mut RegexT) -> &'a mut Pattern {
            // SAFETY: the caller's contract; `Pattern` is a transparent wrapper of the struct.
            unsafe { &mut *p.cast::<Pattern>() }
        }

        /// regcomp's start on a struct whose old contents mean nothing: no pattern, no table, a fresh fastmap. `None`
        /// (with only `buffer`, `allocated`, `used` and `fastmap` written, as glibc does) when there is no memory.
        pub fn init(raw: &mut RePatternBuffer) -> Option<&mut Pattern> {
            raw.buffer = null_mut();
            raw.allocated = 0;
            raw.used = 0;
            // SAFETY: a plain allocation of 256 bytes; the struct takes ownership of it.
            raw.fastmap = unsafe { rusty_libc_malloc::malloc(256) } as *mut c_char;
            if raw.fastmap.is_null() {
                return None;
            }
            raw.translate = null_mut();
            // (NULL buffer and table, a 256-byte fastmap: the invariant holds)
            let p: *mut RegexT = raw;
            // SAFETY: `p` comes from the exclusive borrow `raw`, whose fields now keep the invariant.
            Some(unsafe { &mut *p.cast::<Pattern>() })
        }

        pub fn set_flag(&mut self, b: u32, on: bool) {
            self.0.set_flag(b, on);
        }

        /// The compiled pattern, if the struct holds one.
        pub fn compiled(&self) -> Option<&Compiled> {
            let b = self.0.buffer as *const Compiled;
            if b.is_null() || self.0.used == 0 {
                return None;
            }
            // SAFETY: `buffer` is not NULL, so a `Compiled`'s worth of bytes is readable there (the invariant).
            if unsafe { (*b).magic } != api::MAGIC {
                return None;
            }
            // SAFETY: the magic says it is the `Compiled` a compile stored; it lives until `free_compiled`, which needs
            // `&mut self`, so not while this borrow of `self` lasts.
            Some(unsafe { &*b })
        }

        /// The caller's translation table.
        pub fn translate(&self) -> Option<&[u8; 256]> {
            // SAFETY: NULL or 256 readable bytes, not written while `self` is borrowed (the invariant).
            unsafe { self.0.translate.cast::<[u8; 256]>().as_ref() }
        }

        /// The fastmap.
        pub fn fastmap(&self) -> Option<&[u8; 256]> {
            // SAFETY: NULL or 256 bytes, not written while `self` is borrowed (the invariant).
            unsafe { self.0.fastmap.cast::<[u8; 256]>().as_ref() }
        }

        /// glibc's re_compile_internal: compile `pat` into this struct (dropping what it held), REG_NOERROR or the error.
        pub fn compile(&mut self, pat: &[u8], syntax: u64) -> i32 {
            self.0.set_flag(B_FASTMAP_ACCURATE | B_NOT_BOL | B_NOT_EOL | B_CAN_BE_NULL, false);
            self.0.syntax = syntax as c_ulong;
            self.0.used = 0;
            self.0.re_nsub = 0;
            self.0.set_regs_allocated(REGS_UNALLOCATED);
            self.free_compiled();
            match api::compile(pat, syntax, self.translate()) {
                Ok(c) => {
                    let sz = core::mem::size_of::<Compiled>();
                    // SAFETY: a plain allocation; the struct takes ownership of it below.
                    let mem = unsafe { rusty_libc_malloc::malloc(sz) } as *mut Compiled;
                    if mem.is_null() {
                        return REG_ESPACE;
                    }
                    self.0.re_nsub = c.nfa.nsub as usize;
                    // SAFETY: `mem` is a fresh block of `size_of::<Compiled>()` bytes, aligned (malloc aligns to 16).
                    unsafe { mem.write(c) };
                    self.0.buffer = mem.cast();
                    self.0.allocated = sz;
                    self.0.used = sz;
                    REG_NOERROR
                }
                Err(e) => {
                    self.0.buffer = null_mut();
                    self.0.allocated = 0;
                    e
                }
            }
        }

        /// Drop and free the compiled pattern (if `buffer` holds one of ours) and clear `buffer`.
        pub fn free_compiled(&mut self) {
            let b = self.0.buffer as *mut Compiled;
            if !b.is_null()
                && self.0.allocated == core::mem::size_of::<Compiled>()
                // SAFETY: not NULL, so a `Compiled`'s worth of bytes is readable there (the invariant).
                && unsafe { (*b).magic } == api::MAGIC
            {
                // SAFETY: the `Compiled` a compile stored; nothing borrows it (we hold `&mut self`); dropped once,
                // since `buffer` is cleared below.
                unsafe { core::ptr::drop_in_place(b) };
                // SAFETY: its own block from malloc (see `compile`), freed once.
                unsafe { rusty_libc_malloc::free(b.cast()) };
            }
            self.0.buffer = null_mut();
            self.0.allocated = 0;
        }

        /// glibc's re_compile_fastmap: fill the fastmap from the compiled pattern (0, as glibc returns).
        pub fn compile_fastmap(&mut self) -> c_int {
            let Some(c) = self.compiled() else { return 0 };
            if self.0.fastmap.is_null() {
                return 0;
            }
            let mut fm = [0u8; 256];
            let mut cbn = false;
            c.nfa.fastmap(self.0.syntax & RE_ICASE != 0, &mut fm, &mut cbn);
            // SAFETY: not NULL, so 256 writable bytes that only this struct's owner uses (the invariant; `&mut self`).
            if let Some(dst) = unsafe { self.0.fastmap.cast::<[u8; 256]>().as_mut() } {
                *dst = fm;
            }
            if cbn {
                self.0.set_flag(B_CAN_BE_NULL, true);
            }
            self.0.set_flag(B_FASTMAP_ACCURATE, true);
            0
        }

        /// Give the struct a fresh fastmap (re_comp's buffer). False when there is no memory.
        pub fn alloc_fastmap(&mut self) -> bool {
            // SAFETY: a plain allocation of 256 bytes, owned by the struct from here on (the old pointer is NULL).
            self.0.fastmap = unsafe { rusty_libc_malloc::malloc(256) } as *mut c_char;
            !self.0.fastmap.is_null()
        }

        /// Free the fastmap (if any) and clear the pointer.
        ///
        /// # Safety
        /// `fastmap` is NULL or a block from this library's malloc that nothing else frees (what regcomp allocated, or
        /// one a program handed to regfree: glibc frees it too).
        pub unsafe fn free_fastmap(&mut self) {
            if !self.0.fastmap.is_null() {
                // SAFETY: a malloc block (the caller's contract), freed once: the pointer is cleared below.
                unsafe { rusty_libc_malloc::free(self.0.fastmap.cast()) };
            }
            self.0.fastmap = null_mut();
        }

        /// Free the translation table (if any) and clear the pointer.
        ///
        /// # Safety
        /// `translate` is NULL or a block from this library's malloc that nothing else frees (glibc's regfree frees it).
        pub unsafe fn free_translate(&mut self) {
            if !self.0.translate.is_null() {
                // SAFETY: a malloc block (the caller's contract), freed once: the pointer is cleared below.
                unsafe { rusty_libc_malloc::free(self.0.translate.cast()) };
            }
            self.0.translate = null_mut();
        }

        /// re_comp before a new pattern: glibc's regfree with the fastmap kept, then every other field zeroed. (The
        /// translation table is cleared, not freed: re_comp's buffer never has one, so glibc's free of it never runs.)
        pub fn clear_keep_fastmap(&mut self) {
            let fastmap = self.0.fastmap;
            self.free_compiled();
            self.0 = RePatternBuffer::ZERO;
            self.0.fastmap = fastmap;
        }

        /// glibc's re_copy_regs: store the match `pmatch` into `regs` (allocating or growing its arrays as
        /// `regs_allocated` says), unused registers -1; record and return the new `regs_allocated` state
        /// (REGS_UNALLOCATED when memory ran out).
        pub fn copy_regs(&mut self, regs: &mut Registers, pmatch: &[Reg]) -> u32 {
            let ra = regs.fill(pmatch, self.0.regs_allocated());
            self.0.set_regs_allocated(ra);
            ra
        }

        /// re_set_registers: the caller's own arrays (REGS_REALLOCATE: they may be reallocated), or none.
        ///
        /// # Safety
        /// With `num_regs` > 0: `starts` and `ends` are distinct blocks from malloc of `num_regs` elements each that
        /// stay valid while `regs` is used with this pattern.
        pub unsafe fn set_registers(&mut self, regs: &mut Registers, num_regs: u32, starts: *mut RegoffT, ends: *mut RegoffT) {
            if num_regs != 0 {
                self.0.set_regs_allocated(REGS_REALLOCATE);
                regs.0.num_regs = num_regs;
                regs.0.start = starts;
                regs.0.end = ends;
            } else {
                self.0.set_regs_allocated(REGS_UNALLOCATED);
                regs.0.num_regs = 0;
                regs.0.start = null_mut();
                regs.0.end = null_mut();
            }
        }
    }

    /// A `struct re_registers` whose arrays keep the contract the `regs_allocated` state of the pattern it is used with
    /// describes: REGS_UNALLOCATED, nothing (the arrays are allocated on the first copy); REGS_REALLOCATE, `start` and
    /// `end` are distinct malloc blocks of `num_regs` elements; REGS_FIXED, distinct arrays of `num_regs` writable
    /// elements. Nothing else uses the struct or the arrays while the view lives.
    #[repr(transparent)]
    pub struct Registers(ReRegisters);

    impl Deref for Registers {
        type Target = ReRegisters;
        #[inline(always)]
        fn deref(&self) -> &ReRegisters {
            &self.0
        }
    }

    impl Registers {
        /// The registers at `p`, or `None` for NULL.
        ///
        /// # Safety
        /// If not NULL, `p` points to a `struct re_registers` that keeps the invariant of [`Registers`] for the pattern
        /// it is used with, and nothing else uses it for `'a`.
        #[inline(always)]
        pub unsafe fn from_mut_ptr<'a>(p: *mut ReRegisters) -> Option<&'a mut Registers> {
            // SAFETY: the caller's contract; `Registers` is a transparent wrapper of the struct.
            unsafe { p.cast::<Registers>().as_mut() }
        }

        /// As [`Registers::from_mut_ptr`] for a pointer that is not NULL.
        ///
        /// # Safety
        /// As [`Registers::from_mut_ptr`], and `p` is not NULL.
        #[inline(always)]
        pub unsafe fn from_mut_ptr_nonnull<'a>(p: *mut ReRegisters) -> &'a mut Registers {
            // SAFETY: the caller's contract; `Registers` is a transparent wrapper of the struct.
            unsafe { &mut *p.cast::<Registers>() }
        }

        fn fill(&mut self, pmatch: &[Reg], regs_allocated: u32) -> u32 {
            let r = &mut self.0;
            let nregs = pmatch.len();
            let need = nregs + 1;
            let mut rval = REGS_REALLOCATE;
            if regs_allocated == REGS_UNALLOCATED {
                // SAFETY: a plain allocation, owned by the registers from here on.
                r.start = unsafe { rusty_libc_malloc::malloc(need * 4) } as *mut RegoffT;
                if r.start.is_null() {
                    return REGS_UNALLOCATED;
                }
                // SAFETY: as above.
                r.end = unsafe { rusty_libc_malloc::malloc(need * 4) } as *mut RegoffT;
                if r.end.is_null() {
                    // SAFETY: the block allocated just above, freed once (the state goes back to REGS_UNALLOCATED).
                    unsafe { rusty_libc_malloc::free(r.start.cast()) };
                    return REGS_UNALLOCATED;
                }
                r.num_regs = need as u32;
            } else if regs_allocated == REGS_REALLOCATE {
                if need > r.num_regs as usize {
                    // SAFETY: REGS_REALLOCATE: `start` is a malloc block (the invariant).
                    let ns = unsafe { rusty_libc_malloc::realloc(r.start.cast(), need * 4) } as *mut RegoffT;
                    if ns.is_null() {
                        return REGS_UNALLOCATED;
                    }
                    // SAFETY: REGS_REALLOCATE: `end` is a malloc block distinct from `start` (the invariant).
                    let ne = unsafe { rusty_libc_malloc::realloc(r.end.cast(), need * 4) } as *mut RegoffT;
                    if ne.is_null() {
                        // SAFETY: the block realloc just returned, freed once (as glibc does; the state goes back to
                        // REGS_UNALLOCATED, so the old pointers are not used again).
                        unsafe { rusty_libc_malloc::free(ns.cast()) };
                        return REGS_UNALLOCATED;
                    }
                    r.start = ns;
                    r.end = ne;
                    r.num_regs = need as u32;
                }
            } else {
                rval = REGS_FIXED;
            }
            let n = r.num_regs as usize;
            // SAFETY: `start` holds `num_regs` writable elements (allocated above, or the REGS_REALLOCATE/REGS_FIXED
            // invariant) that nothing else uses meanwhile.
            let starts = unsafe { ffi::slice_mut(r.start, n) };
            // SAFETY: as for `start`; the two arrays are distinct (the invariant), so the slices do not overlap.
            let ends = unsafe { ffi::slice_mut(r.end, n) };
            // (nregs <= num_regs in every state: grown above, or the search used at most num_regs registers)
            for (i, (s, e)) in starts.iter_mut().zip(ends.iter_mut()).enumerate() {
                (*s, *e) = match pmatch.get(i) {
                    Some(m) => (m.so, m.eo),
                    None => (-1, -1),
                };
            }
            rval
        }
    }
}

/// The fastmap glibc's re_search_internal would use: one that exists, is accurate, belongs to a
/// pattern that cannot match the empty string, when start and last_start differ.
fn fastmap_in_use(p: &Pattern, start: isize, last_start: isize) -> Option<&[u8; 256]> {
    if p.flag(B_FASTMAP_ACCURATE) && start != last_start && !p.flag(B_CAN_BE_NULL) { p.fastmap() } else { None }
}

fn xlat_for<'a>(p: &'a Pattern, c: &'a Compiled, buf: &'a mut [u8; 256]) -> &'a [u8; 256] {
    match p.translate() {
        None => &c.xlat,
        Some(t) => {
            *buf = api::make_xlat(p.syntax & RE_ICASE != 0, Some(t));
            buf
        }
    }
}

/// regcomp after the struct has been set up: the syntax from `cflags`, the compile, the fastmap.
fn regcomp_in(p: &mut Pattern, pat: &[u8], cflags: c_int) -> c_int {
    let mut syntax = if cflags & REG_EXTENDED != 0 { RE_SYNTAX_POSIX_EXTENDED } else { RE_SYNTAX_POSIX_BASIC };
    if cflags & REG_ICASE != 0 {
        syntax |= RE_ICASE;
    }
    if cflags & REG_NEWLINE != 0 {
        syntax &= !RE_DOT_NEWLINE;
        syntax |= RE_HAT_LISTS_NOT_NEWLINE;
        p.set_flag(B_NEWLINE_ANCHOR, true);
    } else {
        p.set_flag(B_NEWLINE_ANCHOR, false);
    }
    p.set_flag(B_NO_SUB, cflags & REG_NOSUB != 0);
    let mut ret = p.compile(pat, syntax);
    if ret == REG_ERPAREN {
        ret = REG_EPAREN;
    }
    if ret == REG_NOERROR {
        p.compile_fastmap();
    } else {
        // SAFETY: the fastmap is the block `Pattern::init` allocated for this regcomp.
        unsafe { p.free_fastmap() };
    }
    ret
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regcomp(preg: *mut RegexT, pattern: *const c_char, cflags: c_int) -> c_int {
    // SAFETY: `preg` points to writable `regex_t` storage that this call owns (regcomp's contract); its old contents are
    // not read (`init` writes the fields it relies on first).
    let raw = unsafe { &mut *preg };
    let Some(p) = Pattern::init(raw) else { return REG_ESPACE };
    // SAFETY: `pattern` is a C string (regcomp's contract), unchanged during the call.
    let pat = unsafe { ffi::cstr_bytes(pattern) };
    regcomp_in(p, pat, cflags)
}

/// regerror's copy: `msg` (without its NUL) into `buf`, cut and NUL-terminated if it does not fit; the size the whole
/// message needs, NUL included.
fn copy_message(msg: &[u8], buf: &mut [u8]) -> usize {
    let msg_size = msg.len() + 1;
    if !buf.is_empty() {
        if msg_size > buf.len() {
            let cpy = buf.len() - 1;
            buf[cpy] = 0;
            buf[..cpy].copy_from_slice(&msg[..cpy]);
        } else {
            buf[..msg.len()].copy_from_slice(msg);
            buf[msg.len()] = 0;
        }
    }
    msg_size
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regerror(errcode: c_int, _preg: *const RegexT, errbuf: *mut c_char, errbuf_size: usize) -> usize {
    if error_message(errcode).is_none() {
        rusty_libc_core::process::abort();
    }
    // glibc: gettext() of the message in the "libc" domain
    let msg = rusty_libc_core::i18n::tr(ERROR_MSGS[errcode as usize]);
    // SAFETY: `errbuf` holds `errbuf_size` writable bytes (regerror's contract; with size 0 it is not touched).
    let buf = unsafe { ffi::bytes_mut(errbuf.cast::<u8>(), errbuf_size) };
    copy_message(msg.to_bytes(), buf)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regfree(preg: *mut RegexT) {
    // SAFETY: `preg` is a pattern regcomp or re_compile_pattern filled, used by nobody else now (regfree's contract).
    let p = unsafe { Pattern::from_mut_ptr(preg) };
    p.free_compiled();
    // SAFETY: regfree's contract: the fastmap is regcomp's block or one the program allocated with malloc (glibc frees
    // it as well).
    unsafe { p.free_fastmap() };
    // SAFETY: the same for the translation table.
    unsafe { p.free_translate() };
}

/// regexec on a pattern: `text` is the string up to its end (REG_STARTEND: up to `rm_eo`), the search starts at `start`.
fn exec(p: &Pattern, text: &[u8], start: isize, pmatch: &mut [Reg], eflags: c_int) -> c_int {
    let Some(c) = p.compiled() else { return REG_NOMATCH };
    let length = text.len();
    let mut xbuf = [0u8; 256];
    let xlat = xlat_for(p, c, &mut xbuf);
    let fm = fastmap_in_use(p, start, length as isize);
    let nm = pmatch.len();
    let err = api::run(c, xlat, p.flag(B_NEWLINE_ANCHOR), text, start, length as isize, length, eflags, nm, pmatch, fm, p.translate());
    (err != REG_NOERROR) as c_int
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn regexec(preg: *const RegexT, string: *const c_char, nmatch: usize, pmatch: *mut RegMatch, eflags: c_int) -> c_int {
    if eflags & !(REG_NOTBOL | REG_NOTEOL | REG_STARTEND) != 0 {
        return REG_BADPAT;
    }
    let (start, text): (isize, &[u8]);
    if eflags & REG_STARTEND != 0 {
        // SAFETY: with REG_STARTEND `pmatch[0]` holds the range to search (regexec's contract).
        let m = unsafe { pmatch.read() };
        if m.so < 0 || m.eo < 0 {
            return REG_NOMATCH;
        }
        start = m.so as isize;
        // SAFETY: the string is readable up to `rm_eo` (regexec's contract for REG_STARTEND).
        text = unsafe { ffi::bytes(string.cast::<u8>(), m.eo as usize) };
    } else {
        start = 0;
        // SAFETY: `string` is a C string (regexec's contract).
        text = unsafe { ffi::cstr_bytes(string) };
    }
    // SAFETY: `preg` is a compiled pattern (regexec's contract); regexec only reads it, so threads may share it.
    let p = unsafe { Pattern::from_ptr(preg) };
    let pm: &mut [Reg] = if p.flag(B_NO_SUB) || nmatch == 0 {
        &mut []
    } else {
        // SAFETY: `pmatch` holds `nmatch` elements this call may write (regexec's contract).
        unsafe { ffi::slice_mut(pmatch, nmatch) }
    };
    exec(p, text, start, pm, eflags)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn re_set_syntax(syntax: c_ulong) -> c_ulong {
    let old = re_syntax_options.load(Ordering::Relaxed);
    re_syntax_options.store(syntax, Ordering::Relaxed);
    old
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_compile_pattern(pattern: *const c_char, length: usize, bufp: *mut RePatternBuffer) -> *const c_char {
    // SAFETY: `bufp` is a pattern buffer the caller set up (zeroed, or with its own fastmap/translate) or compiled before,
    // used by nobody else now (re_compile_pattern's contract).
    let p = unsafe { Pattern::from_mut_ptr(bufp) };
    // SAFETY: `pattern` holds `length` readable bytes.
    let pat = unsafe { ffi::bytes(pattern.cast::<u8>(), length) };
    let syntax = re_syntax_options.load(Ordering::Relaxed);
    p.set_flag(B_NO_SUB, syntax & RE_NO_SUB != 0);
    p.set_flag(B_NEWLINE_ANCHOR, true);
    let ret = p.compile(pat, syntax);
    if ret == REG_NOERROR { null() } else { ERROR_MSGS[ret as usize].as_ptr().cast() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_compile_fastmap(bufp: *mut RePatternBuffer) -> c_int {
    // SAFETY: a pattern buffer used by nobody else now (re_compile_fastmap's contract).
    unsafe { Pattern::from_mut_ptr(bufp) }.compile_fastmap()
}

/// glibc's re_search_stub on `text`: a search (or with `ret_len` a match) from `start` over `range` positions, the
/// match ending at most at `stop`; the match position (or length), -1 for no match, -2 for an internal error.
#[allow(clippy::too_many_arguments)]
fn search(p: &mut Pattern, text: &[u8], start: isize, range: isize, stop: isize, regs: Option<&mut Registers>, ret_len: bool) -> RegoffT {
    let length = text.len() as isize;
    let mut last_start = start.wrapping_add(range);
    if start < 0 || start > length {
        return -1;
    }
    if length < last_start || (0 <= range && last_start < start) {
        last_start = length;
    } else if last_start < 0 || (range < 0 && start <= last_start) {
        last_start = 0;
    }
    let mut eflags = 0;
    if p.flag(B_NOT_BOL) {
        eflags |= REG_NOTBOL;
    }
    if p.flag(B_NOT_EOL) {
        eflags |= REG_NOTEOL;
    }
    if start < last_start && !p.fastmap.is_null() && !p.flag(B_FASTMAP_ACCURATE) {
        p.compile_fastmap();
    }
    let mut regs = if p.flag(B_NO_SUB) { None } else { regs };
    let nregs: usize = match &regs {
        None => 1,
        Some(r) if p.regs_allocated() == REGS_FIXED && r.num_regs as usize <= p.re_nsub => r.num_regs as usize,
        Some(_) => p.re_nsub + 1,
    };
    if nregs < 1 {
        regs = None;
    }
    let nregs = if regs.is_none() { 1 } else { nregs };
    let Some(c) = p.compiled() else { return -1 };
    let mut pmatch: V<Reg> = V::from_elem(Reg { so: -1, eo: -1 }, nregs);
    if pmatch.oom {
        return -2;
    }
    let mut xbuf = [0u8; 256];
    let xlat = xlat_for(p, c, &mut xbuf);
    let stop = if stop < 0 { 0 } else { stop as usize };
    let fm = fastmap_in_use(p, start, last_start);
    let ft = p.translate();
    let result = api::run(c, xlat, p.flag(B_NEWLINE_ANCHOR), text, start, last_start, stop.min(text.len()), eflags, nregs, &mut pmatch, fm, ft);
    let mut rval: RegoffT = 0;
    if result != REG_NOERROR {
        rval = if result == REG_NOMATCH { -1 } else { -2 };
    } else if let Some(r) = regs
        && p.copy_regs(r, &pmatch) == REGS_UNALLOCATED
    {
        rval = -2;
    }
    if rval == 0 {
        rval = if ret_len { pmatch[0].eo - start as i32 } else { pmatch[0].so };
    }
    rval
}

/// The C side of re_search and re_match: the raw arguments into a pattern, the text and the registers.
///
/// # Safety
/// `bufp` is a compiled pattern buffer and `regs` NULL or registers for it (as [`Registers`] describes), both used by
/// nobody else during the call; with `length` >= 0 `string` holds `length` readable bytes.
#[allow(clippy::too_many_arguments)]
unsafe fn search_raw(bufp: *mut RePatternBuffer, string: *const c_char, length: isize, start: isize, range: isize, stop: isize, regs: *mut ReRegisters, ret_len: bool) -> RegoffT {
    if length < 0 {
        // (no start position lies in a text of negative length: glibc's range check answers -1)
        return -1;
    }
    // SAFETY: the caller's contract.
    let p = unsafe { Pattern::from_mut_ptr(bufp) };
    // SAFETY: the caller's contract.
    let regs = unsafe { Registers::from_mut_ptr(regs) };
    // SAFETY: `length` >= 0 readable bytes (the caller's contract).
    let text = unsafe { ffi::bytes(string.cast::<u8>(), length as usize) };
    search(p, text, start, range, stop, regs, ret_len)
}

/// The C side of re_search_2 and re_match_2: the two strings joined (in a copy when both are non-empty).
///
/// # Safety
/// As [`search_raw`], for `string1`/`length1` and `string2`/`length2`.
#[allow(clippy::too_many_arguments)]
unsafe fn search_2_raw(
    bufp: *mut RePatternBuffer,
    string1: *const c_char,
    length1: isize,
    string2: *const c_char,
    length2: isize,
    start: isize,
    range: isize,
    regs: *mut ReRegisters,
    stop: isize,
    ret_len: bool,
) -> RegoffT {
    if length1 < 0 || length2 < 0 || stop < 0 {
        return -2;
    }
    if length1.checked_add(length2).is_none_or(|l| l > i32::MAX as isize) {
        return -2;
    }
    // SAFETY: `length1` readable bytes (the caller's contract).
    let s1 = unsafe { ffi::bytes(string1.cast::<u8>(), length1 as usize) };
    // SAFETY: `length2` readable bytes (the caller's contract).
    let s2 = unsafe { ffi::bytes(string2.cast::<u8>(), length2 as usize) };
    // SAFETY: the caller's contract.
    let p = unsafe { Pattern::from_mut_ptr(bufp) };
    // SAFETY: the caller's contract.
    let regs = unsafe { Registers::from_mut_ptr(regs) };
    let mut joined: V<u8> = V::new();
    let text: &[u8] = if s2.is_empty() {
        s1
    } else if s1.is_empty() {
        s2
    } else {
        joined.extend_from_slice(s1);
        joined.extend_from_slice(s2);
        if joined.oom {
            return -2;
        }
        &joined
    };
    search(p, text, start, range, stop, regs, ret_len)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_match(bufp: *mut RePatternBuffer, string: *const c_char, length: RegoffT, start: RegoffT, regs: *mut ReRegisters) -> RegoffT {
    // SAFETY: re_match's contract is `search_raw`'s.
    unsafe { search_raw(bufp, string, length as isize, start as isize, 0, length as isize, regs, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_search(bufp: *mut RePatternBuffer, string: *const c_char, length: RegoffT, start: RegoffT, range: RegoffT, regs: *mut ReRegisters) -> RegoffT {
    // SAFETY: re_search's contract is `search_raw`'s.
    unsafe { search_raw(bufp, string, length as isize, start as isize, range as isize, length as isize, regs, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_match_2(
    bufp: *mut RePatternBuffer,
    string1: *const c_char,
    length1: RegoffT,
    string2: *const c_char,
    length2: RegoffT,
    start: RegoffT,
    regs: *mut ReRegisters,
    stop: RegoffT,
) -> RegoffT {
    // SAFETY: re_match_2's contract is `search_2_raw`'s.
    unsafe { search_2_raw(bufp, string1, length1 as isize, string2, length2 as isize, start as isize, 0, regs, stop as isize, true) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_search_2(
    bufp: *mut RePatternBuffer,
    string1: *const c_char,
    length1: RegoffT,
    string2: *const c_char,
    length2: RegoffT,
    start: RegoffT,
    range: RegoffT,
    regs: *mut ReRegisters,
    stop: RegoffT,
) -> RegoffT {
    // SAFETY: re_search_2's contract is `search_2_raw`'s.
    unsafe { search_2_raw(bufp, string1, length1 as isize, string2, length2 as isize, start as isize, range as isize, regs, stop as isize, false) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_set_registers(bufp: *mut RePatternBuffer, regs: *mut ReRegisters, num_regs: u32, starts: *mut RegoffT, ends: *mut RegoffT) {
    // SAFETY: a pattern buffer used by nobody else now (re_set_registers' contract).
    let p = unsafe { Pattern::from_mut_ptr(bufp) };
    // SAFETY: `regs` points to a `struct re_registers` used by nobody else now (re_set_registers' contract; glibc writes
    // through it without a NULL check, and so does this).
    let r = unsafe { Registers::from_mut_ptr_nonnull(regs) };
    // SAFETY: the arrays are malloc blocks of `num_regs` elements that the program hands over (re_set_registers'
    // contract: the library may reallocate them).
    unsafe { p.set_registers(r, num_regs, starts, ends) };
}

// ---- BSD interface: one global pattern buffer ----

/// re_comp's pattern. glibc's re_comp/re_exec keep one buffer without a lock: the interface is not thread-safe, so a
/// program calls them from one thread at a time.
static RE_COMP_BUF: SyncCell<Pattern> = SyncCell::new(Pattern::ZERO);

/// re_comp on the global buffer: `None` asks whether a pattern is there.
fn re_comp_in(b: &mut Pattern, s: Option<&CStr>) -> *mut c_char {
    let Some(s) = s else {
        if b.buffer.is_null() {
            return c"No previous regular expression".as_ptr() as *mut c_char;
        }
        return null_mut();
    };
    if !b.buffer.is_null() {
        b.clear_keep_fastmap();
    }
    if b.fastmap.is_null() && !b.alloc_fastmap() {
        return ERROR_MSGS[REG_ESPACE as usize].as_ptr() as *mut c_char;
    }
    b.set_flag(B_NEWLINE_ANCHOR, true);
    let ret = b.compile(s.to_bytes(), re_syntax_options.load(Ordering::Relaxed));
    if ret == REG_NOERROR { null_mut() } else { ERROR_MSGS[ret as usize].as_ptr() as *mut c_char }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_comp(s: *const c_char) -> *mut c_char {
    // SAFETY: `s` is NULL or a C string (re_comp's contract).
    let s = unsafe { ffi::cstr(s) };
    // SAFETY: the BSD interface is not thread-safe (see RE_COMP_BUF): no other re_comp/re_exec runs meanwhile, and
    // `re_comp_in` does not reach the cell again.
    unsafe { RE_COMP_BUF.with_unsync(|b| re_comp_in(b, s)) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn re_exec(s: *const c_char) -> c_int {
    // SAFETY: RE_COMP_BUF is a pattern only re_comp writes, and no re_comp runs meanwhile (see RE_COMP_BUF); `s` is a
    // C string (re_exec's contract).
    (unsafe { regexec(RE_COMP_BUF.as_ptr().cast::<RegexT>(), s, 0, null_mut(), 0) } == 0) as c_int
}

// ---- the obsolete <regexp.h> interface (glibc keeps `step`, `advance`, `loc1`, `loc2`, `locs` as compat symbols) ----

/// The first character `step` matched. (An atomic with the layout of `char *`: programs read it directly.)
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static loc1: AtomicPtr<c_char> = AtomicPtr::new(null_mut());
/// The first character after the match.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static loc2: AtomicPtr<c_char> = AtomicPtr::new(null_mut());
/// Declared by the old header; unused (glibc defines it and never touches it).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub static locs: AtomicPtr<c_char> = AtomicPtr::new(null_mut());

// the old version names as aliases of the same variables (glibc 2.43 has them only as compat symbols loc1@GLIBC_2.2.5 ...)
#[cfg(all(feature = "export", not(feature = "shared")))]
core::arch::global_asm!(
    ".globl __rl_data_loc1",
    ".set __rl_data_loc1, loc1",
    ".symver __rl_data_loc1, loc1@GLIBC_2.2.5",
    ".globl __rl_data_loc2",
    ".set __rl_data_loc2, loc2",
    ".symver __rl_data_loc2, loc2@GLIBC_2.2.5",
    ".globl __rl_data_locs",
    ".set __rl_data_locs, locs",
    ".symver __rl_data_locs, locs@GLIBC_2.2.5",
);

/// The compiled expression inside an old-style `expbuf`: glibc skips the first pointer-sized bytes and rounds
/// down to pointer alignment.
fn expbuf_regex(expbuf: *const c_char) -> *const RegexT {
    let a = core::mem::align_of::<*const RegexT>();
    let p = expbuf as usize + a;
    (p - p % a) as *const RegexT
}

/// Find the next match of the compiled expression `expbuf` in `string`; `loc1` and `loc2` mark it. Returns 0 if
/// there is none. (The match is made with REG_NOTEOL, as in glibc.)
///
/// # Safety
/// `string` is a C string, `expbuf` a buffer holding a compiled `regex_t` as the old `compile` made it.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn step(string: *const c_char, expbuf: *const c_char) -> c_int {
    let mut m = RegMatch { so: 0, eo: 0 };
    // SAFETY: `string` is a C string and `expbuf` holds a compiled `regex_t` at `expbuf_regex(expbuf)` (step's contract);
    // `m` is one writable register.
    if unsafe { regexec(expbuf_regex(expbuf), string, 1, &mut m, REG_NOTEOL) } == REG_NOMATCH {
        return 0;
    }
    loc1.store(string.wrapping_offset(m.so as isize).cast_mut(), Ordering::Relaxed);
    loc2.store(string.wrapping_offset(m.eo as isize).cast_mut(), Ordering::Relaxed);
    1
}

/// Match the beginning of `string` with the compiled expression: only a match that starts at the first character counts;
/// `loc2` is set to the first unmatched character.
///
/// # Safety
/// As `step`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn advance(string: *const c_char, expbuf: *const c_char) -> c_int {
    let mut m = RegMatch { so: 0, eo: 0 };
    // SAFETY: as in `step` (advance's contract is step's).
    if unsafe { regexec(expbuf_regex(expbuf), string, 1, &mut m, REG_NOTEOL) } == REG_NOMATCH || m.so != 0 {
        return 0;
    }
    loc2.store(string.wrapping_offset(m.eo as isize).cast_mut(), Ordering::Relaxed);
    1
}
