//! Translation of the C library's own messages, as glibc's `_()` does it: `__dcgettext("libc", msgid,
//! LC_MESSAGES)` with the catalogs `/usr/share/locale/<lang>/LC_MESSAGES/libc.mo`.
//!
//! The crates below rusty-libc-locale cannot call `dcgettext` (dependency direction), and a static program
//! that never calls `setlocale` must not link the catalog loader. So the translation is a hook:
//! rusty-libc-locale installs it the first time `setlocale` or `newlocale` selects an LC_MESSAGES locale
//! other than C, C.<charset> or POSIX. Until then every message is its English text (what glibc's
//! `dcgettext` returns in the C locale, whatever `LANGUAGE` says), at the cost of one relaxed load and a
//! branch. Once installed, the hook does what glibc does, including in threads that use the C locale
//! (`dcgettext` returns the message itself there).
//!
//! Messages with conversions ("%s: invalid option -- '%c'\n") are translated as a whole; a translated
//! format is then run through the printf engine of rusty-libc-stdio (the second hook, installed with
//! the first), so translations that reorder arguments (`%2$s`) work as in glibc. The English text keeps
//! each caller's own formatting code, unchanged.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use core::ffi::{CStr, c_char};
use core::sync::atomic::{AtomicUsize, Ordering};

/// `dcgettext(domain, msgid, LC_MESSAGES)` in the locale `loc` (0: the calling thread's locale, as glibc's
/// `_()`; otherwise a `locale_t`, as `strerror_l` uses). `domain` NULL means the program's current text
/// domain (`dgettext(NULL, ...)`, which argp uses when the argp has no domain).
pub type TranslateFn = unsafe fn(domain: *const c_char, msgid: *const c_char, loc: usize) -> *const c_char;
/// Format the printf format `fmt` with `args` (each argument as a 64-bit word: integers, characters and
/// pointers) and hand the text to `out`.
pub type FormatFn = unsafe fn(fmt: *const c_char, args: &[u64], out: &mut dyn FnMut(&[u8]));

static TRANSLATE: AtomicUsize = AtomicUsize::new(0);
static FORMAT: AtomicUsize = AtomicUsize::new(0);

/// glibc's `_libc_intl_domainname`.
pub const LIBC_DOMAIN: &CStr = c"libc";

/// Install the translation hooks (rusty-libc-locale, when a non-C LC_MESSAGES locale is selected).
pub fn install(translate: TranslateFn, format: FormatFn) {
    FORMAT.store(format as usize, Ordering::Release);
    TRANSLATE.store(translate as usize, Ordering::Release);
}

/// True once message translation can happen.
#[inline(always)]
pub fn active() -> bool {
    TRANSLATE.load(Ordering::Relaxed) != 0
}

#[inline(always)]
fn hook() -> Option<TranslateFn> {
    let f = TRANSLATE.load(Ordering::Acquire);
    // SAFETY: stored from a `TranslateFn`.
    if f == 0 { None } else { Some(unsafe { core::mem::transmute::<usize, TranslateFn>(f) }) }
}

/// The translation hook is only reached once a locale was selected: keep that path out of line.
#[cold]
#[inline(never)]
fn call(f: TranslateFn, domain: *const c_char, msgid: *const c_char, loc: usize) -> *const c_char {
    // SAFETY: `msgid` is a C string (callers), `domain` NULL or a C string.
    unsafe { f(domain, msgid, loc) }
}

/// glibc's `_(msgid)`: the message in the calling thread's LC_MESSAGES locale.
#[inline]
pub fn tr(msgid: &'static CStr) -> &'static CStr {
    match hook() {
        None => msgid,
        // SAFETY: a translation is a NUL-terminated string that lives as long as the catalog (forever).
        Some(f) => unsafe { CStr::from_ptr(call(f, LIBC_DOMAIN.as_ptr(), msgid.as_ptr(), 0)) },
    }
}

/// `_(msgid)` for a message that is not a literal (the loader's error text in `dlerror`, regex's table):
/// the translation, or `msgid` itself.
///
/// # Safety
/// `msgid` is a NUL-terminated string.
#[inline]
pub unsafe fn tr_ptr(msgid: *const c_char) -> *const c_char {
    match hook() {
        None => msgid,
        Some(f) => call(f, LIBC_DOMAIN.as_ptr(), msgid, 0),
    }
}

/// `_(msgid)` in the LC_MESSAGES category of the locale object `loc` (`strerror_l`: glibc switches to `loc`
/// with `uselocale` around the lookup). `loc` 0 is the calling thread's locale.
///
/// # Safety
/// `loc` is 0, LC_GLOBAL_LOCALE or a locale object (the translation hook reads it as `locale::of_locale` does).
#[inline]
pub unsafe fn tr_l(msgid: &'static CStr, loc: usize) -> &'static CStr {
    match hook() {
        None => msgid,
        // SAFETY: as in `tr`.
        Some(f) => unsafe { CStr::from_ptr(call(f, LIBC_DOMAIN.as_ptr(), msgid.as_ptr(), loc)) },
    }
}

/// `dgettext(domain, msgid)` (argp's user texts, translated in the argp's own domain; NULL: the program's
/// current text domain).
///
/// # Safety
/// `msgid` is NULL or a NUL-terminated string; `domain` NULL or a NUL-terminated string.
#[inline]
pub unsafe fn dtr(domain: *const c_char, msgid: *const c_char) -> *const c_char {
    if msgid.is_null() {
        return msgid;
    }
    match hook() {
        None => msgid,
        Some(f) => call(f, domain, msgid, 0),
    }
}

/// Translate the printf format `msgid`; if the locale has a translation, format it with `args` into `out`
/// and return true. False means "no translation": the caller prints the English text its own way.
#[inline]
pub fn tr_format(msgid: &'static CStr, args: &[u64], out: &mut dyn FnMut(&[u8])) -> bool {
    let Some(f) = hook() else { return false };
    let t = call(f, LIBC_DOMAIN.as_ptr(), msgid.as_ptr(), 0);
    if core::ptr::eq(t, msgid.as_ptr()) {
        return false;
    }
    // SAFETY: `t` is a translated format; the hooks were installed together.
    unsafe { format(t, args, out) };
    true
}

/// Format an already translated printf format (see [`FormatFn`]). Only valid once [`active`] is true.
///
/// # Safety
/// `fmt` is a NUL-terminated format whose conversions match `args`.
#[cold]
pub unsafe fn format(fmt: *const c_char, args: &[u64], out: &mut dyn FnMut(&[u8])) {
    let f = FORMAT.load(Ordering::Acquire);
    if f == 0 {
        return;
    }
    // SAFETY: the word was stored by `install` from a `FormatFn` (same size as usize, never 0 here).
    let f = unsafe { core::mem::transmute::<usize, FormatFn>(f) };
    // SAFETY: `fmt` is a NUL-terminated format matching `args` (caller's contract), what the hook needs.
    unsafe { f(fmt, args, out) }
}

/// Split a translated `__libc_message` format into pieces: glibc's fatal-message writer knows only `%s`
/// (each takes the next string of `args`); everything else is literal text. Calls `piece` for each part.
pub fn libc_message_pieces<'a>(fmt: &'a [u8], args: &[&'a [u8]], piece: &mut dyn FnMut(&'a [u8])) {
    let mut i = 0;
    let mut start = 0;
    let mut next_arg = 0;
    while i < fmt.len() {
        if fmt[i] == b'%' && fmt.get(i + 1) == Some(&b's') {
            if i > start {
                piece(&fmt[start..i]);
            }
            // glibc reads past the given arguments with va_arg; a translation never has more %s than the original
            if let Some(a) = args.get(next_arg) {
                piece(a);
            }
            next_arg += 1;
            i += 2;
            start = i;
        } else {
            i += 1;
        }
    }
    if start < fmt.len() {
        piece(&fmt[start..]);
    }
}
