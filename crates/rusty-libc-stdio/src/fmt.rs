//! The printf engine: parses a format string and writes the result to a [`Sink`].
//!
//! Written from the C standard, POSIX and observed glibc 2.43 behaviour (the rules for unknown
//! conversions, truncated specs, `%m`, `%b`, `(null)`/`(nil)` come from probing glibc).
use crate::float;
use rusty_libc_core::errno;

const EINVAL: i32 = 22;
const EOVERFLOW: i32 = 75;
const EILSEQ: i32 = 84;

/// A format string's character type: `u8` for the narrow functions, `u32` (`wchar_t`) for the wide ones.
/// The engine only ever looks at ASCII format characters; `at` maps anything else to 0xff.
pub trait FmtChar: Copy {
    const WIDE: bool;
    /// The character at `i` as an ASCII byte (0xff for anything else; 0 is the terminator).
    unsafe fn at(p: *const Self, i: usize) -> u8;
    /// The character at `i`, whole.
    unsafe fn raw(p: *const Self, i: usize) -> u32;
    /// Emit the literal run `p[start..start + len]`.
    unsafe fn emit_run<S: Sink>(o: &mut Out<S>, p: *const Self, start: usize, len: usize);
    /// Does the format contain a `$` (only then can it use positional arguments)?
    unsafe fn has_dollar(p: *const Self) -> bool;
    /// An ASCII character as a format character.
    fn from_ascii(b: u8) -> Self;
}

impl FmtChar for u8 {
    const WIDE: bool = false;
    #[inline(always)]
    fn from_ascii(b: u8) -> u8 {
        b
    }
    #[inline(always)]
    unsafe fn at(p: *const u8, i: usize) -> u8 {
        // SAFETY: the caller's contract: `p[i]` is inside the string (both steps: the address, then the read).
        let q = unsafe { p.add(i) };
        // SAFETY: as above.
        unsafe { *q }
    }
    #[inline(always)]
    unsafe fn raw(p: *const u8, i: usize) -> u32 {
        // SAFETY: as in `at`.
        u32::from(unsafe { Self::at(p, i) })
    }
    #[inline(always)]
    unsafe fn emit_run<S: Sink>(o: &mut Out<S>, p: *const u8, start: usize, len: usize) {
        // SAFETY: the caller's contract: `p[start..start + len]` is inside the string (the address, then the slice).
        let q = unsafe { p.add(start) };
        // SAFETY: as above.
        o.put(unsafe { core::slice::from_raw_parts(q, len) })
    }
    #[inline(always)]
    unsafe fn has_dollar(p: *const u8) -> bool {
        // Short formats are decided here, eight bytes at a time (aligned word reads never cross a
        // page, like the string functions' tail handling); a long one goes to strchr.
        const ONES: u64 = 0x0101_0101_0101_0101;
        const HIGH: u64 = 0x8080_8080_8080_8080;
        let addr = p as usize;
        let mut q = (addr & !7) as *const u64;
        // SAFETY: an aligned word that holds the string's first byte: it lies in the string's page (aligned words never
        // cross one). Its bytes outside the string are read as the string functions read a tail (volatile, so the compiler
        // assumes nothing about them) and never decide the result: those before `p` are masked, the scan stops at the NUL.
        let mut w = unsafe { core::ptr::read_volatile(q) } | ((1u64 << ((addr & 7) * 8)) - 1); // bytes before `p` cannot match
        for _ in 0..4 {
            let hit = (w.wrapping_sub(ONES) & !w & HIGH) | ((w ^ (ONES * 0x24)).wrapping_sub(ONES) & !(w ^ (ONES * 0x24)) & HIGH);
            if hit != 0 {
                // the lowest flagged byte is exact (a borrow only disturbs bytes above a real match)
                let byte = (w >> (hit.trailing_zeros() & !7)) as u8;
                return byte == b'$';
            }
            q = q.wrapping_add(1);
            // SAFETY: the previous word held no NUL, so the string goes on into this aligned word (same reasoning).
            w = unsafe { core::ptr::read_volatile(q) };
        }
        // SAFETY: `q` points into the string (no NUL so far), which is NUL-terminated.
        !unsafe { rusty_libc_mem::strchr(q as *const core::ffi::c_char, b'$' as i32) }.is_null()
    }
}

impl FmtChar for u32 {
    const WIDE: bool = true;
    #[inline(always)]
    fn from_ascii(b: u8) -> u32 {
        u32::from(b)
    }
    #[inline(always)]
    unsafe fn at(p: *const u32, i: usize) -> u8 {
        // SAFETY: the caller's contract.
        let c = unsafe { Self::raw(p, i) };
        if c < 0x80 { c as u8 } else { 0xff }
    }
    #[inline(always)]
    unsafe fn raw(p: *const u32, i: usize) -> u32 {
        // SAFETY: the caller's contract: `p[i]` is inside the string (the address, then the read).
        let q = unsafe { p.add(i) };
        // SAFETY: as above.
        unsafe { *q }
    }
    #[inline(always)]
    unsafe fn emit_run<S: Sink>(o: &mut Out<S>, p: *const u32, start: usize, len: usize) {
        // SAFETY: the caller's contract: `p[start..start + len]` is inside the string (the address, then the slice).
        let q = unsafe { p.add(start) };
        // SAFETY: as above.
        o.put_w(unsafe { core::slice::from_raw_parts(q, len) })
    }
    unsafe fn has_dollar(p: *const u32) -> bool {
        let mut i = 0;
        // SAFETY: the caller's contract: NUL-terminated; `i` only passes characters seen to be non-NUL.
        while unsafe { Self::raw(p, i) } != 0 {
            // SAFETY: as above.
            if unsafe { Self::raw(p, i) } == u32::from(b'$') {
                return true;
            }
            i += 1;
        }
        false
    }
}

/// After `encode_char` failed: the Unicode tag characters U+E0000..U+E007F, which a charset that cannot write them skips silently
/// (glibc's `UNICODE_TAG_HANDLER` in its gconv loops, reached through `wcrtomb`), give zero bytes instead of an error. Kept out of
/// line so the common conversions (`%d`, `%s`) do not carry it.
#[cold]
#[inline(never)]
fn tag_zero(wc: u32) -> Option<usize> {
    if (wc >> 7) == (0xe0000 >> 7) { Some(0) } else { None }
}

/// Where formatted output goes.
///
/// A narrow sink takes bytes. A wide sink (`WIDE`) takes wide characters: `put` is then only called
/// with ASCII text (digits, signs, `inf`, ...) which it widens, and everything that can be anything
/// else (`%ls`, `%s` converted, literal text of a wide format) comes through `put_wide`.
pub trait Sink {
    /// A sink of wide characters.
    const WIDE: bool = false;
    /// Write wide characters. A narrow sink converts them to its multibyte form (the current
    /// charset); a character that cannot be written fails with EILSEQ.
    fn put_wide(&mut self, w: &[u32]) -> bool {
        for &c in w {
            let mut b = [0u8; 6];
            let Some(n) = rusty_libc_wchar::mbyte::encode_char(c, &mut b).or_else(|| tag_zero(c)) else {
                errno::set(EILSEQ);
                return false;
            };
            if !self.put(&b[..n]) {
                return false;
            }
        }
        true
    }
    /// Does the sink offer `direct`?
    const DIRECT: bool = false;
    /// A pointer to `n` bytes that the caller then fills completely, counted as if `put` had been given them (the text
    /// is formatted in place, no copy through a buffer); null when the sink cannot offer that, then `put` is used.
    fn direct(&mut self, _n: usize) -> *mut u8 {
        core::ptr::null_mut()
    }
    /// Write bytes. Returning `false` stops formatting (an I/O error; errno is already set).
    fn put(&mut self, bytes: &[u8]) -> bool;
    /// When the formatting fails half way (a user conversion returned -1), does the text produced so far stay
    /// in the output? (glibc: in a string yes, in a stream no.)
    fn partial_output_on_error(&self) -> bool {
        true
    }
    fn put_repeat(&mut self, byte: u8, mut n: usize) -> bool {
        let chunk = [byte; 64];
        while n > 0 {
            let k = n.min(64);
            if !self.put(&chunk[..k]) {
                return false;
            }
            n -= k;
        }
        true
    }
}

/// The kind of value a conversion takes from the argument list.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Int,
    Long,
    Double,
    LongDouble,
    Ptr,
}

/// A value taken from the argument list. Long doubles are the 16 raw bytes of the x87 format.
#[derive(Clone, Copy)]
pub enum Val {
    I(u64),
    D(f64),
    LD([u8; 16]),
    /// A binary128 value (`strfromf128`).
    Q(u128),
}

/// Supplies arguments to the engine. `pos` is the 1-based position for `%n$` forms.
pub trait Args {
    fn get(&mut self, kind: Kind, pos: Option<usize>) -> Val;
    /// The C `va_list` behind the arguments, for the argument-type functions of `register_printf_type`
    /// (null when there is none).
    fn raw_va(&mut self) -> *mut core::ffi::c_void {
        core::ptr::null_mut()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Len {
    None,
    HH,
    H,
    L,
    LL,
    BigL,
    J,
    Z,
    T,
    /// a `%w` / `%wf` with a width other than 8, 16, 32 or 64 (fast: 8, 16, 32, 64 too): glibc fails the call with EINVAL
    Bad,
}

#[derive(Clone, Copy, Default)]
struct Flags {
    alt: bool,
    group: bool,
    plus: bool,
    space: bool,
    left: bool,
    zero: bool,
    i18n: bool,
}

struct Spec {
    flags: Flags,
    /// glibc's positional path keeps the pad character '0' when a negative width argument turns on left justification (it only resets
    /// it for a '-' flag): floating-point output is then padded on the right with '0' instead of ' '.
    pad0: bool,
    width: usize,
    prec: Option<usize>,
    len: Len,
    conv: u8,
    /// The conversion character as it stood in the format (wide formats: possibly not ASCII).
    conv_raw: u32,
    wide_fmt: bool,
}

/// Two hexadecimal digits per byte value: the high digit in the low byte, so a little-endian store
/// writes them in reading order.
const fn hex_pairs(upper: bool) -> [u16; 256] {
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut t = [0u16; 256];
    let mut i = 0;
    while i < 256 {
        t[i] = digs[i >> 4] as u16 | ((digs[i & 15] as u16) << 8);
        i += 1;
    }
    t
}
static HEX_LOWER: [u16; 256] = hex_pairs(false);
static HEX_UPPER: [u16; 256] = hex_pairs(true);

const PAIRS: &[u8; 200] = b"0001020304050607080910111213141516171819202122232425262728293031323334353637383940414243444546474849\
5051525354555657585960616263646566676869707172737475767778798081828384858687888990919293949596979899";

/// Number of digits of `v` in `base` (1 for 0).
#[inline]
fn ndigits(v: u64, base: u64) -> usize {
    let bits = 64 - (v | 1).leading_zeros() as usize;
    match base {
        10 => {
            // bits * log10(2), then one comparison
            const POW10: [u64; 20] = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000, 1_000_000_000, 10_000_000_000, 100_000_000_000, 1_000_000_000_000, 10_000_000_000_000, 100_000_000_000_000, 1_000_000_000_000_000, 10_000_000_000_000_000, 100_000_000_000_000_000, 1_000_000_000_000_000_000, 10_000_000_000_000_000_000];
            let t = (bits * 1233) >> 12;
            t + 1 - usize::from((v | 1) < POW10[t])
        }
        16 => bits.div_ceil(4),
        8 => bits.div_ceil(3),
        2 => bits,
        _ => {
            let mut n = 1;
            let mut x = v / base;
            while x != 0 {
                n += 1;
                x /= base;
            }
            n
        }
    }
}

/// Write exactly `nd` digits of `v` (`nd` = `ndigits(v, base)`) to `dst[..nd]`.
///
/// # Safety
/// `dst` is valid for `nd` bytes.
#[inline]
unsafe fn put_digits(mut v: u64, base: u64, upper: bool, dst: *mut u8, nd: usize) {
    // Every store below is at an index under `nd`: the loops count `i` down from `nd`, and the leading stores (`dst[0]`,
    // `dst[1]`) happen only when that many digits are left.
    macro_rules! put {
        ($i:expr, $b:expr) => {{
            let (i, b) = ($i, $b);
            debug_assert!(i < nd);
            // SAFETY: the caller's contract (`dst` valid for `nd` bytes) and `i < nd` (see above): the address, then the store.
            let q = unsafe { dst.add(i) };
            // SAFETY: as above.
            unsafe { *q = b };
        }};
    }
    let mut i = nd;
    if base == 10 {
        while v >= 100 {
            let r = (v % 100) as usize;
            v /= 100;
            i -= 2;
            put!(i, PAIRS[2 * r]);
            put!(i + 1, PAIRS[2 * r + 1]);
        }
        if v >= 10 {
            put!(0, PAIRS[2 * v as usize]);
            put!(1, PAIRS[2 * v as usize + 1]);
        } else {
            put!(0, b'0' + v as u8);
        }
        return;
    }
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    if base == 16 {
        // two digits per table lookup (the table holds the two characters in memory order)
        let tab = if upper { &HEX_UPPER } else { &HEX_LOWER };
        while i >= 2 {
            i -= 2;
            // SAFETY: `i + 1 < nd` (i counts down in steps of two from `nd`): two bytes of `dst` (the address, then the store).
            let q = unsafe { dst.add(i) };
            // SAFETY: as above.
            unsafe { (q as *mut u16).write_unaligned(tab[(v & 0xff) as usize]) };
            v >>= 8;
        }
        if i == 1 {
            put!(0, digs[(v & 15) as usize]);
        }
    } else if base == 8 {
        while i > 0 {
            i -= 1;
            put!(i, b'0' + (v & 7) as u8);
            v >>= 3;
        }
    } else if base == 2 {
        while i > 0 {
            i -= 1;
            put!(i, b'0' + (v & 1) as u8);
            v >>= 1;
        }
    } else {
        while i > 0 {
            i -= 1;
            put!(i, digs[(v % base) as usize]);
            v /= base;
        }
    }
}

fn digits_u64(mut v: u64, base: u64, upper: bool, buf: &mut [u8; 70]) -> usize {
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut i = 70;
    if base == 16 {
        // all digits at once, two per table lookup; the leading zeros are skipped by the start index
        let tab = if upper { &HEX_UPPER } else { &HEX_LOWER };
        let nd = if v == 0 { 1 } else { (64 - v.leading_zeros() as usize).div_ceil(4) };
        let b = v.to_be_bytes();
        if v >> 32 == 0 {
            let w = [tab[b[4] as usize], tab[b[5] as usize], tab[b[6] as usize], tab[b[7] as usize]];
            // SAFETY: 8 bytes at offset 62 of 70.
            unsafe { (buf.as_mut_ptr().wrapping_add(62) as *mut [u16; 4]).write_unaligned(w) };
        } else {
            let w = [tab[b[0] as usize], tab[b[1] as usize], tab[b[2] as usize], tab[b[3] as usize], tab[b[4] as usize], tab[b[5] as usize], tab[b[6] as usize], tab[b[7] as usize]];
            // SAFETY: 16 bytes at offset 54 of 70.
            unsafe { (buf.as_mut_ptr().wrapping_add(54) as *mut [u16; 8]).write_unaligned(w) };
        }
        return 70 - nd;
    }
    if base == 10 {
        // two digits per division
        while v >= 100 {
            let r = (v % 100) as usize;
            v /= 100;
            i -= 2;
            buf[i] = PAIRS[2 * r];
            buf[i + 1] = PAIRS[2 * r + 1];
        }
        if v >= 10 {
            i -= 2;
            buf[i] = PAIRS[2 * v as usize];
            buf[i + 1] = PAIRS[2 * v as usize + 1];
        } else {
            i -= 1;
            buf[i] = b'0' + v as u8;
        }
        return i;
    }
    if base.is_power_of_two() {
        let shift = base.trailing_zeros();
        let mask = base - 1;
        loop {
            i -= 1;
            buf[i] = digs[(v & mask) as usize];
            v >>= shift;
            if v == 0 {
                break;
            }
        }
        return i;
    }
    loop {
        i -= 1;
        buf[i] = digs[(v % base) as usize];
        v /= base;
        if v == 0 {
            break;
        }
    }
    i
}

/// Read a decimal number at `p`; returns (value, next index, overflowed).
///
/// # Safety
/// `p` is a NUL-terminated format and `i` is not past its NUL.
unsafe fn read_int<F: FmtChar>(p: *const F, mut i: usize) -> (usize, usize, bool) {
    let mut v: usize = 0;
    let mut over = false;
    while fmt_at!(p, i).is_ascii_digit() {
        match v.checked_mul(10).and_then(|x| x.checked_add((fmt_at!(p, i) - b'0') as usize)) {
            Some(x) if x <= i32::MAX as usize => v = x,
            _ => over = true,
        }
        i += 1;
    }
    (v, i, over)
}

/// `n$` at `i`: digits (leading zeros allowed), then '$', with n > 0. Returns (n, index after '$').
///
/// # Safety
/// As `read_int`.
unsafe fn try_pos<F: FmtChar>(p: *const F, i: usize) -> Option<(usize, usize)> {
    if !fmt_at!(p, i).is_ascii_digit() {
        return None;
    }
    // SAFETY: the caller's contract.
    let (n, j, _) = unsafe { read_int(p, i) };
    if fmt_at!(p, j) == b'$' && n > 0 { Some((n, j + 1)) } else { None }
}

/// Positional-argument kinds found in a format string, for `%n$` forms.
pub struct PosKinds {
    pub kinds: [Option<Kind>; 128],
    pub max: usize,
}

fn kind_of(conv: u8, len: Len) -> Option<Kind> {
    Some(match conv {
        b'd' | b'i' | b'o' | b'u' | b'x' | b'X' | b'b' | b'B' => {
            if matches!(len, Len::L | Len::LL | Len::BigL | Len::J | Len::Z | Len::T) { Kind::Long } else { Kind::Int }
        }
        b'c' | b'C' => Kind::Int,
        b's' | b'S' | b'p' | b'n' => Kind::Ptr,
        b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => if len == Len::BigL { Kind::LongDouble } else { Kind::Double },
        _ => return None,
    })
}

/// Scan a format for positional specs: the kind of each referenced argument position.
/// `None` if the format uses no positional forms. Specs without `n$` in a format that also has
/// positional ones take the next unused sequential position, counting only such specs (glibc).
pub unsafe fn scan_positional<F: FmtChar>(fmt: *const F) -> Option<PosKinds> {
    // with user-defined conversions registered the engine reads the arguments itself
    if crate::printf_ext::active() {
        return None;
    }
    let mut pk = PosKinds { kinds: [None; 128], max: 0 };
    let mut any = false;
    let mut seq = 0usize;
    let mut i = 0;
    let note = |pos: usize, k: Kind, pk: &mut PosKinds| {
        if (1..=128).contains(&pos) {
            pk.kinds[pos - 1] = Some(k);
            if pos > pk.max {
                pk.max = pos;
            }
        }
    };
    while fmt_at!(fmt, i) != 0 {
        if fmt_at!(fmt, i) != b'%' {
            i += 1;
            continue;
        }
        i += 1;
        if fmt_at!(fmt, i) == b'%' {
            i += 1;
            continue;
        }
        let mut pos = 0;
        // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
        if let Some((n, j)) = unsafe { try_pos(fmt, i) } {
            pos = n;
            i = j;
            any = true;
        }
        while matches!(fmt_at!(fmt, i), b'-' | b' ' | b'+' | b'#' | b'0' | b'\'' | b'I') {
            i += 1;
        }
        if fmt_at!(fmt, i) == b'*' {
            i += 1;
            let mut explicit = false;
            // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
            if let Some((n, j)) = unsafe { try_pos(fmt, i) } {
                note(n, Kind::Int, &mut pk);
                i = j;
                any = true;
                explicit = true;
            }
            if !explicit {
                seq += 1;
                note(seq, Kind::Int, &mut pk);
            }
        } else {
            while fmt_at!(fmt, i).is_ascii_digit() {
                i += 1;
            }
        }
        if fmt_at!(fmt, i) == b'.' {
            i += 1;
            if fmt_at!(fmt, i) == b'*' {
                i += 1;
                let mut explicit = false;
                // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
                if let Some((n, j)) = unsafe { try_pos(fmt, i) } {
                    note(n, Kind::Int, &mut pk);
                    i = j;
                    any = true;
                    explicit = true;
                }
                if !explicit {
                    seq += 1;
                    note(seq, Kind::Int, &mut pk);
                }
            } else {
                while fmt_at!(fmt, i).is_ascii_digit() {
                    i += 1;
                }
            }
        }
        // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
        let (len, ni) = unsafe { parse_len(fmt, i) };
        i = ni;
        let c = fmt_at!(fmt, i);
        if c == 0 {
            break;
        }
        i += 1;
        if let Some(k) = kind_of(c, len) {
            if pos != 0 {
                note(pos, k, &mut pk);
            } else {
                seq += 1;
                note(seq, k, &mut pk);
            }
        }
    }
    if any { Some(pk) } else { None }
}

/// The length modifier at `i` and the index after it.
///
/// # Safety
/// As `read_int`.
unsafe fn parse_len<F: FmtChar>(fmt: *const F, mut i: usize) -> (Len, usize) {
    let c = fmt_at!(fmt, i);
    let len = match c {
        b'h' => {
            if fmt_at!(fmt, i + 1) == b'h' {
                i += 1;
                Len::HH
            } else {
                Len::H
            }
        }
        b'l' => {
            if fmt_at!(fmt, i + 1) == b'l' {
                i += 1;
                Len::LL
            } else {
                Len::L
            }
        }
        b'L' => Len::BigL,
        b'q' => Len::LL,
        b'j' => Len::J,
        b'z' | b'Z' => Len::Z,
        b't' => Len::T,
        // C23 %wN and %wfN (glibc 2.37): N bits exactly, or the fastest type of at least N bits (long, except 8)
        b'w' => {
            let mut j = i + 1;
            let fast = fmt_at!(fmt, j) == b'f';
            if fast {
                j += 1;
            }
            let mut bits = 0u32;
            let start = j;
            while fmt_at!(fmt, j).is_ascii_digit() && j - start < 3 {
                bits = bits * 10 + u32::from(fmt_at!(fmt, j) - b'0');
                j += 1;
            }
            let len = match (fast, bits) {
                (_, 8) => Len::HH,
                (false, 16) => Len::H,
                (false, 32) => Len::None,
                (false, 64) | (true, 16 | 32 | 64) => Len::L,
                _ => Len::Bad,
            };
            return (len, j);
        }
        _ => return (Len::None, i),
    };
    (len, i + 1)
}

/// strerror text for `%m` and `perror`: glibc's `__strerror_r` (the message translated in the calling thread's
/// LC_MESSAGES locale; `_("Unknown error ")` and the number for an unknown one).
pub(crate) fn strerror_text(code: i32, buf: &mut [u8; 128]) -> &[u8] {
    rusty_libc_core::messages::strerror_r_text(code, buf)
}

pub struct Out<'a, S: Sink> {
    sink: &'a mut S,
    total: usize,
    failed: bool,
}

impl<S: Sink> Out<'_, S> {
    /// Wide characters (counted as characters).
    pub fn put_w(&mut self, w: &[u32]) {
        if self.failed || w.is_empty() {
            return;
        }
        if !S::WIDE {
            // a byte sink: the multibyte form, counted in bytes
            for &c in w {
                let mut b = [0u8; 6];
                let Some(n) = rusty_libc_wchar::mbyte::encode_char(c, &mut b).or_else(|| tag_zero(c)) else {
                    errno::set(EILSEQ);
                    self.failed = true;
                    return;
                };
                self.put(&b[..n]);
            }
            return;
        }
        self.total = self.total.saturating_add(w.len());
        if !self.sink.put_wide(w) {
            self.failed = true;
        }
    }
    /// `n` bytes to fill in place (see `Sink::direct`); null if not offered. The bytes are counted here.
    fn direct(&mut self, n: usize) -> *mut u8 {
        if !S::DIRECT || S::WIDE || self.failed || n == 0 {
            return core::ptr::null_mut();
        }
        let p = self.sink.direct(n);
        if !p.is_null() {
            self.total = self.total.saturating_add(n);
        }
        p
    }
    /// ASCII text (or, for a narrow sink, any bytes).
    pub fn put(&mut self, b: &[u8]) {
        if self.failed || b.is_empty() {
            return;
        }
        self.total = self.total.saturating_add(b.len());
        if !self.sink.put(b) {
            self.failed = true;
        }
    }
    fn rep(&mut self, byte: u8, n: usize) {
        if self.failed || n == 0 {
            return;
        }
        self.total = self.total.saturating_add(n);
        if !self.sink.put_repeat(byte, n) {
            self.failed = true;
        }
    }
}

/// Write `pad` spaces or zeros around already-assembled pieces according to the spec.
struct Num<'a> {
    sign: &'a [u8],     // "-", "+", " " or ""
    prefix: &'a [u8],   // "0x", "0b", ...
    zeros: usize,       // zeros required by precision (integers)
    body: &'a [u8],     // the digits / text
    tail: &'a [u8],     // exponent or similar (floats)
    mid: [Piece<'a>; 5], // extra pieces for floats; unused slots are empty
}

#[derive(Clone, Copy)]
enum Piece<'a> {
    Bytes(&'a [u8]),
    Zeros(usize),
    None,
}

fn piece_len(p: &Piece) -> usize {
    match p {
        Piece::Bytes(b) => b.len(),
        Piece::Zeros(n) => *n,
        Piece::None => 0,
    }
}

/// Copy `n` bytes without a call: output pieces are short, and a call costs more than the copy.
///
/// # Safety
/// Both ranges must be valid for `n` bytes and must not overlap.
#[inline(always)]
pub unsafe fn small_copy(dst: *mut u8, src: *const u8, n: usize) {
    // Every access below is a word inside `src[..n]` or `dst[..n]`: the first word at offset 0, the second ending at `n`
    // (they overlap when `n` is not twice the word size), chosen by the range `n` is in. The caller's contract makes those
    // bytes valid and the two ranges disjoint.
    if (8..=16).contains(&n) {
        // SAFETY: see above (bytes 0..8 of `src`).
        let a = unsafe { (src as *const u64).read_unaligned() };
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { src.add(n - 8) };
        // SAFETY: see above (bytes n-8..n of `src`).
        let b = unsafe { (q as *const u64).read_unaligned() };
        // SAFETY: see above (bytes 0..8 of `dst`).
        unsafe { (dst as *mut u64).write_unaligned(a) };
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { dst.add(n - 8) };
        // SAFETY: see above (bytes n-8..n of `dst`).
        unsafe { (q as *mut u64).write_unaligned(b) };
    } else if (4..8).contains(&n) {
        // SAFETY: see above (bytes 0..4 of `src`).
        let a = unsafe { (src as *const u32).read_unaligned() };
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { src.add(n - 4) };
        // SAFETY: see above (bytes n-4..n of `src`).
        let b = unsafe { (q as *const u32).read_unaligned() };
        // SAFETY: see above (bytes 0..4 of `dst`).
        unsafe { (dst as *mut u32).write_unaligned(a) };
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { dst.add(n - 4) };
        // SAFETY: see above (bytes n-4..n of `dst`).
        unsafe { (q as *mut u32).write_unaligned(b) };
    } else if n > 16 {
        // SAFETY: the caller's contract.
        unsafe { rusty_libc_mem::memcpy(dst.cast(), src.cast(), n) };
    } else if n >= 2 {
        // 2 or 3 bytes: two overlapping 16-bit moves (a byte loop here is turned into a call to memcpy)
        // SAFETY: see above (bytes 0..2 of `src`).
        let a = unsafe { (src as *const u16).read_unaligned() };
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { src.add(n - 2) };
        // SAFETY: see above (bytes n-2..n of `src`).
        let b = unsafe { (q as *const u16).read_unaligned() };
        // SAFETY: see above (bytes 0..2 of `dst`).
        unsafe { (dst as *mut u16).write_unaligned(a) };
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { dst.add(n - 2) };
        // SAFETY: see above (bytes n-2..n of `dst`).
        unsafe { (q as *mut u16).write_unaligned(b) };
    } else if n == 1 {
        // SAFETY: the caller's contract: one byte each.
        let c = unsafe { *src };
        // SAFETY: as above.
        unsafe { *dst = c };
    }
}

/// Fill `n` bytes with `byte` without a call (overlapping word stores for 8..=192 bytes).
///
/// # Safety
/// `dst` is valid for `n` bytes.
#[inline(always)]
unsafe fn small_fill(dst: *mut u8, byte: u8, n: usize) {
    // Every store below is a word inside `dst[..n]` (valid by the caller's contract): words from offset 0 while a whole word
    // fits before `n`, and a last one ending at `n`.
    if n >= 8 {
        let w = u64::from_ne_bytes([byte; 8]);
        let mut i = 0;
        while i + 8 < n {
            // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
            let q = unsafe { dst.add(i) };
            // SAFETY: see above (`i + 8 < n`).
            unsafe { (q as *mut u64).write_unaligned(w) };
            i += 8;
        }
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { dst.add(n - 8) };
        // SAFETY: see above (bytes n-8..n, `n >= 8`).
        unsafe { (q as *mut u64).write_unaligned(w) };
    } else if n >= 4 {
        let w = u32::from_ne_bytes([byte; 4]);
        // SAFETY: see above (bytes 0..4).
        unsafe { (dst as *mut u32).write_unaligned(w) };
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { dst.add(n - 4) };
        // SAFETY: see above (bytes n-4..n).
        unsafe { (q as *mut u32).write_unaligned(w) };
    } else if n >= 2 {
        let w = u16::from_ne_bytes([byte; 2]);
        // SAFETY: see above (bytes 0..2).
        unsafe { (dst as *mut u16).write_unaligned(w) };
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { dst.add(n - 2) };
        // SAFETY: see above (bytes n-2..n).
        unsafe { (q as *mut u16).write_unaligned(w) };
    } else if n == 1 {
        // SAFETY: see above (one byte).
        unsafe { *dst = byte };
    }
}

/// `rpad`: the byte that fills the right-hand side of a left-justified number (0: none).
fn write_num<S: Sink>(o: &mut Out<S>, n: &Num, width: usize, left: bool, zero_pad: bool, rpad: u8) {
    let mut len = n.sign.len() + n.prefix.len() + n.zeros + n.body.len() + n.tail.len();
    for p in &n.mid {
        len += piece_len(p);
    }
    let pad = width.saturating_sub(len);
    // short numbers are assembled in one buffer and handed to the sink once
    if len + pad <= 192 && !o.failed {
        let mut raw = core::mem::MaybeUninit::<[u8; 192]>::uninit();
        let base = raw.as_mut_ptr() as *mut u8;
        let mut k = 0usize;
        // The total length was checked against the buffer size above, and every piece is copied or filled exactly once, in
        // order, to the next free bytes: each write stays inside `raw[..len + pad]`, and `raw[..k]` is written at the end.
        // most pieces of a number are empty: one test each instead of the size dispatch
        let copy = |src: &[u8], k: &mut usize| {
            if !src.is_empty() {
                // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                let q = unsafe { base.add(*k) };
                // SAFETY: see above; `src` is not `raw`.
                unsafe { small_copy(q, src.as_ptr(), src.len()) };
                *k += src.len();
            }
        };
        let fill = |byte: u8, cnt: usize, k: &mut usize| {
            if cnt != 0 {
                // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                let q = unsafe { base.add(*k) };
                // SAFETY: see above.
                unsafe { small_fill(q, byte, cnt) };
                *k += cnt;
            }
        };
        if !left && !zero_pad {
            fill(b' ', pad, &mut k);
        }
        copy(n.sign, &mut k);
        copy(n.prefix, &mut k);
        if !left && zero_pad {
            fill(b'0', pad, &mut k);
        }
        fill(b'0', n.zeros, &mut k);
        copy(n.body, &mut k);
        for p in &n.mid {
            match p {
                Piece::Bytes(b) => copy(b, &mut k),
                Piece::Zeros(z) => fill(b'0', *z, &mut k),
                Piece::None => {}
            }
        }
        copy(n.tail, &mut k);
        if left && rpad != 0 {
            fill(rpad, pad, &mut k);
        }
        // SAFETY: see above: the first `k` bytes were written.
        o.put(unsafe { core::slice::from_raw_parts(base, k) });
        return;
    }
    if !left && !zero_pad {
        o.rep(b' ', pad);
    }
    o.put(n.sign);
    o.put(n.prefix);
    if !left && zero_pad {
        o.rep(b'0', pad);
    }
    o.rep(b'0', n.zeros);
    o.put(n.body);
    for p in &n.mid {
        match p {
            Piece::Bytes(b) => o.put(b),
            Piece::Zeros(z) => o.rep(b'0', *z),
            Piece::None => {}
        }
    }
    o.put(n.tail);
    if left && rpad != 0 {
        o.rep(rpad, pad);
    }
}

fn val_i(v: Val) -> u64 {
    match v {
        Val::I(x) => x,
        _ => 0,
    }
}

/// Decode the x87 80-bit extended format from 16 raw bytes: (sign, exponent field, 64-bit mantissa).
fn decode_x87(b: [u8; 16]) -> (bool, i32, u64) {
    let mant = u64::from_le_bytes(b[..8].try_into().unwrap());
    let se = u16::from_le_bytes([b[8], b[9]]);
    ((se >> 15) != 0, i32::from(se & 0x7fff), mant)
}

/// Format `format` into `sink`, taking arguments from `args`. Returns the number of bytes
/// produced, or -1 with `errno` set.
///
/// # Safety
/// `fmt` must be a NUL-terminated string and `args` must supply values matching the conversions.
#[inline(always)]
pub unsafe fn format<S: Sink, A: Args, F: FmtChar>(sink: &mut S, fmt: *const F, args: &mut A) -> i32 {
    // user-defined conversions (printf.h): one relaxed load while nothing is registered
    if crate::printf_ext::active() {
        // SAFETY: the caller's contract.
        return unsafe { crate::printf_ext::format_ext::<S, A, F>(sink, fmt, args) };
    }
    // SAFETY: the caller's contract.
    unsafe { format_builtin(sink, fmt, args) }
}

/// The printf engine without user-defined conversions.
///
/// # Safety
/// As `format`.
pub unsafe fn format_builtin<S: Sink, A: Args, F: FmtChar>(sink: &mut S, fmt: *const F, args: &mut A) -> i32 {
    let mut o = Out { sink, total: 0, failed: false };
    let mut i = 0usize;
    let mut run_start = 0usize;
    // glibc switches to a slower path (positional parsing) at the first `%n$` or unknown
    // conversion; there a spec cut off by the end of the string is printed instead of failing.
    let mut slow = false;
    loop {
        // literal text: plain comparisons on the raw character (no 0x80 mapping needed here)
        let rc = fmt_raw!(fmt, i);
        if rc != 0 && rc != u32::from(b'%') {
            i += 1;
            continue;
        }
        let c = if rc == 0 { 0 } else { b'%' };
        if i > run_start {
            // SAFETY: `fmt[run_start..i]` is literal text already scanned (no NUL in it): inside the format.
            unsafe { F::emit_run(&mut o, fmt, run_start, i - run_start) };
        }
        if o.failed {
            return -1;
        }
        if c == 0 {
            break;
        }
        // parse a conversion specification
        i += 1;
        // a bare `%s`, `%d`, `%i`, `%u`, `%x` or `%c`, optionally with a width of up to four digits (no flags,
        // precision or length): straight to the conversion
        let mut bj = i;
        let mut bw = 0usize;
        while bj < i + 4 && fmt_at!(fmt, bj).is_ascii_digit() && (bj > i || fmt_at!(fmt, bj) != b'0') {
            bw = bw * 10 + usize::from(fmt_at!(fmt, bj) - b'0');
            bj += 1;
        }
        let bare = fmt_at!(fmt, bj);
        // a bare `%c` on a byte sink: the argument's low byte, no Spec
        if bare == b'c' && bw == 0 && !S::WIDE {
            let v = val_i(args.get(Kind::Int, None)) as u8;
            o.put(&[v]);
            i = bj + 1;
            run_start = i;
            if o.failed {
                return -1;
            }
            continue;
        }
        let mut is_bare = matches!(bare, b's' | b'd' | b'i' | b'u' | b'x' | b'c' | b'o' | b'X' | b'p' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A');
        let mut bare = bare;
        let mut bflags = Flags::default();
        // the same with simple flags in front (`%#x`, `%08X`, `%-5d`): flags, a width of up to four digits, one of
        // those conversions; anything else (precision, length, `*`, `$`, `'`, `I`) takes the general path below
        if !is_bare && matches!(fmt_at!(fmt, i), b'-' | b' ' | b'+' | b'#' | b'0') {
            let mut fj = i;
            loop {
                match fmt_at!(fmt, fj) {
                    b'-' => bflags.left = true,
                    b' ' => bflags.space = true,
                    b'+' => bflags.plus = true,
                    b'#' => bflags.alt = true,
                    b'0' => bflags.zero = true,
                    _ => break,
                }
                fj += 1;
            }
            let mut wj = fj;
            let mut ww = 0usize;
            while wj < fj + 4 && fmt_at!(fmt, wj).is_ascii_digit() {
                ww = ww * 10 + usize::from(fmt_at!(fmt, wj) - b'0');
                wj += 1;
            }
            let b2 = fmt_at!(fmt, wj);
            if matches!(b2, b's' | b'd' | b'i' | b'u' | b'x' | b'c' | b'o' | b'X' | b'p' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A') {
                is_bare = true;
                bare = b2;
                bj = wj;
                bw = ww;
            } else {
                bflags = Flags::default();
            }
        }
        let mut spec = Spec { flags: bflags, pad0: false, width: if is_bare { bw } else { 0 }, prec: None, len: Len::None, conv: if is_bare { bare } else { 0 }, conv_raw: if is_bare { fmt_raw!(fmt, bj) } else { 0 }, wide_fmt: F::WIDE };
        let mut pos: Option<usize> = None;
        if is_bare {
            i = bj;
        } else {
            let mut positional_seen = false;
            // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
            if let Some((n, j)) = unsafe { try_pos(fmt, i) } {
                pos = Some(n);
                positional_seen = true;
                i = j;
            }
            loop {
                match fmt_at!(fmt, i) {
                    b'-' => spec.flags.left = true,
                    b' ' => spec.flags.space = true,
                    b'+' => spec.flags.plus = true,
                    b'#' => spec.flags.alt = true,
                    b'0' => spec.flags.zero = true,
                    b'\'' => spec.flags.group = true,
                    b'I' => spec.flags.i18n = true,
                    _ => break,
                }
                i += 1;
            }
            // width
            let explicit_minus = spec.flags.left;
            let mut neg_width_arg = false;
            if fmt_at!(fmt, i) == b'*' {
                i += 1;
                let mut wpos = None;
                // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
                if let Some((n, j)) = unsafe { try_pos(fmt, i) } {
                    wpos = Some(n);
                    positional_seen = true;
                    i = j;
                }
                let w = val_i(args.get(Kind::Int, wpos)) as u32 as i32;
                if w < 0 {
                    spec.flags.left = true;
                    neg_width_arg = true;
                    spec.width = (i64::from(w)).unsigned_abs() as usize;
                } else {
                    spec.width = w as usize;
                }
            } else if fmt_at!(fmt, i).is_ascii_digit() {
                // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
                let (n, j, over) = unsafe { read_int(fmt, i) };
                if over {
                    errno::set(EOVERFLOW);
                    return -1;
                }
                spec.width = n;
                i = j;
            }
            // precision
            if fmt_at!(fmt, i) == b'.' {
                i += 1;
                if fmt_at!(fmt, i) == b'*' {
                    i += 1;
                    let mut ppos = None;
                    // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
                    if let Some((n, j)) = unsafe { try_pos(fmt, i) } {
                        ppos = Some(n);
                        positional_seen = true;
                        i = j;
                    }
                    let p = val_i(args.get(Kind::Int, ppos)) as u32 as i32;
                    spec.prec = if p < 0 { None } else { Some(p as usize) };
                } else {
                    // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
                    let (n, j, over) = unsafe { read_int(fmt, i) };
                    if over {
                        errno::set(EOVERFLOW);
                        return -1;
                    }
                    spec.prec = Some(n);
                    i = j;
                }
            }
            // SAFETY: the function's contract: the format is NUL-terminated and `i` is not past its NUL.
            let (len, ni) = unsafe { parse_len(fmt, i) };
            if len == Len::Bad {
                errno::set(EINVAL);
                return -1;
            }
            spec.len = len;
            i = ni;
            let conv = fmt_at!(fmt, i);
            spec.conv = conv;
            spec.conv_raw = fmt_raw!(fmt, i);
            if positional_seen {
                slow = true;
            }
            spec.pad0 = neg_width_arg && spec.flags.zero && !explicit_minus && slow;
            // glibc's fast path accepts a single 'h' only before integer conversions; anything else
            // (such as %hc) goes through the slow path, which changes how a cut-off spec is treated
            if conv != 0 && spec.len == Len::H && !matches!(conv, b'd' | b'i' | b'u' | b'o' | b'x' | b'X' | b'n' | b'b' | b'B' | b'%') {
                slow = true;
            }
            if conv == 0 {
                if slow {
                    unknown(&mut o, &spec);
                    break;
                }
                errno::set(EINVAL);
                return -1;
            }
        }
        i += 1;
        run_start = i;
        // SAFETY: the function's contract: `args` supplies values matching the conversions.
        if unsafe { convert(&mut o, &spec, pos, args) } {
            slow = true;
        }
        if o.failed {
            return -1;
        }
        if let Some(e) = o_error(&o) {
            errno::set(e);
            return -1;
        }
    }
    if o.failed {
        return -1;
    }
    if o.total > i32::MAX as usize {
        errno::set(EOVERFLOW);
        return -1;
    }
    o.total as i32
}

fn o_error<S: Sink>(o: &Out<S>) -> Option<i32> {
    if o.total > i32::MAX as usize { Some(EOVERFLOW) } else { None }
}

/// Print an unknown conversion the way glibc does: the flags, width and precision, then the character.
fn unknown<S: Sink>(o: &mut Out<S>, s: &Spec) {
    o.put(b"%");
    let f = &s.flags;
    if f.alt {
        o.put(b"#");
    }
    if f.group {
        o.put(b"'");
    }
    if f.plus {
        o.put(b"+");
    } else if f.space {
        o.put(b" ");
    }
    if f.left {
        o.put(b"-");
    }
    if f.zero && !f.left {
        o.put(b"0");
    }
    if f.i18n {
        o.put(b"I");
    }
    let mut buf = [0u8; 70];
    if s.width != 0 {
        let i = digits_u64(s.width as u64, 10, false, &mut buf);
        o.put(&buf[i..]);
    }
    if let Some(p) = s.prec {
        o.put(b".");
        if p == 0 {
            o.put(b"0");
        } else {
            let i = digits_u64(p as u64, 10, false, &mut buf);
            o.put(&buf[i..]);
        }
    }
    if s.conv != 0 {
        if s.wide_fmt {
            o.put_w(&[s.conv_raw]);
        } else {
            o.put(&[s.conv]);
        }
    }
}

/// Returns true when the conversion character was unknown.
///
/// # Safety
/// `args` supplies a value of the kind the conversion takes (pointer conversions: null or valid for their use).
unsafe fn convert<S: Sink, A: Args>(o: &mut Out<S>, s: &Spec, pos: Option<usize>, args: &mut A) -> bool {
    let f = s.flags;
    match s.conv {
        b'%' => o.put(b"%"),
        b'd' | b'i' => {
            let v = val_i(args.get(kind_of(s.conv, s.len).unwrap(), pos));
            let signed: i64 = match s.len {
                Len::HH => i64::from(v as i8),
                Len::H => i64::from(v as i16),
                Len::None => i64::from(v as i32),
                _ => v as i64,
            };
            let neg = signed < 0;
            let mag = signed.unsigned_abs();
            let sign: &[u8] = if neg { b"-" } else if f.plus { b"+" } else if f.space { b" " } else { b"" };
            emit_int(o, s, sign, b"", mag, 10, false);
        }
        b'u' | b'o' | b'x' | b'X' | b'b' | b'B' => {
            let v = val_i(args.get(kind_of(s.conv, s.len).unwrap(), pos));
            let mag: u64 = match s.len {
                Len::HH => u64::from(v as u8),
                Len::H => u64::from(v as u16),
                Len::None => u64::from(v as u32),
                _ => v,
            };
            let (base, upper) = match s.conv {
                b'u' => (10, false),
                b'o' => (8, false),
                b'x' => (16, false),
                b'X' => (16, true),
                _ => (2, false),
            };
            let prefix: &[u8] = if f.alt && mag != 0 {
                match s.conv {
                    b'x' => b"0x",
                    b'X' => b"0X",
                    b'b' => b"0b",
                    b'B' => b"0B",
                    _ => b"",
                }
            } else {
                b""
            };
            emit_int(o, s, b"", prefix, mag, base, upper);
        }
        b'c' | b'C' => {
            let v = val_i(args.get(Kind::Int, pos)) as u32;
            let wide_arg = s.conv == b'C' || s.len == Len::L;
            let pad = s.width.saturating_sub(1);
            if S::WIDE {
                // `%c` is btowc of the byte (WEOF for a non-ASCII one), `%lc` the wide character itself
                let ch = if wide_arg { v } else if v & 0xff < 0x80 { v & 0xff } else { u32::MAX };
                if !f.left {
                    o.rep(b' ', pad);
                }
                o.put_w(&[ch]);
                if f.left {
                    o.rep(b' ', pad);
                }
            } else if wide_arg {
                // a wide character written as its multibyte form (the width counts bytes)
                let mut b = [0u8; 6];
                let Some(n) = rusty_libc_wchar::mbyte::encode_char(v, &mut b).or_else(|| tag_zero(v)) else {
                    errno::set(EILSEQ);
                    o.failed = true;
                    return false;
                };
                let pad = s.width.saturating_sub(n);
                if !f.left {
                    o.rep(b' ', pad);
                }
                o.put(&b[..n]);
                if f.left {
                    o.rep(b' ', pad);
                }
            } else {
                let b = [(v & 0xff) as u8];
                if !f.left {
                    o.rep(b' ', pad);
                }
                o.put(&b);
                if f.left {
                    o.rep(b' ', pad);
                }
            }
        }
        b's' | b'S' => {
            let p = val_i(args.get(Kind::Ptr, pos)) as usize;
            let wide = s.conv == b'S' || s.len == Len::L;
            // SAFETY: the function's contract: a `%s` argument is null or a string of its kind.
            unsafe { emit_str(o, s, p, wide) };
        }
        b'm' => {
            let mut buf = [0u8; 40];
            let mut big;
            let code = errno::get();
            // `%#m` prints the macro name ("ENOENT"), or the number when there is no name
            // (through rusty-libc-core's one copy of the names: a direct use of the ERRNAMES constant puts a private table with
            // 133 load-time relocations into every crate that instantiates this generic code)
            let named: &[u8] = if f.alt { rusty_libc_core::messages::error_name(code).map_or(b"", |n| n.to_bytes()) } else { b"" };
            let text: &[u8] = if f.alt {
                if named.is_empty() {
                    let mut tmp = [0u8; 70];
                    let st = digits_u64(i64::from(code).unsigned_abs(), 10, false, &mut tmp);
                    let mut n = 0;
                    if code < 0 {
                        buf[0] = b'-';
                        n = 1;
                    }
                    for &d in &tmp[st..] {
                        buf[n] = d;
                        n += 1;
                    }
                    &buf[..n]
                } else {
                    named
                }
            } else if let Some(m) = rusty_libc_core::messages::error_message_tr(code) {
                m.to_bytes()
            } else {
                big = [0u8; 128];
                strerror_text(code, &mut big)
            };
            if S::WIDE && !text.is_ascii() {
                // a translated message into a wide stream: converted like a narrow `%s` (glibc's vfwprintf does the same)
                let mut z = [0u8; 1024];
                let k = text.len().min(z.len() - 1);
                z[..k].copy_from_slice(&text[..k]);
                // SAFETY: `z` is NUL-terminated (`k < len`, zero-filled).
                unsafe { emit_str(o, s, z.as_ptr() as usize, false) };
                return false;
            }
            let n = match s.prec {
                Some(p) => text.len().min(p),
                None => text.len(),
            };
            let pad = s.width.saturating_sub(n);
            if !f.left {
                o.rep(b' ', pad);
            }
            o.put(&text[..n]);
            if f.left {
                o.rep(b' ', pad);
            }
        }
        b'p' => {
            let p = val_i(args.get(Kind::Ptr, pos));
            if p == 0 {
                let pad = s.width.saturating_sub(5);
                if !f.left {
                    o.rep(b' ', pad);
                }
                o.put(b"(nil)");
                if f.left {
                    o.rep(b' ', pad);
                }
            } else {
                let sign: &[u8] = if f.plus { b"+" } else if f.space { b" " } else { b"" };
                emit_int(o, s, sign, b"0x", p, 16, false);
            }
        }
        b'n' => {
            let p = val_i(args.get(Kind::Ptr, pos)) as usize;
            let total = o.total;
            if p != 0 {
                match s.len {
                    // SAFETY: the function's contract: a `%n` argument points to an integer of the size its length
                    // modifier names (each arm stores that one).
                    Len::HH => unsafe { *(p as *mut i8) = total as i8 },
                    // SAFETY: as above.
                    Len::H => unsafe { *(p as *mut i16) = total as i16 },
                    // SAFETY: as above.
                    Len::None => unsafe { *(p as *mut i32) = total as i32 },
                    // SAFETY: as above.
                    _ => unsafe { *(p as *mut i64) = total as i64 },
                }
            }
        }
        b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => {
            emit_float(o, s, args.get(kind_of(s.conv, s.len).unwrap(), pos));
        }
        _ => {
            unknown(o, s);
            return true;
        }
    }
    false
}

/// Digit translation for the `I` flag: the current LC_CTYPE's out-digits, or None when digits stay ASCII.
fn out_digits(on: bool) -> Option<&'static rusty_libc_core::locale::CatData> {
    if !on {
        return None;
    }
    rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE)
}

/// One ASCII character of a number, translated to the locale's digit if it is a digit and `tr` is set.
fn put_ch<S: Sink>(o: &mut Out<S>, tr: Option<&rusty_libc_core::locale::CatData>, c: u8) {
    use rusty_libc_core::locale::idx;
    match tr {
        Some(d) if c.is_ascii_digit() => {
            let k = (c - b'0') as usize;
            if S::WIDE {
                o.put_w(&[d.word(idx::CTYPE_OUTDIGIT0_WC + k)]);
            } else {
                o.put(d.bytes(idx::CTYPE_OUTDIGIT0_MB + k));
            }
        }
        _ => o.put(&[c]),
    }
}

/// A run of ASCII text of a number, digits translated if `tr` is set.
fn put_txt<S: Sink>(o: &mut Out<S>, tr: Option<&rusty_libc_core::locale::CatData>, t: &[u8]) {
    if tr.is_none() {
        o.put(t);
    } else {
        for &c in t {
            put_ch(o, tr, c);
        }
    }
}

fn put_zeros<S: Sink>(o: &mut Out<S>, tr: Option<&rusty_libc_core::locale::CatData>, n: usize) {
    if tr.is_none() {
        o.rep(b'0', n);
    } else {
        for _ in 0..n {
            put_ch(o, tr, b'0');
        }
    }
}

fn put_sep<S: Sink>(o: &mut Out<S>, nu: &rusty_libc_core::locale::Numeric) {
    if S::WIDE {
        if nu.thousands_wc != 0 {
            o.put_w(&[nu.thousands_wc]);
        }
    } else {
        o.put(nu.thousands_sep);
    }
}

/// An integer conversion with the `'` flag (digit grouping) or the `I` flag (locale digits), the
/// way glibc's vfprintf-process-arg.c lays it out: the width counts the separators (their bytes in
/// narrow output) and the translated digits (bytes too), zero padding is not grouped.
fn emit_int_loc<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], prefix: &[u8], mag: u64, base: u64, upper: bool) {
    let mut buf = [0u8; 70];
    let start = digits_u64(mag, base, upper, &mut buf);
    let mut digits = &buf[start..];
    if mag == 0 && s.prec == Some(0) {
        digits = if s.conv == b'o' && s.flags.alt { b"0" } else { b"" };
    }
    let f = s.flags;
    let nu = rusty_libc_core::locale::numeric();
    let use_out = f.i18n && base == 10;
    let tr = out_digits(use_out);
    let prec = s.prec.unwrap_or(1) as isize;
    let nd = digits.len();
    let mut it = if f.group { nu.group_iter(nd) } else { nu.group_iter(0) };
    let mut number_length = nd as isize;
    if let (Some(d), false) = (tr, S::WIDE) {
        number_length = digits.iter().map(|&c| d.bytes(rusty_libc_core::locale::idx::CTYPE_OUTDIGIT0_MB + (c - b'0') as usize).len() as isize).sum();
    }
    if f.group {
        let seplen = if S::WIDE { isize::from(nu.thousands_wc != 0) } else { nu.thousands_sep.len() as isize };
        number_length += it.separators as isize * seplen;
    }
    let octal_marker = prec <= number_length && mag != 0 && f.alt && base == 8;
    let prec_inc = (prec - nd as isize).max(0);
    let pad_zero = f.zero && s.prec.is_none() && !f.left;
    let mut width = s.width as isize;
    let emit_digits = |o: &mut Out<S>, it: &mut rusty_libc_core::locale::GroupIter| {
        for &c in digits {
            if f.group && it.next_digit() {
                put_sep(o, &nu);
            }
            put_ch(o, tr, c);
        }
    };
    if !f.left {
        width -= number_length + prec_inc;
        width -= prefix.len() as isize + isize::from(octal_marker) + sign.len() as isize;
        if !pad_zero {
            o.rep(b' ', width.max(0) as usize);
            width = 0;
        }
        o.put(sign);
        o.put(prefix);
        width += prec_inc;
        o.rep(b'0', width.max(0) as usize);
        if octal_marker {
            o.put(b"0");
        }
        emit_digits(o, &mut it);
    } else {
        o.put(sign);
        o.put(prefix);
        width -= sign.len() as isize + prefix.len() as isize + isize::from(octal_marker);
        width -= number_length + prec_inc;
        o.rep(b'0', prec_inc as usize);
        if octal_marker {
            o.put(b"0");
        }
        emit_digits(o, &mut it);
        o.rep(b' ', width.max(0) as usize);
    }
}

/// The right-hand padding of a left-justified float: ' ', or in glibc's positional path after a negative width argument with the
/// '0' flag, '0' for decimal floats and nothing at all (0) for hex floats.
fn float_rpad(s: &Spec) -> u8 {
    if !s.pad0 {
        b' '
    } else if matches!(s.conv, b'a' | b'A') {
        0
    } else {
        b'0'
    }
}

/// A decimal floating point number under a non-C numeric locale or with the `'`/`I` flags, laid
/// out the way glibc's printf_fp.c does: the width is computed as if every separator and the
/// decimal point were one character (also in narrow output with multibyte ones), the grouping
/// covers the integer digits, zero padding is not grouped.
fn write_pieces_loc<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], p: &float::Pieces, zero_pad: bool) {
    let nu = rusty_libc_core::locale::numeric();
    let hex = s.conv | 0x20 == b'a';
    let sep_present = if S::WIDE { nu.thousands_wc != 0 } else { !nu.thousands_sep.is_empty() };
    let intdig = p.int.len() + p.int_zeros;
    let grouping = s.flags.group && !hex && sep_present;
    let mut it = if grouping { nu.group_iter(intdig) } else { nu.group_iter(0) };
    let tr = out_digits(s.flags.i18n && !hex);
    // glibc quirk kept: in the built-in C locale (C, POSIX; not C.UTF-8) narrow `%If` writes no digits
    let vanish = s.flags.i18n && !hex && !S::WIDE && match tr {
        None => true,
        Some(d) => d.flags() & rusty_libc_core::locale::F_BUILTIN_C != 0,
    };
    let chars = p.prefix.len() + intdig + usize::from(p.point) + p.frac_lead_zeros + p.frac.len() + p.frac_zeros + p.tail_len + it.separators as usize;
    let width = (s.width as isize - sign.len() as isize - chars as isize).max(0) as usize;
    let left = s.flags.left;
    if !left && !zero_pad {
        o.rep(b' ', width);
    }
    o.put(sign);
    o.put(p.prefix);
    if !left && zero_pad {
        o.rep(b'0', width);
    }
    for i in 0..intdig {
        if grouping && it.next_digit() {
            put_sep(o, &nu);
        }
        if !vanish {
            put_ch(o, tr, if i < p.int.len() { p.int[i] } else { b'0' });
        }
    }
    if p.point {
        if S::WIDE {
            o.put_w(&[nu.decimal_wc]);
        } else {
            o.put(nu.decimal_point);
        }
    }
    if vanish {
        // only the non-digits of the tail (the exponent letter and sign) remain
        for &c in &p.tail[..p.tail_len] {
            if !c.is_ascii_digit() {
                o.put(&[c]);
            }
        }
    } else {
        put_zeros(o, tr, p.frac_lead_zeros);
        put_txt(o, tr, p.frac);
        put_zeros(o, tr, p.frac_zeros);
        put_txt(o, tr, &p.tail[..p.tail_len]);
    }
    let rpad = float_rpad(s);
    if left && rpad != 0 {
        o.rep(rpad, width);
    }
}

/// Do a float conversion's flags or the current numeric locale need the slow, localized layout?
#[inline]
fn float_needs_locale(s: &Spec) -> bool {
    if s.flags.group || s.flags.i18n {
        return true;
    }
    let d = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_NUMERIC);
    !rusty_libc_core::locale::numeric_dot(d)
}

fn emit_int<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], prefix: &[u8], mag: u64, base: u64, upper: bool) {
    if s.flags.group || (s.flags.i18n && base == 10) {
        return emit_int_loc(o, s, sign, prefix, mag, base, upper);
    }
    if S::DIRECT && sign.len() <= 1 && prefix.len() <= 2 {
        let nd = ndigits(mag, base);
        let digits_len = if mag == 0 && s.prec == Some(0) { 0 } else { nd };
        let mut zeros = s.prec.map_or(0, |p| p.saturating_sub(digits_len));
        // '#' with octal: make sure the first digit is 0 (the only digit that is 0 is the one of the value 0)
        if s.conv == b'o' && s.flags.alt && zeros == 0 && (digits_len == 0 || mag != 0) {
            zeros = 1;
        }
        let zero_pad = s.flags.zero && s.prec.is_none() && !s.flags.left;
        let total = sign.len() + prefix.len() + zeros + digits_len;
        let pad = s.width.saturating_sub(total);
        let p = o.direct(total + pad);
        if !p.is_null() {
            // `p` has room for `total + pad` bytes (`direct`'s promise) and each one is written once, in order: every write
            // below goes to the next free bytes of `p[..total + pad]`.
            let mut k = 0usize;
            if !zero_pad && !s.flags.left {
                // SAFETY: see above.
                unsafe { small_fill(p, b' ', pad) };
                k += pad;
            }
            if let Some(&sg) = sign.first() {
                // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                let q = unsafe { p.add(k) };
                // SAFETY: see above.
                unsafe { *q = sg };
                k += 1;
            }
            for &c in prefix {
                // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                let q = unsafe { p.add(k) };
                // SAFETY: see above.
                unsafe { *q = c };
                k += 1;
            }
            if zero_pad {
                // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                let q = unsafe { p.add(k) };
                // SAFETY: see above.
                unsafe { small_fill(q, b'0', pad) };
                k += pad;
            }
            // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
            let q = unsafe { p.add(k) };
            // SAFETY: see above.
            unsafe { small_fill(q, b'0', zeros) };
            k += zeros;
            if digits_len != 0 {
                // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                let q = unsafe { p.add(k) };
                // SAFETY: see above.
                unsafe { put_digits(mag, base, upper, q, digits_len) };
                k += digits_len;
            }
            if s.flags.left {
                // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                let q = unsafe { p.add(k) };
                // SAFETY: see above.
                unsafe { small_fill(q, b' ', pad) };
            }
            return;
        }
    }
    let mut buf = [0u8; 70];
    let start = digits_u64(mag, base, upper, &mut buf);
    // plain case (no width, no precision): sign and digits go out as one piece
    if s.width == 0 && s.prec.is_none() && prefix.is_empty() && sign.len() <= 1 && !(s.conv == b'o' && s.flags.alt) {
        if let Some(&sg) = sign.first() {
            buf[start - 1] = sg;
            o.put(&buf[start - 1..]);
        } else {
            o.put(&buf[start..]);
        }
        return;
    }
    // no width or precision, a two-character prefix (`0x`, `0b`): written in front of the digits, then the sign
    if s.width == 0 && s.prec.is_none() && prefix.len() == 2 && sign.len() <= 1 {
        buf[start - 1] = prefix[1];
        buf[start - 2] = prefix[0];
        let mut st = start - 2;
        if let Some(&sg) = sign.first() {
            st -= 1;
            buf[st] = sg;
        }
        o.put(&buf[st..]);
        return;
    }
    let mut digits = &buf[start..];
    // zero value with zero precision prints no digits
    if mag == 0 && s.prec == Some(0) {
        digits = &[];
    }
    let mut zeros = s.prec.map_or(0, |p| p.saturating_sub(digits.len()));
    // '#' with octal: make sure the first digit is 0
    if s.conv == b'o' && s.flags.alt && zeros == 0 && (digits.is_empty() || digits[0] != b'0') {
        zeros = 1;
    }
    // the '0' flag is ignored when a precision is given or when left-justified
    let zero_pad = s.flags.zero && s.prec.is_none() && !s.flags.left;
    // numbers of ordinary size: assembled in one buffer and handed to the sink once,
    // without going through the generic piece list of `write_num`
    let total = sign.len() + prefix.len() + zeros + digits.len();
    let pad = s.width.saturating_sub(total);
    if sign.len() <= 1 && prefix.len() <= 2 && total + pad <= 192 && !o.failed {
        let mut raw = core::mem::MaybeUninit::<[u8; 192]>::uninit();
        let base = raw.as_mut_ptr() as *mut u8;
        // `total + pad <= 192` and every byte up to `k` is written exactly once, in order: each write below goes to the next
        // free bytes of `raw[..total + pad]`.
        let mut k = 0usize;
        if !zero_pad && !s.flags.left {
            // SAFETY: see above.
            unsafe { small_fill(base, b' ', pad) };
            k += pad;
        }
        if let Some(&sg) = sign.first() {
            // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
            let q = unsafe { base.add(k) };
            // SAFETY: see above.
            unsafe { *q = sg };
            k += 1;
        }
        for &c in prefix {
            // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
            let q = unsafe { base.add(k) };
            // SAFETY: see above.
            unsafe { *q = c };
            k += 1;
        }
        if zero_pad {
            // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
            let q = unsafe { base.add(k) };
            // SAFETY: see above.
            unsafe { small_fill(q, b'0', pad) };
            k += pad;
        }
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { base.add(k) };
        // SAFETY: see above.
        unsafe { small_fill(q, b'0', zeros) };
        k += zeros;
        // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
        let q = unsafe { base.add(k) };
        // SAFETY: see above; `digits` is not `raw`.
        unsafe { small_copy(q, digits.as_ptr(), digits.len()) };
        k += digits.len();
        if s.flags.left {
            // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
            let q = unsafe { base.add(k) };
            // SAFETY: see above.
            unsafe { small_fill(q, b' ', pad) };
            k += pad;
        }
        // SAFETY: see above: the first `k` bytes were written.
        o.put(unsafe { core::slice::from_raw_parts(base, k) });
        return;
    }
    let n = Num { sign, prefix, zeros, body: digits, tail: b"", mid: [Piece::None; 5] };
    write_num(o, &n, s.width, s.flags.left, zero_pad, b' ');
}

/// A growing buffer of wide characters (stack first, heap for long strings).
struct WBuf {
    inline: core::mem::MaybeUninit<[u32; 128]>,
    heap: *mut u32,
    cap: usize,
    len: usize,
    oom: bool,
}

impl WBuf {
    fn new() -> WBuf {
        WBuf { inline: core::mem::MaybeUninit::uninit(), heap: core::ptr::null_mut(), cap: 0, len: 0, oom: false }
    }
    // Invariant: the first `len` characters are initialised, in `inline` while `heap` is null (`len <= 128`), else in `heap`,
    // the buffer's own malloc'd block of `cap >= len` characters.
    fn push(&mut self, c: u32) {
        if self.heap.is_null() {
            if self.len < 128 {
                // SAFETY: `len < 128`: inside `inline`.
                unsafe { (self.inline.as_mut_ptr() as *mut u32).wrapping_add(self.len).write(c) };
                self.len += 1;
                return;
            }
            let nc = 512;
            let h: *mut u32 = crate::file::alloc(nc * 4).cast();
            if h.is_null() {
                self.oom = true;
                return;
            }
            // SAFETY: the 128 initialised characters of `inline` into the fresh block of 512.
            unsafe { core::ptr::copy_nonoverlapping(self.inline.as_ptr() as *const u32, h, self.len) };
            self.heap = h;
            self.cap = nc;
        } else if self.len == self.cap {
            let nc = self.cap * 2;
            // SAFETY: `heap` is our own malloc'd block.
            let h = unsafe { rusty_libc_malloc::realloc(self.heap.cast(), nc * 4) } as *mut u32;
            if h.is_null() {
                self.oom = true;
                return;
            }
            self.heap = h;
            self.cap = nc;
        }
        // SAFETY: `len < cap`: inside the heap block.
        unsafe { *self.heap.wrapping_add(self.len) = c };
        self.len += 1;
    }
    fn as_slice(&self) -> &[u32] {
        if self.heap.is_null() {
            // SAFETY: the invariant: `len` initialised characters in `inline`.
            unsafe { core::slice::from_raw_parts(self.inline.as_ptr() as *const u32, self.len) }
        } else {
            // SAFETY: the invariant: `len` initialised characters in the heap block.
            unsafe { core::slice::from_raw_parts(self.heap, self.len) }
        }
    }
    fn release(&mut self) {
        if !self.heap.is_null() {
            // SAFETY: our own block, forgotten right below.
            unsafe { crate::file::free(self.heap.cast()) };
            self.heap = core::ptr::null_mut();
        }
    }
}

/// `%s` / `%ls`: the string at address `p` (0: "(null)").
///
/// # Safety
/// `p` is 0 or the address of a NUL-terminated string of its kind (`wide`: `wchar_t`), or of at least `prec` characters
/// (bytes for a narrow string) when there is a precision.
unsafe fn emit_str<S: Sink>(o: &mut Out<S>, s: &Spec, p: usize, wide: bool) {
    let f = s.flags;
    if p == 0 {
        let text: &[u8] = if s.prec.is_none_or(|p| p >= 6) { b"(null)" } else { b"" };
        let pad = s.width.saturating_sub(text.len());
        if !f.left {
            o.rep(b' ', pad);
        }
        o.put(text);
        if f.left {
            o.rep(b' ', pad);
        }
        return;
    }
    if wide {
        // a wide string
        let w = p as *const u32;
        if S::WIDE {
            let n = match s.prec {
                // SAFETY: the function's contract (this and the next arm).
                None => unsafe { rusty_libc_wchar::wstring::wcslen(w as *const rusty_libc_wchar::wchar_t) },
                // SAFETY: as above.
                Some(limit) => unsafe { rusty_libc_wchar::wstring::wcsnlen(w as *const rusty_libc_wchar::wchar_t, limit) },
            };
            let pad = s.width.saturating_sub(n);
            if !f.left {
                o.rep(b' ', pad);
            }
            // SAFETY: `n` characters at `w` were just measured.
            o.put_w(if n == 0 { &[] } else { unsafe { core::slice::from_raw_parts(w, n) } });
            if f.left {
                o.rep(b' ', pad);
            }
            return;
        }
        // narrow output: converted to the multibyte form; the precision counts bytes (whole
        // characters only), the width too
        let limit = s.prec.unwrap_or(usize::MAX);
        let mut bytes = 0usize;
        let mut k = 0usize;
        // SAFETY: the function's contract: `k` only passes characters seen to be non-NUL.
        while unsafe { *w.wrapping_add(k) } != 0 && bytes < limit {
            let mut b = [0u8; 6];
            // SAFETY: as above (the character just tested).
            let wc = unsafe { *w.wrapping_add(k) };
            let Some(n) = rusty_libc_wchar::mbyte::encode_char(wc, &mut b).or_else(|| tag_zero(wc)) else {
                errno::set(EILSEQ);
                o.failed = true;
                return;
            };
            if bytes + n > limit {
                break;
            }
            bytes += n;
            k += 1;
        }
        let pad = s.width.saturating_sub(bytes);
        if !f.left {
            o.rep(b' ', pad);
        }
        // SAFETY: the `k` characters just read.
        o.put_w(unsafe { core::slice::from_raw_parts(w, k) });
        if f.left {
            o.rep(b' ', pad);
        }
        return;
    }
    if S::WIDE {
        // a multibyte string converted to wide characters: at most `prec` of them; the width counts them
        let cs = rusty_libc_wchar::charset();
        let max_bytes = match s.prec {
            // SAFETY: the function's contract (this and the next arm; strnlen stops at the NUL).
            None => unsafe { rusty_libc_mem::strlen(p as *const core::ffi::c_char) },
            // SAFETY: as above.
            Some(limit) => unsafe { rusty_libc_mem::strnlen(p as *const core::ffi::c_char, limit.saturating_mul(6)) },
        };
        // SAFETY: `max_bytes` bytes at `p` were just measured.
        let bytes = unsafe { core::slice::from_raw_parts(p as *const u8, max_bytes) };
        let limit = s.prec.unwrap_or(usize::MAX);
        // all ASCII (any charset decodes it as itself): widened straight into the sink
        let take = bytes.len().min(limit);
        if bytes[..take].iter().all(|&b| b < 0x80) {
            let pad = s.width.saturating_sub(take);
            if !f.left {
                o.rep(b' ', pad);
            }
            o.put(&bytes[..take]);
            if f.left {
                o.rep(b' ', pad);
            }
            return;
        }
        let mut wb = WBuf::new();
        let mut pos = 0usize;
        while pos < bytes.len() && wb.len < limit {
            // plain ASCII needs no decoder
            let b0 = bytes[pos];
            if b0 < 0x80 {
                wb.push(u32::from(b0));
                pos += 1;
                continue;
            }
            match rusty_libc_wchar::mbyte::decode_cs(cs, &bytes[pos..]) {
                rusty_libc_wchar::mbyte::Decoded::Char(c, n) => {
                    wb.push(c);
                    pos += n;
                }
                _ => {
                    // glibc has already written the padding (one more than the width: it takes the
                    // length of the failed conversion as -1) when it notices
                    if s.width > 0 && !f.left && s.prec.is_none() {
                        o.rep(b' ', s.width + 1);
                    }
                    if !o.failed {
                        errno::set(EILSEQ);
                    }
                    o.failed = true;
                    wb.release();
                    return;
                }
            }
        }
        if wb.oom {
            errno::set(12);
            o.failed = true;
            wb.release();
            return;
        }
        let pad = s.width.saturating_sub(wb.len);
        if !f.left {
            o.rep(b' ', pad);
        }
        o.put_w(wb.as_slice());
        if f.left {
            o.rep(b' ', pad);
        }
        wb.release();
        return;
    }
    let b = p as *const u8;
    let n = match s.prec {
        // SAFETY: the function's contract (this and the next arm).
        None => unsafe { rusty_libc_mem::strlen(b.cast()) },
        // SAFETY: as above.
        Some(limit) => unsafe { rusty_libc_mem::strnlen(b.cast(), limit) },
    };
    let pad = s.width.saturating_sub(n);
    if !f.left {
        o.rep(b' ', pad);
    }
    // SAFETY: `n` bytes at `b` were just measured.
    o.put(unsafe { core::slice::from_raw_parts(b, n) });
    if f.left {
        o.rep(b' ', pad);
    }
}

fn emit_float<S: Sink>(o: &mut Out<S>, s: &Spec, v: Val) {
    let f = s.flags;
    let upper = s.conv.is_ascii_uppercase();
    // decompose into sign, class and (mantissa, exponent)
    let (neg, class, mant, exp2, bits64) = match v {
        Val::D(x) => {
            let b = x.to_bits();
            let e = ((b >> 52) & 0x7ff) as i32;
            let frac = b & ((1u64 << 52) - 1);
            let neg = b >> 63 != 0;
            if e == 0x7ff {
                (neg, if frac == 0 { 1 } else { 2 }, 0u128, 0i32, b)
            } else if e == 0 {
                (neg, 0, u128::from(frac), -1074, b)
            } else {
                (neg, 0, u128::from(frac | (1u64 << 52)), e - 1075, b)
            }
        }
        Val::LD(raw) => {
            let (neg, e, m) = decode_x87(raw);
            if e != 0 && m >> 63 == 0 {
                // a pseudo-normal number (non-zero exponent, integer bit clear) is a NaN to glibc's isnan (tst-ldbl-nonnormal-printf)
                (neg, 2, 0, 0, 0)
            } else if e == 0x7fff {
                // infinity has an all-zero fraction (the explicit integer bit is ignored)
                (neg, if m << 1 == 0 { 1 } else { 2 }, 0, 0, 0)
            } else if e == 0 {
                (neg, 0, u128::from(m), -16445, 0)
            } else {
                (neg, 0, u128::from(m), e - 16383 - 63, 0)
            }
        }
        Val::Q(b) => {
            let neg = b >> 127 != 0;
            let e = ((b >> 112) & 0x7fff) as i32;
            let frac = b & ((1u128 << 112) - 1);
            if e == 0x7fff {
                (neg, if frac == 0 { 1 } else { 2 }, 0, 0, 0)
            } else if e == 0 {
                (neg, 0, frac, -16494, 0)
            } else {
                (neg, 0, frac | (1u128 << 112), e - 16383 - 112, 0)
            }
        }
        Val::I(_) => (false, 0, 0, 0, 0),
    };
    let sign: &[u8] = if neg { b"-" } else if f.plus { b"+" } else if f.space { b" " } else { b"" };
    if class != 0 {
        let text: &[u8] = match (class, upper) {
            (1, false) => b"inf",
            (1, true) => b"INF",
            (_, false) => b"nan",
            (_, true) => b"NAN",
        };
        // NaN keeps its sign too ("-nan"), as glibc prints it
        let n = Num { sign, prefix: b"", zeros: 0, body: text, tail: b"", mid: [Piece::None; 5] };
        write_num(o, &n, s.width, f.left, false, b' ');
        return;
    }
    let is_ld = matches!(v, Val::LD(_));
    let is_q = matches!(v, Val::Q(_));
    let conv_l = s.conv.to_ascii_lowercase();
    let zero_pad = f.zero && !f.left;
    let rm = float::rounding_class(neg); // the program's rounding mode decides the last digit, as in glibc
    if conv_l == b'a' {
        let mut hex = [0u8; 20];
        if let Val::Q(b) = v {
            let mut small = [0u8; 28];
            let p = float::layout_hex128(&mut small, b & !(1u128 << 127), s.prec, f.alt, upper, rm);
            write_pieces(o, s, sign, &p, zero_pad);
        } else if is_ld {
            emit_hex_ld(o, s, sign, mant as u64, exp2, upper, zero_pad, rm);
        } else {
            let mut small = [0u8; 16];
            let p = float::layout_hex(&mut small, bits64 & 0x7fff_ffff_ffff_ffff, s.prec, f.alt, upper, rm);
            let _ = &mut hex;
            write_pieces(o, s, sign, &p, zero_pad);
        }
        return;
    }
    if is_q {
        let mut d = [0u8; 21000];
        let (len, dp) = float::exact_digits::<530>(mant, exp2, &mut d);
        let p = float::layout(&mut d, len, dp, s.conv, s.prec, f.alt, upper, rm);
        write_pieces(o, s, sign, &p, zero_pad);
    } else if is_ld {
        let prec = match conv_l {
            b'g' => s.prec.unwrap_or(6).max(1),
            _ => s.prec.unwrap_or(6),
        };
        let mut small = [0u8; 48];
        let fast = if conv_l == b'g' && f.alt { None } else { float::fast_digits(mant as u64, exp2, conv_l, prec, &mut small, rm) };
        if let Some((len, dp)) = fast {
            let p = float::layout(&mut small, len, dp, s.conv, s.prec, f.alt, upper, rm);
            write_pieces(o, s, sign, &p, zero_pad);
            return;
        }
        let mut d = [0u8; 21000];
        let (len, dp) = float::exact_digits::<530>(mant, exp2, &mut d);
        let p = float::layout(&mut d, len, dp, s.conv, s.prec, f.alt, upper, rm);
        write_pieces(o, s, sign, &p, zero_pad);
    } else {
        // common case: 128-bit arithmetic, digits already rounded; '%#g' keeps the exact path for
        // glibc's carry quirk, which needs the digits before rounding
        let prec = match conv_l {
            b'g' => s.prec.unwrap_or(6).max(1),
            _ => s.prec.unwrap_or(6),
        };
        let mut small = [0u8; 48];
        let fast = if conv_l == b'g' && f.alt { None } else { float::fast_digits(mant as u64, exp2, conv_l, prec, &mut small, rm) };
        if let Some((len, dp)) = fast {
            let p = float::layout(&mut small, len, dp, s.conv, s.prec, f.alt, upper, rm);
            write_pieces(o, s, sign, &p, zero_pad);
            return;
        }
        let mut d = [0u8; 1500];
        let (len, dp) = float::exact_digits::<40>(mant, exp2, &mut d);
        let p = float::layout(&mut d, len, dp, s.conv, s.prec, f.alt, upper, rm);
        write_pieces(o, s, sign, &p, zero_pad);
    }
}

fn write_pieces<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], p: &float::Pieces, zero_pad: bool) {
    if float_needs_locale(s) {
        return write_pieces_loc(o, s, sign, p, zero_pad);
    }
    // right-justified numbers of ordinary size: assembled in one buffer, without the generic piece list of `write_num`
    if !s.flags.left {
        let len = sign.len() + p.prefix.len() + p.int.len() + p.int_zeros + usize::from(p.point) + p.frac_lead_zeros + p.frac.len() + p.frac_zeros + p.tail_len;
        let pad = s.width.saturating_sub(len);
        if len + pad <= 192 && !o.failed {
            let mut raw = core::mem::MaybeUninit::<[u8; 192]>::uninit();
            let base = raw.as_mut_ptr() as *mut u8;
            // `len + pad <= 192` and every piece is written once, in order, to the next free bytes: each write stays inside
            // `raw[..len + pad]`, and `raw[..k]` is written at the end.
            let mut k = 0usize;
            let copy = |src: &[u8], k: &mut usize| {
                if !src.is_empty() {
                    // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                    let q = unsafe { base.add(*k) };
                    // SAFETY: see above; `src` is not `raw`.
                    unsafe { small_copy(q, src.as_ptr(), src.len()) };
                    *k += src.len();
                }
            };
            let fill = |byte: u8, cnt: usize, k: &mut usize| {
                if cnt != 0 {
                    // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                    let q = unsafe { base.add(*k) };
                    // SAFETY: see above.
                    unsafe { small_fill(q, byte, cnt) };
                    *k += cnt;
                }
            };
            if !zero_pad {
                fill(b' ', pad, &mut k);
            }
            copy(sign, &mut k);
            copy(p.prefix, &mut k);
            if zero_pad {
                fill(b'0', pad, &mut k);
            }
            copy(p.int, &mut k);
            fill(b'0', p.int_zeros, &mut k);
            if p.point {
                // SAFETY: as below: the address stays inside the object (an in-bounds `add`, which the compiler folds better).
                let q = unsafe { base.add(k) };
                // SAFETY: see above.
                unsafe { *q = b'.' };
                k += 1;
            }
            fill(b'0', p.frac_lead_zeros, &mut k);
            copy(p.frac, &mut k);
            fill(b'0', p.frac_zeros, &mut k);
            copy(&p.tail[..p.tail_len], &mut k);
            // SAFETY: see above: the first `k` bytes were written.
            o.put(unsafe { core::slice::from_raw_parts(base, k) });
            return;
        }
    }
    let point: &[u8] = if p.point { b"." } else { b"" };
    let n = Num {
        sign,
        prefix: p.prefix,
        zeros: 0,
        body: p.int,
        tail: &p.tail[..p.tail_len],
        mid: [
            Piece::Zeros(p.int_zeros),
            Piece::Bytes(point),
            Piece::Zeros(p.frac_lead_zeros),
            Piece::Bytes(p.frac),
            Piece::Zeros(p.frac_zeros),
        ],
    };
    write_num(o, &n, s.width, s.flags.left, zero_pad, float_rpad(s));
}

#[allow(clippy::collapsible_if)]
/// `%La`: the x87 format has an explicit leading bit, and glibc prints its top hex digit as is.
#[allow(clippy::too_many_arguments)]
fn emit_hex_ld<S: Sink>(o: &mut Out<S>, s: &Spec, sign: &[u8], mant: u64, exp2: i32, upper: bool, zero_pad: bool, rm: u8) {
    let digs: &[u8; 16] = if upper { b"0123456789ABCDEF" } else { b"0123456789abcdef" };
    let mut exp = if mant == 0 { 0 } else { exp2 + 60 };
    // 16 hex digits of the 64-bit mantissa: the first is the integer part, 15 follow the point
    let mut nib = [0u8; 16];
    for (i, n) in nib.iter_mut().enumerate() {
        *n = ((mant >> (60 - 4 * i)) & 0xf) as u8;
    }
    let mut lead = nib[0];
    let mut frac_n = 15usize;
    if let Some(p) = s.prec {
        if p < 15 {
            let first = nib[1 + p];
            let rest = nib[2 + p..].iter().any(|&x| x != 0);
            let prev = if p == 0 { lead } else { nib[p] };
            let up = match rm {
                1 => first != 0 || rest,
                2 => false,
                _ => first > 8 || (first == 8 && (rest || prev % 2 == 1)),
            };
            frac_n = p;
            if up {
                let mut i = p;
                loop {
                    if i == 0 {
                        lead += 1;
                        if lead == 16 {
                            // 0xf.f rounded up is 0x10.0: glibc prints it as 0x1.0 with the exponent raised by 4
                            lead = 1;
                            exp += 4;
                        }
                        break;
                    }
                    if nib[i] == 15 {
                        nib[i] = 0;
                        i -= 1;
                    } else {
                        nib[i] += 1;
                        break;
                    }
                }
            }
        }
    }
    let mut digits = [0u8; 15];
    for i in 0..frac_n.min(15) {
        digits[i] = digs[nib[1 + i] as usize];
    }
    let mut shown = frac_n.min(15);
    let want = match s.prec {
        Some(p) => p,
        None => {
            while shown > 0 && nib[shown] == 0 {
                shown -= 1;
            }
            shown
        }
    };
    let lead_c = [digs[lead as usize]];
    let (t, tl) = {
        let mut t = [0u8; 8];
        t[0] = if upper { b'P' } else { b'p' };
        t[1] = if exp < 0 { b'-' } else { b'+' };
        let mut v = exp.unsigned_abs();
        let mut tmp = [0u8; 6];
        let mut k = 6;
        loop {
            k -= 1;
            tmp[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        let mut n = 2;
        for &d in &tmp[k..] {
            t[n] = d;
            n += 1;
        }
        (t, n)
    };
    let p = float::Pieces {
        prefix: if upper { b"0X" } else { b"0x" },
        int: &lead_c,
        int_zeros: 0,
        point: want > 0 || s.flags.alt,
        frac_lead_zeros: 0,
        frac: &digits[..shown],
        frac_zeros: want.saturating_sub(shown),
        tail: t,
        tail_len: tl,
    };
    write_pieces(o, s, sign, &p, zero_pad);
}
