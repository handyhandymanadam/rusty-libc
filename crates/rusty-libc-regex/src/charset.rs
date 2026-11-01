//! The character set the matcher works in: everything locale dependent in the parser and the matcher goes
//! through these functions: classification of a character, case conversion (glibc's REG_ICASE converts the
//! pattern and the text to upper case), the word characters used by `\w \b \< \>`, the collation order used by
//! bracket ranges, and, in multibyte locales, how a byte string splits into characters.
//!
//! Single-byte locales (the C locale and the ISO-8859-x ones) classify bytes with the locale's ctype tables, as
//! glibc's `isalnum`, `toupper` ... do. Multibyte locales (UTF-8, EUC-JP ...) work on wide characters
//! (`iswalnum`, `towupper`, `mbrtowc`): see `mbset` for how a set of characters becomes byte automata.
use rusty_libc_wchar::Charset;
use rusty_libc_wchar::mbyte::{Decoded, decode_cs};

/// Character classes of `[[:name:]]`, in glibc's order of testing.
pub const CLASS_NAMES: [&[u8]; 12] =
    [b"alnum", b"cntrl", b"lower", b"space", b"alpha", b"digit", b"print", b"upper", b"blank", b"graph", b"punct", b"xdigit"];

/// Is the byte `c` in class number `class` (index into CLASS_NAMES), in the locale in force?
pub fn in_class(class: usize, c: u8) -> bool {
    let c = c as i32;
    match class {
        0 => rusty_libc_ctype::is_alnum(c),
        1 => rusty_libc_ctype::is_cntrl(c),
        2 => rusty_libc_ctype::is_lower(c),
        3 => rusty_libc_ctype::is_space(c),
        4 => rusty_libc_ctype::is_alpha(c),
        5 => rusty_libc_ctype::is_digit(c),
        6 => rusty_libc_ctype::is_print(c),
        7 => rusty_libc_ctype::is_upper(c),
        8 => rusty_libc_ctype::is_blank(c),
        9 => rusty_libc_ctype::is_graph(c),
        10 => rusty_libc_ctype::is_punct(c),
        11 => rusty_libc_ctype::is_xdigit(c),
        _ => false,
    }
}

pub fn class_by_name(name: &[u8]) -> Option<usize> {
    CLASS_NAMES.iter().position(|n| *n == name)
}

pub fn to_upper(c: u8) -> u8 {
    rusty_libc_ctype::to_upper(c as i32) as u8
}

pub fn to_lower(c: u8) -> u8 {
    rusty_libc_ctype::to_lower(c as i32) as u8
}

/// glibc's IS_WORD_CHAR: isalnum or underscore.
#[inline]
pub fn is_word(c: u8) -> bool {
    rusty_libc_ctype::is_alnum(c as i32) || c == b'_'
}

/// Collation sequence value of a byte in the C locale (the C locale collates by byte value).
pub fn collseq(c: u8) -> u32 {
    c as u32
}

pub use rusty_libc_locale::coll::{Collation, NO_SEQ};

// ---- multibyte locales ----

/// How the locale in force turns bytes into characters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mb {
    /// One byte is one character.
    None,
    Utf8,
    /// Another multibyte charset (EUC-JP, EUC-KR, GBK ...), decoded with rusty-libc-iconv.
    Other,
}

/// The multibyte kind of the locale in force (`MB_CUR_MAX > 1`).
pub fn mb_kind() -> Mb {
    if rusty_libc_wchar::mbyte::mb_cur_max() <= 1 {
        return Mb::None;
    }
    match rusty_libc_wchar::charset() {
        Charset::Utf8 => Mb::Utf8,
        Charset::Other => Mb::Other,
        Charset::C => Mb::None,
    }
}

fn cs_of(k: Mb) -> Charset {
    match k {
        Mb::Utf8 => Charset::Utf8,
        Mb::Other => Charset::Other,
        Mb::None => Charset::C,
    }
}

/// The character at the start of `bytes`: its value and length, or `None` when the bytes do not start a valid
/// character (glibc then treats the byte as a character of its own, with the value of the byte).
pub fn decode(k: Mb, bytes: &[u8]) -> Option<(u32, usize)> {
    if let Some(&b) = bytes.first()
        && b < 0x80
        && k == Mb::Utf8
    {
        return Some((b as u32, 1));
    }
    match decode_cs(cs_of(k), bytes) {
        Decoded::Char(w, n) => Some((w, n)),
        _ => None,
    }
}

/// Encode a character in the locale's charset.
pub fn encode(k: Mb, wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    rusty_libc_wchar::mbyte::encode_cs(cs_of(k), wc, out)
}

/// glibc's IS_WIDE_WORD_CHAR: `iswalnum` or underscore.
pub fn is_word_wc(wc: u32) -> bool {
    wc == b'_' as u32 || rusty_libc_wchar::wctype::is_alnum(wc)
}

/// `towlower` in the locale in force.
pub fn lower_wc(wc: u32) -> u32 {
    rusty_libc_wchar::wctype::to_lower(wc)
}

/// `towupper` in the locale in force.
pub fn upper_wc(wc: u32) -> u32 {
    rusty_libc_wchar::wctype::to_upper(wc)
}

/// Is the character `wc` in the wide class named `name`?
pub fn in_class_wc(class: usize, wc: u32) -> bool {
    use rusty_libc_wchar::wctype as w;
    match class {
        0 => w::is_alnum(wc),
        1 => w::is_cntrl(wc),
        2 => w::is_lower(wc),
        3 => w::is_space(wc),
        4 => w::is_alpha(wc),
        5 => w::is_digit(wc),
        6 => w::is_print(wc),
        7 => w::is_upper(wc),
        8 => w::is_blank(wc),
        9 => w::is_graph(wc),
        10 => w::is_punct(wc),
        11 => w::is_xdigit(wc),
        _ => false,
    }
}

/// The single bytes that are complete characters of the charset (glibc's `sb_char`): 0..0x7f in UTF-8.
pub fn sb_chars(k: Mb) -> [u64; 4] {
    if k == Mb::Utf8 {
        // a byte is a whole character exactly when it is ASCII (every compile asks; 256 decodes each time were a third of it)
        return [!0, !0, 0, 0];
    }
    // the other charsets: made once per locale (256 decodes through rusty-libc-iconv were about 20 us of every first compile)
    let Some(d) = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) else {
        return sb_chars_btowc(k);
    };
    let key = core::ptr::from_ref(d) as usize;
    let name = d.bytes(14);
    let nl = name.len().min(47);
    SB_CACHE.with(|c| {
        if !(c.valid && c.key == key && c.name_len == nl && c.name[..nl] == name[..nl]) {
            c.set = sb_chars_btowc(k);
            c.key = key;
            c.name = [0; 48];
            c.name[..nl].copy_from_slice(&name[..nl]);
            c.name_len = nl;
            c.valid = true;
        }
        c.set
    })
}

struct SbCache {
    valid: bool,
    key: usize,
    name: [u8; 48],
    name_len: usize,
    set: [u64; 4],
}

static SB_CACHE: crate::sync::Spin<SbCache> = crate::sync::Spin::new(SbCache { valid: false, key: 0, name: [0; 48], name_len: 0, set: [0; 4] });

/// glibc's `sb_char`, which its regex builds from `btowc`: the bytes `sb_chars_decoded` finds, except that GBK's byte 0x80
/// (the euro sign to `mbrtowc`) is no single-byte character to `btowc` (see `rusty_libc_wchar::btowc`), so `.` and `[^x]`
/// do not take it alone (FIXLIST #143).
fn sb_chars_btowc(k: Mb) -> [u64; 4] {
    // (from the charset's decoder body without 256 trips through mbrtowc, when it can say: FIXLIST #148)
    let mut s = rusty_libc_wchar::mbyte::other_single_bytes().filter(|_| k == Mb::Other).unwrap_or_else(|| sb_chars_decoded(k));
    let (name, nl) = rusty_libc_wchar::mbyte::codeset_name();
    if name[..nl].eq_ignore_ascii_case(b"GBK") {
        s[2] &= !1;
    }
    s
}

/// `sb_chars` by decoding every byte.
pub(crate) fn sb_chars_decoded(k: Mb) -> [u64; 4] {
    let mut s = [0u64; 4];
    for b in 0..=255u32 {
        let ok = matches!(decode_cs(cs_of(k), &[b as u8]), Decoded::Char(_, 1));
        if ok {
            s[(b >> 6) as usize] |= 1u64 << (b & 63);
        }
    }
    s
}
