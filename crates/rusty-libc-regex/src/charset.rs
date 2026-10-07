use rusty_libc_wchar::Charset;
use rusty_libc_wchar::mbyte::{Decoded, decode_cs};

pub const CLASS_NAMES: [&[u8]; 12] =
    [b"alnum", b"cntrl", b"lower", b"space", b"alpha", b"digit", b"print", b"upper", b"blank", b"graph", b"punct", b"xdigit"];

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

#[inline]
pub fn is_word(c: u8) -> bool {
    rusty_libc_ctype::is_alnum(c as i32) || c == b'_'
}

pub fn collseq(c: u8) -> u32 {
    c as u32
}

pub use rusty_libc_locale::coll::{Collation, NO_SEQ};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mb {
    None,
    Utf8,
    Other,
}

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

pub fn encode(k: Mb, wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    rusty_libc_wchar::mbyte::encode_cs(cs_of(k), wc, out)
}

pub fn is_word_wc(wc: u32) -> bool {
    wc == b'_' as u32 || rusty_libc_wchar::wctype::is_alnum(wc)
}

pub fn lower_wc(wc: u32) -> u32 {
    rusty_libc_wchar::wctype::to_lower(wc)
}

pub fn upper_wc(wc: u32) -> u32 {
    rusty_libc_wchar::wctype::to_upper(wc)
}

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

pub fn sb_chars(k: Mb) -> [u64; 4] {
    let mut s = [0u64; 4];
    for b in 0..=255u32 {
        let ok = matches!(decode_cs(cs_of(k), &[b as u8]), Decoded::Char(_, 1));
        if ok {
            s[(b >> 6) as usize] |= 1u64 << (b & 63);
        }
    }
    s
}
