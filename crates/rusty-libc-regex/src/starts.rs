//! Where the characters of a text start, in a multibyte charset that is neither C nor UTF-8 (EUC-JP, GBK ...): glibc builds the
//! same from `mbrtowc` (a valid character is one unit, an invalid byte a character of its own).
//!
//! Decoding every character through rusty-libc-iconv costs 60 to 100 ns each, more than the DFA spends on the whole text. Three
//! shortcuts give the same answers:
//! * an ASCII byte at the start of a character is a character of its own in every such charset;
//! * in the stateless charsets (the EUC ones, GBK, GB2312, GB18030, BIG5) what a prefix of a character decodes to does not
//!   depend on the bytes after it, so the answer for a lead and second byte is remembered in a 64 KiB table (made on first use,
//!   per charset): a two byte character, one byte (not a character, or a one byte character), or "needs a third byte";
//! * for the last kind the answer for the first three bytes is kept in a small direct-mapped cache (EUC-JP's JIS X 0212, EUC-TW
//!   planes ...).
//!
//! What is left (four byte characters, the charsets that hold a character back for a combining mark, such as BIG5-HKSCS) takes
//! the full decoding.
use crate::charset;
use crate::sync::Spin;
use crate::vec::V;
use rusty_libc_wchar::Charset;
use rusty_libc_wchar::mbyte::{Decoded, decode_cs};

/// Characters looked at with the table's lock held (a long text does not keep other threads waiting).
const CHUNK: usize = 4096;
const PAIR_TWO: u8 = 1;
const PAIR_ONE: u8 = 2;
const PAIR_MORE: u8 = 3;
/// Entries of the three byte cache (a power of two).
const TRIPLE_SLOTS: usize = 1 << 14;
const T_THREE: u32 = 1;
const T_ONE: u32 = 2;
const T_FULL: u32 = 3;

struct Memo {
    /// Identity of the locale's ctype data and the codeset name it was made for.
    key: usize,
    name: [u8; 48],
    name_len: usize,
    /// By lead byte and second byte: 0 not looked at yet, else a `PAIR_*` verdict. Empty: no table (not a stateless charset,
    /// or no memory).
    pair: V<u8>,
    /// Direct-mapped: the first three bytes in the low 24 bits, a `T_*` verdict above them; 0 is an empty slot.
    triple: V<u32>,
}

static MEMO: Spin<Memo> = Spin::new(Memo { key: 0, name: [0; 48], name_len: 0, pair: V::new(), triple: V::new() });

/// The codesets whose characters never depend on the bytes after them.
fn is_stateless(name: &[u8]) -> bool {
    let mut norm = [0u8; 48];
    let mut n = 0;
    for &c in name {
        if c != b'-' && c != b'_' && n < norm.len() {
            norm[n] = c.to_ascii_uppercase();
            n += 1;
        }
    }
    matches!(&norm[..n], b"EUCJP" | b"EUCKR" | b"EUCTW" | b"GBK" | b"GB2312" | b"GB18030" | b"BIG5" | b"UHC" | b"CP949")
}

/// Is every ASCII byte a character start in the charset in force? (The EUC charsets have no trail bytes below 0x80.)
pub fn ascii_always_starts() -> bool {
    let Some(d) = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) else {
        return false;
    };
    let name = d.bytes(14);
    let mut norm = [0u8; 48];
    let mut n = 0;
    for &c in name {
        if c != b'-' && c != b'_' && n < norm.len() {
            norm[n] = c.to_ascii_uppercase();
            n += 1;
        }
    }
    matches!(&norm[..n], b"EUCJP" | b"EUCKR" | b"EUCTW" | b"GB2312")
}

/// The length of the character that starts `text[i..]` in the charset in force.
fn decode_len(text: &[u8], i: usize) -> usize {
    match charset::decode(charset::Mb::Other, &text[i..text.len().min(i + 6)]) {
        Some((_, n)) => n.max(1),
        None => 1,
    }
}

impl Memo {
    /// Make the tables for the charset in force when they were made for another.
    fn refresh(&mut self) {
        let Some(d) = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) else {
            // (the C locale, after a pattern was compiled in another: the tables of the charset before do not apply)
            self.key = 0;
            self.pair = V::new();
            self.triple = V::new();
            return;
        };
        let key = core::ptr::from_ref(d) as usize;
        let name = d.bytes(14);
        let nl = name.len().min(47);
        if self.key == key && self.name_len == nl && self.name[..nl] == name[..nl] {
            return;
        }
        self.key = key;
        self.name = [0; 48];
        self.name[..nl].copy_from_slice(&name[..nl]);
        self.name_len = nl;
        self.pair = V::new();
        self.triple = V::new();
        if is_stateless(&name[..nl]) {
            self.pair = V::from_elem(0, 1 << 16);
            if self.pair.oom {
                self.pair = V::new();
            }
        }
    }

    /// The length of the character at `text[at..]` (the byte there is not ASCII).
    fn char_len(&mut self, text: &[u8], at: usize) -> usize {
        let len = text.len();
        if self.pair.len() != 1 << 16 || at + 1 >= len {
            return decode_len(text, at);
        }
        let k = usize::from(text[at]) << 8 | usize::from(text[at + 1]);
        let mut e = self.pair[k];
        if e == 0 {
            e = match decode_cs(Charset::Other, &text[at..at + 2]) {
                Decoded::Char(_, 2) => PAIR_TWO,
                Decoded::Incomplete => PAIR_MORE,
                _ => PAIR_ONE,
            };
            self.pair[k] = e;
        }
        match e {
            PAIR_TWO => 2,
            PAIR_ONE => 1,
            _ if at + 2 < len => self.triple_len(text, at),
            _ => decode_len(text, at),
        }
    }

    /// A character whose first two bytes are the start of a longer one.
    fn triple_len(&mut self, text: &[u8], at: usize) -> usize {
        if self.triple.is_empty() {
            self.triple = V::from_elem(0, TRIPLE_SLOTS);
            if self.triple.oom {
                self.triple = V::new();
                return decode_len(text, at);
            }
        }
        let k = u32::from(text[at]) | u32::from(text[at + 1]) << 8 | u32::from(text[at + 2]) << 16;
        let slot = (k.wrapping_mul(0x9e37_79b1) >> 18) as usize & (TRIPLE_SLOTS - 1);
        let e = self.triple[slot];
        if e & 0xff_ffff == k && e >> 24 != 0 {
            return match e >> 24 {
                T_THREE => 3,
                T_ONE => 1,
                _ => decode_len(text, at),
            };
        }
        let v = match decode_cs(Charset::Other, &text[at..at + 3]) {
            Decoded::Char(_, 3) => T_THREE,
            Decoded::Incomplete => T_FULL,
            Decoded::Char(_, 1) | Decoded::Invalid => T_ONE,
            Decoded::Char(..) => T_FULL,
        };
        self.triple[slot] = k | v << 24;
        match v {
            T_THREE => 3,
            T_ONE => 1,
            _ => decode_len(text, at),
        }
    }
}

/// `bits` (zeros, room for one bit more than `text` has bytes) gets a 1 at every byte that starts a character.
pub fn fill(text: &[u8], bits: &mut [u64]) {
    let len = text.len();
    let mut i = 0;
    while i < len {
        let stop = (i + CHUNK).min(len);
        i = MEMO.with(|m| {
            m.refresh();
            let mut at = i;
            // (the bits of a word are collected in a register: a read-modify-write of memory for each character was most of the time)
            let mut word = at >> 6;
            let mut acc = 0u64;
            while at < stop {
                if at >> 6 != word {
                    bits[word] |= acc;
                    word = at >> 6;
                    acc = 0;
                }
                acc |= 1 << (at & 63);
                at += if text[at] < 0x80 { 1 } else { m.char_len(text, at) };
            }
            bits[word] |= acc;
            at
        });
    }
    bits[len >> 6] |= 1 << (len & 63);
}
