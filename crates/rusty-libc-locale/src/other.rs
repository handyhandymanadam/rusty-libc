//! `mbrtowc` and `wcrtomb` for the locale charsets that are neither C nor UTF-8 (EUC-JP, GBK, ISO-8859-x ...), done with
//! rusty-libc-iconv. They are the hooks rusty-libc-wchar calls (`set_other_hooks`): the tables live behind them so that a program that
//! never leaves the C and UTF-8 locales does not carry them.
use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_core::sync_cell::SyncCell;
use rusty_libc_iconv::Converter;
use rusty_libc_wchar::mbstate_t;
use rusty_libc_wchar::mbyte::{Status, codeset_name};

/// Install the hooks (called when a locale with another charset is installed or created).
pub(crate) fn install() {
    rusty_libc_wchar::mbyte::set_other_hooks(towc, encode, each, tomb);
    rusty_libc_wchar::mbyte::set_other_rows_hook(rows);
    rusty_libc_wchar::mbyte::set_other_singles_hook(singles);
}

/// The single-byte characters of the codeset in force (`Converter::single_bytes`).
pub(crate) fn singles() -> Option<[u64; 4]> {
    let (name, nl) = codeset_name();
    let conv = take(0, &name[..nl])?;
    let s = conv.single_bytes();
    give_back(0, &name[..nl], conv);
    s
}

/// The multibyte characters of the codeset in force as rows (`Converter::each_row`).
pub(crate) fn rows(ranges: Option<&[(u32, u32)]>, f: &mut dyn FnMut(&[u8], &[u64; 4]), runs: &mut dyn FnMut(&[u8], u32, u32)) -> bool {
    let (name, nl) = codeset_name();
    let Some(conv) = take(0, &name[..nl]) else { return false };
    let ok = conv.each_row(ranges, f, runs);
    give_back(0, &name[..nl], conv);
    ok
}

/// One converter of each direction is kept for the next call (opening one costs more than a conversion): a call takes it
/// out of its slot and puts it back, so two threads never share one; a thread that finds the slot empty opens its own.
struct Slot {
    name: [u8; 48],
    len: usize,
    conv: Option<Converter>,
}

static LOCK: AtomicBool = AtomicBool::new(false);
/// The kept converters: touched only while LOCK (a spin lock: a slot is taken or given back in a few instructions) is held.
static SLOTS: SyncCell<[Slot; 3]> = SyncCell::new([Slot { name: [0; 48], len: 0, conv: None }, Slot { name: [0; 48], len: 0, conv: None }, Slot { name: [0; 48], len: 0, conv: None }]);

/// Run `f` on slot `dir` with LOCK held.
fn with_slot<R>(dir: usize, f: impl FnOnce(&mut Slot) -> R) -> R {
    while LOCK.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
    // SAFETY: LOCK is held, so nothing else touches SLOTS; `f` does not reach SLOTS again.
    let r = unsafe { SLOTS.with_unsync(|s| f(&mut s[dir])) };
    LOCK.store(false, Ordering::Release);
    r
}

/// A converter for `dir` (0: charset to UCS-4, 1: UCS-4 to charset, 2: INTERNAL to charset: only the encoder step) in the codeset in force, reset to its initial state.
fn take(dir: usize, name: &[u8]) -> Option<Converter> {
    let have = with_slot(dir, |slot| if slot.len == name.len() && slot.name[..slot.len] == *name { slot.conv.take() } else { None });
    match have {
        Some(mut c) => {
            let _ = c.flush_raw(None);
            Some(c)
        }
        None => {
            match dir {
                0 => Converter::open(b"UCS-4LE", name).ok(),
                1 => Converter::open(name, b"UCS-4LE").ok(),
                _ => Converter::open(name, b"WCHAR_T").ok(),
            }
        }
    }
}

fn give_back(dir: usize, name: &[u8], conv: Converter) {
    with_slot(dir, |slot| {
        slot.name[..name.len()].copy_from_slice(name);
        slot.len = name.len();
        slot.conv = Some(conv);
    });
}

/// `mbrtowc`-style decoding for a stateless multibyte charset (single byte sets and EUC): characters
/// are tried byte by byte until rusty-libc-iconv accepts them; a half-read character is kept in the state
/// (its length in `count`, its bytes in `value`).
pub(crate) unsafe fn towc(name: &[u8], st: &mut mbstate_t, src: &mut *const u8, avail: usize, out: *mut u32, cap: usize) -> (Status, usize) {
    let Some(mut conv) = take(0, name) else { return (Status::Illegal, 0) };
    // SAFETY: the hook's contract (up to `avail` readable bytes at `*src`, `cap` writable characters at `out`) is
    // towc_with's.
    let r = unsafe { towc_with(&mut conv, st, src, avail, out, cap) };
    give_back(0, name, conv);
    r
}

/// # Safety
/// Up to `avail` bytes at `*src` are readable (reading stops at the first character that completes, so `avail` may be
/// larger than the buffer, as mbrtowc's `n` may be); `cap` characters at `out` are writable.
unsafe fn towc_with(conv: &mut Converter, st: &mut mbstate_t, src: &mut *const u8, mut avail: usize, out: *mut u32, cap: usize) -> (Status, usize) {
    let mut produced = 0usize;
    loop {
        if avail == 0 {
            return (Status::Empty, produced);
        }
        if produced == cap {
            return (Status::Full, produced);
        }
        let mut buf = [0u8; 8];
        let inlen = (st.count & 7) as usize;
        let mut n = inlen.min(4);
        for (i, b) in buf.iter_mut().enumerate().take(n) {
            *b = (st.value >> (8 * i)) as u8;
        }
        // the character CP1255/CP1258/TCVN/BIG5-HKSCS hold back lives in the state's upper bits
        // (shifted left by 3, the lower 3 bits count the bytes of a half-read character), as in glibc
        let high = (st.count as u32) & !7;
        let mut taken = 0usize;
        let mut give_back = 0usize;
        // None: the byte went into the decoder (a base letter waiting for a combining mark)
        let (ch, new_high) = loop {
            if taken == avail {
                // the input ends inside a character: keep what was read
                let mut v = 0u32;
                for (i, b) in buf.iter().enumerate().take(n) {
                    v |= u32::from(*b) << (8 * i);
                }
                st.count = (n as u32 | high) as i32;
                st.value = v;
                *src = (*src).wrapping_add(taken);
                return (Status::Incomplete, produced);
            }
            if n >= 4 {
                return (Status::Illegal, produced);
            }
            // SAFETY: `taken < avail`: a readable byte (the caller's contract).
            buf[n] = unsafe { (*src).wrapping_add(taken).read() };
            n += 1;
            taken += 1;
            conv.set_dec_state_word(high);
            // room for one character, as in glibc's mbrtowc: when the held-back character comes out
            // first the new byte stays unread (E2big) and is read again by the next call
            let mut o = [0u32; 1];
            let (mut ip, mut op) = (0usize, 0usize);
            let Some(res) = conv.decode_ucs4(&buf[..n], &mut ip, &mut o, &mut op) else { return (Status::Illegal, produced) };
            match res {
                Ok(()) if ip == n && op == 1 => break (Some(o[0]), conv.dec_state_word() & !7),
                Ok(()) if ip == n && op == 0 && conv.dec_state_word() & !7 != 0 => break (None, conv.dec_state_word() & !7),
                Ok(()) => return (Status::Illegal, produced),
                Err(rusty_libc_iconv::Error::E2big) if op == 1 => {
                    give_back = n - ip;
                    break (Some(o[0]), conv.dec_state_word() & !7);
                }
                Err(rusty_libc_iconv::Error::Inval) => continue,
                Err(_) => return (Status::Illegal, produced),
            }
        };
        let used = taken.saturating_sub(give_back);
        *src = (*src).wrapping_add(used);
        avail -= used;
        st.count = new_high as i32;
        if let Some(ch) = ch {
            // SAFETY: `produced < cap`: a writable character (the caller's contract).
            unsafe { out.wrapping_add(produced).write(ch) };
            produced += 1;
        }
    }
}

/// Encode `wc` in codeset `name` (the locale's, or a wide stream's) with rusty-libc-iconv.
pub(crate) fn encode(name: &[u8], wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    let mut conv = take(1, name)?;
    let inp = wc.to_le_bytes();
    let mut o = [0u8; 16];
    let (mut ip, mut op) = (0usize, 0usize);
    let r = conv.convert_raw(&inp, &mut ip, &mut o, &mut op);
    let ok = r.is_ok() && ip == 4 && op != 0 && op <= 6;
    give_back(1, name, conv);
    if !ok {
        return None;
    }
    out[..op].copy_from_slice(&o[..op]);
    Some(op)
}

/// `wcsrtombs`-style encoding: the wide characters at `*src` (`avail` of them) into at most `cap` bytes at `out`, through
/// the whole encoder step with its state (BIG5-HKSCS holds U+00CA and U+00EA back in `count`, shifted left by 3). The step
/// decides in glibc's order between a full output, an unencodable character and a skipped tag character.
pub(crate) unsafe fn tomb(st: &mut mbstate_t, src: &mut *const u32, avail: usize, out: *mut u8, cap: usize) -> (Status, usize) {
    let (name, nl) = codeset_name();
    let Some(mut conv) = take(2, &name[..nl]) else { return (Status::Illegal, 0) };
    conv.set_enc_state_word((st.count as u32) & !7);
    // SAFETY: the caller passes `avail` readable wide characters at `*src`.
    let inp = unsafe { rusty_libc_core::ffi::bytes((*src).cast::<u8>(), avail * 4) };
    // SAFETY: and `cap` writable bytes at `out`, apart from the input.
    let o = unsafe { rusty_libc_core::ffi::bytes_mut(out, cap) };
    let (mut ip, mut op) = (0usize, 0usize);
    let r = conv.convert_raw(inp, &mut ip, o, &mut op);
    st.count = ((conv.enc_state_word() & !7) | (st.count as u32 & 7)) as i32;
    // (`ip / 4` characters were read)
    *src = (*src).wrapping_add(ip / 4);
    give_back(2, &name[..nl], conv);
    let status = match r {
        Ok(_) => Status::Empty,
        Err(rusty_libc_iconv::Error::E2big) => Status::Full,
        Err(rusty_libc_iconv::Error::Ilseq) => Status::Illegal,
        Err(rusty_libc_iconv::Error::Inval) => Status::Incomplete,
    };
    (status, op)
}

/// Every character of the codeset in force, found by trying the byte sequences: with one converter for the whole walk, which
/// is what makes the first bracket expression compiled in an EUC locale cost a few milliseconds less than character-wise
/// `mbrtowc` calls would.
pub(crate) fn each(f: &mut dyn FnMut(&[u8], u32, u32)) {
    let (name, nl) = codeset_name();
    let Some(mut conv) = take(0, &name[..nl]) else { return };
    // the stateless CJK charsets: the same walk with the decoder's per-character bodies called directly, without a reset
    // and the conversion loop for each candidate (same characters in the same order; EUC-JP has about 50,000 candidates)
    if !conv.each_char(f) {
        let mut prefix = [0u8; 4];
        walk(&mut conv, &mut prefix, 0, &mut |b, wc| f(b, wc, 1));
    }
    give_back(0, &name[..nl], conv);
}

fn walk(conv: &mut Converter, prefix: &mut [u8; 4], len: usize, f: &mut dyn FnMut(&[u8], u32)) {
    for b in 0..=255u8 {
        prefix[len] = b;
        let n = len + 1;
        let _ = conv.flush_raw(None);
        let mut o = [0u32; 1];
        let (mut ip, mut op) = (0usize, 0usize);
        match conv.decode_ucs4(&prefix[..n], &mut ip, &mut o, &mut op) {
            Some(Ok(())) if ip == n && op == 1 => f(&prefix[..n], o[0]),
            Some(Err(rusty_libc_iconv::Error::Inval)) if n < 4 => walk(conv, prefix, n, f),
            _ => {}
        }
    }
}
