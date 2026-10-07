use core::sync::atomic::{AtomicBool, Ordering};
use rusty_libc_iconv::Converter;
use rusty_libc_wchar::mbstate_t;
use rusty_libc_wchar::mbyte::{Status, codeset_name};

pub(crate) fn install() {
    rusty_libc_wchar::mbyte::set_other_hooks(towc, encode, each, tomb);
}

struct Slot {
    name: [u8; 48],
    len: usize,
    conv: Option<Converter>,
}

static LOCK: AtomicBool = AtomicBool::new(false);
static mut SLOTS: [Slot; 3] = [Slot { name: [0; 48], len: 0, conv: None }, Slot { name: [0; 48], len: 0, conv: None }, Slot { name: [0; 48], len: 0, conv: None }];

fn lock() {
    while LOCK.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
}

fn unlock() {
    LOCK.store(false, Ordering::Release);
}

fn take(dir: usize, name: &[u8]) -> Option<Converter> {
    lock();
    let slot = unsafe { &mut (*core::ptr::addr_of_mut!(SLOTS))[dir] };
    let have = if slot.len == name.len() && slot.name[..slot.len] == *name { slot.conv.take() } else { None };
    unlock();
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
    lock();
    let slot = unsafe { &mut (*core::ptr::addr_of_mut!(SLOTS))[dir] };
    slot.name[..name.len()].copy_from_slice(name);
    slot.len = name.len();
    slot.conv = Some(conv);
    unlock();
}

pub(crate) unsafe fn towc(st: &mut mbstate_t, src: &mut *const u8, avail: usize, out: *mut u32, cap: usize) -> (Status, usize) {
    let (name, nl) = codeset_name();
    let Some(mut conv) = take(0, &name[..nl]) else { return (Status::Illegal, 0) };
    let r = unsafe { towc_with(&mut conv, st, src, avail, out, cap) };
    give_back(0, &name[..nl], conv);
    r
}

unsafe fn towc_with(conv: &mut Converter, st: &mut mbstate_t, src: &mut *const u8, mut avail: usize, out: *mut u32, cap: usize) -> (Status, usize) {
    unsafe {
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
            let high = (st.count as u32) & !7;
            let mut taken = 0usize;
            let mut give_back = 0usize;
            let (ch, new_high) = loop {
                if taken == avail {
                    let mut v = 0u32;
                    for (i, b) in buf.iter().enumerate().take(n) {
                        v |= u32::from(*b) << (8 * i);
                    }
                    st.count = (n as u32 | high) as i32;
                    st.value = v;
                    *src = (*src).add(taken);
                    return (Status::Incomplete, produced);
                }
                if n >= 4 {
                    return (Status::Illegal, produced);
                }
                buf[n] = *(*src).add(taken);
                n += 1;
                taken += 1;
                conv.set_dec_state_word(high);
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
            *src = (*src).add(used);
            avail -= used;
            st.count = new_high as i32;
            if let Some(ch) = ch {
                *out.add(produced) = ch;
                produced += 1;
            }
        }
    }
}

pub(crate) fn encode(wc: u32, out: &mut [u8; 6]) -> Option<usize> {
    let (name, nl) = codeset_name();
    let mut conv = take(1, &name[..nl])?;
    let inp = wc.to_le_bytes();
    let mut o = [0u8; 16];
    let (mut ip, mut op) = (0usize, 0usize);
    let r = conv.convert_raw(&inp, &mut ip, &mut o, &mut op);
    let ok = r.is_ok() && ip == 4 && op != 0 && op <= 6;
    give_back(1, &name[..nl], conv);
    if !ok {
        return None;
    }
    out[..op].copy_from_slice(&o[..op]);
    Some(op)
}

pub(crate) unsafe fn tomb(st: &mut mbstate_t, src: &mut *const u32, avail: usize, out: *mut u8, cap: usize) -> (Status, usize) {
    let (name, nl) = codeset_name();
    let Some(mut conv) = take(2, &name[..nl]) else { return (Status::Illegal, 0) };
    conv.set_enc_state_word((st.count as u32) & !7);
    let (inp, o) = unsafe { (core::slice::from_raw_parts(*src as *const u8, avail * 4), core::slice::from_raw_parts_mut(out, cap)) };
    let (mut ip, mut op) = (0usize, 0usize);
    let r = conv.convert_raw(inp, &mut ip, o, &mut op);
    st.count = ((conv.enc_state_word() & !7) | (st.count as u32 & 7)) as i32;
    *src = unsafe { (*src).add(ip / 4) };
    give_back(2, &name[..nl], conv);
    let status = match r {
        Ok(_) => Status::Empty,
        Err(rusty_libc_iconv::Error::E2big) => Status::Full,
        Err(rusty_libc_iconv::Error::Ilseq) => Status::Illegal,
        Err(rusty_libc_iconv::Error::Inval) => Status::Incomplete,
    };
    (status, op)
}

pub(crate) fn each(f: &mut dyn FnMut(&[u8], u32)) {
    let (name, nl) = codeset_name();
    let Some(mut conv) = take(0, &name[..nl]) else { return };
    let mut prefix = [0u8; 4];
    walk(&mut conv, &mut prefix, 0, f);
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
