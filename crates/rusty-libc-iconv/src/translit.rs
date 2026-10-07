use crate::engine::{EBody, St, enc_loop};
use crate::translit_tables::{DEFAULT_MISSING, FROM_IDX, FROM_TBL, TO_IDX, TO_TBL};

enum Tab {
    C,
    Locale(Loc),
}

struct Loc {
    size: usize,
    src_idx: *const u32,
    src_tbl: *const u32,
    to_idx: *const u32,
    to_tbl: *const u32,
    default_missing: *const u32,
    default_missing_len: usize,
    ignore: *const u32,
    ignore_len: usize,
}

impl Tab {
    fn current() -> Tab {
        let ct = rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE);
        if ct.is_null() {
            return Tab::C;
        }
        let d = unsafe { &*ct };
        if d.flags & rusty_libc_core::locale::F_BUILTIN_C != 0 || d.nstrings < 70 {
            return Tab::C;
        }
        let wp = |i: usize| d.cstr(i) as *const u32;
        Tab::Locale(Loc {
            size: d.word(61) as usize,
            src_idx: wp(62),
            src_tbl: wp(63),
            to_idx: wp(64),
            to_tbl: wp(65),
            default_missing: wp(67),
            default_missing_len: d.word(66) as usize,
            ignore: wp(69),
            ignore_len: d.word(68) as usize,
        })
    }

    fn size(&self) -> usize {
        match self {
            Tab::C => FROM_IDX.len(),
            Tab::Locale(l) => l.size,
        }
    }

    fn src_idx(&self, i: usize) -> usize {
        match self {
            Tab::C => FROM_IDX[i] as usize,
            Tab::Locale(l) => unsafe { *l.src_idx.add(i) as usize },
        }
    }

    fn to_idx(&self, i: usize) -> usize {
        match self {
            Tab::C => TO_IDX[i] as usize,
            Tab::Locale(l) => unsafe { *l.to_idx.add(i) as usize },
        }
    }

    fn src_tbl(&self, i: usize) -> u32 {
        match self {
            Tab::C => FROM_TBL[i],
            Tab::Locale(l) => unsafe { *l.src_tbl.add(i) },
        }
    }

    fn to_tbl(&self, i: usize) -> u32 {
        match self {
            Tab::C => TO_TBL[i],
            Tab::Locale(l) => unsafe { core::ptr::read_volatile(l.to_tbl.add(i)) },
        }
    }

    fn to_slice(&self, idx: usize, len: usize) -> &[u32] {
        match self {
            Tab::C => &TO_TBL[idx..idx + len],
            Tab::Locale(l) => unsafe { core::slice::from_raw_parts(l.to_tbl.add(idx), len) },
        }
    }

    fn default_missing(&self) -> &[u32] {
        match self {
            Tab::C => &DEFAULT_MISSING,
            Tab::Locale(l) => unsafe { core::slice::from_raw_parts(l.default_missing, l.default_missing_len) },
        }
    }

    fn ignored(&self, c: u32) -> bool {
        let Tab::Locale(l) = self else { return false };
        for i in 0..l.ignore_len {
            let (lo, hi, step) = unsafe { (*l.ignore.add(3 * i), *l.ignore.add(3 * i + 1), *l.ignore.add(3 * i + 2)) };
            if lo <= c && c <= hi && step != 0 && (c - lo).is_multiple_of(step) {
                return true;
            } else if c < lo {
                break;
            }
        }
        false
    }
}

#[allow(clippy::too_many_arguments)]
pub fn transliterate<F: FnMut(&[u32], &mut [u8]) -> EBody>(
    flags: u32,
    inp: &[u32],
    out: &mut [u8],
    used: &mut usize,
    wrote: &mut usize,
    irr: &mut usize,
    min_out: usize,
    tags: bool,
    prep: &mut dyn FnMut(&mut [u8], &mut usize) -> Option<St>,
    body: &mut F,
) -> St {
    let tab = Tab::current();
    let size = tab.size();
    let end = inp.len();
    if end == 0 {
        return St::Empty;
    }
    let mut low = 0usize;
    let mut high = size;
    while low < high {
        let med = (low + high) / 2;
        let idx = tab.src_idx(med);
        let mut cnt = 0usize;
        loop {
            if tab.src_tbl(idx + cnt) != inp[cnt] {
                break;
            }
            cnt += 1;
            if !(tab.src_tbl(idx + cnt) != 0 && cnt < end) {
                break;
            }
        }
        if cnt > 0 && tab.src_tbl(idx + cnt) == 0 {
            let mut idx2 = tab.to_idx(med);
            loop {
                let mut len = 0usize;
                while tab.to_tbl(idx2 + len) != 0 {
                    len += 1;
                }
                let alt = tab.to_slice(idx2, len);
                let mut ai = 0usize;
                let mut ao = 0usize;
                let mut res = match prep(out, &mut ao) {
                    Some(st) => st,
                    None => enc_loop(flags, alt, &mut ai, out, &mut ao, None, min_out, tags, prep, crate::engine::no_fast_enc, body),
                };
                if res != St::Illegal {
                    if res == St::Empty {
                        *used = cnt;
                        *irr += 1;
                        res = St::Ok;
                    }
                    if res != St::Full {
                        *wrote = ao;
                    }
                    return res;
                }
                idx2 += len + 1;
                if tab.to_tbl(idx2) == 0 {
                    break;
                }
            }
        } else if cnt > 0 && cnt == end {
            return St::Incomplete;
        }
        if cnt >= end || tab.src_tbl(idx + cnt) < inp[cnt] {
            low = med + 1;
        } else {
            high = med;
        }
    }
    if tab.ignored(inp[0]) {
        *used = 1;
        *wrote = 0;
        *irr += 1;
        return St::Ok;
    }
    let default = tab.default_missing();
    if !default.is_empty() {
        let mut ai = 0usize;
        let mut ao = 0usize;
        let mut res = match prep(out, &mut ao) {
            Some(st) => st,
            None => enc_loop(flags, default, &mut ai, out, &mut ao, None, min_out, tags, prep, crate::engine::no_fast_enc, body),
        };
        if res != St::Illegal {
            if res == St::Empty {
                *irr += 1;
                *used = 1;
                res = St::Ok;
            }
            *wrote = ao;
            return res;
        }
    }
    St::Illegal
}
