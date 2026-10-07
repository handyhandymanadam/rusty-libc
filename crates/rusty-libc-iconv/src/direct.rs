use crate::directdata::{BIG5_TO_GB, GB_TO_BIG5, IBM420_TO_1008, IBM1008_TO_420};
use crate::engine::{IGNORE, St};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    GbkToGb,
    GbToGbk,
    GbToBig5,
    Big5ToGb,
    Ibm1008To420,
    Ibm420To1008,
}

pub fn run(k: Kind, flags: u32, inp: &[u8], ip: &mut usize, out: &mut [u8], op: &mut usize, irr: &mut usize) -> St {
    let mut result = St::Empty;
    let (mut i, mut o) = (*ip, *op);
    let (end, cap) = (inp.len(), out.len());
    let ignore = flags & IGNORE != 0;
    while i != end {
        if o >= cap {
            result = St::Full;
            break;
        }
        match k {
            Kind::Ibm1008To420 => {
                out[o] = IBM1008_TO_420[inp[i] as usize];
                o += 1;
                i += 1;
            }
            Kind::Ibm420To1008 => {
                out[o] = IBM420_TO_1008[inp[i] as usize];
                o += 1;
                i += 1;
            }
            Kind::GbkToGb => {
                let ch = inp[i] as u32;
                if ch <= 0x7f {
                    out[o] = ch as u8;
                    o += 1;
                    i += 1;
                } else {
                    if i + 1 >= end {
                        result = St::Incomplete;
                        break;
                    }
                    if cap - o < 2 {
                        result = St::Full;
                        break;
                    }
                    let mut code = (ch << 8) | inp[i + 1] as u32;
                    if code == 0xa844 {
                        code = 0xa1aa;
                    }
                    if code < 0xa1a1 || code > 0xf7fe || inp[i + 1] < 0xa1 || (0xa2a1..=0xa2aa).contains(&code) || (0xa6e0..=0xa6f5).contains(&code) || (0xa8bb..=0xa8c0).contains(&code) {
                        result = St::Illegal;
                        if !ignore {
                            break;
                        }
                        i += 2;
                        *irr += 1;
                        *irr |= crate::engine::ILLEGAL_SEEN;
                        continue;
                    }
                    out[o] = inp[i];
                    out[o + 1] = inp[i + 1];
                    o += 2;
                    i += 2;
                }
            }
            Kind::GbToGbk => {
                let ch = inp[i];
                i += 1;
                if ch > 0x7f {
                    if i + 1 >= end {
                        result = St::Incomplete;
                        break;
                    }
                    if cap - o < 2 {
                        result = St::Full;
                        break;
                    }
                    out[o] = ch;
                    o += 1;
                    out[o] = inp[i];
                    o += 1;
                    i += 1;
                } else {
                    out[o] = ch;
                    o += 1;
                }
            }
            Kind::GbToBig5 | Kind::Big5ToGb => {
                let ch = inp[i] as u32;
                let (lo, hi) = if k == Kind::GbToBig5 { (0xa1, 0xf7) } else { (0xa1, 0xf9) };
                if ch <= 0x7f {
                    out[o] = ch as u8;
                    o += 1;
                    i += 1;
                } else if ch >= lo && ch <= hi {
                    if i + 1 >= end {
                        result = St::Incomplete;
                        break;
                    }
                    let b2 = inp[i + 1] as u32;
                    let idx = if k == Kind::GbToBig5 {
                        if b2 < 0xa1 {
                            result = St::Illegal;
                            if !ignore {
                                break;
                            }
                            i += 1;
                            *irr += 1;
                            *irr |= crate::engine::ILLEGAL_SEEN;
                            continue;
                        }
                        ((ch - 0xa1) * 94 + (b2 - 0xa1)) as usize
                    } else if (0x40..=0x7e).contains(&b2) {
                        ((ch - 0xa1) * 157 + (b2 - 0x40)) as usize
                    } else if (0xa1..=0xfe).contains(&b2) {
                        ((ch - 0xa1) * 157 + 0x3f + (b2 - 0xa1)) as usize
                    } else {
                        result = St::Illegal;
                        if !ignore {
                            break;
                        }
                        i += 1;
                        *irr += 1;
                        *irr |= crate::engine::ILLEGAL_SEEN;
                        continue;
                    };
                    let tab: &[u16] = if k == Kind::GbToBig5 { &GB_TO_BIG5 } else { &BIG5_TO_GB };
                    let v = tab.get(idx).copied().unwrap_or(0);
                    if v == 0 {
                        result = St::Illegal;
                        if !ignore {
                            break;
                        }
                        *irr |= crate::engine::ILLEGAL_SEEN;
                        if o + 1 >= cap {
                            result = St::Full;
                            break;
                        }
                        let (a, b) = if k == Kind::GbToBig5 { (0xa1, 0xbc) } else { (0xa1, 0xf5) };
                        out[o] = a;
                        out[o + 1] = b;
                        o += 2;
                        i += 2;
                        *irr += 1;
                        *irr |= crate::engine::ILLEGAL_SEEN;
                        continue;
                    }
                    let two = v >= 0x100;
                    if two && o + 1 >= cap {
                        result = St::Full;
                        break;
                    }
                    if two {
                        out[o] = (v >> 8) as u8;
                        out[o + 1] = v as u8;
                        o += 2;
                    } else {
                        out[o] = v as u8;
                        o += 1;
                    }
                    i += 2;
                } else {
                    result = St::Illegal;
                    if !ignore {
                        break;
                    }
                    i += 1;
                    *irr += 1;
                    *irr |= crate::engine::ILLEGAL_SEEN;
                }
            }
        }
    }
    *ip = i;
    *op = o;
    result
}
