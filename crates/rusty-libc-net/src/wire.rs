use crate::util::Buf;

pub const T_A: u16 = 1;
pub const T_NS: u16 = 2;
pub const T_CNAME: u16 = 5;
pub const T_SOA: u16 = 6;
pub const T_PTR: u16 = 12;
pub const T_MX: u16 = 15;
pub const T_TXT: u16 = 16;
pub const T_AAAA: u16 = 28;
pub const T_OPT: u16 = 41;
pub const T_ANY: u16 = 255;
pub const C_IN: u16 = 1;

pub const NOERROR: u8 = 0;
pub const FORMERR: u8 = 1;
pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;
pub const NOTIMP: u8 = 4;
pub const REFUSED: u8 = 5;

pub const MAXCDNAME: usize = 255;
pub const HFIXEDSZ: usize = 12;
pub const QFIXEDSZ: usize = 4;
pub const RRFIXEDSZ: usize = 10;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Header {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

pub const FLAG_QR: u16 = 0x8000;
pub const FLAG_AA: u16 = 0x0400;
pub const FLAG_TC: u16 = 0x0200;
pub const FLAG_RD: u16 = 0x0100;
pub const FLAG_RA: u16 = 0x0080;
pub const FLAG_AD: u16 = 0x0020;
pub const FLAG_CD: u16 = 0x0010;

impl Header {
    pub fn rcode(&self) -> u8 {
        (self.flags & 15) as u8
    }
    pub fn opcode(&self) -> u8 {
        ((self.flags >> 11) & 15) as u8
    }
    pub fn is_response(&self) -> bool {
        self.flags & FLAG_QR != 0
    }
    pub fn truncated(&self) -> bool {
        self.flags & FLAG_TC != 0
    }
    pub fn parse(m: &[u8]) -> Option<Header> {
        if m.len() < HFIXEDSZ {
            return None;
        }
        let g = |i: usize| ((m[i] as u16) << 8) | m[i + 1] as u16;
        Some(Header { id: g(0), flags: g(2), qdcount: g(4), ancount: g(6), nscount: g(8), arcount: g(10) })
    }
    pub fn write(&self, m: &mut [u8]) {
        let v = [self.id, self.flags, self.qdcount, self.ancount, self.nscount, self.arcount];
        for (i, x) in v.iter().enumerate() {
            m[2 * i] = (x >> 8) as u8;
            m[2 * i + 1] = *x as u8;
        }
    }
}

pub fn get16(m: &[u8], off: usize) -> Option<u16> {
    Some(((*m.get(off)? as u16) << 8) | *m.get(off + 1)? as u16)
}
pub fn get32(m: &[u8], off: usize) -> Option<u32> {
    Some(((get16(m, off)? as u32) << 16) | get16(m, off + 2)? as u32)
}
pub fn put16(m: &mut [u8], off: usize, v: u16) {
    m[off] = (v >> 8) as u8;
    m[off + 1] = v as u8;
}

pub fn name_pton(src: &[u8], dst: &mut [u8]) -> Option<(usize, bool)> {
    let mut bp = 1usize;
    let mut label = 0usize;
    let mut escaped = false;
    let mut i = 0usize;
    let at = |i: usize| src.get(i).copied().unwrap_or(0);
    while i < src.len() && src[i] != 0 {
        let mut c = src[i];
        i += 1;
        if escaped {
            if c.is_ascii_digit() {
                let mut n = (c - b'0') as u32 * 100;
                let c2 = at(i);
                i += 1;
                if !c2.is_ascii_digit() {
                    return None;
                }
                n += (c2 - b'0') as u32 * 10;
                let c3 = at(i);
                i += 1;
                if !c3.is_ascii_digit() {
                    return None;
                }
                n += (c3 - b'0') as u32;
                if n > 255 {
                    return None;
                }
                c = n as u8;
            }
            escaped = false;
        } else if c == b'\\' {
            escaped = true;
            continue;
        } else if c == b'.' {
            let len = bp - label - 1;
            if len & 0xc0 != 0 || label >= dst.len() {
                return None;
            }
            dst[label] = len as u8;
            if at(i) == 0 {
                if len != 0 {
                    if bp >= dst.len() {
                        return None;
                    }
                    dst[bp] = 0;
                    bp += 1;
                }
                if bp > MAXCDNAME {
                    return None;
                }
                return Some((bp, true));
            }
            if len == 0 || at(i) == b'.' {
                return None;
            }
            label = bp;
            bp += 1;
            continue;
        }
        if bp >= dst.len() {
            return None;
        }
        dst[bp] = c;
        bp += 1;
    }
    if escaped {
        return None;
    }
    let len = bp - label - 1;
    if len & 0xc0 != 0 || label >= dst.len() {
        return None;
    }
    dst[label] = len as u8;
    if len != 0 {
        if bp >= dst.len() {
            return None;
        }
        dst[bp] = 0;
        bp += 1;
    }
    if bp > MAXCDNAME {
        return None;
    }
    Some((bp, false))
}

fn special(c: u8) -> bool {
    matches!(c, b'"' | b'.' | b';' | b'\\' | b'(' | b')' | b'@' | b'$')
}

pub fn name_ntop<const N: usize>(src: &[u8]) -> Option<Buf<N>> {
    let mut o = Buf::<N>::new();
    let mut i = 0usize;
    loop {
        let l = *src.get(i)? as usize;
        i += 1;
        if l == 0 {
            break;
        }
        if l >= 64 {
            return None;
        }
        if o.len != 0 && !o.push(b'.') {
            return None;
        }
        for _ in 0..l {
            let c = *src.get(i)?;
            i += 1;
            if special(c) {
                if !(o.push(b'\\') && o.push(c)) {
                    return None;
                }
            } else if !(c > 0x20 && c < 0x7f) {
                if !(o.push(b'\\') && o.push(b'0' + c / 100) && o.push(b'0' + (c % 100) / 10) && o.push(b'0' + c % 10)) {
                    return None;
                }
            } else if !o.push(c) {
                return None;
            }
        }
    }
    if o.len == 0 && !o.push(b'.') {
        return None;
    }
    Some(o)
}

pub fn name_unpack(msg: &[u8], src: usize, dst: &mut [u8]) -> Option<usize> {
    let mut len: Option<usize> = None;
    let mut checked = 0usize;
    let mut dp = 0usize;
    let mut sp = src;
    if sp >= msg.len() {
        return None;
    }
    loop {
        let n = *msg.get(sp)? as usize;
        sp += 1;
        if n == 0 {
            break;
        }
        match n & 0xc0 {
            0 => {
                if n + 1 >= dst.len() - dp || n >= msg.len() - sp {
                    return None;
                }
                checked += n + 1;
                dst[dp] = n as u8;
                dp += 1;
                dst[dp..dp + n].copy_from_slice(&msg[sp..sp + n]);
                dp += n;
                sp += n;
            }
            0xc0 => {
                if sp >= msg.len() {
                    return None;
                }
                if len.is_none() {
                    len = Some(sp - src + 1);
                }
                let target = ((n & 0x3f) << 8) | msg[sp] as usize;
                if target >= msg.len() {
                    return None;
                }
                sp = target;
                checked += 2;
                if checked >= msg.len() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    if dp >= dst.len() {
        return None;
    }
    dst[dp] = 0;
    Some(len.unwrap_or_else(|| sp - src))
}

pub fn name_skip(msg: &[u8], off: usize) -> Option<usize> {
    let mut cp = off;
    while cp < msg.len() {
        let n = msg[cp] as usize;
        cp += 1;
        if n == 0 {
            return Some(cp);
        }
        match n & 0xc0 {
            0 => {
                if msg.len() - cp < n {
                    return None;
                }
                cp += n;
            }
            0xc0 => {
                if cp == msg.len() {
                    return None;
                }
                return Some(cp + 1);
            }
            _ => return None,
        }
    }
    None
}

pub fn name_expand<const N: usize>(msg: &[u8], off: usize) -> Option<(Buf<N>, usize)> {
    let mut tmp = [0u8; MAXCDNAME + 1];
    let used = name_unpack(msg, off, &mut tmp)?;
    Some((name_ntop::<N>(&tmp)?, used))
}

pub fn same_name(a: &[u8], b: &[u8]) -> bool {
    let a = a.strip_suffix(b".").unwrap_or(a);
    let b = b.strip_suffix(b".").unwrap_or(b);
    crate::util::eq_nocase(a, b)
}

pub const RESOLV_EDNS_BUFFER_SIZE: usize = 1200;

pub fn edns_payload(anslen: usize) -> u16 {
    anslen.clamp(512, RESOLV_EDNS_BUFFER_SIZE) as u16
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opt {
    pub payload: u16,
    pub dnssec_ok: bool,
}

pub fn build_query(id: u16, name: &[u8], qtype: u16, qclass: u16, rd: bool, opt: Option<Opt>, out: &mut [u8]) -> Option<usize> {
    if out.len() < HFIXEDSZ + MAXCDNAME + QFIXEDSZ + 11 {
        return None;
    }
    let h = Header { id, flags: if rd { FLAG_RD } else { 0 }, qdcount: 1, ancount: 0, nscount: 0, arcount: opt.is_some() as u16 };
    h.write(out);
    let (n, _) = name_pton(name, &mut out[HFIXEDSZ..HFIXEDSZ + MAXCDNAME + 1])?;
    let mut p = HFIXEDSZ + n;
    put16(out, p, qtype);
    put16(out, p + 2, qclass);
    p += 4;
    if let Some(opt) = opt {
        out[p] = 0;
        put16(out, p + 1, T_OPT);
        put16(out, p + 3, opt.payload);
        out[p + 5] = 0;
        out[p + 6] = 0;
        put16(out, p + 7, if opt.dnssec_ok { 0x8000 } else { 0 });
        put16(out, p + 9, 0);
        p += 11;
    }
    Some(p)
}

#[derive(Clone, Copy, Debug)]
pub struct Rr {
    pub name_off: usize,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub rdata: usize,
    pub rdlen: usize,
}

pub struct Cursor<'a> {
    pub msg: &'a [u8],
    pub pos: usize,
    pub left: usize,
}

impl<'a> Cursor<'a> {
    pub fn answers(msg: &'a [u8]) -> Option<(Header, Cursor<'a>)> {
        let h = Header::parse(msg)?;
        let mut pos = HFIXEDSZ;
        for _ in 0..h.qdcount {
            pos = name_skip(msg, pos)?;
            pos += QFIXEDSZ;
            if pos > msg.len() {
                return None;
            }
        }
        let left = h.ancount as usize + h.nscount as usize + h.arcount as usize;
        Some((h, Cursor { msg, pos, left }))
    }
}

impl Iterator for Cursor<'_> {
    type Item = Option<Rr>;
    fn next(&mut self) -> Option<Option<Rr>> {
        if self.left == 0 {
            return None;
        }
        self.left -= 1;
        let m = self.msg;
        let name_off = self.pos;
        let parse = || -> Option<(Rr, usize)> {
            let p = name_skip(m, name_off)?;
            let rtype = get16(m, p)?;
            let class = get16(m, p + 2)?;
            let ttl = get32(m, p + 4)?;
            let rdlen = get16(m, p + 8)? as usize;
            let rdata = p + 10;
            if rdata + rdlen > m.len() {
                return None;
            }
            Some((Rr { name_off, rtype, class, ttl, rdata, rdlen }, rdata + rdlen))
        };
        match parse() {
            Some((rr, next)) => {
                self.pos = next;
                Some(Some(rr))
            }
            None => {
                self.left = 0;
                Some(None)
            }
        }
    }
}

pub fn first_question<const N: usize>(msg: &[u8]) -> Option<(Buf<N>, u16, u16)> {
    let h = Header::parse(msg)?;
    if h.qdcount < 1 {
        return None;
    }
    let (name, used) = name_expand::<N>(msg, HFIXEDSZ)?;
    let p = HFIXEDSZ + used;
    Some((name, get16(msg, p)?, get16(msg, p + 2)?))
}
