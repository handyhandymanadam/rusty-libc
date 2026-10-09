pub enum Rewrite<T> {
    Plain,
    Zero,
    Copy { buf: *mut T, pre: usize, resume: usize, sod: usize, hex: bool },
}

pub trait Unit: Copy {
    fn code(self) -> u32;
    fn from_code(c: u32) -> Self;
}
impl Unit for u8 {
    fn code(self) -> u32 {
        u32::from(self)
    }
    fn from_code(c: u32) -> Self {
        c as u8
    }
}
impl Unit for i32 {
    fn code(self) -> u32 {
        self as u32
    }
    fn from_code(c: u32) -> Self {
        c as i32
    }
}

fn digit(c: u32, hex: bool) -> bool {
    (u32::from(b'0')..=u32::from(b'9')).contains(&c) || (hex && (u32::from(b'a')..=u32::from(b'f')).contains(&(c | 0x20)))
}

pub unsafe fn rewrite<T: Unit>(s: *const T, sep: &[u32], grouping: &[u8], space: impl Fn(u32) -> bool) -> Rewrite<T> {
    let g0 = grouping.first().map_or(0, |&b| b as i8);
    if sep.is_empty() || sep[0] == 0 || g0 <= 0 || g0 == 127 {
        return Rewrite::Plain;
    }
    unsafe {
        let get = |i: usize| (*s.add(i)).code();
        let mut i = 0;
        while get(i) != 0 && space(get(i)) {
            i += 1;
        }
        if get(i) == u32::from(b'-') || get(i) == u32::from(b'+') {
            i += 1;
        }
        let hex = get(i) == u32::from(b'0') && get(i + 1) | 0x20 == u32::from(b'x');
        if hex {
            i += 2;
        }
        let sod = i;
        if !digit(get(sod), hex) {
            return Rewrite::Plain;
        }
        let at_sep = |p: usize| sep.iter().enumerate().all(|(k, &c)| get(p + k) == c);
        let (mut p, mut units, mut seps) = (sod, 0usize, false);
        loop {
            if digit(get(p), hex) {
                p += 1;
            } else if at_sep(p) {
                p += sep.len();
                seps = true;
            } else {
                break;
            }
            units += 1;
        }
        if !seps {
            return Rewrite::Plain;
        }
        let cp = p;
        let tp = if hex {
            cp
        } else {
            let text = rusty_libc_malloc::malloc(units) as *mut u8;
            if text.is_null() {
                return Rewrite::Plain;
            }
            let (mut q, mut k) = (sod, 0usize);
            while q < cp {
                if digit(get(q), false) {
                    *text.add(k) = b'0';
                    q += 1;
                } else {
                    *text.add(k) = b',';
                    q += sep.len();
                }
                k += 1;
            }
            let n = rusty_libc_core::locale::correctly_grouped_prefix(core::slice::from_raw_parts(text, units), grouping);
            rusty_libc_malloc::free(text.cast());
            let (mut q, mut k) = (sod, 0usize);
            while k < n {
                q += if digit(get(q), false) { 1 } else { sep.len() };
                k += 1;
            }
            q
        };
        if tp == sod {
            return Rewrite::Zero;
        }
        let mut rest = 0usize;
        if tp == cp {
            while get(cp + rest) != 0 {
                rest += 1;
            }
        }
        let buf = rusty_libc_malloc::malloc((cp + rest + 1) * size_of::<T>()) as *mut T;
        if buf.is_null() {
            return Rewrite::Plain;
        }
        let mut o = 0usize;
        for k in 0..sod {
            *buf.add(o) = *s.add(k);
            o += 1;
        }
        let mut q = sod;
        while q < tp {
            if digit(get(q), hex) {
                *buf.add(o) = *s.add(q);
                o += 1;
                q += 1;
            } else {
                q += sep.len();
            }
        }
        let pre = o;
        for k in 0..rest {
            *buf.add(o) = *s.add(cp + k);
            o += 1;
        }
        *buf.add(o) = T::from_code(0);
        Rewrite::Copy { buf, pre, resume: tp, sod, hex }
    }
}

pub unsafe fn end_of<T: Unit>(s: *const T, r: &Rewrite<T>, consumed: usize, sep_len: usize) -> usize {
    match *r {
        Rewrite::Plain => consumed,
        Rewrite::Zero => 0,
        Rewrite::Copy { pre, resume, sod, hex, .. } => {
            if consumed == 0 {
                0
            } else if consumed >= pre {
                resume + (consumed - pre)
            } else if consumed <= sod {
                consumed
            } else {
                unsafe {
                    let (mut q, mut k) = (sod, sod);
                    while k < consumed {
                        if digit((*s.add(q)).code(), hex) {
                            k += 1;
                            q += 1;
                        } else {
                            q += sep_len;
                        }
                    }
                    q
                }
            }
        }
    }
}

pub unsafe fn release<T>(r: Rewrite<T>) {
    if let Rewrite::Copy { buf, .. } = r {
        unsafe { rusty_libc_malloc::free(buf.cast()) };
    }
}
