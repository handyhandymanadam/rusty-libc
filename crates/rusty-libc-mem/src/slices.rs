use core::ffi::c_int;

#[inline(always)]
fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

pub fn swab_bytes(from: &[u8], to: &mut [u8]) {
    let n = from.len().min(to.len()) & !1;
    let (from, to) = (&from[..n], &mut to[..n]);
    let mut i = 0;
    while i < n {
        to[i] = from[i + 1];
        to[i + 1] = from[i];
        i += 2;
    }
}

pub(crate) fn swab_overlapping(buf: &mut [u8], s: usize, d: usize, n: usize) {
    let mut i = 0;
    while i + 1 < n {
        let (a, b) = (buf[s + i], buf[s + i + 1]);
        buf[d + i] = b;
        buf[d + i + 1] = a;
        i += 2;
    }
}

pub fn memfrob_bytes(buf: &mut [u8]) {
    for b in buf {
        *b ^= 42;
    }
}

pub fn strverscmp_cstr(a: &core::ffi::CStr, b: &core::ffi::CStr) -> c_int {
    const S_N: usize = 0;
    const S_I: usize = 3;
    const S_F: usize = 6;
    const S_Z: usize = 9;
    const CMP: i8 = 2;
    const LEN: i8 = 3;
    const NEXT_STATE: [usize; 12] = [S_N, S_I, S_Z, S_N, S_I, S_I, S_N, S_F, S_F, S_N, S_F, S_Z];
    const RESULT_TYPE: [i8; 36] = [
        CMP, CMP, CMP, CMP, LEN, CMP, CMP, CMP, CMP,
        CMP, -1, -1, 1, LEN, LEN, 1, LEN, LEN,
        CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP, CMP,
        CMP, 1, 1, -1, CMP, CMP, -1, CMP, CMP,
    ];
    let (s1, s2) = (a.to_bytes_with_nul(), b.to_bytes_with_nul());
    let mut i = 0;
    let mut c1 = s1[0];
    let mut c2 = s2[0];
    i += 1;
    let mut state = S_N + usize::from(c1 == b'0') + usize::from(is_digit(c1));
    while c1 == c2 {
        if c1 == 0 {
            return 0;
        }
        state = NEXT_STATE[state];
        c1 = s1[i];
        c2 = s2[i];
        i += 1;
        state += usize::from(c1 == b'0') + usize::from(is_digit(c1));
    }
    let diff = c_int::from(c1) - c_int::from(c2);
    let kind = RESULT_TYPE[state * 3 + usize::from(c2 == b'0') + usize::from(is_digit(c2))];
    match kind {
        CMP => diff,
        LEN => {
            let mut j = i;
            loop {
                if !is_digit(s1[j]) {
                    break;
                }
                if !is_digit(s2[j]) {
                    return 1;
                }
                j += 1;
            }
            if is_digit(s2[j]) { -1 } else { diff }
        }
        other => c_int::from(other),
    }
}
