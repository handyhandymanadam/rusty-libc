pub fn code_of(codeset: &[u8]) -> u8 {
    match canon(codeset) {
        Some("UTF-8") => 1,
        _ => 0,
    }
}

pub fn code_of_other(codeset: &[u8]) -> Option<u8> {
    match canon(codeset) {
        Some("UTF-8") | None => None,
        Some("ANSI_X3.4-1968") => Some(0),
        Some(_) => Some(2),
    }
}

fn canon(name: &[u8]) -> Option<&'static str> {
    let s = core::str::from_utf8(name).ok()?;
    rusty_libc_iconv::canonical_name(s)
}

fn strip(s: &[u8], out: &mut [u8; 140]) -> usize {
    let mut n = 0;
    let mut slashes = 0;
    for &c in s {
        if n + 3 >= out.len() {
            break;
        }
        if c.is_ascii_alphanumeric() || matches!(c, b'_' | b'-' | b'.' | b',' | b':') {
            out[n] = c.to_ascii_uppercase();
            n += 1;
        } else if c == b'/' {
            slashes += 1;
            if slashes == 3 {
                break;
            }
            out[n] = b'/';
            n += 1;
        }
    }
    while slashes < 2 {
        out[n] = b'/';
        n += 1;
        slashes += 1;
    }
    n
}

pub fn same_charset(a: &[u8], b: &[u8]) -> bool {
    let (mut x, mut y) = ([0u8; 140], [0u8; 140]);
    let (nx, ny) = (strip(a, &mut x), strip(b, &mut y));
    if x[..nx] == y[..ny] {
        return true;
    }
    match (canon(a), canon(b)) {
        (Some(p), Some(q)) => p == q,
        _ => false,
    }
}
