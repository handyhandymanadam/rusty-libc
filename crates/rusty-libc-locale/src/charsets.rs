//! Character set names as locales use them: which charset a locale's codeset string denotes, and
//! glibc's `__gconv_compare_alias` test used to reject a locale whose codeset differs from the one
//! in its name.

/// The charset code stored in LC_CTYPE's flags: 0 for the C locale's ASCII (and anything this
/// library cannot decode), 1 for UTF-8.
pub fn code_of(codeset: &[u8]) -> u8 {
    match canon(codeset) {
        Some("UTF-8") => 1,
        _ => 0,
    }
}

/// 2 for a charset other than ASCII and UTF-8 that rusty-libc-iconv implements.
pub fn code_of_other(codeset: &[u8]) -> Option<u8> {
    match canon(codeset) {
        Some("UTF-8") | None => None,
        Some("ANSI_X3.4-1968") => Some(0),
        Some(_) => Some(2),
    }
}

fn canon(name: &[u8]) -> Option<&'static str> {
    // the codeset of nearly every locale, answered without iconv's alias tables (a binary search over them costs a few
    // page faults at every setlocale of a program's start; test `utf8_fast_path` checks the answer is the same)
    if name == b"UTF-8" {
        return Some("UTF-8");
    }
    let s = core::str::from_utf8(name).ok()?;
    rusty_libc_iconv::canonical_name(s)
}

/// glibc's strip(): keep letters, digits and `_-.,:`, upper-cased, with exactly two slashes.
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

/// True if the two codeset names denote the same charset (`UTF-8` and `utf8`, `ISO-8859-1` and
/// `latin1`).
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

#[cfg(test)]
mod fast_path_tests {
    #[test]
    fn utf8_fast_path() {
        assert_eq!(rusty_libc_iconv::canonical_name("UTF-8"), Some("UTF-8"));
        assert_eq!(super::code_of(b"UTF-8"), 1);
        assert_eq!(super::code_of_other(b"UTF-8"), None);
    }
}
