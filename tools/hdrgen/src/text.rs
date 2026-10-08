fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

pub fn word_positions(s: &str, w: &str) -> Vec<usize> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(p) = s[from..].find(w) {
        let i = from + p;
        let e = i + w.len();
        let before_ok = i == 0 || !is_word(b[i - 1]) || !is_word(w.as_bytes()[0]);
        let after_ok = e >= b.len() || !is_word(b[e]) || !is_word(w.as_bytes()[w.len() - 1]);
        if before_ok && after_ok {
            out.push(i);
            from = e;
        } else {
            from = i + 1;
        }
    }
    out
}

pub fn contains_word(s: &str, w: &str) -> bool {
    !word_positions(s, w).is_empty()
}

pub fn replace_word(s: &str, w: &str, r: &str, not_before_paren: bool) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last = 0;
    for i in word_positions(s, w) {
        if not_before_paren && s.as_bytes().get(i + w.len()) == Some(&b'(') {
            continue;
        }
        out.push_str(&s[last..i]);
        out.push_str(r);
        last = i + w.len();
    }
    out.push_str(&s[last..]);
    out
}
