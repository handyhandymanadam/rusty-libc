// Included at the end of tests.rs: differential tests for ISO-2022-CN-EXT and TSCII.

/// Characters of CNS 11643 planes 1..=7 and of ISO-IR-165 (the sets ISO-2022-CN-EXT adds), for texts.
fn cnext_pool() -> Vec<u32> {
    let mut v = Vec::new();
    let m = &crate::mbdata::euc_tw::mb();
    for (si, s) in m.sets.iter().enumerate() {
        if s.nbytes != 2 || (!s.prefix().is_empty() && !(s.prefix()[0] == 0x8e && (0xa1..=0xa7).contains(&s.prefix()[1]))) {
            continue;
        }
        for b1 in s.lead_lo..=s.lead_hi {
            for b2 in s.trail_lo..=s.trail_hi {
                if let Some(c) = m.dec2(si, b1, b2) {
                    v.push(c);
                }
            }
        }
    }
    let m = &crate::mbdata::isoir165::mb();
    for b1 in 0x21..=0x7eu8 {
        for b2 in 0x21..=0x7eu8 {
            if let Some(c) = m.dec2(1, b1, b2) {
                v.push(c);
            }
        }
    }
    v
}

/// ISO-2022-CN-EXT: every character alone (with and without room), then texts from all its sets
/// with every escape sequence, bad sequences and truncations, in random chunks, both directions.
#[test]
fn iso2022cnext_differential() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("iso2022cnext_differential");
    let mut bad: Vec<String> = Vec::new();
    {
        let (mut h, mut o) = (Host::open("ISO-2022-CN-EXT", "UCS-4LE").unwrap(), Converter::new("ISO-2022-CN-EXT", "UCS-4LE").unwrap());
        for cp in (0u32..0x30000).chain([0xe0001, 0xe0041, 0x2ffff, 0x110000]) {
            for oc in [16usize, 1, 4] {
                if let Err(e) = pair_check_f("ISO-2022-CN-EXT", "UCS-4LE", &cp.to_le_bytes(), oc, &mut h, &mut o, true) {
                    bad.push(e);
                    break;
                }
            }
            if bad.len() > 3 {
                break;
            }
        }
    }
    let pool = cnext_pool();
    let mut r = Rng(std::env::var("ICONV_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x2022_c4e1));
    let escs: &[&[u8]] = &[
        b"\x1b$)A", b"\x1b$)E", b"\x1b$)G", b"\x1b$*H", b"\x1b$+I", b"\x1b$+J", b"\x1b$+K", b"\x1b$+L", b"\x1b$+M", b"\x1b$)B", b"\x1b$+N", b"\x1b$*I", b"\x1b$)", b"\x1b$+", b"\x1b$", b"\x1b", b"\x0e", b"\x0f", b"\x1bN",
        b"\x1bO", b"\x1bP", b"\x1b$)E\x0e", b"\x1b$)A\x0e", b"\x1b$)G\x0e", b"\x1b$*H\x1bN", b"\x1b$+I\x1bO", b"\x1b$+J\x1bO", b"\x1b$+K\x1bO", b"\x1b$+L\x1bO", b"\x1b$+M\x1bO", b"\n",
    ];
    for it in 0..std::env::var("ICONV_FUZZ_CNEXT").ok().and_then(|v| v.parse().ok()).unwrap_or(40000usize) {
        let suf = ["", "//TRANSLIT", "//IGNORE", "//TRANSLIT//IGNORE"][it % 4];
        // decoding
        let mut inp = Vec::new();
        for _ in 0..r.below(14) {
            match r.below(6) {
                0 | 1 => inp.extend_from_slice(escs[r.below(escs.len())]),
                2 | 3 => inp.extend([0x21 + r.below(0x5e) as u8, 0x21 + r.below(0x5e) as u8]),
                4 => inp.push(if r.below(8) == 0 { r.next() as u8 } else { 0x20 + r.below(0x60) as u8 }),
                _ => inp.extend([0x23 + r.below(5) as u8, 0x21 + r.below(0x5e) as u8]),
            }
        }
        if suf.contains("IGNORE") {
            // glibc's loop runs past the end of its input when an SO with no announced set is the last
            // byte it is given and errors are ignored (it moves past the SO, then skips one more):
            // undefined. The ignoring runs therefore start with an announcement (the first thing
            // decoded, and one is never withdrawn); the failing runs test the SO error itself.
            let mut v = b"\x1b$)A".to_vec();
            v.extend_from_slice(&inp);
            inp = v;
        }
        let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
        let tgt = ["UTF-8", "UTF-16LE", "UCS-4LE", "ASCII"][r.below(4)];
        if let Err(e) = compare_run(&format!("{tgt}{}", if suf.contains("IGNORE") { "//IGNORE" } else { "" }), "ISO-2022-CN-EXT", &inp, &ic, &oc, true) {
            bad.push(e);
        }
        // encoding
        let mut text = Vec::new();
        for _ in 0..r.below(16) {
            let c = match r.below(6) {
                0 => 0x20 + r.below(0x5f) as u32,
                1 => [0x0a, 0x0d, 0, 0xe0001, 0xe0061, 0x20ac][r.below(6)],
                2 => rand_cp(&mut r),
                _ => pool[r.below(pool.len())],
            };
            put_utf8(&mut text, c);
        }
        let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
        if let Err(e) = compare_run(&format!("ISO-2022-CN-EXT{suf}"), "UTF-8", &text, &ic, &oc, true) {
            bad.push(e);
        }
        if bad.len() > 3 {
            break;
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(3)].join("\n"));
}

/// TSCII: every byte and byte pair, every Tamil character alone and in pairs, then random texts in
/// random chunks (small output rooms make the decoder queue characters in its state).
#[test]
fn tscii_differential() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("tscii_differential");
    let mut bad: Vec<String> = Vec::new();
    {
        let (mut h, mut o) = (Host::open("UTF-32LE", "TSCII").unwrap(), Converter::new("UTF-32LE", "TSCII").unwrap());
        'a: for b in 0..=255u8 {
            for oc in [64usize, 4, 8, 12, 16] {
                if let Err(e) = pair_check("UTF-32LE", "TSCII", &[b], oc, &mut h, &mut o) {
                    bad.push(e);
                    break 'a;
                }
                for c in 0..=255u8 {
                    if let Err(e) = pair_check("UTF-32LE", "TSCII", &[b, c], oc, &mut h, &mut o) {
                        bad.push(e);
                        break 'a;
                    }
                }
            }
        }
    }
    {
        let (mut h, mut o) = (Host::open("TSCII", "UCS-4LE").unwrap(), Converter::new("TSCII", "UCS-4LE").unwrap());
        let cps: Vec<u32> = (0x0b80..0x0c00).chain([0xa9, 0x2018, 0x2019, 0x201c, 0x201d, 0x41, 0x0a, 0x2020, 0xe0041, 0x80]).collect();
        'b: for &a in &cps {
            for oc in [16usize, 1, 2] {
                if let Err(e) = pair_check("TSCII", "UCS-4LE", &a.to_le_bytes(), oc, &mut h, &mut o) {
                    bad.push(e);
                    break 'b;
                }
            }
            for &b in &cps {
                let mut input = a.to_le_bytes().to_vec();
                input.extend(b.to_le_bytes());
                for oc in [16usize, 1, 2, 3] {
                    if let Err(e) = pair_check("TSCII", "UCS-4LE", &input, oc, &mut h, &mut o) {
                        bad.push(e);
                        break 'b;
                    }
                }
            }
        }
    }
    let mut r = Rng(std::env::var("ICONV_FUZZ_SEED").ok().and_then(|v| v.parse().ok()).unwrap_or(0x7c11_0001));
    // bytes that matter to the state machine
    let interesting: &[u8] = &[0x82, 0x87, 0x8a, 0x8b, 0x8c, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xaa, 0xb8, 0xb9, 0xbc, 0xc9, 0xca, 0xcb, 0xec, 0xa0, 0xff, 0x41, 0x0a];
    // Tamil characters that combine
    let tamil: &[u32] = &[0xb95, 0xb9a, 0xb9f, 0xbb7, 0xbb8, 0xbb9, 0xb9c, 0xbb0, 0xbbf, 0xbc0, 0xbc1, 0xbc2, 0xbc6, 0xbc7, 0xbc8, 0xbca, 0xbcb, 0xbcc, 0xbcd, 0xbbe, 0xbd7, 0xb85, 0xbe6, 0x41, 0xa9, 0x2018, 0x20ac, 0xbaa, 0xb99, 0xb9e];
    for it in 0..std::env::var("ICONV_FUZZ_TSCII").ok().and_then(|v| v.parse().ok()).unwrap_or(60000usize) {
        let suf = ["", "//TRANSLIT", "//IGNORE", "//TRANSLIT//IGNORE"][it % 4];
        let mut inp = Vec::new();
        for _ in 0..r.below(16) {
            inp.push(if r.below(3) == 0 { 0x80 + r.below(0x80) as u8 } else { interesting[r.below(interesting.len())] });
        }
        let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
        let tgt = ["UTF-8", "UTF-16LE", "UCS-4LE", "ASCII"][r.below(4)];
        if let Err(e) = compare_run(&format!("{tgt}{}", if suf.contains("IGNORE") { "//IGNORE" } else { "" }), "TSCII", &inp, &ic, &oc, true) {
            bad.push(e);
        }
        let mut text = Vec::new();
        for _ in 0..r.below(16) {
            let c = if r.below(5) == 0 { rand_cp(&mut r) } else { tamil[r.below(tamil.len())] };
            put_utf8(&mut text, c);
        }
        let (ic, oc) = (rand_chunks(&mut r, false), rand_chunks(&mut r, true));
        if let Err(e) = compare_run(&format!("TSCII{suf}"), "UTF-8", &text, &ic, &oc, true) {
            bad.push(e);
        }
        if bad.len() > 3 {
            break;
        }
    }
    assert!(bad.is_empty(), "{} mismatches, first:\n{}", bad.len(), bad[..bad.len().min(3)].join("\n"));
}

/// FIXLIST #109: the converters of a `fopen (..., ",ccs=NAME")` stream as glibc 2.43's libio finds them: names stripped and
/// looked up as they are (no suffixes, no empty name, no INTERNAL), INTERNAL on the other side, no byte order mark written,
/// transliteration on output.
#[test]
fn open_ccs_as_glibc_libio() {
    for n in ["UTF-8", "utf8", " Utf-8 ", "UTF@8", "UTF-8/", "UTF-8///", "latin1", "+ISO-8859-1", "ISO-10646/UTF8/", "UCS-4"] {
        assert!(Converter::open_ccs(n.as_bytes()).is_ok(), "{n:?} is a charset");
    }
    let long = format!("U{}TF-8", " ".repeat(300));
    assert!(Converter::open_ccs(long.as_bytes()).is_ok());
    for n in ["", "//", "///", "@@", "utf_8", "UTF-8//TRANSLIT", "UTF-8//IGNORE", "/UTF-8", "WCHAR_T", "INTERNAL", "NO-SUCH", "C", "ISO-10646/UCS4/X"] {
        assert!(Converter::open_ccs(n.as_bytes()).is_err(), "{n:?} is no charset here");
    }
    assert!(Converter::open_ccs("X".repeat(300).as_bytes()).is_err());
    let enc = |name: &str, text: &[u32]| {
        let (_, mut e) = Converter::open_ccs(name.as_bytes()).unwrap();
        let input: Vec<u8> = text.iter().flat_map(|c| c.to_ne_bytes()).collect();
        let (mut ip, mut op, mut out) = (0, 0, [0u8; 64]);
        e.convert_raw(&input, &mut ip, &mut out, &mut op).unwrap();
        out[..op].to_vec()
    };
    assert_eq!(enc("UTF-16", &[0x78]), [0x78, 0]);
    assert_eq!(enc("UTF-32", &[0x78]), [0x78, 0, 0, 0]);
    assert_eq!(enc("UNICODE", &[0x78]), [0x78, 0]);
    assert_eq!(enc("latin1", &[0x20ac]), *b"EUR");
    // a UCS-4 value above 0x10FFFF reads as it is (INTERNAL, not UCS-4LE, on the other side)
    let (mut d, _) = Converter::open_ccs(b"UCS-4BE").unwrap();
    let (mut ip, mut op, mut out) = (0, 0, [0u8; 4]);
    d.convert_raw(&[0x63, 0x61, 0x66, 0xc3], &mut ip, &mut out, &mut op).unwrap();
    assert_eq!(u32::from_ne_bytes(out), 0x6361_66c3);
}

/// `Converter::each_char` (the characters of a CJK charset for regex brackets, rusty-libc-locale other.rs) reports what the
/// walk over every candidate sequence of up to 4 bytes with `decode_ucs4` after a reset finds, in the same order, in every
/// charset it answers for.
#[test]
fn each_char_matches_decode() {
    fn slow(c: &mut Converter, s: &[u8]) -> Result<u32, bool> {
        let _ = c.flush_raw(None);
        let mut o = [0u32; 1];
        let (mut ip, mut op) = (0usize, 0usize);
        match c.decode_ucs4(s, &mut ip, &mut o, &mut op) {
            Some(Ok(())) if ip == s.len() && op == 1 => Ok(o[0]),
            Some(Err(crate::Error::Inval)) => Err(true),
            _ => Err(false),
        }
    }
    fn collect(c: &mut Converter, p: &mut [u8; 4], len: usize, out: &mut Vec<(Vec<u8>, u32)>) {
        for b in 0..=255u8 {
            p[len] = b;
            let n = len + 1;
            match slow(c, &p[..n]) {
                Ok(wc) => out.push((p[..n].to_vec(), wc)),
                Err(true) if n < 4 => collect(c, p, n, out),
                _ => {}
            }
        }
    }
    for name in ["EUC-KR", "EUC-CN", "EUC-JP", "UHC", "GBK", "SJIS", "CP932", "BIG5", "JOHAB", "EUC-TW", "GB18030", "EUC-JP-MS", "ISO_6937",
        "ISO_6937-2", "T.61", "ANSI_X3.110", "IBM932", "IBM943"] {
        let mut c = Converter::open(b"UCS-4LE", name.as_bytes()).unwrap_or_else(|_| panic!("{name} opens"));
        let mut slow_list: Vec<(Vec<u8>, u32)> = Vec::new();
        collect(&mut c, &mut [0u8; 4], 0, &mut slow_list);
        assert!(slow_list.len() >= 128, "{name}: {} characters", slow_list.len());
        let mut fast_list: Vec<(Vec<u8>, u32)> = Vec::new();
        let mut runs = 0;
        assert!(
            c.each_char(&mut |b, wc, n| {
                if n == 1 {
                    fast_list.push((b.to_vec(), wc));
                    return;
                }
                // a run of GB18030's four-byte codes: expand it in the code order
                assert_eq!(name, "GB18030");
                assert_eq!(b.len(), 4);
                runs += 1;
                let idx = (((b[0] as u32 - 0x81) * 10 + (b[1] as u32 - 0x30)) * 126 + (b[2] as u32 - 0x81)) * 10 + (b[3] as u32 - 0x30);
                for i in 0..n {
                    fast_list.push((crate::cjk::gb18030_code(idx + i).to_vec(), wc + i));
                }
            }),
            "{name}: each_char answers"
        );
        // (the runs come after the walk of the shorter codes: compare in byte order)
        fast_list.sort();
        assert!(slow_list.is_sorted(), "{name}: the walk is in byte order");
        assert_eq!(slow_list, fast_list, "{name}");
        if name == "GB18030" {
            assert!(runs > 0 && runs < 1000, "{name}: {runs} runs");
        }
    }
}

/// `Converter::each_row` (the rows of the multibyte characters, for regex `.` and brackets in the EUC, GBK, BIG5 ... locales)
/// gives, in every charset it answers for, exactly the characters of two or more bytes that the walk over all candidate
/// sequences (every pair of bytes, valid or not, and the three- and four-byte forms) finds, in the same order; and with
/// `ranges`, those whose value is in the ranges.
#[test]
fn each_row_matches_walk() {
    fn slow(c: &mut Converter, s: &[u8]) -> Result<u32, bool> {
        let _ = c.flush_raw(None);
        let mut o = [0u32; 1];
        let (mut ip, mut op) = (0usize, 0usize);
        match c.decode_ucs4(s, &mut ip, &mut o, &mut op) {
            Some(Ok(())) if ip == s.len() && op == 1 => Ok(o[0]),
            Some(Err(crate::Error::Inval)) => Err(true),
            _ => Err(false),
        }
    }
    fn collect(c: &mut Converter, p: &mut [u8; 4], len: usize, out: &mut Vec<(Vec<u8>, u32)>) {
        for b in 0..=255u8 {
            p[len] = b;
            let n = len + 1;
            match slow(c, &p[..n]) {
                Ok(wc) => out.push((p[..n].to_vec(), wc)),
                Err(true) if n < 4 => collect(c, p, n, out),
                _ => {}
            }
        }
    }
    fn expand(c: &Converter, gb: bool, ranges: Option<&[(u32, u32)]>) -> Option<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        let mut last: Option<Vec<u8>> = None;
        let mut nruns = 0;
        let ok = c.each_row(ranges, &mut |head, mask| {
            assert!(mask.iter().any(|&w| w != 0));
            if let Some(l) = &last {
                assert!(l.as_slice() < head, "heads in order");
            }
            last = Some(head.to_vec());
            for t in 0..=255u32 {
                if mask[(t >> 6) as usize] >> (t & 63) & 1 != 0 {
                    let mut b = head.to_vec();
                    b.push(t as u8);
                    out.push(b);
                }
            }
        }, &mut |code, _, n| {
            assert!(code.len() == 4 && n > 0);
            nruns += 1;
        });
        // (GB18030 reports its runs of four-byte codes whatever the ranges are, the others none)
        assert_eq!(nruns > 0, gb && ok);
        ok.then_some(out)
    }
    let mut answered = 0;
    for name in ["EUC-KR", "EUC-CN", "EUC-JP", "UHC", "GBK", "SJIS", "CP932", "BIG5", "JOHAB", "EUC-TW", "GB18030", "EUC-JP-MS", "BIG5-HKSCS"] {
        let mut c = Converter::open(b"UCS-4LE", name.as_bytes()).unwrap_or_else(|_| panic!("{name} opens"));
        let mut walk: Vec<(Vec<u8>, u32)> = Vec::new();
        collect(&mut c, &mut [0u8; 4], 0, &mut walk);
        // the single-byte characters, as a set
        let mut want = [0u64; 4];
        for (b, _) in walk.iter().filter(|w| w.0.len() == 1) {
            want[usize::from(b[0] >> 6)] |= 1u64 << (b[0] & 63);
        }
        assert_eq!(c.single_bytes(), Some(want), "{name}: single bytes");
        // (the rows hold the table characters; GB18030's four-byte codes are the runs of `each_char`)
        walk.retain(|(b, _)| b.len() >= 2 && !(name == "GB18030" && b.len() == 4));
        let Some(rows) = expand(&c, name == "GB18030", None) else {
            eprintln!("{name}: no rows");
            continue;
        };
        answered += 1;
        for (b, wc) in &walk {
            assert!(*wc >= 0x80 && *wc <= 0x10ffff && !(0xd800..=0xdfff).contains(wc), "{name}: {b:02x?} is {wc:x}");
        }
        let all: Vec<Vec<u8>> = walk.iter().map(|(b, _)| b.clone()).collect();
        assert_eq!(rows.len(), all.len(), "{name}: number of characters");
        assert!(rows == all, "{name}: rows are the walk's characters");
        // ranges: a few ranges (compared), many (bitmap), edges at the cells' values
        let mut vals: Vec<u32> = walk.iter().map(|w| w.1).collect();
        vals.sort_unstable();
        vals.dedup();
        let mut seed = 0x9e37_79b9u32;
        let mut rnd = move || {
            seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12345);
            seed >> 8
        };
        for round in 0..24 {
            let nr = [1, 2, 3, 5, 6, 7, 20, 200][round % 8];
            let mut r: Vec<(u32, u32)> = Vec::new();
            for _ in 0..nr {
                let a = vals[rnd() as usize % vals.len()];
                let w = [0, 1, 40, 700, 5000, 60000][rnd() as usize % 6];
                r.push((a, a + w));
            }
            if round % 3 == 0 {
                r.push((0x20000 + rnd() % 0x1000, 0x2ffff));
            }
            r.sort_unstable();
            let mut m: Vec<(u32, u32)> = Vec::new();
            for (lo, hi) in r {
                match m.last_mut() {
                    Some(l) if lo <= l.1 + 1 => l.1 = l.1.max(hi),
                    _ => m.push((lo, hi)),
                }
            }
            let want: Vec<Vec<u8>> = walk.iter().filter(|(_, wc)| m.iter().any(|&(lo, hi)| *wc >= lo && *wc <= hi)).map(|(b, _)| b.clone()).collect();
            let got = expand(&c, name == "GB18030", Some(&m)).unwrap();
            assert!(got == want, "{name}: ranges {m:x?}: {} against {}", got.len(), want.len());
        }
        // many large ranges (a class such as the letters: rows whose cells lie in one range need no per-cell look-up), with the
        // characters above U+FFFF out, some in, all in
        for wide_end in [0xfffeu32, 0x2_8000, 0x10ffff] {
            let step = (0xfffe - 0x80) / 12;
            let mut m: Vec<(u32, u32)> = (0..12).map(|i| (0x80 + i * step + 1, 0x80 + (i + 1) * step - 1)).collect();
            m.push((0x10000, wide_end.max(0x10000)));
            if wide_end < 0x10000 {
                m.pop();
            }
            let want: Vec<Vec<u8>> = walk.iter().filter(|(_, wc)| m.iter().any(|&(lo, hi)| *wc >= lo && *wc <= hi)).map(|(b, _)| b.clone()).collect();
            let got = expand(&c, name == "GB18030", Some(&m)).unwrap();
            assert!(got == want, "{name}: many large ranges to {wide_end:x}: {} against {}", got.len(), want.len());
        }
        // everything but one character, and one character
        let mid = walk[walk.len() / 2].1;
        let rest = [(0u32, mid - 1), (mid + 1, 0x10ffff)];
        let want: Vec<Vec<u8>> = walk.iter().filter(|w| w.1 != mid).map(|w| w.0.clone()).collect();
        assert!(expand(&c, name == "GB18030", Some(&rest)).unwrap() == want, "{name}: all but one");
        let one: Vec<Vec<u8>> = walk.iter().filter(|w| w.1 == mid).map(|w| w.0.clone()).collect();
        assert!(expand(&c, name == "GB18030", Some(&[(mid, mid)])).unwrap() == one, "{name}: one");
    }
    assert!(answered >= 9, "{answered} charsets answered");
}
