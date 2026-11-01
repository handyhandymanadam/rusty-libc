// Included at the end of tests.rs: every name `iconv -l` prints converts like glibc's.

/// Every name `iconv -l` prints (all 1180, aliases included): a corpus from many scripts goes into
/// the charset and back, with no suffix, //TRANSLIT and //IGNORE, byte for byte against glibc in both
/// directions (the bytes decoded are the ones glibc wrote), in one call and in small chunks.
#[test]
fn every_listed_name_converts() {
    let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _r = Report("every_listed_name_converts");
    let corpus: &[&str] = &[
        "Hello, world! 0123456789 ~`!@#$%^&*()_+-=[]{}|;':\",./<>?\n\tend\r\n",
        "caf\u{e9} na\u{ef}ve \u{c5}ngstr\u{f6}m \u{df} \u{153} \u{20ac} \u{a3} \u{a5} \u{a9} \u{ae} \u{2122} \u{2013}\u{2014} \u{2018}\u{2019}\u{201c}\u{201d} \u{2026} \u{2022}",
        "\u{391}\u{3b1}\u{3b2}\u{3b3} \u{3a9}\u{3c9} \u{410}\u{431}\u{432}\u{44f} \u{401}\u{451} \u{5d0}\u{5d1}\u{5d2} \u{627}\u{644}\u{639}\u{631}\u{628}\u{64a}\u{629}",
        "\u{e01}\u{e02}\u{e2f} \u{ba}\u{ba5} \u{b95}\u{bbe}\u{bcd}\u{bb7}\u{bc6}\u{bca}\u{b9f}\u{bc1} \u{928}\u{92e}\u{938}\u{94d}\u{924}\u{947} \u{1ea0}\u{1ea1}\u{1ebf}\u{1ec7} a\u{300}e\u{301}",
        "\u{4e2d}\u{6587}\u{6f22}\u{5b57}\u{9aa8} \u{65e5}\u{672c}\u{8a9e}\u{3042}\u{3044}\u{30a2}\u{30a4}\u{ff76}\u{ff85} \u{d55c}\u{ae00}\u{c870}\u{c120} \u{3105}\u{3106} \u{2460}\u{2461} \u{ff21}\u{ff41} \u{300c}\u{300d}\u{25a0}\u{25cb}",
        "\u{1f600} \u{20000} \u{fffd} \u{e000} x\u{7f}y\u{80}z\u{a0}w \u{2500}\u{2502}\u{250c} \u{221e}\u{2211}\u{222b} \u{fb01} \u{1d11e}",
    ];
    let names = host_names();
    let mut bad = Vec::new();
    let mut r = Rng(0xa11_5a3e5);
    for n in &names {
        let base = n.trim_end_matches('/');
        for suf in ["", "//TRANSLIT", "//IGNORE", "//TRANSLIT//IGNORE"] {
            let to = format!("{base}{suf}");
            for text in corpus {
                let (ic, oc) = if r.below(3) == 0 { (vec![1 + r.below(7)], vec![1 + r.below(9), 64]) } else { (vec![4096], vec![4096]) };
                if let Err(e) = compare_run(&to, "UTF-8", text.as_bytes(), &ic, &oc, true) {
                    bad.push(e);
                    break;
                }
                // what glibc wrote (when it could write anything) goes back through both decoders
                let Some(mut h) = Host::open(&format!("{base}//TRANSLIT//IGNORE"), "UTF-8") else { continue };
                let mut bytes = h.call(text.as_bytes(), 4096).out;
                bytes.extend(h.flush(64).out);
                for back in ["UTF-8", "UTF-16LE", "UCS-4LE//IGNORE"] {
                    let (ic, oc) = if r.below(3) == 0 { (vec![1 + r.below(6)], vec![1 + r.below(12), 128]) } else { (vec![4096], vec![4096]) };
                    if let Err(e) = compare_run(back, base, &bytes, &ic, &oc, true) {
                        bad.push(e);
                        break;
                    }
                }
            }
            if bad.len() > 5 {
                break;
            }
        }
        if bad.len() > 5 {
            break;
        }
    }
    assert!(bad.is_empty(), "{} mismatches over {} names, first:\n{}", bad.len(), names.len(), bad[..bad.len().min(4)].join("\n"));
}
