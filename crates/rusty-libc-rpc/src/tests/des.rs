//! DES (`cbc_crypt`, `ecb_crypt`, ...), the secure RPC key helpers and net names against glibc.
use super::*;

fn h2b(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
fn fips_vector() {
    // the worked example of the DES standard (key 133457799BBCDFF1)
    let key = h2b("133457799BBCDFF1");
    let mut k = [key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]];
    let mut data = h2b("0123456789ABCDEF");
    let mut d = [0u8; 8];
    d.copy_from_slice(&data);
    let r = unsafe { crate::des::ecb_crypt(k.as_mut_ptr().cast(), d.as_mut_ptr().cast(), 8, crate::des::DES_ENCRYPT | crate::des::DES_SW) };
    assert_eq!(r, 0);
    assert_eq!(d.to_vec(), h2b("85E813540F0AB405"));
    let r = unsafe { crate::des::ecb_crypt(k.as_mut_ptr().cast(), d.as_mut_ptr().cast(), 8, crate::des::DES_DECRYPT | crate::des::DES_SW) };
    assert_eq!(r, 0);
    assert_eq!(d.to_vec(), data.split_off(0));
    // weak-key and all-zero examples, against glibc below
}

#[test]
fn ecb_cbc_against_glibc() {
    let _g = lock();
    let apis = both();
    let mut rng = Rng(0xDE5);
    let mut cases = 0;
    for round in 0..400 {
        let key = rng.bytes(8);
        let len = match round % 8 {
            0 => 0,
            1 => 8,
            2 => 16,
            3 => 7,
            4 if round % 40 == 4 => 8192,
            5 if round % 40 == 5 => 8200,
            4 | 5 => 64,
            _ => 8 * (1 + rng.below(100) as usize),
        };
        let data = rng.bytes(len.max(1));
        let iv = rng.bytes(8);
        for mode in 0..4u32 {
            let mut outs = Vec::new();
            for (_, a) in apis.iter() {
                let mut k = [0u8; 8];
                k.copy_from_slice(&key);
                let mut buf = data.clone();
                buf.resize(len.max(8192 + 8), 0xEE);
                let mut ivb = [0u8; 8];
                ivb.copy_from_slice(&iv);
                let r = unsafe { (a.cbc_crypt)(k.as_mut_ptr().cast(), buf.as_mut_ptr().cast(), len as u32, mode, ivb.as_mut_ptr().cast()) };
                let r2 = {
                    let mut buf2 = data.clone();
                    buf2.resize(len.max(8192 + 8), 0xEE);
                    let r2 = unsafe { (a.ecb_crypt)(k.as_mut_ptr().cast(), buf2.as_mut_ptr().cast(), len as u32, mode) };
                    (r2, buf2)
                };
                outs.push((r, buf, ivb, r2));
            }
            let ctx = format!("round {round} len {len} mode {mode}");
            assert_eq!(outs[0].0, outs[1].0, "cbc result, {ctx}");
            assert_eq!(outs[0].2, outs[1].2, "cbc ivec, {ctx}");
            assert_eq!((outs[0].3).0, (outs[1].3).0, "ecb result, {ctx}");
            assert!(outs[0].1 == outs[1].1, "cbc buffer, {ctx}");
            assert!((outs[0].3).1 == (outs[1].3).1, "ecb buffer, {ctx}");
            cases += 1;
        }
    }
    assert!(cases > 1000);
}

#[test]
fn setparity_and_passwd2des() {
    let _g = lock();
    let apis = both();
    for base in 0..32usize {
        let mut outs = Vec::new();
        for (_, a) in apis.iter() {
            let mut k: Vec<u8> = (0..8).map(|i| (base * 8 + i) as u8).collect();
            k.extend_from_slice(&[0; 4]);
            unsafe { (a.des_setparity)(k.as_mut_ptr().cast()) };
            outs.push(k);
        }
        assert_eq!(outs[0], outs[1], "bytes {}..", base * 8);
    }
    let mut rng = Rng(8);
    for _ in 0..300 {
        let n = rng.below(14) as usize;
        let mut pw: Vec<u8> = (0..n).map(|_| 1 + rng.below(255) as u8).collect();
        pw.push(0);
        let mut outs = Vec::new();
        for (_, a) in apis.iter() {
            let mut key = [0xAAu8; 12];
            unsafe { (a.passwd2des)(pw.as_mut_ptr().cast(), key.as_mut_ptr().cast()) };
            outs.push(key);
        }
        assert_eq!(outs[0], outs[1], "password {pw:02x?}");
    }
}

#[test]
fn xencrypt_xdecrypt() {
    let _g = lock();
    let apis = both();
    let mut rng = Rng(77);
    for round in 0..200 {
        let nbytes = [0usize, 1, 8, 16, 24, 48, 192, 7][round % 8];
        let mut hex: Vec<u8> = rng.bytes(nbytes).iter().flat_map(|b| format!("{b:02x}").into_bytes()).collect();
        if round % 13 == 0 && !hex.is_empty() {
            hex[0] = b'g';
        }
        if round % 17 == 0 {
            hex.push(b'f'); // odd length
        }
        hex.push(0);
        let pw = format!("secret{}", rng.below(1000)).into_bytes();
        let mut pwz = pw.clone();
        pwz.push(0);
        let mut outs = Vec::new();
        for (_, a) in apis.iter() {
            let mut s = hex.clone();
            s.extend_from_slice(&[0xAA; 8]);
            let r = unsafe { (a.xencrypt)(s.as_mut_ptr().cast(), pwz.as_mut_ptr().cast()) };
            let enc = s.clone();
            let r2 = unsafe { (a.xdecrypt)(s.as_mut_ptr().cast(), pwz.as_mut_ptr().cast()) };
            outs.push((r, enc, r2, s));
        }
        assert_eq!(outs[0], outs[1], "round {round}");
    }
}

#[test]
fn netnames() {
    let _g = lock();
    let apis = both();
    for domain in [None, Some("example.org"), Some("example.org."), Some(""), Some("a".repeat(300).leak() as &str)] {
        for uid in [0u32, 1000, 65534, 4294967295] {
            let mut outs = Vec::new();
            for (_, a) in apis.iter() {
                let mut nn = [0x55 as c_char; 300];
                let d = domain.map(|d| std::ffi::CString::new(d).unwrap());
                let r = unsafe { (a.user2netname)(nn.as_mut_ptr(), uid, d.as_ref().map_or(core::ptr::null(), |d| d.as_ptr())) };
                outs.push((r, if r != 0 { unsafe { std::ffi::CStr::from_ptr(nn.as_ptr()) }.to_bytes().to_vec() } else { Vec::new() }));
            }
            assert_eq!(outs[0], outs[1], "user2netname {domain:?} {uid}");
        }
    }
    for host in [None, Some("host"), Some("host.sub.example.org"), Some("host.example.org."), Some("x".repeat(100).leak() as &str)] {
        for domain in [None, Some("example.org"), Some("example.org."), Some("")] {
            let mut outs = Vec::new();
            for (_, a) in apis.iter() {
                let mut nn = [0x55 as c_char; 300];
                let h = host.map(|d| std::ffi::CString::new(d).unwrap());
                let d = domain.map(|d| std::ffi::CString::new(d).unwrap());
                let r = unsafe { (a.host2netname)(nn.as_mut_ptr(), h.as_ref().map_or(core::ptr::null(), |h| h.as_ptr()), d.as_ref().map_or(core::ptr::null(), |d| d.as_ptr())) };
                let s = unsafe { std::ffi::CStr::from_ptr(nn.as_ptr()) }.to_bytes().to_vec();
                outs.push((r, s));
            }
            assert_eq!(outs[0], outs[1], "host2netname {host:?} {domain:?}");
        }
    }
    let mut outs = Vec::new();
    for (_, a) in apis.iter() {
        let mut nn = [0 as c_char; 300];
        let r = unsafe { (a.getnetname)(nn.as_mut_ptr()) };
        outs.push((r, unsafe { std::ffi::CStr::from_ptr(nn.as_ptr()) }.to_bytes().to_vec()));
    }
    assert_eq!(outs[0], outs[1], "getnetname");
    for name in ["unix.host@example.org", "unix.1000@example.org", "nodot", "unix.noat", "a.b@c@d", ".@"] {
        for hostlen in [0, 3, 10, 255, 300] {
            let mut outs = Vec::new();
            for (_, a) in apis.iter() {
                let mut nn: Vec<u8> = name.bytes().collect();
                nn.push(0);
                let mut out = [0x77 as c_char; 600];
                let r = unsafe { (a.netname2host)(nn.as_mut_ptr().cast(), out.as_mut_ptr(), hostlen) };
                outs.push((r, nn, out[..(hostlen as usize + 2).min(600)].to_vec()));
            }
            assert_eq!(outs[0], outs[1], "netname2host {name} {hostlen}");
        }
    }
    // no NIS: the public key database and the netname mapping find nothing, in both
    for (name, a) in apis.iter() {
        let mut key = [0 as c_char; 1024];
        assert_eq!(unsafe { (a.getpublickey)(c"unix.1000@example.org".as_ptr(), key.as_mut_ptr()) }, 0, "{name}");
        assert_eq!(unsafe { (a.getsecretkey)(c"unix.1000@example.org".as_ptr(), key.as_mut_ptr(), c"pw".as_ptr()) }, 0, "{name}");
        let (mut u, mut g, mut n) = (0u32, 0u32, 0);
        let mut gl = [0u32; 16];
        assert_eq!(unsafe { (a.netname2user)(c"unix.1000@example.org".as_ptr(), &mut u, &mut g, &mut n, gl.as_mut_ptr()) }, 0, "{name}");
    }
}

#[test]
fn key_server_calls_fail_without_keyserv() {
    let _g = lock();
    if std::path::Path::new("/var/run/keyservsock").exists() {
        return; // a key server is running here: nothing to compare
    }
    for (name, a) in both() {
        let mut blk = des_block { key: des_block_key { high: 1, low: 2 } };
        let mut remote = *b"unix.1000@example.org\0";
        let mut sec = [b'0' as c_char; 49];
        sec[48] = 0;
        unsafe {
            assert_eq!((a.key_setsecret)(sec.as_mut_ptr()), -1, "{name}");
            assert_eq!((a.key_secretkey_is_set)(), 0, "{name}");
            assert_eq!((a.key_encryptsession)(remote.as_mut_ptr().cast(), &mut blk), -1, "{name}");
            assert_eq!((a.key_decryptsession)(remote.as_mut_ptr().cast(), &mut blk), -1, "{name}");
            let mut nobj = netobj { n_len: 4, n_bytes: remote.as_mut_ptr().cast() };
            assert_eq!((a.key_encryptsession_pk)(remote.as_mut_ptr().cast(), &mut nobj, &mut blk), -1, "{name}");
            assert_eq!((a.key_decryptsession_pk)(remote.as_mut_ptr().cast(), &mut nobj, &mut blk), -1, "{name}");
            assert_eq!((a.key_get_conv)(sec.as_mut_ptr(), &mut blk), -1, "{name}");
        }
    }
}
