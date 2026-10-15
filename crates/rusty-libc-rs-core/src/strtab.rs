pub const fn packed_len(t: &[&str]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < t.len() {
        n += t[i].len() + 1;
        i += 1;
    }
    n
}

pub const fn packed_len_bytes(t: &[&[u8]]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < t.len() {
        n += t[i].len() + 1;
        i += 1;
    }
    n
}

pub struct StrTab<const N: usize, const B: usize> {
    off: [u16; N],
    blob: [u8; B],
}

impl<const N: usize, const B: usize> StrTab<N, B> {
    pub const fn new(t: &[&str; N]) -> Self {
        let mut b: [&[u8]; N] = [&[]; N];
        let mut i = 0;
        while i < N {
            b[i] = t[i].as_bytes();
            i += 1;
        }
        Self::from_bytes(&b)
    }

    pub const fn from_bytes(t: &[&[u8]; N]) -> Self {
        assert!(B == packed_len_bytes(t) && B <= 65536);
        let mut off = [0u16; N];
        let mut blob = [0u8; B];
        let (mut k, mut i) = (0usize, 0);
        while i < N {
            off[i] = k as u16;
            let b = t[i];
            let mut j = 0;
            while j < b.len() {
                assert!(b[j] != 0);
                blob[k] = b[j];
                k += 1;
                j += 1;
            }
            k += 1;
            i += 1;
        }
        StrTab { off, blob }
    }

    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        N
    }

    #[inline]
    pub fn bytes_with_nul(&self, i: usize) -> Option<&[u8]> {
        let start = *self.off.get(i)? as usize;
        let end = match self.off.get(i + 1) {
            Some(&e) => e as usize,
            None => B,
        };
        self.blob.get(start..end)
    }

    #[inline]
    pub fn bytes(&self, i: usize) -> &[u8] {
        match self.bytes_with_nul(i) {
            Some(b) => &b[..b.len() - 1],
            None => &[],
        }
    }

    #[inline]
    pub fn get(&self, i: usize) -> &str {
        core::str::from_utf8(self.bytes(i)).unwrap_or("")
    }

    #[inline]
    pub fn cstr(&self, i: usize) -> Option<&core::ffi::CStr> {
        core::ffi::CStr::from_bytes_with_nul(self.bytes_with_nul(i)?).ok()
    }

    pub fn position(&self, s: &[u8]) -> Option<usize> {
        (0..N).find(|&i| self.bytes(i) == s)
    }
}

