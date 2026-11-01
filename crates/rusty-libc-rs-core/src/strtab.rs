//! Tables of strings without pointers: every string back to back in one byte array (each followed by a NUL), found by 16-bit
//! offsets. A `static` (or a `const` indexed at run time) of `&str`s holds one pointer per string, and in libc.so.6 every such
//! pointer is a relative relocation the loader writes at every start, which makes the page holding it a private copy (Drepper,
//! "How To Write Shared Libraries" 4.1.2, section 2.4.3 and appendix B, p. 44: string arrays as one string plus an offset
//! table need no relocations). Build one from a `const` array at compile time:
//!
//! ```ignore
//! const NAMES: [&str; 3] = ["one", "two", "three"];
//! static TAB: StrTab<3, { packed_len(&NAMES) }> = StrTab::new(&NAMES);
//! ```
//!
//! The `const` array then stays a compile-time value as long as nothing indexes it at run time. No `unsafe`: this file is also
//! compiled into ld.so (included by path).

/// The bytes a [`StrTab`] of these strings needs: each string and its NUL.
pub const fn packed_len(t: &[&str]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < t.len() {
        n += t[i].len() + 1;
        i += 1;
    }
    n
}

/// [`packed_len`] for byte strings.
pub const fn packed_len_bytes(t: &[&[u8]]) -> usize {
    let mut n = 0;
    let mut i = 0;
    while i < t.len() {
        n += t[i].len() + 1;
        i += 1;
    }
    n
}

/// `N` strings in `B` bytes (see the module documentation).
pub struct StrTab<const N: usize, const B: usize> {
    off: [u16; N],
    blob: [u8; B],
}

impl<const N: usize, const B: usize> StrTab<N, B> {
    /// The table of `t`; `B` must be `packed_len(t)` and at most 65536 (checked at compile time).
    pub const fn new(t: &[&str; N]) -> Self {
        let mut b: [&[u8]; N] = [&[]; N];
        let mut i = 0;
        while i < N {
            b[i] = t[i].as_bytes();
            i += 1;
        }
        Self::from_bytes(&b)
    }

    /// The table of byte strings `t` (none may hold a NUL); `B` must be `packed_len_bytes(t)`, at most 65536.
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
            k += 1; // the NUL
            i += 1;
        }
        StrTab { off, blob }
    }

    /// The number of strings.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        N
    }

    /// String `i` with its NUL; `None` past the end.
    #[inline]
    pub fn bytes_with_nul(&self, i: usize) -> Option<&[u8]> {
        let start = *self.off.get(i)? as usize;
        let end = match self.off.get(i + 1) {
            Some(&e) => e as usize,
            None => B,
        };
        self.blob.get(start..end)
    }

    /// String `i` without its NUL (empty past the end).
    #[inline]
    pub fn bytes(&self, i: usize) -> &[u8] {
        match self.bytes_with_nul(i) {
            Some(b) => &b[..b.len() - 1],
            None => &[],
        }
    }

    /// String `i` (empty past the end).
    #[inline]
    pub fn get(&self, i: usize) -> &str {
        core::str::from_utf8(self.bytes(i)).unwrap_or("")
    }

    /// String `i` as a C string; `None` past the end.
    #[inline]
    pub fn cstr(&self, i: usize) -> Option<&core::ffi::CStr> {
        core::ffi::CStr::from_bytes_with_nul(self.bytes_with_nul(i)?).ok()
    }

    /// The index of the first string equal to `s`.
    pub fn position(&self, s: &[u8]) -> Option<usize> {
        (0..N).find(|&i| self.bytes(i) == s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const T: [&str; 4] = ["one", "", "three", "x"];
    static TAB: StrTab<4, { packed_len(&T) }> = StrTab::new(&T);

    #[test]
    fn lookups() {
        for (i, s) in T.iter().enumerate() {
            assert_eq!(TAB.get(i), *s);
            assert_eq!(TAB.bytes(i), s.as_bytes());
            assert_eq!(TAB.cstr(i).unwrap().to_bytes(), s.as_bytes());
        }
        assert_eq!(TAB.get(4), "");
        assert!(TAB.cstr(4).is_none());
        assert_eq!(TAB.position(b"three"), Some(2));
        assert_eq!(TAB.position(b""), Some(1));
        assert_eq!(TAB.position(b"two"), None);
        assert_eq!(TAB.len(), 4);
    }
}
