//! gethostid(3)'s rules as glibc 2.43 applies them (sysdeps/unix/sysv/linux/gethostid.c), shared by both faces: the C
//! face's `gethostid` (rusty-libc-net, with its own resolver) and the Rust face's `system::gethostid` (the running C
//! library's resolver). No I/O here: each face reads /etc/hostid, gets the node name and resolves it its own way.
//!
//! glibc's order: one read of up to 4 bytes from /etc/hostid; exactly 4 bytes are the id. Otherwise the host name
//! (`gethostname(buf, MAXHOSTNAMELEN)`: fails for a name of 64 bytes or more); 0 when that fails or the name is empty.
//! Then the first address `gethostbyname_r` gives for the name, its first `min(4, h_length)` bytes read as the
//! `in_addr`'s `s_addr` (zero-padded), with its 16-bit halves swapped; 0 when the lookup fails.

/// glibc's `MAXHOSTNAMELEN` (sys/param.h), the buffer gethostid passes to gethostname.
pub const MAXHOSTNAMELEN: usize = 64;

/// The id from /etc/hostid: `n` is what the one read returned; only a full 4-byte read counts (a short file falls back
/// to the host name).
pub fn from_file(n: usize, id: [u8; 4]) -> Option<i32> {
    (n == 4).then_some(i32::from_ne_bytes(id))
}

/// The fallback after /etc/hostid gave no id: `nodename` is uname's node name (without its NUL); `lookup` resolves it
/// to the first address's first `min(4, h_length)` bytes, zero-padded (None when the lookup fails). `lookup` is not
/// called when glibc would not get that far (empty name, or 64 bytes and longer).
pub fn from_host_name(nodename: &[u8], lookup: impl FnOnce(&[u8]) -> Option<[u8; 4]>) -> i32 {
    // gethostname(hostname, MAXHOSTNAMELEN) fails with ENAMETOOLONG when the name and its NUL do not fit
    if nodename.len() >= MAXHOSTNAMELEN || nodename.is_empty() {
        return 0;
    }
    lookup(nodename).map_or(0, from_address)
}

/// `(int32_t) (in.s_addr << 16 | in.s_addr >> 16)` for the address bytes `a` (network order, as in `struct in_addr`).
pub fn from_address(a: [u8; 4]) -> i32 {
    u32::from_ne_bytes(a).rotate_left(16) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules() {
        assert_eq!(from_file(4, 0x1234_5678_i32.to_ne_bytes()), Some(0x1234_5678));
        assert_eq!(from_file(4, (-2_i32).to_ne_bytes()), Some(-2));
        for n in 0..4 {
            assert_eq!(from_file(n, [1, 2, 3, 4]), None);
        }
        // fedora-main: 192.168.1.124 -> a8c07c01 (coreutils hostid)
        assert_eq!(from_address([192, 168, 1, 124]) as u32, 0xa8c0_7c01);
        assert_eq!(from_address([127, 0, 0, 1]) as u32, 0x007f_0100);
        // negative: the top bit comes from the address's second byte (b1 b0 b3 b2 from the most significant byte down)
        assert!(from_address([0, 0x80, 0, 0]) < 0);
        assert!(from_address([0, 0, 0x80, 0]) > 0);
        assert_eq!(from_host_name(b"", |_| panic!("not called")), 0);
        assert_eq!(from_host_name(&[b'a'; 64], |_| panic!("not called")), 0);
        assert_eq!(from_host_name(&[b'a'; 63], |n| (n.len() == 63).then_some([10, 0, 0, 1])), from_address([10, 0, 0, 1]));
        assert_eq!(from_host_name(b"h", |_| None), 0);
    }
}
