pub const MAXHOSTNAMELEN: usize = 64;

pub fn from_file(n: usize, id: [u8; 4]) -> Option<i32> {
    (n == 4).then_some(i32::from_ne_bytes(id))
}

pub fn from_host_name(nodename: &[u8], lookup: impl FnOnce(&[u8]) -> Option<[u8; 4]>) -> i32 {
    if nodename.len() >= MAXHOSTNAMELEN || nodename.is_empty() {
        return 0;
    }
    lookup(nodename).map_or(0, from_address)
}

pub fn from_address(a: [u8; 4]) -> i32 {
    u32::from_ne_bytes(a).rotate_left(16) as i32
}

