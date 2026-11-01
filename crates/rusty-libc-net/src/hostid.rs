//! gethostid(3) (unistd.h; here because it needs the resolver: glibc's gethostid calls `__gethostbyname_r`). The rules
//! are shared with the Rust face in `rusty_libc_rs_core::hostid`. tools/hdrgen reads this file for the unistd.h
//! declaration (the other unistd.h functions live in rusty-libc-sys).

use crate::dns;
use crate::netdb::{hostbyname_r, use_inet6};
use crate::types::*;
use crate::util::HeapVec;
use core::ffi::{c_int, c_long};
use rusty_libc_core::errno;

/// gethostid(3) as glibc 2.43 (sysdeps/unix/sysv/linux/gethostid.c): the 4 bytes of /etc/hostid (one read; a shorter
/// file does not count); otherwise the host name's first address from gethostbyname_r (this library's resolver, as
/// glibc calls its internal `__gethostbyname_r`, with a scratch buffer of 1024 bytes doubled on ERANGE), its halves
/// swapped; 0 when the name is empty or 64 bytes and longer, the lookup fails or memory runs short. The rules are
/// shared with the Rust face (`rusty_libc_rs_core::hostid`). errno as glibc leaves it: from a failed open or read of
/// /etc/hostid, then the lookup's result (0 after a lookup that found the name), ENOMEM when the buffer cannot grow.
/// Difference: a lookup that succeeds with an empty address list gives 0 (glibc would read through the NULL entry);
/// glibc's sources and ours never return one (a name without addresses is NO_DATA).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gethostid() -> c_long {
    use rusty_libc_core::unistd;
    use rusty_libc_rs_core::hostid;
    // __open_nocancel (HOSTIDFILE, O_RDONLY|O_LARGEFILE): O_LARGEFILE is 0 on x86-64
    match crate::util::open(c"/etc/hostid", 0, 0) {
        Ok(fd) => {
            let mut id = [0u8; 4];
            let n = unistd::read_nocancel(fd, &mut id);
            let _ = unistd::close(fd); // __close_nocancel_nostatus: errno untouched
            match n {
                Ok(n) => {
                    if let Some(v) = hostid::from_file(n, id) {
                        return v as c_long;
                    }
                }
                Err(e) => errno::set(e.0),
            }
        }
        Err(e) => errno::set(e.0),
    }
    let mut un = [0u8; 390];
    if !dns::uname(&mut un) {
        return 0;
    }
    let node = &un[65..130];
    let node = &node[..node.iter().position(|&b| b == 0).unwrap_or(node.len())];
    if node.len() >= hostid::MAXHOSTNAMELEN {
        errno::set(ENAMETOOLONG); // gethostname (hostname, MAXHOSTNAMELEN) failed
    }
    hostid::from_host_name(node, host_first_address) as c_long
}

/// gethostid's lookup: `__gethostbyname_r (name, ...)` with glibc's scratch buffer (1024 bytes, doubled while the
/// result is ERANGE with h_errno NETDB_INTERNAL), then the first `min(4, h_length)` bytes of `h_addr_list[0]`.
fn host_first_address(name: &[u8]) -> Option<[u8; 4]> {
    let af = if use_inet6() { AF_INET6 } else { AF_INET };
    let mut first = [0u8; 1024];
    let mut heap: Option<HeapVec<u8>> = None;
    let mut res = hostent { h_name: core::ptr::null_mut(), h_aliases: core::ptr::null_mut(), h_addrtype: 0, h_length: 0, h_addr_list: core::ptr::null_mut() };
    loop {
        let buf: &mut [u8] = match heap.as_mut() {
            Some(h) => h.as_mut_slice(),
            None => &mut first,
        };
        let len = buf.len();
        let mut herr: c_int = 0;
        let (r, ok) = hostbyname_r(1, Some(name), af, &mut res, buf, &mut herr);
        if r == 0 && ok {
            break;
        }
        // hostbyname_r leaves errno == r, so glibc's `errno == ERANGE` is `r == ERANGE`
        if r != 0 && herr == NETDB_INTERNAL && r == ERANGE {
            // scratch_buffer_grow: the old block goes first; a failed allocation sets ENOMEM
            drop(heap.take());
            match len.checked_mul(2).and_then(HeapVec::zeroed) {
                Some(h) => heap = Some(h),
                None => {
                    errno::set(ENOMEM);
                    return None;
                }
            }
            continue;
        }
        return None;
    }
    // The entry and its address list were written into `buf` by hostbyname_r: follow the pointers as offsets into it.
    let buf: &[u8] = match heap.as_ref() {
        Some(h) => h,
        None => &first,
    };
    let at = |p: usize, len: usize| p.checked_sub(buf.as_ptr() as usize).and_then(|o| buf.get(o..o.checked_add(len)?));
    let entry0 = at(res.h_addr_list as usize, 8)?; // h_addr_list[0]
    let a = usize::from_ne_bytes(entry0.try_into().ok()?);
    if a == 0 {
        return None;
    }
    let n = usize::try_from(res.h_length).unwrap_or(0).min(4);
    let mut out = [0u8; 4];
    out[..n].copy_from_slice(at(a, n)?);
    Some(out)
}
