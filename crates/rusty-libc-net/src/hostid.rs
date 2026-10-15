use crate::dns;
use crate::netdb::{hostbyname_r, use_inet6};
use crate::types::*;
use crate::util::HeapVec;
use core::ffi::{c_int, c_long};
use rusty_libc_core::errno;

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub extern "C" fn gethostid() -> c_long {
    use rusty_libc_core::unistd;
    use rusty_libc_rs_core::hostid;
    match crate::util::open(c"/etc/hostid", 0, 0) {
        Ok(fd) => {
            let mut id = [0u8; 4];
            let n = unistd::read_nocancel(fd, &mut id);
            let _ = unistd::close(fd);
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
        errno::set(ENAMETOOLONG);
    }
    hostid::from_host_name(node, host_first_address) as c_long
}

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
        if r != 0 && herr == NETDB_INTERNAL && r == ERANGE {
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
    let buf: &[u8] = match heap.as_ref() {
        Some(h) => h,
        None => &first,
    };
    let at = |p: usize, len: usize| p.checked_sub(buf.as_ptr() as usize).and_then(|o| buf.get(o..o.checked_add(len)?));
    let entry0 = at(res.h_addr_list as usize, 8)?;
    let a = usize::from_ne_bytes(entry0.try_into().ok()?);
    if a == 0 {
        return None;
    }
    let n = usize::try_from(res.h_length).unwrap_or(0).min(4);
    let mut out = [0u8; 4];
    out[..n].copy_from_slice(at(a, n)?);
    Some(out)
}
