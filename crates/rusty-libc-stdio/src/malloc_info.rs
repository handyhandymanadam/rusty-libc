use crate::file::{self, File as FILE};
use crate::fmt::Sink;
use crate::rust_api::{Arg, format_to};
use core::ffi::c_int;

struct Out(*mut FILE);

impl Sink for Out {
    fn put(&mut self, bytes: &[u8]) -> bool {
        unsafe { file::write_bytes(self.0, bytes.as_ptr(), bytes.len()) == bytes.len() }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn malloc_info(options: c_int, f: *mut FILE) -> c_int {
    unsafe {
        if options != 0 {
            return 22;
        }
        let m = rusty_libc_malloc::mallinfo2();
        let mut o = Out(f);
        let n = |v: usize| Arg::Uint(v as u64);
        let (blocks, avail) = (m.ordblks.max(1), m.fordblks);
        let heap = format_to(
            &mut o,
            c"<malloc version=\"1\">\n<heap nr=\"0\">\n<sizes>\n</sizes>\n<total type=\"rest\" count=\"%zu\" size=\"%zu\"/>\n<system type=\"current\" size=\"%zu\"/>\n<system type=\"max\" size=\"%zu\"/>\n<aspace type=\"total\" size=\"%zu\"/>\n<aspace type=\"mprotect\" size=\"%zu\"/>\n</heap>\n",
            &[n(blocks), n(avail), n(m.arena), n(m.arena), n(m.arena), n(m.arena)],
        );
        let rest = format_to(
            &mut o,
            c"<total type=\"rest\" count=\"%zu\" size=\"%zu\"/>\n<total type=\"mmap\" count=\"%zu\" size=\"%zu\"/>\n<system type=\"current\" size=\"%zu\"/>\n<system type=\"max\" size=\"%zu\"/>\n<aspace type=\"total\" size=\"%zu\"/>\n<aspace type=\"mprotect\" size=\"%zu\"/>\n</malloc>\n",
            &[n(blocks), n(avail), n(m.hblks), n(m.hblkhd), n(m.arena), n(m.arena), n(m.arena), n(m.arena)],
        );
        if heap < 0 || rest < 0 { -1 } else { 0 }
    }
}
