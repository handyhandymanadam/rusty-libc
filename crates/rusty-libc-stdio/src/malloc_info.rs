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
    {
        if options != 0 {
            return 22;
        }
        let mut o = Out(f);
        let n = |v: usize| Arg::Uint(v as u64);
        let mut bad = format_to(&mut o, c"<malloc version=\"1\">\n", &[]) < 0;
        let mut list = [[0usize; 8]; 256];
        let mut count = 0usize;
        let mut t = [0usize; 6];
        rusty_libc_malloc::arena_infos(|a| {
            if count < list.len() {
                list[count] = [a.main as usize, a.nblocks, a.avail, a.system, a.max_system, a.aspace, a.aspace_mprotect, a.subheaps];
                count += 1;
            }
            t[0] += a.nblocks;
            t[1] += a.avail;
            t[2] += a.system;
            t[3] += a.max_system;
            t[4] += a.aspace;
            t[5] += a.aspace_mprotect;
        });
        for (i, a) in list[..count].iter().enumerate() {
            bad |= format_to(
                &mut o,
                c"<heap nr=\"%zu\">\n<sizes>\n</sizes>\n<total type=\"rest\" count=\"%zu\" size=\"%zu\"/>\n<system type=\"current\" size=\"%zu\"/>\n<system type=\"max\" size=\"%zu\"/>\n<aspace type=\"total\" size=\"%zu\"/>\n<aspace type=\"mprotect\" size=\"%zu\"/>\n",
                &[n(i), n(a[1]), n(a[2]), n(a[3]), n(a[4]), n(a[5]), n(a[6])],
            ) < 0;
            if a[0] == 0 {
                bad |= format_to(&mut o, c"<aspace type=\"subheaps\" size=\"%zu\"/>\n", &[n(a[7])]) < 0;
            }
            bad |= format_to(&mut o, c"</heap>\n", &[]) < 0;
        }
        let (mmaps, mmapped) = rusty_libc_malloc::mmap_totals();
        bad |= format_to(
            &mut o,
            c"<total type=\"rest\" count=\"%zu\" size=\"%zu\"/>\n<total type=\"mmap\" count=\"%zu\" size=\"%zu\"/>\n<system type=\"current\" size=\"%zu\"/>\n<system type=\"max\" size=\"%zu\"/>\n<aspace type=\"total\" size=\"%zu\"/>\n<aspace type=\"mprotect\" size=\"%zu\"/>\n</malloc>\n",
            &[n(t[0]), n(t[1]), n(mmaps), n(mmapped), n(t[2]), n(t[3]), n(t[4]), n(t[5])],
        ) < 0;
        if bad { -1 } else { 0 }
    }
}
