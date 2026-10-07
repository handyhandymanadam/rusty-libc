use crate::elf::*;
use crate::map::*;
use crate::util::*;
use core::ptr::null;

#[derive(Clone, Copy)]
pub struct VerRef {
    pub name: *const u8,
    pub hash: u32,
    pub file: *const u8,
    pub hidden: bool,
}

pub struct Flags {
    pub plt: bool,
    pub skip: *mut LinkMap,
    pub newest: bool,
}

pub struct Found {
    pub sym: *const Sym,
    pub map: *mut LinkMap,
}

unsafe fn check_match(m: *mut LinkMap, sym: *const Sym, idx: usize, name: &[u8], ver: Option<&VerRef>, fl: &Flags, num_versions: &mut u32, versioned: &mut *const Sym) -> bool {
    unsafe {
        let s = &*sym;
        let typ = s.info & 0xf;
        if (s.value == 0 && s.shndx != SHN_ABS && typ != STT_TLS) || (fl.plt && s.shndx == SHN_UNDEF) {
            return false;
        }
        if !matches!(typ, STT_NOTYPE | STT_OBJECT | STT_FUNC | STT_COMMON | STT_TLS | STT_GNU_IFUNC) {
            return false;
        }
        if s.shndx == SHN_UNDEF && s.value == 0 {
            return false;
        }
        if !cstr_eq((*m).strtab.add(s.name as usize), name) {
            return false;
        }
        let vs = (*m).versym;
        match ver {
            Some(v) => {
                if vs.is_null() {
                } else {
                    let e = *vs.add(idx);
                    let ndx = (e & 0x7fff) as usize;
                    let vi = if ndx < (*m).nvers { (*(*m).vers.add(ndx)) } else { VerInfo { name: null(), hash: 0, file: null(), hidden: false } };
                    let same = vi.hash == v.hash && !vi.name.is_null() && streq(vi.name, v.name);
                    if !same {
                        if !v.hidden && (vi.name.is_null() || *vi.name == 0) && (e & 0x8000) == 0 {
                            if *num_versions == 0 {
                                *versioned = sym;
                            }
                            *num_versions += 1;
                        }
                        return false;
                    }
                }
            }
            None => {
                if !vs.is_null() {
                    let e = *vs.add(idx);
                    if (e & 0x7fff) as u32 >= if fl.newest { 2 } else { 3 } {
                        if e & 0x8000 == 0 {
                            if *num_versions == 0 {
                                *versioned = sym;
                            }
                            *num_versions += 1;
                        }
                        return false;
                    }
                }
            }
        }
        true
    }
}

unsafe fn lookup_in(m: *mut LinkMap, name: &[u8], gh: u32, eh: &mut Option<u32>, ver: Option<&VerRef>, fl: &Flags, nver: &mut u32, versioned: &mut *const Sym) -> *const Sym {
    unsafe {
        if (*m).symtab.is_null() || (*m).strtab.is_null() {
            return null();
        }
        if (*m).gnu_nbuckets != 0 {
            let bits = 64u32;
            let size = (*m).gnu_bloom_size;
            let w = gh / bits;
            let word = *(*m).gnu_bloom.add((if size & (size - 1) == 0 { w & (size - 1) } else { w % size }) as usize);
            let mask = (1u64 << (gh % bits)) | (1u64 << ((gh >> (*m).gnu_bloom_shift) % bits));
            if word & mask != mask {
                return null();
            }
            let mut i = *(*m).gnu_buckets.add((gh % (*m).gnu_nbuckets) as usize);
            if i < (*m).gnu_symoffset {
                return null();
            }
            loop {
                let ch = *(*m).gnu_chain.add((i - (*m).gnu_symoffset) as usize);
                if (ch | 1) == (gh | 1) {
                    let sym = (*m).symtab.add(i as usize);
                    if check_match(m, sym, i as usize, name, ver, fl, nver, versioned) {
                        return sym;
                    }
                }
                if ch & 1 != 0 {
                    break;
                }
                i += 1;
            }
            return null();
        }
        if (*m).hash_nbucket != 0 {
            let h = *eh.get_or_insert_with(|| elf_hash(name));
            let mut i = *(*m).hash_buckets.add((h % (*m).hash_nbucket) as usize);
            while i != 0 {
                let sym = (*m).symtab.add(i as usize);
                if check_match(m, sym, i as usize, name, ver, fl, nver, versioned) {
                    return sym;
                }
                i = *(*m).hash_chains.add(i as usize);
            }
        }
        null()
    }
}

const UNIQUE_MAX: usize = 1024;
struct UniqueTab {
    name: [(*const u8, usize); UNIQUE_MAX],
    found: [(*const Sym, *mut LinkMap); UNIQUE_MAX],
    n: usize,
}
static mut UNIQUE: UniqueTab = UniqueTab { name: [(core::ptr::null(), 0); UNIQUE_MAX], found: [(core::ptr::null(), core::ptr::null_mut()); UNIQUE_MAX], n: 0 };
static UNIQUE_LOCK: Lock = Lock::new();

unsafe fn unique_sym(name: &[u8], sym: *const Sym, m: *mut LinkMap) -> Found {
    unsafe {
        UNIQUE_LOCK.lock();
        let t = &mut *(&raw mut UNIQUE);
        for i in 0..t.n {
            let (p, len) = t.name[i];
            if len == name.len() && core::slice::from_raw_parts(p, len) == name {
                let (s, mm) = t.found[i];
                UNIQUE_LOCK.unlock();
                return Found { sym: s, map: mm };
            }
        }
        if t.n < UNIQUE_MAX {
            let i = t.n;
            t.name[i] = (name.as_ptr(), name.len());
            t.found[i] = (sym, m);
            t.n += 1;
            (*m).nodelete = true;
        }
        UNIQUE_LOCK.unlock();
        Found { sym, map: m }
    }
}

pub unsafe fn lookup(name: &[u8], ver: Option<&VerRef>, scopes: &[&[*mut LinkMap]], fl: &Flags) -> Option<Found> {
    unsafe { lookup_hashed(name, gnu_hash(name), ver, scopes, fl) }
}

pub unsafe fn lookup_hashed(name: &[u8], gh: u32, ver: Option<&VerRef>, scopes: &[&[*mut LinkMap]], fl: &Flags) -> Option<Found> {
    unsafe {
        let mut eh: Option<u32> = None;
        for scope in scopes {
            for &m in scope.iter() {
                if m == fl.skip || (*m).removed {
                    continue;
                }
                let mut nver = 0u32;
                let mut versioned: *const Sym = null();
                let mut s = lookup_in(m, name, gh, &mut eh, ver, fl, &mut nver, &mut versioned);
                if !s.is_null() && (*m).nfiltees > 0 {
                    let mut hit: Option<Found> = None;
                    for k in 0..(*m).nfiltees {
                        let fm = *(*m).filtees.add(k);
                        let (mut feh, mut fnv, mut fvs): (Option<u32>, u32, *const Sym) = (None, 0, null());
                        let fsym = lookup_in(fm, name, gh, &mut feh, ver, fl, &mut fnv, &mut fvs);
                        if !fsym.is_null() {
                            hit = Some(Found { sym: fsym, map: fm });
                            break;
                        }
                    }
                    if let Some(h) = hit {
                        return Some(h);
                    }
                    if (*m).filter_hard {
                        s = null();
                    }
                }
                if !s.is_null() {
                    if (*s).info >> 4 == STB_GNU_UNIQUE {
                        let nm = core::slice::from_raw_parts((*m).strtab.add((*s).name as usize), name.len());
                        return Some(unique_sym(nm, s, m));
                    }
                    return Some(Found { sym: s, map: m });
                }
                if nver == 1 && !versioned.is_null() {
                    return Some(Found { sym: versioned, map: m });
                }
            }
        }
        None
    }
}

pub unsafe fn sym_addr(f: &Found) -> usize {
    unsafe { (*f.map).l_addr.wrapping_add((*f.sym).value as usize) }
}

pub unsafe fn ref_version(m: *mut LinkMap, idx: usize) -> Option<VerRef> {
    unsafe {
        if (*m).versym.is_null() || (*m).vers.is_null() {
            return None;
        }
        let e = *(*m).versym.add(idx);
        let ndx = (e & 0x7fff) as usize;
        if ndx <= 1 || ndx >= (*m).nvers {
            return None;
        }
        let vi = *(*m).vers.add(ndx);
        if vi.name.is_null() {
            return None;
        }
        Some(VerRef { name: vi.name, hash: vi.hash, file: vi.file, hidden: vi.hidden })
    }
}
