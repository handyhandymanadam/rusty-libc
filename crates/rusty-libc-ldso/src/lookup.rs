#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::elf::*;
use crate::ffi::CStrRef;
use crate::map::*;
use crate::sync_cell::SyncCell;
use crate::util::*;

#[derive(Clone, Copy)]
pub struct VerRef {
    pub name: CStrRef,
    pub hash: u32,
    pub file: Option<CStrRef>,
    pub hidden: bool,
}

pub struct Flags {
    pub plt: bool,
    pub skip: Option<Map>,
    pub newest: bool,
}

#[derive(Clone, Copy)]
pub struct Found {
    pub sym: &'static Sym,
    pub map: Map,
}

#[allow(clippy::too_many_arguments)]
fn check_match(m: Map, s: &'static Sym, idx: usize, name: &[u8], ver: Option<&VerRef>, fl: &Flags, num_versions: &mut u32, versioned: &mut Option<&'static Sym>) -> bool {
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
    if !m.sym_name(s).eq_bytes(name) {
        return false;
    }
    let vs = m.versym();
    match ver {
        Some(v) => {
            if vs.is_null() {
            } else {
                let e = unsafe { *vs.wrapping_add(idx) };
                let ndx = (e & 0x7fff) as usize;
                let vi = m.vers().get(ndx).copied().unwrap_or(VerInfo { name: None, hash: 0, file: None, hidden: false });
                let same = vi.hash == v.hash && vi.name.is_some_and(|n| n.eq_str(v.name));
                if !same {
                    if !v.hidden && vi.name.is_none_or(|n| n.is_empty()) && (e & 0x8000) == 0 {
                        if *num_versions == 0 {
                            *versioned = Some(s);
                        }
                        *num_versions += 1;
                    }
                    return false;
                }
            }
        }
        None => {
            if !vs.is_null() {
                let e = unsafe { *vs.wrapping_add(idx) };
                if (e & 0x7fff) as u32 >= if fl.newest { 2 } else { 3 } {
                    if e & 0x8000 == 0 {
                        if *num_versions == 0 {
                            *versioned = Some(s);
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

#[allow(clippy::too_many_arguments)]
fn lookup_in(m: Map, name: &[u8], gh: u32, eh: &mut Option<u32>, ver: Option<&VerRef>, fl: &Flags, nver: &mut u32, versioned: &mut Option<&'static Sym>) -> Option<&'static Sym> {
    if m.symtab().is_null() || m.strtab().is_null() {
        return None;
    }
    let nb = m.gnu_nbuckets();
    if nb != 0 {
        let bits = 64u32;
        let size = m.gnu_bloom_size();
        let w = gh / bits;
        let word = m.gnu_bloom_words()[(if size & (size.wrapping_sub(1)) == 0 { w & (size.wrapping_sub(1)) } else { w % size }) as usize];
        let mask = (1u64 << (gh % bits)) | (1u64 << ((gh >> m.gnu_bloom_shift()) % bits));
        if word & mask != mask {
            return None;
        }
        let mut i = m.gnu_bucket_words()[(gh % nb) as usize];
        let symoff = m.gnu_symoffset();
        if i < symoff {
            return None;
        }
        let chain = m.gnu_chain();
        loop {
            let ch = unsafe { *chain.wrapping_add((i - symoff) as usize) };
            if (ch | 1) == (gh | 1) {
                let sym = unsafe { m.sym(i as usize) };
                if check_match(m, sym, i as usize, name, ver, fl, nver, versioned) {
                    return Some(sym);
                }
            }
            if ch & 1 != 0 {
                break;
            }
            i += 1;
        }
        return None;
    }
    if m.hash_nbucket() != 0 {
        let h = *eh.get_or_insert_with(|| elf_hash(name));
        let chains = m.hash_chain_words();
        let mut i = m.hash_bucket_words()[(h % m.hash_nbucket()) as usize];
        while i != 0 {
            let sym = unsafe { m.sym(i as usize) };
            if check_match(m, sym, i as usize, name, ver, fl, nver, versioned) {
                return Some(sym);
            }
            i = chains[i as usize];
        }
    }
    None
}

const UNIQUE_MAX: usize = 1024;
struct UniqueTab {
    name: [Option<&'static [u8]>; UNIQUE_MAX],
    found: [Option<Found>; UNIQUE_MAX],
    n: usize,
}
static UNIQUE: SyncCell<UniqueTab> = SyncCell::new(UniqueTab { name: [None; UNIQUE_MAX], found: [None; UNIQUE_MAX], n: 0 });
static UNIQUE_LOCK: Lock = Lock::new();

pub(crate) fn fork_child_reset() {
    UNIQUE_LOCK.reset();
}

fn unique_sym(name: &'static [u8], sym: &'static Sym, m: Map) -> Found {
    UNIQUE_LOCK.lock();
    let r = unsafe {
        UNIQUE.with_unsync(|t| {
            for i in 0..t.n {
                if let Some(f) = t.found[i]
                    && t.name[i] == Some(name) && f.map.l_ns() == m.l_ns()
                {
                    return f;
                }
            }
            if t.n < UNIQUE_MAX {
                let i = t.n;
                t.name[i] = Some(name);
                t.found[i] = Some(Found { sym, map: m });
                t.n += 1;
                m.set_nodelete(true);
            }
            Found { sym, map: m }
        })
    };
    UNIQUE_LOCK.unlock();
    r
}

pub fn lookup(name: &[u8], ver: Option<&VerRef>, scopes: &[&[Map]], fl: &Flags) -> Option<Found> {
    lookup_hashed(name, gnu_hash(name), ver, scopes, fl)
}

pub fn lookup_hashed(name: &[u8], gh: u32, ver: Option<&VerRef>, scopes: &[&[Map]], fl: &Flags) -> Option<Found> {
    let mut eh: Option<u32> = None;
    for scope in scopes {
        for &m in scope.iter() {
            if Some(m) == fl.skip || m.removed() {
                continue;
            }
            let mut nver = 0u32;
            let mut versioned: Option<&'static Sym> = None;
            let mut s = lookup_in(m, name, gh, &mut eh, ver, fl, &mut nver, &mut versioned);
            if s.is_none() && nver == 1 && versioned.is_some() {
                s = versioned;
            }
            if s.is_some() && m.nfiltees() > 0 {
                let mut hit: Option<Found> = None;
                for &fm in m.filtees() {
                    let (mut feh, mut fnv, mut fvs): (Option<u32>, u32, Option<&'static Sym>) = (None, 0, None);
                    let mut fsym = lookup_in(fm, name, gh, &mut feh, ver, fl, &mut fnv, &mut fvs);
                    if fsym.is_none() && fnv == 1 && fvs.is_some() {
                        fsym = fvs;
                    }
                    if let Some(fs) = fsym {
                        hit = Some(Found { sym: fs, map: fm });
                        break;
                    }
                }
                if let Some(h) = hit {
                    return Some(h);
                }
                if m.filter_hard() {
                    s = None;
                }
            }
            if let Some(s) = s {
                if s.info >> 4 == STB_GNU_UNIQUE {
                    let nm = &m.sym_name(s).bytes()[..name.len()];
                    return Some(unique_sym(nm, s, m));
                }
                return Some(Found { sym: s, map: m });
            }
        }
    }
    None
}

pub fn sym_addr(f: &Found) -> usize {
    sym_value_addr(f.map.l_addr(), f.sym)
}

pub fn sym_value_addr(l_addr: usize, sym: &Sym) -> usize {
    if sym.shndx == SHN_ABS { sym.value as usize } else { l_addr.wrapping_add(sym.value as usize) }
}

pub unsafe fn ref_version(m: Map, idx: usize) -> Option<VerRef> {
    if m.versym().is_null() || m.vers_ptr().is_null() {
        return None;
    }
    let e = unsafe { *m.versym().wrapping_add(idx) };
    let ndx = (e & 0x7fff) as usize;
    if ndx <= 1 || ndx >= m.nvers() {
        return None;
    }
    let vi = m.vers()[ndx];
    Some(VerRef { name: vi.name?, hash: vi.hash, file: vi.file, hidden: vi.hidden })
}
