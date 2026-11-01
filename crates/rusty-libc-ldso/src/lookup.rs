//! Symbol lookup: GNU hash and SysV hash tables, symbol versions, scope order.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::elf::*;
use crate::ffi::CStrRef;
use crate::map::*;
use crate::sync_cell::SyncCell;
use crate::util::*;

/// A versioned reference: the name and hash of the version the referencing object asked for.
#[derive(Clone, Copy)]
pub struct VerRef {
    pub name: CStrRef,
    pub hash: u32,
    pub file: Option<CStrRef>,
    pub hidden: bool,
}

pub struct Flags {
    /// The reference is a PLT slot (JUMP_SLOT): an undefined symbol with a value (a PLT address) does not count.
    pub plt: bool,
    /// Skip this map (R_X86_64_COPY: the program's own copy is the one being filled in).
    pub skip: Option<Map>,
    /// dlsym: prefer the newest default version over the oldest.
    pub newest: bool,
}

#[derive(Clone, Copy)]
pub struct Found {
    pub sym: &'static Sym,
    pub map: Map,
}

/// Does `s` (index `idx` in `m`) match the wanted name and version?
#[allow(clippy::too_many_arguments)]
fn check_match(m: Map, s: &'static Sym, idx: usize, name: &[u8], ver: Option<&VerRef>, fl: &Flags, num_versions: &mut u32, versioned: &mut Option<&'static Sym>) -> bool {
    let typ = s.info & 0xf;
    // no value: not a definition (except absolute symbols and TLS symbols, whose value is an offset)
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
                // an unversioned library defines it: accept
            } else {
                // SAFETY: DT_VERSYM has one entry per symbol and `idx` is the index of a symbol of `m` (its hash table).
                let e = unsafe { *vs.wrapping_add(idx) };
                let ndx = (e & 0x7fff) as usize;
                let vi = m.vers().get(ndx).copied().unwrap_or(VerInfo { name: None, hash: 0, file: None, hidden: false });
                let same = vi.hash == v.hash && vi.name.is_some_and(|n| n.eq_str(v.name));
                if !same {
                    // glibc 2.35 and later: an exact version match, or the global default version (empty name, not
                    // hidden) as a fallback that counts when it is the only one
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
                // SAFETY: as above.
                let e = unsafe { *vs.wrapping_add(idx) };
                if (e & 0x7fff) as u32 >= if fl.newest { 2 } else { 3 } {
                    // a versioned (not the oldest) definition: only a fallback, and never a hidden one
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
        // the Bloom filter has a power-of-two number of words (the ELF rule): a mask, not a division
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
            // SAFETY: the object's GNU hash chain: from a bucket's first symbol the entries run, one per symbol, up to one
            // with bit 0 set (the loader trusts the object's table, as glibc does).
            let ch = unsafe { *chain.wrapping_add((i - symoff) as usize) };
            if (ch | 1) == (gh | 1) {
                // SAFETY: a symbol of the chain is a symbol of the table.
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
            // SAFETY: DT_HASH's buckets and chains hold symbol indices (below nchain, the number of symbols).
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
/// glibc's table of STB_GNU_UNIQUE symbols (one per namespace): the first definition of a name found by any lookup is the one every later lookup
/// gets, even from an object whose scope does not contain the first definer (two RTLD_LOCAL libraries share `var`).
struct UniqueTab {
    /// (`Option`: an all-zero table, so it stays in .bss)
    name: [Option<&'static [u8]>; UNIQUE_MAX],
    found: [Option<Found>; UNIQUE_MAX],
    n: usize,
}
static UNIQUE: SyncCell<UniqueTab> = SyncCell::new(UniqueTab { name: [None; UNIQUE_MAX], found: [None; UNIQUE_MAX], n: 0 });
static UNIQUE_LOCK: Lock = Lock::new();

/// Called by `tls::__libc_ldso_fork_child` (see there).
pub(crate) fn fork_child_reset() {
    UNIQUE_LOCK.reset();
}

fn unique_sym(name: &'static [u8], sym: &'static Sym, m: Map) -> Found {
    UNIQUE_LOCK.lock();
    // SAFETY: UNIQUE is only touched here, under UNIQUE_LOCK, and nothing below comes back here.
    let r = unsafe {
        UNIQUE.with_unsync(|t| {
            for i in 0..t.n {
                // one table per namespace (glibc keys it by the defining map's `l_ns`)
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
                // the table keeps pointing into this library (and its string table): it cannot go away
                m.set_nodelete(true);
            }
            Found { sym, map: m }
        })
    };
    UNIQUE_LOCK.unlock();
    r
}

/// Look `name` up in the maps of the scopes, in order. Returns the first definition.
pub fn lookup(name: &[u8], ver: Option<&VerRef>, scopes: &[&[Map]], fl: &Flags) -> Option<Found> {
    lookup_hashed(name, gnu_hash(name), ver, scopes, fl)
}

/// [`lookup`] for a caller that has the GNU hash of `name` already.
pub fn lookup_hashed(name: &[u8], gh: u32, ver: Option<&VerRef>, scopes: &[&[Map]], fl: &Flags) -> Option<Found> {
    let mut eh: Option<u32> = None;
    for scope in scopes {
        for &m in scope.iter() {
            if Some(m) == fl.skip || m.removed() {
                continue;
            }
            // glibc counts the versioned definitions per object: an unversioned lookup that meets exactly one
            // versioned default definition in an object takes it right there (not only after every object was searched)
            let mut nver = 0u32;
            let mut versioned: Option<&'static Sym> = None;
            let mut s = lookup_in(m, name, gh, &mut eh, ver, fl, &mut nver, &mut versioned);
            if s.is_none() && nver == 1 && versioned.is_some() {
                // (an unversioned lookup that met exactly one versioned default definition here: dlsym)
                s = versioned;
            }
            if s.is_some() && m.nfiltees() > 0 {
                // a filter object: its filtees define the symbol if they have it (DT_AUXILIARY falls back to this
                // object's own definition, DT_FILTER does not)
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
                // a STB_GNU_UNIQUE definition in a dlopen()ed library pins it (glibc marks it NODELETE: the unique
                // symbol table would keep pointing into the unmapped library)
                if s.info >> 4 == STB_GNU_UNIQUE {
                    // (the name must outlive the call: it points into the string table of the library that defines it)
                    let nm = &m.sym_name(s).bytes()[..name.len()];
                    return Some(unique_sym(nm, s, m));
                }
                return Some(Found { sym: s, map: m });
            }
        }
    }
    None
}

/// The address a found symbol stands for (the symbol's value in its map; TLS symbols are handled by the caller).
pub fn sym_addr(f: &Found) -> usize {
    sym_value_addr(f.map.l_addr(), f.sym)
}

/// Load base plus symbol value, except for an absolute symbol (SHN_ABS), whose value is not relocated (glibc's SYMBOL_ADDRESS).
pub fn sym_value_addr(l_addr: usize, sym: &Sym) -> usize {
    if sym.shndx == SHN_ABS { sym.value as usize } else { l_addr.wrapping_add(sym.value as usize) }
}

/// The version a reference to symbol `idx` of `m` asks for (None for unversioned and for the local/global base index).
///
/// # Safety
/// `idx` is the index of a symbol of `m` (from its relocation table).
pub unsafe fn ref_version(m: Map, idx: usize) -> Option<VerRef> {
    if m.versym().is_null() || m.vers_ptr().is_null() {
        return None;
    }
    // SAFETY: DT_VERSYM has one entry per symbol; `idx` is one (caller's contract).
    let e = unsafe { *m.versym().wrapping_add(idx) };
    let ndx = (e & 0x7fff) as usize;
    if ndx <= 1 || ndx >= m.nvers() {
        return None;
    }
    let vi = m.vers()[ndx];
    Some(VerRef { name: vi.name?, hash: vi.hash, file: vi.file, hidden: vi.hidden })
}
