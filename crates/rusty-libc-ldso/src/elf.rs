#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ehdr {
    pub ident: [u8; 16],
    pub typ: u16,
    pub machine: u16,
    pub version: u32,
    pub entry: u64,
    pub phoff: u64,
    pub shoff: u64,
    pub flags: u32,
    pub ehsize: u16,
    pub phentsize: u16,
    pub phnum: u16,
    pub shentsize: u16,
    pub shnum: u16,
    pub shstrndx: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Phdr {
    pub typ: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub paddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Dyn {
    pub tag: i64,
    pub val: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Rela {
    pub offset: u64,
    pub info: u64,
    pub addend: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Sym {
    pub name: u32,
    pub info: u8,
    pub other: u8,
    pub shndx: u16,
    pub value: u64,
    pub size: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Verdef {
    pub version: u16,
    pub flags: u16,
    pub ndx: u16,
    pub cnt: u16,
    pub hash: u32,
    pub aux: u32,
    pub next: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Verdaux {
    pub name: u32,
    pub next: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Verneed {
    pub version: u16,
    pub cnt: u16,
    pub file: u32,
    pub aux: u32,
    pub next: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Vernaux {
    pub hash: u32,
    pub flags: u16,
    pub other: u16,
    pub name: u32,
    pub next: u32,
}

pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const EM_X86_64: u16 = 62;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;
pub const PT_PHDR: u32 = 6;
pub const PT_TLS: u32 = 7;
pub const PT_GNU_EH_FRAME: u32 = 0x6474e550;
pub const PT_GNU_STACK: u32 = 0x6474e551;
pub const PT_GNU_RELRO: u32 = 0x6474e552;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

pub const DT_NULL: i64 = 0;
pub const DT_NEEDED: i64 = 1;
pub const DT_AUXILIARY: i64 = 0x7fff_fffd;
pub const DT_FILTER: i64 = 0x7fff_ffff;
pub const DT_PLTRELSZ: i64 = 2;
pub const DT_PLTGOT: i64 = 3;
pub const DT_HASH: i64 = 4;
pub const DT_STRTAB: i64 = 5;
pub const DT_SYMTAB: i64 = 6;
pub const DT_RELA: i64 = 7;
pub const DT_RELASZ: i64 = 8;
pub const DT_RELAENT: i64 = 9;
pub const DT_STRSZ: i64 = 10;
pub const DT_SYMENT: i64 = 11;
pub const DT_INIT: i64 = 12;
pub const DT_FINI: i64 = 13;
pub const DT_SONAME: i64 = 14;
pub const DT_RPATH: i64 = 15;
pub const DT_SYMBOLIC: i64 = 16;
pub const DT_REL: i64 = 17;
pub const DT_RELSZ: i64 = 18;
pub const DT_PLTREL: i64 = 20;
pub const DT_DEBUG: i64 = 21;
pub const DT_TEXTREL: i64 = 22;
pub const DT_JMPREL: i64 = 23;
pub const DT_BIND_NOW: i64 = 24;
pub const DT_INIT_ARRAY: i64 = 25;
pub const DT_FINI_ARRAY: i64 = 26;
pub const DT_INIT_ARRAYSZ: i64 = 27;
pub const DT_FINI_ARRAYSZ: i64 = 28;
pub const DT_RUNPATH: i64 = 29;
pub const DT_FLAGS: i64 = 30;
pub const DT_PREINIT_ARRAY: i64 = 32;
pub const DT_PREINIT_ARRAYSZ: i64 = 33;
pub const DT_RELRSZ: i64 = 35;
pub const DT_RELR: i64 = 36;
pub const DT_RELRENT: i64 = 37;
pub const DT_GNU_HASH: i64 = 0x6ffffef5;
pub const DT_VERSYM: i64 = 0x6ffffff0;
pub const DT_RELACOUNT: i64 = 0x6ffffff9;
pub const DT_DEPAUDIT: i64 = 0x6ffffefb;
pub const DT_AUDIT: i64 = 0x6ffffefc;
pub const DT_FLAGS_1: i64 = 0x6ffffffb;
pub const DT_VERDEF: i64 = 0x6ffffffc;
pub const DT_VERDEFNUM: i64 = 0x6ffffffd;
pub const DT_VERNEED: i64 = 0x6ffffffe;
pub const DT_VERNEEDNUM: i64 = 0x6fffffff;

pub const DF_ORIGIN: u64 = 1;
pub const DF_TEXTREL: u64 = 4;
pub const DF_SYMBOLIC: u64 = 2;
pub const DF_STATIC_TLS: u64 = 0x10;
pub const DF_BIND_NOW: u64 = 8;
pub const DF_1_NOW: u64 = 1;
pub const DF_1_GLOBAL: u64 = 2;
pub const DF_1_NODELETE: u64 = 8;
pub const DF_1_ORIGIN: u64 = 0x80;

pub const STB_LOCAL: u8 = 0;
pub const STB_GLOBAL: u8 = 1;
pub const STB_WEAK: u8 = 2;
pub const STB_GNU_UNIQUE: u8 = 10;
pub const STT_NOTYPE: u8 = 0;
pub const STT_OBJECT: u8 = 1;
pub const STT_FUNC: u8 = 2;
pub const STT_SECTION: u8 = 3;
pub const STT_COMMON: u8 = 5;
pub const STT_TLS: u8 = 6;
pub const STT_GNU_IFUNC: u8 = 10;
pub const STV_DEFAULT: u8 = 0;
pub const SHN_UNDEF: u16 = 0;
pub const SHN_ABS: u16 = 0xfff1;

pub const R_X86_64_NONE: u32 = 0;
pub const R_X86_64_64: u32 = 1;
pub const R_X86_64_COPY: u32 = 5;
pub const R_X86_64_GLOB_DAT: u32 = 6;
pub const R_X86_64_JUMP_SLOT: u32 = 7;
pub const R_X86_64_RELATIVE: u32 = 8;
pub const R_X86_64_DTPMOD64: u32 = 16;
pub const R_X86_64_DTPOFF64: u32 = 17;
pub const R_X86_64_TPOFF64: u32 = 18;
pub const R_X86_64_SIZE64: u32 = 33;
pub const R_X86_64_TLSDESC: u32 = 36;
pub const R_X86_64_IRELATIVE: u32 = 37;

pub const AT_NULL: usize = 0;
pub const AT_PHDR: usize = 3;
pub const AT_PHENT: usize = 4;
pub const AT_PHNUM: usize = 5;
pub const AT_PAGESZ: usize = 6;
pub const AT_BASE: usize = 7;
pub const AT_FLAGS: usize = 8;
pub const AT_ENTRY: usize = 9;
pub const AT_UID: usize = 11;
pub const AT_EUID: usize = 12;
pub const AT_GID: usize = 13;
pub const AT_EGID: usize = 14;
pub const AT_SECURE: usize = 23;
pub const AT_RANDOM: usize = 25;
pub const AT_EXECFN: usize = 31;
pub const AT_SYSINFO_EHDR: usize = 33;

pub fn elf_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 0;
    for &c in name {
        h = (h << 4).wrapping_add(c as u32);
        let g = h & 0xf000_0000;
        if g != 0 {
            h ^= g >> 24;
        }
        h &= !g;
    }
    h
}

pub fn gnu_hash(name: &[u8]) -> u32 {
    let mut h: u32 = 5381;
    for &c in name {
        h = h.wrapping_mul(33).wrapping_add(c as u32);
    }
    h
}
