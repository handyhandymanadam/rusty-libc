//! `LD_DEBUG` and `LD_DEBUG_OUTPUT` (glibc's process_dl_debug, `_dl_debug_printf`): the categories as glibc's DL_DEBUG_* bits,
//! the file descriptor the debugging lines go to (standard error, or `$LD_DEBUG_OUTPUT.PID`), and every line tagged with the
//! process id. libc.so.6 prints its own lines (the `tls` category of the thread code) through `__libc_ldso_debug_write`.
use crate::sys;
use crate::util::Out;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering::Relaxed};

pub const LIBS: u32 = 1 << 0;
pub const IMPCALLS: u32 = 1 << 1;
pub const BINDINGS: u32 = 1 << 2;
pub const SYMBOLS: u32 = 1 << 3;
pub const VERSIONS: u32 = 1 << 4;
pub const RELOC: u32 = 1 << 5;
pub const FILES: u32 = 1 << 6;
pub const STATISTICS: u32 = 1 << 7;
pub const UNUSED: u32 = 1 << 8;
pub const SCOPES: u32 = 1 << 9;
pub const HELP: u32 = 1 << 10;
pub const TLS: u32 = 1 << 11;
pub const SECURITY: u32 = 1 << 12;

/// Set at start-up, read afterwards.
static MASK: AtomicU32 = AtomicU32::new(0);
static FD: AtomicI32 = AtomicI32::new(2);

const OPTS: [(&[u8], &[u8], u32); 13] = [
    (b"libs", b"display library search paths", LIBS | IMPCALLS),
    (b"reloc", b"display relocation processing", RELOC | IMPCALLS),
    (b"files", b"display progress for input file", FILES | IMPCALLS),
    (b"symbols", b"display symbol table processing", SYMBOLS | IMPCALLS),
    (b"bindings", b"display information about symbol binding", BINDINGS | IMPCALLS),
    (b"versions", b"display version dependencies", VERSIONS | IMPCALLS),
    (b"scopes", b"display scope information", SCOPES),
    (b"tls", b"display TLS structures processing", TLS),
    (b"security", b"show security warnings for input files", SECURITY),
    (b"all", b"all previous options combined", LIBS | RELOC | FILES | SYMBOLS | BINDINGS | VERSIONS | IMPCALLS | SCOPES | TLS | SECURITY),
    (b"statistics", b"display relocation statistics", STATISTICS),
    (b"unused", b"determined unused DSOs", UNUSED),
    (b"help", b"display this help message and exit", HELP),
];

pub fn mask() -> u32 {
    MASK.load(Relaxed)
}

/// Read the value of `LD_DEBUG`: words separated by spaces, commas or colons; an unknown word is reported on standard
/// error and skipped; `help` prints the list and ends the process.
pub fn parse(v: &[u8]) {
    let mut m = 0;
    for w in v.split(|&c| c == b' ' || c == b',' || c == b':').filter(|w| !w.is_empty()) {
        match OPTS.iter().find(|o| o.0 == w) {
            Some(o) => m |= o.2,
            None => {
                let mut o = Out::new(2);
                o.bytes(b"warning: debug option `");
                o.bytes(w);
                o.bytes(b"' unknown; try LD_DEBUG=help\n");
            }
        }
    }
    MASK.store(MASK.load(Relaxed) | m, Relaxed);
    if m & HELP != 0 {
        let mut o = Out::new(1);
        o.bytes(b"Valid options for the LD_DEBUG environment variable are:\n\n");
        for (name, text, _) in OPTS {
            o.bytes(b"  ");
            o.bytes(name);
            o.bytes(&b"         "[name.len() - 3..]);
            o.bytes(text);
            o.bytes(b"\n");
        }
        o.bytes(b"\nTo direct the debugging output into a file instead of standard output\na filename can be specified using the LD_DEBUG_OUTPUT environment variable.\n");
        drop(o);
        sys::exit(0);
    }
}

/// `LD_DEBUG_OUTPUT=NAME` with some category set: the lines go to NAME.PID (appended, created, not through a symbolic
/// link), or to standard output when that file cannot be opened.
pub fn open_output(name: &[u8]) {
    if MASK.load(Relaxed) == 0 {
        return;
    }
    if name.len() > 4096 {
        return;
    }
    // the name buffer in a scratch mapping (not 4 KB of the start-up frame); without memory: standard output, as when
    // the file cannot be opened
    let Some(mut scratch) = crate::util::Scratch::new(4096 + 24) else {
        FD.store(1, Relaxed);
        return;
    };
    let path = &mut scratch.bytes()[..4096 + 24];
    path[..name.len()].copy_from_slice(name);
    let mut n = name.len();
    path[n] = b'.';
    n += 1;
    n += dec(sys::getpid() as u64, &mut path[n..]);
    path[n] = 0;
    const FLAGS: usize = 0o1 | 0o2000 | 0o100 | 0o400000; // O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW
    let p = core::ffi::CStr::from_bytes_until_nul(&path[..n + 1]).unwrap_or(c"");
    let fd = sys::openat(p, FLAGS, 0o666);
    FD.store(if fd < 0 { 1 } else { fd as i32 }, Relaxed);
}

fn dec(mut v: u64, out: &mut [u8]) -> usize {
    let mut t = [0u8; 20];
    let mut i = t.len();
    loop {
        i -= 1;
        t[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    let n = t.len() - i;
    out[..n].copy_from_slice(&t[i..]);
    n
}

/// One debugging line (or several): each line gets glibc's tag, the process id right-aligned in ten columns, a colon and
/// a tab.
pub fn write(msg: &[u8]) {
    Msg::new().t(msg);
}

/// The `LD_DEBUG` categories, for libc.so.6.
#[unsafe(no_mangle)]
pub extern "C" fn __libc_ldso_debug_mask() -> u32 {
    mask()
}

/// Print `len` bytes at `buf` as debugging output (tagged, to the debugging file), for libc.so.6.
///
/// # Safety
/// `buf` points to `len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __libc_ldso_debug_write(buf: *const u8, len: usize) {
    // SAFETY: `len` readable bytes (caller's contract).
    write(unsafe { crate::ffi::slice(buf, len) });
}

#[inline(always)]
pub fn on(bits: u32) -> bool {
    MASK.load(Relaxed) & bits != 0
}

/// (Its methods are out of line: a message is a short sequence of calls, not the byte loops inlined each time.)
/// One `_dl_debug_printf` (or, from [`Msg::cont`], `_dl_debug_printf_c`) call: the pieces of the format in order, written
/// with one system call when they fit the buffer. As glibc's `_dl_debug_vdprintf`: the tag goes before the first piece
/// and before any piece that follows a newline *of the format* (newlines inside a `%s` argument get no tag), and a
/// newline that ends the format gets none after it.
pub struct Msg {
    o: Out,
    pending: bool,
}

impl Msg {
    /// `_dl_debug_printf`: starts with the tag.
    #[inline(never)]
    pub fn new() -> Msg {
        Msg { o: Out::new(FD.load(Relaxed)), pending: true }
    }

    /// `_dl_debug_printf_c`: continues the current line (no tag until a newline of the format).
    #[inline(never)]
    pub fn cont() -> Msg {
        Msg { o: Out::new(FD.load(Relaxed)), pending: false }
    }

    #[inline(never)]
    fn tag(&mut self) {
        if self.pending {
            self.pending = false;
            let mut tag = [b' '; 12];
            let mut d = [0u8; 20];
            let n = dec(sys::getpid() as u64, &mut d).min(10);
            tag[10 - n..10].copy_from_slice(&d[..n]);
            tag[10] = b':';
            tag[11] = b'\t';
            self.o.bytes(&tag);
        }
    }

    /// Literal text of the format.
    #[inline(never)]
    pub fn t(&mut self, lit: &[u8]) -> &mut Msg {
        for piece in lit.split_inclusive(|&c| c == b'\n') {
            self.tag();
            self.o.bytes(piece);
            if piece.last() == Some(&b'\n') {
                self.pending = true;
            }
        }
        self
    }

    /// A `%s` argument.
    #[inline(never)]
    pub fn s(&mut self, a: &[u8]) -> &mut Msg {
        self.tag();
        self.o.bytes(a);
        self
    }

    /// A `%u`/`%lu` argument.
    #[inline(never)]
    pub fn u(&mut self, v: u64) -> &mut Msg {
        let mut d = [0u8; 20];
        let n = dec(v, &mut d);
        self.s(&d[..n])
    }

    /// `%*u`: right-aligned in `width` columns.
    #[inline(never)]
    pub fn u_pad(&mut self, v: u64, width: usize) -> &mut Msg {
        let mut d = [0u8; 20];
        let n = dec(v, &mut d);
        self.tag();
        for _ in n..width {
            self.o.bytes(b" ");
        }
        self.o.bytes(&d[..n]);
        self
    }

    /// `0x%0*lx` with 16 digits (`(int) sizeof (void *) * 2`).
    #[inline(never)]
    pub fn hex16(&mut self, v: u64) -> &mut Msg {
        let mut d = [b'0'; 18];
        d[1] = b'x';
        for i in 0..16 {
            d[17 - i] = b"0123456789abcdef"[((v >> (4 * i)) & 0xf) as usize];
        }
        self.s(&d)
    }

    /// `0x%lx`.
    #[inline(never)]
    pub fn hex(&mut self, mut v: u64) -> &mut Msg {
        let mut d = [0u8; 18];
        let mut i = d.len();
        loop {
            i -= 1;
            d[i] = b"0123456789abcdef"[(v & 0xf) as usize];
            v >>= 4;
            if v == 0 {
                break;
            }
        }
        i -= 2;
        d[i] = b'0';
        d[i + 1] = b'x';
        self.s(&d[i..])
    }
}

impl Default for Msg {
    fn default() -> Msg {
        Msg::new()
    }
}

// ---- names as glibc prints them ----

use crate::map::Map;

/// glibc's `DSO_FILENAME (l->l_name)`: the name, or for the program (whose `l_name` is empty) the program's name.
pub fn fname(m: Map) -> &'static [u8] {
    let n = raw(m);
    if !n.is_empty() {
        return n;
    }
    let p = crate::reloc::prog_name();
    if p.is_empty() { b"<main program>" } else { p }
}

/// `l->l_name` itself: empty for the program (glibc's main map has no name, also when it was given to `ld.so`).
pub fn raw(m: Map) -> &'static [u8] {
    if m.is_main() { b"" } else { m.name() }
}

/// The name of a scope entry (`_dl_show_scope`): `l_name`, or the program's name (RTLD_PROGNAME).
fn scope_name(m: Map) -> &'static [u8] {
    let n = raw(m);
    if !n.is_empty() {
        return n;
    }
    let p = crate::reloc::prog_name();
    if p.is_empty() { b"<program name unknown>" } else { p }
}

// ---- the messages (out of line: none of their buffers is on the stack of the code that calls them) ----

/// A message without arguments (`_dl_debug_printf ("...")`).
#[cold]
#[inline(never)]
pub fn line(text: &[u8]) {
    Msg::new().t(text);
}

/// libs: `find library=%s [%lu]; searching`.
#[cold]
#[inline(never)]
pub fn find_library(name: &[u8], nsid: usize) {
    Msg::new().t(b"find library=").s(name).t(b" [").u(nsid as u64).t(b"]; searching\n");
}

/// libs: `  trying file=%s`.
#[cold]
#[inline(never)]
pub fn trying(path: &[u8]) {
    Msg::new().t(b"  trying file=").s(path).t(b"\n");
}

/// libs: a secure program's search refuses a file without the set-user-ID bit.
#[cold]
#[inline(never)]
pub fn refusing(path: &[u8]) {
    Msg::new().t(b"  refusing to load file=").s(path).t(b", the shared object cannot be tested for being SUID or the bit is not set\n");
}

/// libs: the end of `print_search_path`: `\t\t(%s from file %s)` or `\t\t(%s)`.
pub fn search_path_end(m: &mut Msg, what: &[u8], from: Option<Map>) {
    match from {
        Some(f) => {
            m.t(b"\t\t(").s(what).t(b" from file ").s(fname(f)).t(b")\n");
        }
        None => {
            m.t(b"\t\t(").s(what).t(b")\n");
        }
    }
}

/// libs: a DT_AUXILIARY filtee is about to be loaded.
#[cold]
#[inline(never)]
pub fn load_auxiliary(name: &[u8], by: Map) {
    Msg::new().t(b"load auxiliary object=").s(name).t(b" requested by file=").s(fname(by)).t(b"\n");
}

/// impcalls: `\ncalling init: %s\n\n`.
#[cold]
#[inline(never)]
pub fn calling_init(m: Map) {
    Msg::new().t(b"\ncalling init: ").s(fname(m)).t(b"\n\n");
}

/// impcalls: `\ncalling preinit: %s\n\n`.
#[cold]
#[inline(never)]
pub fn calling_preinit(m: Map) {
    Msg::new().t(b"\ncalling preinit: ").s(fname(m)).t(b"\n\n");
}

/// impcalls: `\ncalling fini: %s [%lu]\n\n` (the raw `l_name`: empty for the program).
#[cold]
#[inline(never)]
pub fn calling_fini(m: Map) {
    Msg::new().t(b"\ncalling fini: ").s(raw(m)).t(b" [").u(m.l_ns() as u64).t(b"]\n\n");
}

/// impcalls: libc's `\ninitialize program: %s\n\n` and `\ntransferring control: %s\n\n` (argv[0]).
#[cold]
#[inline(never)]
pub fn program(what: &[u8], argv0: &[u8]) {
    Msg::new().t(b"\n").t(what).s(argv0).t(b"\n\n");
}

/// files: `\nfile=%s [%lu];  needed by %s [%lu]\n` (or `dynamically loaded by` for dlopen).
#[cold]
#[inline(never)]
pub fn file_needed(name: &[u8], nsid: usize, loader: Map, dlopen: bool) {
    Msg::new()
        .t(b"\nfile=")
        .s(name)
        .t(b" [")
        .u(nsid as u64)
        .t(if dlopen { b"];  dynamically loaded by " } else { b"];  needed by " })
        .s(fname(loader))
        .t(b" [")
        .u(loader.l_ns() as u64)
        .t(b"]\n");
}

/// files: `file=%s [%lu];  generating link map`.
#[cold]
#[inline(never)]
pub fn generating(name: &[u8], nsid: usize) {
    Msg::new().t(b"file=").s(name).t(b" [").u(nsid as u64).t(b"];  generating link map\n");
}

/// files: the addresses of a new map.
#[cold]
#[inline(never)]
pub fn map_info(m: Map, size: usize) {
    Msg::new()
        .t(b"  dynamic: ")
        .hex16(m.l_ld() as u64)
        .t(b"  base: ")
        .hex16(m.l_addr() as u64)
        .t(b"   size: ")
        .hex16(size as u64)
        .t(b"\n    entry: ")
        .hex16(m.entry() as u64)
        .t(b"  phdr: ")
        .hex16(m.phdr() as u64)
        .t(b"  phnum:   ")
        .u_pad(m.phnum() as u64, 16)
        .t(b"\n\n");
}

/// files: `opening file=%s [%lu]; direct_opencount=%u\n\n` (the end of a dlopen).
#[cold]
#[inline(never)]
pub fn opening(m: Map, count: usize) {
    Msg::new().t(b"opening file=").s(raw(m)).t(b" [").u(m.l_ns() as u64).t(b"]; direct_opencount=").u(count as u64).t(b"\n\n");
}

/// files: `\nclosing file=%s; direct_opencount=%u\n` (a dlclose that unloads nothing).
#[cold]
#[inline(never)]
pub fn closing(m: Map, count: usize) {
    Msg::new().t(b"\nclosing file=").s(raw(m)).t(b"; direct_opencount=").u(count as u64).t(b"\n");
}

/// files: `\nfile=%s [%lu];  destroying link map\n`.
#[cold]
#[inline(never)]
pub fn destroying(m: Map) {
    Msg::new().t(b"\nfile=").s(raw(m)).t(b" [").u(m.l_ns() as u64).t(b"];  destroying link map\n");
}

/// files: a binding made `undef` hold a reference on the dlopen()ed `def`.
#[cold]
#[inline(never)]
pub fn reldep(def: Map, undef: Map) {
    Msg::new()
        .t(b"\nfile=")
        .s(fname(def))
        .t(b" [")
        .u(def.l_ns() as u64)
        .t(b"];  needed by ")
        .s(fname(undef))
        .t(b" [")
        .u(undef.l_ns() as u64)
        .t(b"] (relocation dependency)\n\n");
}

/// bindings: `marking %s [%lu] as NODELETE due to reference from ...`.
#[cold]
#[inline(never)]
pub fn nodelete_ref(def: Map, undef: Map) {
    let mut m = Msg::new();
    m.t(b"marking ").s(raw(def)).t(b" [").u(def.l_ns() as u64);
    if raw(undef).is_empty() {
        m.t(b"] as NODELETE due to reference from main program\n");
    } else {
        m.t(b"] as NODELETE due to reference from ").s(raw(undef)).t(b" [").u(undef.l_ns() as u64).t(b"]\n");
    }
}

/// bindings: `marking %s [%lu] as NODELETE due to unique symbol`.
#[cold]
#[inline(never)]
pub fn nodelete_unique(m: Map) {
    Msg::new().t(b"marking ").s(raw(m)).t(b" [").u(m.l_ns() as u64).t(b"] as NODELETE due to unique symbol\n");
}

/// files: `marking %s [%lu] as NODELETE` (RTLD_NODELETE).
#[cold]
#[inline(never)]
pub fn nodelete_flag(m: Map) {
    Msg::new().t(b"marking ").s(raw(m)).t(b" [").u(m.l_ns() as u64).t(b"] as NODELETE\n");
}

/// symbols: `symbol=%s;  lookup in file=%s [%lu]` for each object a lookup visits, up to the one that defines the symbol.
#[cold]
#[inline(never)]
pub fn symbol_lookups(name: &[u8], scopes: &[&[Map]], skip: Option<Map>, found: Option<Map>) {
    for scope in scopes {
        for &m in scope.iter() {
            if Some(m) == skip || m.removed() {
                continue;
            }
            Msg::new().t(b"symbol=").s(name).t(b";  lookup in file=").s(fname(m)).t(b" [").u(m.l_ns() as u64).t(b"]\n");
            if Some(m) == found {
                return;
            }
        }
    }
}

/// bindings: `binding file %s [%lu] to %s [%lu]: %s symbol `%s'` and ` [%s]` for a versioned reference.
#[cold]
#[inline(never)]
pub fn binding(undef: Map, def: Map, protected: bool, name: &[u8], ver: Option<&[u8]>) {
    let mut m = Msg::new();
    m.t(b"binding file ")
        .s(fname(undef))
        .t(b" [")
        .u(undef.l_ns() as u64)
        .t(b"] to ")
        .s(fname(def))
        .t(b" [")
        .u(def.l_ns() as u64)
        .t(b"]: ")
        .s(if protected { b"protected" } else { b"normal" })
        .t(b" symbol `")
        .s(name)
        .t(b"'");
    drop(m);
    let mut c = Msg::cont();
    match ver {
        Some(v) => {
            c.t(b" [").s(v).t(b"]\n");
        }
        None => {
            c.t(b"\n");
        }
    }
}

/// reloc: `\nrelocation processing: %s%s\n`.
#[cold]
#[inline(never)]
pub fn relocation(m: Map, lazy: bool) {
    Msg::new().t(b"\nrelocation processing: ").s(fname(m)).s(if lazy { b" (lazy)" } else { b"" }).t(b"\n");
}

/// versions: `checking for version `%s' in file %s [%lu] required by file %s [%lu]`.
#[cold]
#[inline(never)]
pub fn checking_version(ver: &[u8], lib: Map, req: Map) {
    Msg::new()
        .t(b"checking for version `")
        .s(ver)
        .t(b"' in file ")
        .s(fname(lib))
        .t(b" [")
        .u(lib.l_ns() as u64)
        .t(b"] required by file ")
        .s(fname(req))
        .t(b" [")
        .u(req.l_ns() as u64)
        .t(b"]\n");
}

/// scopes: `_dl_show_scope (l, from)`: the object, then each of its scopes from `from` on (`scopes[i]` is scope i), or ` no
/// scope`. Objects for which `hide` says true are left out of scope 0 (the objects a dlopen adds to the global scope only
/// after their constructors, where glibc does it).
#[cold]
#[inline(never)]
pub fn show_scope(m: Map, scopes: &[&[Map]], from: usize, hide: &dyn Fn(Map) -> bool) {
    Msg::new().t(b"object=").s(fname(m)).t(b" [").u(m.l_ns() as u64).t(b"]\n");
    if scopes.is_empty() {
        line(b" no scope\n");
    } else {
        for (i, sc) in scopes.iter().enumerate().skip(from) {
            Msg::new().t(b" scope ").u(i as u64).t(b":");
            for &e in sc.iter() {
                if i == 0 && hide(e) {
                    continue;
                }
                Msg::cont().t(b" ").s(scope_name(e));
            }
            Msg::cont().t(b"\n");
        }
    }
    line(b"\n");
}

/// scopes: `\nadd %s [%lu] to global scope\n`.
#[cold]
#[inline(never)]
pub fn add_global(m: Map) {
    Msg::new().t(b"\nadd ").s(raw(m)).t(b" [").u(m.l_ns() as u64).t(b"] to global scope\n");
}

/// statistics, at the end of start-up (glibc's `print_statistics`): total cycles, the relocation time and its share, the
/// counts, the load time and its share.
#[cold]
#[inline(never)]
pub fn statistics(total: u64, reloc: u64, load: u64, nrel: u64, ncache: u64, nrelative: u64) {
    Msg::new().t(b"\nruntime linker statistics:\n  total startup time in dynamic loader: ").u(total).t(b" cycles\n");
    stat_item(b"            time needed for relocation", reloc, total);
    Msg::new()
        .t(b"                 number of relocations: ")
        .u(nrel)
        .t(b"\n      number of relocations from cache: ")
        .u(ncache)
        .t(b"\n        number of relative relocations: ")
        .u(nrelative)
        .t(b"\n");
    stat_item(b"           time needed to load objects", load, total);
}

/// `print_statistics_item`: `%s: %s cycles (%s%%)` with the share in tenths of a percent.
fn stat_item(title: &[u8], time: u64, total: u64) {
    let permille = if total == 0 { 0 } else { (1000u128 * time as u128 / total as u128) as u64 };
    let mut d = [0u8; 20];
    let n = dec(permille, &mut d);
    // glibc's switch on the digit count: three digits "12.3", two "1.2", one ".5" (no leading zero), more than three
    // nothing
    let mut r = [0u8; 8];
    let k = match n {
        3 => {
            r[..2].copy_from_slice(&d[..2]);
            r[2] = b'.';
            r[3] = d[2];
            4
        }
        2 => {
            r[0] = d[0];
            r[1] = b'.';
            r[2] = d[1];
            3
        }
        1 => {
            r[0] = b'.';
            r[1] = d[0];
            2
        }
        _ => 0,
    };
    Msg::new().s(title).t(b": ").u(time).t(b" cycles (").s(&r[..k]).t(b"%)\n");
}

/// statistics, at exit (`_dl_fini`).
#[cold]
#[inline(never)]
pub fn final_statistics(nrel: u64, ncache: u64) {
    Msg::new()
        .t(b"\nruntime linker statistics:\n           final number of relocations: ")
        .u(nrel)
        .t(b"\nfinal number of relocations from cache: ")
        .u(ncache)
        .t(b"\n");
}

/// Symbol lookups made for relocations and dlsym (glibc's `dl_num_relocations`), counted while `statistics` is on.
pub static NUM_RELOCATIONS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

pub fn count_relocation() {
    NUM_RELOCATIONS.store(NUM_RELOCATIONS.load(Relaxed) + 1, Relaxed);
}

/// Every category but `statistics`: glibc's `_dl_signal_cerror` for a symbol nobody defines,
/// `%s: error: symbol lookup error: undefined symbol: %s[, version %s] (fatal)`.
#[cold]
#[inline(never)]
pub fn lookup_error(undef: Map, name: &[u8], ver: Option<&[u8]>) {
    let mut m = Msg::new();
    m.s(fname(undef)).t(b": error: ").s(b"symbol lookup error").t(b": ").s(b"undefined symbol: ").s(name);
    if let Some(v) = ver {
        m.s(b", version ").s(v);
    }
    m.t(b" (").s(b"fatal").t(b")\n");
}

/// The categories `lookup_error` prints for.
#[inline(always)]
pub fn errors_on() -> bool {
    MASK.load(Relaxed) & !STATISTICS != 0
}
