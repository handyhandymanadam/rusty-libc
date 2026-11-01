//! The module database of glibc's gconv: the `gconv-modules` files of the directories in `GCONV_PATH` and of the system
//! directory, and the search for the cheapest path of conversion steps between two charsets (what iconv/gconv_conf.c and
//! iconv/gconv_db.c do).
//!
//! Every charset this library implements is built in and converts to and from `INTERNAL` (UCS-4 in host byte order), the
//! pivot of all glibc conversions; those are the built-in edges of the graph. The files add edges that go through plug-in
//! modules (shared objects with `gconv`, `gconv_init`, `gconv_end`) and aliases. A module that a `GCONV_PATH` directory
//! lists wins over the built-in edge for the names it defines: the cost of a built-in edge is 1 with the lowest
//! priority, and a module listed in a file has the cost the file gives (1 when it gives none) and the priority of its
//! position in the files, as in glibc where the built-in charsets are modules of the system directory read last.
//!
//! The system directory is read only when a name is not built in: its modules for the charsets this library implements
//! are replaced by the built-in code, so its files only matter for charsets other packages add.
use crate::gconv_sys;
use crate::heapvec::HeapVec;
use crate::names::{self, Cs, SP_INTERNAL};
use core::sync::atomic::{AtomicU8, Ordering};
use rusty_libc_core::lock::Locked;

/// The directory glibc's default `GCONV_PATH` names (Fedora's `%{_libdir}/gconv`).
const SYSTEM_DIR: &[u8] = b"/usr/lib64/gconv/";
/// The extension a module name gets when it has none.
const MODULE_EXT: &[u8] = b".so";
/// The name of `INTERNAL` in a module list (no slashes).
pub(crate) const INTERNAL: &[u8] = b"INTERNAL";
/// The most steps a conversion path may have.
pub(crate) const MAX_STEPS: usize = 8;
/// The longest charset name or module path kept.
pub(crate) const NAME_MAX: usize = 255;
/// The priority (`cost_lo`) of a built-in edge: after every listed module.
const BUILTIN_LO: i64 = i32::MAX as i64;

/// A charset name or path in a fixed buffer.
#[derive(Clone, Copy)]
pub(crate) struct Name {
    buf: [u8; NAME_MAX],
    len: u8,
}

impl Name {
    pub(crate) fn new(s: &[u8]) -> Option<Name> {
        if s.len() > NAME_MAX {
            return None;
        }
        let mut buf = [0u8; NAME_MAX];
        buf[..s.len()].copy_from_slice(s);
        Some(Name {
            buf,
            len: s.len() as u8,
        })
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf[..usize::from(self.len)]
    }
}

/// A piece of the text arena.
#[derive(Clone, Copy)]
struct Str {
    off: u32,
    len: u32,
}

#[derive(Clone, Copy)]
struct Module {
    from: Str,
    to: Str,
    /// The path to `dlopen`, with the extension.
    path: Str,
    cost_hi: i32,
    cost_lo: i32,
    /// The graph nodes of the two names (`NO_NODE` for a target `-`, which means the charset asked for).
    from_node: u32,
    to_node: u32,
}

/// A node of the search graph: a charset name (canonical for the built-in ones, which carry their charset).
#[derive(Clone, Copy)]
struct NodeSlot {
    name: Str,
    cs: Option<Cs>,
}

/// No node.
const NO_NODE: u32 = u32::MAX;
/// The `via` of a built-in edge.
const NO_MODULE: u32 = u32::MAX;

#[derive(Clone, Copy)]
struct Alias {
    from: Str,
    to: Str,
}

/// The database: the strings, the modules and the aliases read so far.
pub(crate) struct Db {
    text: HeapVec<u8>,
    modules: HeapVec<Module>,
    aliases: HeapVec<Alias>,
    /// The charset names that modules and searches mention, one node each.
    nodes: HeapVec<NodeSlot>,
    /// The position of the next module (glibc's `modcounter`), the second part of a module's cost.
    counter: i32,
    /// Has `GCONV_PATH` been looked at?
    user_read: bool,
    /// Has the system directory been read?
    system_read: bool,
}

/// The one database, read on first use.
static DB: Locked<Db> = Locked::new(Db::new());

impl Db {
    const fn new() -> Db {
        Db {
            text: HeapVec::new(),
            modules: HeapVec::new(),
            aliases: HeapVec::new(),
            nodes: HeapVec::new(),
            counter: 0,
            user_read: false,
            system_read: false,
        }
    }

    fn str(&self, s: Str) -> &[u8] {
        &self.text[s.off as usize..(s.off + s.len) as usize]
    }

    fn add_str(&mut self, s: &[u8]) -> Option<Str> {
        let off = self.text.len();
        if !self.text.extend_from(s) {
            return None;
        }
        Some(Str {
            off: u32::try_from(off).ok()?,
            len: s.len() as u32,
        })
    }

    /// The node for the charset `name`, made if new. Names of built-in charsets are canonical (any spelling gives the node
    /// of the charset); other names stand as they are.
    fn intern(&mut self, name: &[u8]) -> Option<u32> {
        let (canonical, cs) = match builtin(name) {
            Some(cs) => (node_name(cs)?, Some(cs)),
            None => (Name::new(name)?, None),
        };
        if let Some(i) = self.nodes.iter().position(|n| self.str(n.name) == canonical.as_bytes()) {
            return u32::try_from(i).ok();
        }
        let name = self.add_str(canonical.as_bytes())?;
        self.nodes.push(NodeSlot { name, cs }).then(|| (self.nodes.len() - 1) as u32)
    }

    /// The alias target of `name` (one level, as glibc's `do_lookup_alias`).
    fn alias_of(&self, name: &[u8]) -> Option<&[u8]> {
        self.aliases
            .iter()
            .find(|a| self.str(a.from) == name)
            .map(|a| self.str(a.to))
    }

    fn has_module_from(&self, name: &[u8]) -> bool {
        self.modules.iter().any(|m| self.str(m.from) == name)
    }

    /// `alias FROM TO`: ignored if a module with that name exists or the alias is known already.
    fn add_alias(&mut self, line: &[u8]) {
        let mut words = line
            .split(u8::is_ascii_whitespace)
            .filter(|w| !w.is_empty());
        let (Some(from), Some(to)) = (words.next(), words.next()) else {
            return;
        };
        let (Some(from), Some(to)) = (upper(from), upper(to)) else {
            return;
        };
        if self.has_module_from(from.as_bytes()) || self.alias_of(from.as_bytes()).is_some() {
            return;
        }
        if let (Some(f), Some(t)) = (self.add_str(from.as_bytes()), self.add_str(to.as_bytes())) {
            let _ = self.aliases.push(Alias { from: f, to: t });
        }
    }

    /// `module FROM TO NAME [COST]` in a file of `dir` (which ends in a slash).
    fn add_module(&mut self, line: &[u8], dir: &[u8], counter: i32) {
        let mut words = line
            .split(u8::is_ascii_whitespace)
            .filter(|w| !w.is_empty());
        let (Some(from), Some(to), Some(module)) = (words.next(), words.next(), words.next())
        else {
            return;
        };
        let cost_hi = words.next().map_or(1, parse_cost);
        let (Some(from), Some(to)) = (upper(from), upper(to)) else {
            return;
        };
        // a module that duplicates an alias is dropped
        if self.alias_of(from.as_bytes()).is_some() {
            return;
        }
        let mut path = HeapVec::<u8>::new();
        let ok = (module[0] == b'/' || path.extend_from(dir))
            && path.extend_from(module)
            && (module.ends_with(MODULE_EXT) || path.extend_from(MODULE_EXT));
        if !ok || path.len() > NAME_MAX {
            return;
        }
        let (Some(f), Some(t), Some(p)) = (
            self.add_str(from.as_bytes()),
            self.add_str(to.as_bytes()),
            self.add_str(&path),
        ) else {
            return;
        };
        let from_node = self.intern(from.as_bytes()).unwrap_or(NO_NODE);
        let to_node = if to.as_bytes() == b"-" { NO_NODE } else { self.intern(to.as_bytes()).unwrap_or(NO_NODE) };
        let new = Module {
            from: f,
            to: t,
            path: p,
            cost_hi,
            cost_lo: counter,
            from_node,
            to_node,
        };
        // the same conversion twice: the cheaper one stays (the first on a tie)
        let existing = self
            .modules
            .iter()
            .position(|m| self.str(m.from) == from.as_bytes() && self.str(m.to) == to.as_bytes());
        match existing {
            None => {
                let _ = self.modules.push(new);
            }
            Some(i) => {
                let old = self.modules[i];
                if (new.cost_hi, new.cost_lo) < (old.cost_hi, old.cost_lo) {
                    self.modules[i] = new;
                }
            }
        }
    }

    /// One `gconv-modules` file: `alias` and `module` lines, `#` comments.
    fn read_conf(&mut self, file: &[u8], dir: &[u8]) {
        let Some(text) = gconv_sys::read_file(file) else {
            return;
        };
        for raw in text.split(|&c| c == b'\n') {
            let line = raw.split(|&c| c == b'#').next().unwrap_or(&[]);
            let line = line.trim_ascii_start();
            let word_end = line
                .iter()
                .position(u8::is_ascii_whitespace)
                .unwrap_or(line.len());
            match &line[..word_end] {
                b"alias" => self.add_alias(&line[word_end..]),
                b"module" => {
                    // (every module line takes a position, whether or not it is kept, as glibc's `modcounter++`)
                    let position = self.counter;
                    self.counter += 1;
                    self.add_module(&line[word_end..], dir, position);
                }
                _ => {}
            }
        }
    }

    /// `gconv_parseconfdir`: `DIR/gconv-modules`, then every `DIR/gconv-modules.d/*.conf`.
    fn read_dir(&mut self, dir: &[u8]) {
        let mut file = HeapVec::<u8>::new();
        if !(file.extend_from(dir) && file.extend_from(b"gconv-modules")) {
            return;
        }
        self.read_conf(&file, dir);
        if !file.extend_from(b".d/") {
            return;
        }
        let Some(names) = gconv_sys::conf_names(&file[..file.len() - 1]) else {
            return;
        };
        for name in names.split(|&c| c == 0).filter(|n| !n.is_empty()) {
            let mut path = HeapVec::<u8>::new();
            if path.extend_from(&file) && path.extend_from(name) {
                self.read_conf(&path, dir);
            }
        }
    }

    /// The directories of `GCONV_PATH` (unless the program is secure), relative ones made absolute.
    fn read_user(&mut self) {
        self.user_read = true;
        if rusty_libc_core::lock::secure() {
            return;
        }
        let Some(path) = gconv_sys::getenv(b"GCONV_PATH") else {
            return;
        };
        let mut cwd = [0u8; 4096];
        let cwd_len = gconv_sys::getcwd(&mut cwd);
        for elem in path.split(|&c| c == b':').filter(|e| !e.is_empty()) {
            let mut dir = HeapVec::<u8>::new();
            if elem[0] != b'/' {
                // (glibc cannot resolve a relative element without the working directory either)
                let Some(n) = cwd_len else { continue };
                if !(dir.extend_from(&cwd[..n]) && dir.push(b'/')) {
                    continue;
                }
            }
            if !dir.extend_from(elem) || (dir.last() != Some(&b'/') && !dir.push(b'/')) {
                continue;
            }
            self.read_dir(&dir);
        }
    }

    /// The system directory: modules and aliases for charsets that are not built in.
    fn read_system(&mut self) {
        self.system_read = true;
        let (modules, aliases) = (self.modules.len(), self.aliases.len());
        self.read_dir(SYSTEM_DIR);
        // The stock modules of the system directory stand for charsets that are built in here: drop the ones that join
        // two names this library already knows, and the aliases of built-in names.
        let mut keep = HeapVec::<Module>::new();
        for i in 0..self.modules.len() {
            let m = self.modules[i];
            let known = |s: &[u8]| builtin(s).is_some();
            if i < modules || !(known(self.str(m.from)) && known(self.str(m.to))) {
                let _ = keep.push(m);
            }
        }
        self.modules.truncate(0);
        let _ = self.modules.extend_from(&keep);
        let mut kept = HeapVec::<Alias>::new();
        for i in 0..self.aliases.len() {
            let a = self.aliases[i];
            if i < aliases || builtin(self.str(a.from)).is_none() {
                let _ = kept.push(a);
            }
        }
        self.aliases.truncate(0);
        let _ = self.aliases.extend_from(&kept);
    }
}

/// An upper-cased copy of a name (glibc upper-cases the charset names of the files); `None` if it is too long.
fn upper(s: &[u8]) -> Option<Name> {
    let mut n = Name::new(s)?;
    n.buf[..usize::from(n.len)].make_ascii_uppercase();
    Some(n)
}

/// A cost field: a decimal number, at least 1 (anything else counts as 1).
fn parse_cost(word: &[u8]) -> i32 {
    let digits = word
        .iter()
        .take_while(|c| c.is_ascii_digit())
        .fold(0i64, |acc, &c| {
            (acc * 10 + i64::from(c - b'0')).min(i64::from(i32::MAX))
        });
    i32::try_from(digits).unwrap_or(1).max(1)
}

/// The built-in charset a module-list name stands for (`INTERNAL` has no slashes in the files).
pub(crate) fn builtin(name: &[u8]) -> Option<Cs> {
    if name == INTERNAL {
        return Some(Cs::Special(SP_INTERNAL));
    }
    names::lookup_key(name)
}

/// Is `cs` the `INTERNAL` pivot?
fn is_internal(cs: Cs) -> bool {
    matches!(cs, Cs::Special(SP_INTERNAL))
}

/// A built-in charset's canonical name with its two slashes (`ISO-8859-1//`), the form `iconv_open` takes; `INTERNAL` has none.
pub(crate) fn plain_name(cs: Cs) -> Option<Name> {
    if is_internal(cs) {
        return Name::new(INTERNAL);
    }
    let canonical = names::cs_name(cs).as_bytes();
    let mut buf = [0u8; NAME_MAX];
    let n = canonical.len();
    if n + 2 > NAME_MAX {
        return None;
    }
    buf[..n].copy_from_slice(canonical);
    buf[n..n + 2].copy_from_slice(b"//");
    Name::new(&buf[..n + 2])
}

/// The name glibc's modules compare against for a built-in charset (`CHARSET_NAME`): the canonical name with its two
/// slashes, except for the three charsets glibc spells differently internally.
pub(crate) fn node_name(cs: Cs) -> Option<Name> {
    let special: Option<&[u8]> = match names::cs_name(cs) {
        "UTF-8" => Some(b"ISO-10646/UTF8/"),
        "UCS-2" => Some(b"ISO-10646/UCS2/"),
        "UCS-4" | "ISO-10646/UCS4/" => Some(b"ISO-10646/UCS4/"),
        _ => None,
    };
    match special {
        Some(s) => Name::new(s),
        None => plain_name(cs),
    }
}

/// One step of a path: a plug-in module, or a run of built-in conversion (`from -> INTERNAL`, `INTERNAL -> to` or both).
#[derive(Clone, Copy)]
pub(crate) struct PathStep {
    /// The module's path, or `None` for a built-in step.
    pub module: Option<Name>,
    pub from: Name,
    pub to: Name,
}

/// A conversion path: the steps in order, first to last.
pub(crate) struct Path {
    pub steps: [PathStep; MAX_STEPS],
    pub len: usize,
}

impl Db {
    /// `GCONV_PATH` read (once) when the first conversion is opened; true if it gave any module.
    fn ensure_user(&mut self) -> bool {
        if !self.user_read {
            self.read_user();
        }
        !self.modules.is_empty()
    }

    /// The cheapest path from `from` to `to` (normalised names with their two slashes) that uses a plug-in module, if
    /// there is one. Costs add up as pairs (the file's cost, then the position in the files); a built-in edge costs 1 and
    /// comes after every listed module on a tie.
    fn find_path(&mut self, to: &[u8], from: &[u8]) -> Option<Path> {
        let internal = self.intern(INTERNAL)? as usize;
        let from_expand = self.alias_of(from).and_then(Name::new);
        let to_expand = self.alias_of(to).and_then(Name::new);
        let starts = [self.intern(from_expand.as_ref().map_or(from, Name::as_bytes))? as usize, self.intern(from)? as usize];
        let goals = [self.intern(to_expand.as_ref().map_or(to, Name::as_bytes))? as usize, self.intern(to)? as usize];
        let count = self.nodes.len();
        // cheapest cost into each node and the edge that gave it (node before it, module or NO_MODULE): Bellman-Ford, where a
        // strictly cheaper way replaces and the edges of the start nodes cost from zero
        let mut dist = HeapVec::filled((i64::MAX, i64::MAX), count)?;
        let mut pred = HeapVec::filled((NO_NODE, NO_MODULE), count)?;
        loop {
            let mut changed = false;
            let mut relax = |f: usize, t: usize, hi: i64, lo: i64, via: u32| {
                let base = if starts.contains(&f) { (0, 0) } else { dist[f] };
                if base.0 == i64::MAX {
                    return;
                }
                let cost = (base.0 + hi, base.1 + lo);
                if cost < dist[t] {
                    dist[t] = cost;
                    pred[t] = (f as u32, via);
                    changed = true;
                }
            };
            for (i, m) in self.modules.iter().enumerate() {
                if m.from_node == NO_NODE {
                    continue;
                }
                // (a target `-` is the charset asked for)
                let target = if m.to_node == NO_NODE { goals[0] } else { m.to_node as usize };
                relax(m.from_node as usize, target, i64::from(m.cost_hi), i64::from(m.cost_lo), i as u32);
            }
            // the built-in edges: every built-in charset converts to and from INTERNAL
            for (n, node) in self.nodes.iter().enumerate() {
                if n != internal && node.cs.is_some() {
                    relax(n, internal, 1, BUILTIN_LO, NO_MODULE);
                    relax(internal, n, 1, BUILTIN_LO, NO_MODULE);
                }
            }
            if !changed {
                break;
            }
        }
        let goal = if dist[goals[1]] < dist[goals[0]] { goals[1] } else { goals[0] };
        if dist[goal].0 == i64::MAX {
            return None;
        }
        // walk back from the goal to a start node: the edges, last first
        let mut chain = [(0usize, 0usize, 0u32); MAX_STEPS];
        let mut n = 0;
        let mut at = goal;
        loop {
            let (before, via) = pred[at];
            if n == MAX_STEPS || before == NO_NODE {
                return None;
            }
            chain[n] = (before as usize, at, via);
            n += 1;
            if starts.contains(&(before as usize)) {
                break;
            }
            at = before as usize;
        }
        let blank = PathStep { module: None, from: Name::new(b"")?, to: Name::new(b"")? };
        let mut path = Path { steps: [blank; MAX_STEPS], len: 0 };
        let mut any_module = false;
        // (consecutive built-in edges join into one step)
        for &(before, after, via) in chain[..n].iter().rev() {
            let (from, to) = (Name::new(self.str(self.nodes[before].name))?, Name::new(self.str(self.nodes[after].name))?);
            if via == NO_MODULE {
                if path.len > 0 && path.steps[path.len - 1].module.is_none() {
                    path.steps[path.len - 1].to = to;
                    continue;
                }
                path.steps[path.len] = PathStep { module: None, from, to };
            } else {
                any_module = true;
                let module = Name::new(self.str(self.modules[via as usize].path))?;
                path.steps[path.len] = PathStep { module: Some(module), from, to };
            }
            path.len += 1;
        }
        any_module.then_some(path)
    }
}

/// What the plug-in layer says about opening `to` from `from`.
#[allow(clippy::large_enum_variant)]
pub(crate) enum Lookup {
    /// A path through at least one plug-in module.
    Path(Path),
    /// No module is involved: the built-in code decides.
    Builtin,
}

/// Do the `GCONV_PATH` directories list any module? 0: not looked at yet, 1: no, 2: yes. Every `iconv_open` asks, so the
/// common case (no `GCONV_PATH`) costs one load.
static USER_MODULES: AtomicU8 = AtomicU8::new(0);

/// Do the `GCONV_PATH` directories list any module? (Reads the variable and the files on the first call, as glibc does once.)
pub(crate) fn user_modules() -> bool {
    match USER_MODULES.load(Ordering::Acquire) {
        1 => false,
        2 => true,
        _ => DB.with(|db| {
            let any = db.ensure_user();
            USER_MODULES.store(if any { 2 } else { 1 }, Ordering::Release);
            any
        }),
    }
}

/// The charset names the `GCONV_PATH` files add to the built-in ones (aliases, and both names of every module), NUL-terminated
/// one after another: what `iconv -l` lists besides the built-in names.
pub(crate) fn extra_names() -> HeapVec<u8> {
    let mut out = HeapVec::new();
    DB.with(|db| {
        db.ensure_user();
        let mut add = |name: &[u8]| {
            if name != INTERNAL && name != b"-" && builtin(name).is_none() {
                let _ = out.extend_from(name) && out.push(0);
            }
        };
        for a in db.aliases.iter() {
            add(db.str(a.from));
        }
        for m in db.modules.iter() {
            add(db.str(m.from));
            add(db.str(m.to));
        }
    });
    out
}

/// The names `to` and `from` (normalised, with their two slashes) after the aliases of the `GCONV_PATH` files, or `None` when
/// neither is an alias.
pub(crate) fn expand_aliases(to: &[u8], from: &[u8]) -> Option<(Name, Name)> {
    DB.with(|db| {
        db.ensure_user();
        let expand = |name: &[u8]| db.alias_of(name).and_then(Name::new);
        let (new_to, new_from) = (expand(to), expand(from));
        if new_to.is_none() && new_from.is_none() {
            return None;
        }
        Some((new_to.or_else(|| Name::new(to))?, new_from.or_else(|| Name::new(from))?))
    })
}

/// Look for a path through plug-in modules from `from` to `to` (normalised names). `system` also reads the system
/// directory (for names that are not built in).
pub(crate) fn lookup(to: &[u8], from: &[u8], system: bool) -> Lookup {
    DB.with(|db| {
        let have_user = db.ensure_user();
        if system && !db.system_read {
            db.read_system();
        }
        if !have_user && !(system && !db.modules.is_empty()) {
            return Lookup::Builtin;
        }
        match db.find_path(to, from) {
            Some(path) => Lookup::Path(path),
            None => Lookup::Builtin,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    /// A fresh directory with `gconv-modules` holding `text`; returns the database that read it and the directory (with a
    /// trailing slash).
    fn db_with(text: &str) -> (Db, String) {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!("gconv-conf-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::Relaxed)));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("gconv-modules"), text).unwrap();
        let dir = format!("{}/", dir.display());
        let mut db = Db::new();
        db.read_dir(dir.as_bytes());
        // (the database has read everything it needs)
        let _ = std::fs::remove_dir_all(dir.trim_end_matches('/'));
        (db, dir)
    }

    fn names(path: &Path) -> Vec<(Option<String>, String, String)> {
        path.steps[..path.len]
            .iter()
            .map(|s| {
                let text = |n: &Name| String::from_utf8(n.as_bytes().to_vec()).unwrap();
                (s.module.as_ref().map(text), text(&s.from), text(&s.to))
            })
            .collect()
    }

    #[test]
    fn reads_modules_aliases_and_comments() {
        let (db, dir) = db_with(
            "# a comment\n\
             module  mycs//  internal  mycs  2   # trailing comment\n\
             module INTERNAL MYCS// /abs/path/mycs.so\n\
             alias MY// MYCS//\n\
             alias MYCS// OTHER//\n\
             module MY// INTERNAL dropped\n\
             module TOO// FEW\n\
             \tmodule\tTAB//\tINTERNAL\ttabbed\t0\n\
             bogus line\n",
        );
        let m = |i: usize| (db.str(db.modules[i].from), db.str(db.modules[i].to), db.str(db.modules[i].path), db.modules[i].cost_hi);
        // (the alias MYCS// conflicts with the module of that name; MY// is an alias, so a module from it is dropped)
        assert_eq!(db.modules.len(), 3);
        assert_eq!(m(0), (&b"MYCS//"[..], &b"INTERNAL"[..], format!("{dir}mycs.so").as_bytes(), 2));
        assert_eq!(m(1), (&b"INTERNAL"[..], &b"MYCS//"[..], &b"/abs/path/mycs.so"[..], 1));
        assert_eq!(m(2), (&b"TAB//"[..], &b"INTERNAL"[..], format!("{dir}tabbed.so").as_bytes(), 1));
        assert_eq!(db.aliases.len(), 1);
        assert_eq!(db.alias_of(b"MY//"), Some(&b"MYCS//"[..]));
    }

    #[test]
    fn same_conversion_keeps_the_cheaper_module() {
        let (db, _) = db_with("module A// INTERNAL one 3\nmodule A// INTERNAL two 2\nmodule A// INTERNAL three 2\n");
        assert_eq!(db.modules.len(), 1);
        assert!(db.str(db.modules[0].path).ends_with(b"two.so"));
    }

    #[test]
    fn path_through_a_module_and_the_built_in_pivot() {
        let (mut db, dir) = db_with("module MYCS// INTERNAL mycs\nmodule INTERNAL MYCS// mycs\nalias MYALIAS// MYCS//\n");
        let module = Some(format!("{dir}mycs.so"));
        let into = db.find_path(b"UTF-8//", b"MYCS//").expect("MYCS to UTF-8");
        assert_eq!(names(&into), [(module.clone(), "MYCS//".into(), "INTERNAL".into()), (None, "INTERNAL".into(), "ISO-10646/UTF8/".into())]);
        let out = db.find_path(b"MYCS//", b"ISO-8859-1//").expect("ISO-8859-1 to MYCS");
        assert_eq!(names(&out), [(None, "ISO-8859-1//".into(), "INTERNAL".into()), (module.clone(), "INTERNAL".into(), "MYCS//".into())]);
        // an alias is followed at either end
        assert!(db.find_path(b"MYALIAS//", b"UTF-16LE//").is_some());
        assert!(db.find_path(b"UTF-16LE//", b"MYALIAS//").is_some());
        // two modules in a row
        let (mut db2, _) = db_with("module A// INTERNAL a\nmodule INTERNAL B// b\n");
        let chain = db2.find_path(b"B//", b"A//").expect("A to B");
        assert_eq!(chain.len, 2);
        assert!(chain.steps[0].module.is_some() && chain.steps[1].module.is_some());
        // no module involved, or no way at all
        assert!(db.find_path(b"UTF-8//", b"ISO-8859-1//").is_none());
        assert!(db.find_path(b"UTF-8//", b"NOSUCH//").is_none());
        assert!(db.find_path(b"NOSUCH//", b"MYCS//").is_none());
    }

    #[test]
    fn cheapest_path_wins_and_a_listed_module_beats_the_built_in_edges() {
        // direct module (cost 3) against the two-module route (1 + 5)
        let (mut db, _) = db_with("module X// INTERNAL a 1\nmodule INTERNAL Y// b 5\nmodule X// Y// direct 3\n");
        let p = db.find_path(b"Y//", b"X//").unwrap();
        assert_eq!(p.len, 1);
        // a module between two built-in charsets (cost 1) is cheaper than the pivot (1 + 1) and is used
        let (mut db, _) = db_with("module ISO-8859-1// UTF-8// fast 1\n");
        let p = db.find_path(b"UTF-8//", b"LATIN1//").unwrap();
        assert_eq!((p.len, p.steps[0].module.is_some()), (1, true));
        // at a higher cost than the pivot it loses, and the built-in code converts
        let (mut db, _) = db_with("module ISO-8859-1// UTF-8// slow 3\n");
        assert!(db.find_path(b"UTF-8//", b"LATIN1//").is_none());
    }

    #[test]
    fn same_charset_both_ways_goes_through_the_pivot() {
        let (mut db, _) = db_with("module MYCS// INTERNAL mycs\nmodule INTERNAL MYCS// mycs\n");
        let p = db.find_path(b"MYCS//", b"MYCS//").unwrap();
        assert_eq!(p.len, 2);
    }

    #[test]
    fn built_in_names_as_glibc_spells_them() {
        let spelled = |n: &[u8]| String::from_utf8(node_name(builtin(n).unwrap()).unwrap().as_bytes().to_vec()).unwrap();
        assert_eq!(spelled(b"UTF-8//"), "ISO-10646/UTF8/");
        assert_eq!(spelled(b"UTF8//"), "ISO-10646/UTF8/");
        assert_eq!(spelled(b"ISO-10646/UTF8/"), "ISO-10646/UTF8/");
        assert_eq!(spelled(b"UCS-4//"), "ISO-10646/UCS4/");
        assert_eq!(spelled(b"UCS2//"), "ISO-10646/UCS2/");
        assert_eq!(spelled(b"LATIN1//"), "ISO-8859-1//");
        assert_eq!(spelled(b"INTERNAL"), "INTERNAL");
        assert_eq!(spelled(b"WCHAR_T//"), "INTERNAL");
        assert!(builtin(b"MYCS//").is_none());
        // every name the library lists round-trips through the spelling used to open the built-in converter
        for n in names::all_names() {
            let cs = builtin(n.as_bytes()).unwrap();
            let plain = plain_name(cs).unwrap();
            assert!(builtin(plain.as_bytes()).is_some(), "{n} -> {:?}", core::str::from_utf8(plain.as_bytes()));
        }
    }

    #[test]
    fn system_directory_adds_nothing_for_built_in_charsets() {
        // (the stock files of glibc's gconv directory name only charsets that are built in here)
        if !std::path::Path::new("/usr/lib64/gconv/gconv-modules").exists() {
            return;
        }
        let mut db = Db::new();
        db.read_system();
        assert!(db.system_read);
        let listed: Vec<_> = db.modules.iter().map(|m| (db.str(m.from), db.str(m.to))).collect();
        assert!(listed.is_empty(), "{listed:?}");
        assert!(db.aliases.iter().all(|a| builtin(db.str(a.from)).is_none()));
    }

    #[test]
    fn cost_field() {
        assert_eq!(parse_cost(b"7"), 7);
        assert_eq!(parse_cost(b"0"), 1);
        assert_eq!(parse_cost(b"x"), 1);
        assert_eq!(parse_cost(b"3x"), 3);
        assert_eq!(parse_cost(b"99999999999"), i32::MAX);
    }
}
