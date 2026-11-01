//! From glibc's parse tree to the node graph the matcher runs on. This follows glibc's `analyze`
//! step by step, because the submatches glibc reports depend on the exact shape of its graph:
//!
//! * `optimize_subexps`: a group directly inside another group is dropped and mapped to it;
//! * `lower_subexps`: a group becomes OPEN, body, CLOSE;
//! * nodes are numbered in post order; the successor lists of ALT and STAR nodes are sorted by node
//!   number (`re_node_set_init_2`), which makes the lower numbered successor the preferred one;
//! * `calc_eclosure`: epsilon closures. An anchor (`^ $ \< \> \b \B ...`) is an epsilon node that
//!   carries a constraint; computing its closure copies ("duplicates") the nodes that follow it
//!   until the next character is consumed, each copy carrying the constraint, and re-points the
//!   anchor at the copies. So a path through an anchor ends at a copy of the end node, not at the
//!   original, which decides which paths the submatch walk may take.
use crate::charset::Mb;
use crate::consts::*;
use crate::parse::*;
use crate::vec::V;

pub const K_CHAR: u8 = 0;
pub const K_SET: u8 = 1;
pub const K_ANY: u8 = 2;
pub const K_OPEN: u8 = 3;
pub const K_CLOSE: u8 = 4;
pub const K_ALT: u8 = 5;
pub const K_ANCHOR: u8 = 6;
/// Zero width: the text must not go on as `guards[arg]` (see `parse::units_tree`); only the exact matcher can check it.
pub const K_GUARD: u8 = 20;
pub const K_BACKREF: u8 = 7;
pub const K_END: u8 = 8;
/// One state of the byte automaton of a multibyte set (`mbset::Frag`): consumes one byte and goes on to the state of the
/// byte's group, or to `next` once the character is complete (`Nfa::next_of`). `arg` indexes `Nfa::mbrefs`.
pub const K_MB: u8 = 9;
/// A state of the implicit automaton of a UTF-8 bracket set (`u8set`): the root (the node of the parse tree) takes a first
/// byte, the nodes of depth 1, 2, 3 (`base + depth - 1`) the following ones. `arg` indexes `Nfa::u8refs`. Only the
/// root's steps depend on the byte alone (`Nfa::next_of`); the others look at the bytes before (`Env::next_at`).
pub const K_U8: u8 = 10;

#[derive(Clone, Copy)]
pub struct U8Ref {
    pub spec: u32,
    pub depth: u32,
    pub base: u32,
}

/// Where a `K_MB` node is: its automaton, its state in it, and the node of the automaton's state 1 (state `d` >= 1 is node
/// `base + d - 1`; state 0 is the node of the parse tree).
#[derive(Clone, Copy)]
pub struct MbRef {
    pub frag: u32,
    pub local: u32,
    pub base: u32,
}

/// Context bits of a position (glibc's CONTEXT_*).
pub const CTX_WORD: u8 = 1;
pub const CTX_NEWLINE: u8 = 2;
pub const CTX_BEGBUF: u8 = 4;
pub const CTX_ENDBUF: u8 = 8;

pub fn prev_bad(c: u16, ctx: u8) -> bool {
    use crate::parse::ctxbits::*;
    (c & PREV_WORD != 0 && ctx & CTX_WORD == 0)
        || (c & PREV_NOTWORD != 0 && ctx & CTX_WORD != 0)
        || (c & PREV_NEWLINE != 0 && ctx & CTX_NEWLINE == 0)
        || (c & PREV_BEGBUF != 0 && ctx & CTX_BEGBUF == 0)
}

pub fn next_bad(c: u16, ctx: u8) -> bool {
    use crate::parse::ctxbits::*;
    (c & NEXT_WORD != 0 && ctx & CTX_WORD == 0)
        || (c & NEXT_NOTWORD != 0 && ctx & CTX_WORD != 0)
        || (c & NEXT_NEWLINE != 0 && ctx & CTX_NEWLINE == 0)
        || (c & NEXT_ENDBUF != 0 && ctx & CTX_ENDBUF == 0)
}

#[derive(Clone, Copy)]
pub struct NNode {
    pub kind: u8,
    pub c: u8,
    pub opt: bool,
    /// Made by `{n,m}` expansion, or a copy made for an anchor.
    pub dup: bool,
    /// Set index (K_SET) or group number, 0-based (K_OPEN, K_CLOSE, K_BACKREF).
    pub arg: u32,
    /// Context constraint (anchors and copies made for anchors).
    pub constraint: u16,
    /// Epsilon successors, sorted by node number.
    pub e: [u32; 2],
    pub ne: u8,
    /// Successor after consuming a character (K_CHAR, K_SET, K_ANY, K_BACKREF).
    pub next: u32,
    /// The node this one is a copy of (copies made for anchors).
    pub org: u32,
}

impl NNode {
    pub fn is_eps(&self) -> bool {
        matches!(self.kind, K_ALT | K_OPEN | K_CLOSE | K_ANCHOR | K_GUARD)
    }

    pub fn edests(&self) -> &[u32] {
        &self.e[..self.ne as usize]
    }

    fn insert_edest(&mut self, x: u32) {
        match self.ne {
            0 => {
                self.e[0] = x;
                self.ne = 1;
            }
            1 => {
                if self.e[0] == x {
                    return;
                }
                if x < self.e[0] {
                    self.e[1] = self.e[0];
                    self.e[0] = x;
                } else {
                    self.e[1] = x;
                }
                self.ne = 2;
            }
            _ => {}
        }
    }
}

pub struct Nfa {
    pub nodes: V<NNode>,
    pub sets: V<Set>,
    pub init: u32,
    pub nsub: u32,
    pub nbackref: u32,
    /// What the `K_GUARD` nodes forbid after them.
    pub guards: V<crate::parse::Rest>,
    pub has_plural: bool,
    /// glibc's subexp_map (empty when it is the identity).
    pub subexp_map: V<u32>,
    /// Groups that a back-reference refers to (0-based), as a bit set over groups 0..63.
    pub ref_groups: u64,
    pub syntax: u64,
    /// The multibyte kind of the locale the pattern was compiled in (`Mb::None`: one byte is one character).
    pub mb: Mb,
    /// Some node's constraint depends on whether a character is a word character.
    pub word_ctx: bool,
    /// In a multibyte charset that is not UTF-8: an ASCII byte is always the start of a character (no character has a
    /// trail byte below 0x80).
    pub ascii_starts: bool,
    ecl_start: V<u32>,
    ecl_len: V<u32>,
    ecl: V<u32>,
    /// Epsilon closure of the start node (plus what back-references in it may skip), sorted.
    pub init_nodes: V<u32>,
    /// The lazily built DFA the matcher uses to find where a match cannot start (see `dfa`).
    pub dfa: crate::dfa::Dfa,
    /// The multibyte sets (none, or one entry: a pattern without them keeps `Nfa`, and with it the compiled pattern's one
    /// block, its old size).
    pub mbsets: V<SetTables>,
}

/// The automata of the `K_MB` nodes and each such node's place in them; the sets of the `K_U8` nodes and each such node's
/// place.
pub struct SetTables {
    pub frags: V<crate::mbset::Frag>,
    pub mbrefs: V<MbRef>,
    pub u8specs: V<crate::u8set::U8Spec>,
    pub u8refs: V<U8Ref>,
}

static NO_SETS: SetTables = SetTables { frags: V::new(), mbrefs: V::new(), u8specs: V::new(), u8refs: V::new() };

impl Nfa {
    #[inline]
    fn set_tables(&self) -> &SetTables {
        self.mbsets.first().unwrap_or(&NO_SETS)
    }

    #[inline]
    pub fn frags(&self) -> &[crate::mbset::Frag] {
        &self.set_tables().frags
    }

    #[inline]
    pub fn mbrefs(&self) -> &[MbRef] {
        &self.set_tables().mbrefs
    }

    #[inline]
    pub fn u8specs(&self) -> &[crate::u8set::U8Spec] {
        &self.set_tables().u8specs
    }

    #[inline]
    pub fn u8refs(&self) -> &[U8Ref] {
        &self.set_tables().u8refs
    }

    /// The node a consumer goes to after consuming byte `b` (which it accepts): `next`, or for a `K_MB` node the node of
    /// the byte's group.
    #[inline]
    pub fn next_of(&self, nd: &NNode, b: u8) -> u32 {
        if nd.kind == K_U8 {
            let r = &self.u8refs()[nd.arg as usize];
            return match (r.depth, b) {
                (0, 0..=0x7f) => nd.next,
                (0, _) => r.base,
                // (the other nodes need the bytes before: `Env::next_at`)
                _ => NONE,
            };
        }
        if nd.kind != K_MB {
            return nd.next;
        }
        let r = &self.mbrefs()[nd.arg as usize];
        let f = &self.frags()[r.frag as usize];
        for (set, t) in f.groups(r.local) {
            if set_has(set, b) {
                return if *t == crate::mbset::EXIT { nd.next } else { r.base + *t - 1 };
            }
        }
        NONE
    }

    /// Does the `K_U8` node `nd` accept byte `b` as far as the byte alone tells (the root: exactly; the others: a
    /// continuation byte)?
    #[inline]
    pub fn u8_accepts(&self, nd: &NNode, b: u8) -> bool {
        let r = &self.u8refs()[nd.arg as usize];
        if r.depth == 0 { set_has(&self.u8specs()[r.spec as usize].root, b) } else { (0x80..=0xbf).contains(&b) }
    }

    /// Does the `K_MB` node `nd` accept byte `b`?
    #[inline]
    pub fn mb_accepts(&self, nd: &NNode, b: u8) -> bool {
        let r = &self.mbrefs()[nd.arg as usize];
        set_has(&self.frags()[r.frag as usize].union[r.local as usize], b)
    }

    pub fn eclosure(&self, n: u32) -> &[u32] {
        let s = self.ecl_start[n as usize] as usize;
        let l = self.ecl_len[n as usize] as usize;
        &self.ecl[s..s + l]
    }
}

/// Pre-order walk where children are read after the visitor ran (like glibc's `preorder`).
fn preorder_mut(nodes: &mut V<TNode>, root: u32, mut f: impl FnMut(&mut V<TNode>, u32)) -> bool {
    let mut stack: V<u32> = V::new();
    stack.push(root);
    while let Some(n) = stack.pop() {
        f(nodes, n);
        let nd = nodes[n as usize];
        if nd.right != NONE {
            stack.push(nd.right);
        }
        if nd.left != NONE {
            stack.push(nd.left);
        }
    }
    stack.oom
}

fn postorder_list(nodes: &V<TNode>, root: u32) -> V<u32> {
    let mut out: V<u32> = V::new();
    let mut stack: V<(u32, bool)> = V::new();
    stack.push((root, false));
    while let Some((n, done)) = stack.pop() {
        if done {
            out.push(n);
            continue;
        }
        stack.push((n, true));
        let nd = &nodes[n as usize];
        if nd.right != NONE {
            stack.push((nd.right, false));
        }
        if nd.left != NONE {
            stack.push((nd.left, false));
        }
    }
    out.oom |= stack.oom;
    out
}

fn preorder_list(nodes: &V<TNode>, root: u32) -> V<u32> {
    let mut out: V<u32> = V::new();
    let mut stack: V<u32> = V::new();
    stack.push(root);
    while let Some(n) = stack.pop() {
        out.push(n);
        let nd = &nodes[n as usize];
        if nd.right != NONE {
            stack.push(nd.right);
        }
        if nd.left != NONE {
            stack.push(nd.left);
        }
    }
    out.oom |= stack.oom;
    out
}

/// Total size cap for the closure tables (entries).
const MAX_ECL: usize = 160_000_000;
const MAX_NNODES: usize = 8_000_000;

struct B {
    nodes: V<NNode>,
    /// 0 = not computed, -1 = in progress, 1 = done
    st: V<i8>,
    es: V<u32>,
    el: V<u32>,
    data: V<u32>,
}

impl B {
    fn add_node(&mut self, org: NNode) -> Result<u32, i32> {
        if self.nodes.len() >= MAX_NNODES {
            return Err(REG_ESPACE);
        }
        let id = self.nodes.len() as u32;
        let mut n = org;
        n.constraint = 0;
        n.ne = 0;
        n.e = [NONE, NONE];
        n.next = NONE;
        n.org = NONE;
        self.nodes.push(n);
        self.st.push(0);
        self.es.push(0);
        self.el.push(0);
        if self.nodes.oom || self.st.oom || self.es.oom || self.el.oom {
            return Err(REG_ESPACE);
        }
        Ok(id)
    }

    fn duplicate_node(&mut self, org_idx: u32, constraint: u16) -> Result<u32, i32> {
        let org = self.nodes[org_idx as usize];
        let id = self.add_node(org)?;
        let n = &mut self.nodes[id as usize];
        n.constraint = constraint | org.constraint;
        n.dup = true;
        n.org = org_idx;
        Ok(id)
    }

    fn search_duplicated_node(&self, org_node: u32, constraint: u16) -> u32 {
        let mut idx = self.nodes.len() - 1;
        while self.nodes[idx].dup && idx > 0 {
            if org_node == self.nodes[idx].org && constraint == self.nodes[idx].constraint {
                return idx as u32;
            }
            idx -= 1;
        }
        NONE
    }

    fn dup_closure(&mut self, top_org: u32, top_clone: u32, root: u32, init_constraint: u16, depth: u32) -> Result<(), i32> {
        if depth > 4000 {
            return Err(REG_ESPACE);
        }
        let mut constraint = init_constraint;
        let mut org_node = top_org;
        let mut clone_node = top_clone;
        loop {
            let org_dest;
            let clone_dest;
            let on = self.nodes[org_node as usize];
            if on.kind == K_BACKREF {
                org_dest = on.next;
                self.nodes[clone_node as usize].ne = 0;
                clone_dest = self.duplicate_node(org_dest, constraint)?;
                self.nodes[clone_node as usize].next = on.next;
                self.nodes[clone_node as usize].insert_edest(clone_dest);
            } else if on.ne == 0 {
                self.nodes[clone_node as usize].next = on.next;
                break;
            } else if on.ne == 1 {
                org_dest = on.e[0];
                self.nodes[clone_node as usize].ne = 0;
                if org_node == root && clone_node != org_node {
                    self.nodes[clone_node as usize].insert_edest(org_dest);
                    break;
                }
                constraint |= on.constraint;
                clone_dest = self.duplicate_node(org_dest, constraint)?;
                self.nodes[clone_node as usize].insert_edest(clone_dest);
            } else {
                let d0 = on.e[0];
                self.nodes[clone_node as usize].ne = 0;
                let found = self.search_duplicated_node(d0, constraint);
                if found == NONE {
                    let cd = self.duplicate_node(d0, constraint)?;
                    self.nodes[clone_node as usize].insert_edest(cd);
                    self.dup_closure(d0, cd, root, constraint, depth + 1)?;
                } else {
                    self.nodes[clone_node as usize].insert_edest(found);
                }
                // glibc re-reads the successor list of the original here
                org_dest = self.nodes[org_node as usize].e[1];
                clone_dest = self.duplicate_node(org_dest, constraint)?;
                self.nodes[clone_node as usize].insert_edest(clone_dest);
            }
            org_node = org_dest;
            clone_node = clone_dest;
        }
        Ok(())
    }

    fn slice(&self, n: u32) -> &[u32] {
        let s = self.es[n as usize] as usize;
        let l = self.el[n as usize] as usize;
        &self.data[s..s + l]
    }
}

pub fn merge_sorted_pub(a: &mut V<u32>, b: &[u32]) {
    merge_sorted(a, b)
}

fn merge_sorted(a: &mut V<u32>, b: &[u32]) {
    let mut out: V<u32> = V::with_capacity(a.len() + b.len());
    let (mut i, mut j) = (0, 0);
    while i < a.len() && j < b.len() {
        if a[i] < b[j] {
            out.push(a[i]);
            i += 1;
        } else if a[i] > b[j] {
            out.push(b[j]);
            j += 1;
        } else {
            out.push(a[i]);
            i += 1;
            j += 1;
        }
    }
    while i < a.len() {
        out.push(a[i]);
        i += 1;
    }
    while j < b.len() {
        out.push(b[j]);
        j += 1;
    }
    *a = out;
}

struct Fr {
    node: u32,
    i: u8,
    ecl: V<u32>,
    incomplete: bool,
    root: bool,
}

fn enter(b: &mut B, node: u32, root: bool) -> Result<Fr, i32> {
    let mut ecl: V<u32> = V::new();
    ecl.push(node);
    b.st[node as usize] = -1;
    let nd = b.nodes[node as usize];
    if nd.constraint != 0 && nd.ne > 0 && !b.nodes[nd.e[0] as usize].dup {
        b.dup_closure(node, node, node, nd.constraint, 0)?;
    }
    Ok(Fr { node, i: 0, ecl, incomplete: false, root })
}

fn calc_eclosure_iter(b: &mut B, start: u32, root: bool) -> Result<(), i32> {
    let mut stack: V<Fr> = V::new();
    stack.push(enter(b, start, root)?);
    loop {
        let top = match stack.len() {
            0 => break,
            n => n - 1,
        };
        let node = stack[top].node;
        let nd = b.nodes[node as usize];
        if nd.is_eps() && (stack[top].i as usize) < nd.ne as usize {
            let edest = nd.e[stack[top].i as usize];
            stack[top].i += 1;
            match b.st[edest as usize] {
                -1 => stack[top].incomplete = true,
                0 => {
                    let fr = enter(b, edest, false)?;
                    stack.push(fr);
                }
                _ => {
                    let mut e = core::mem::take(&mut stack[top].ecl);
                    merge_sorted(&mut e, b.slice(edest));
                    stack[top].ecl = e;
                }
            }
            continue;
        }
        let fr = stack.pop().unwrap();
        let done = !(fr.incomplete && !fr.root);
        if done {
            if b.data.len() + fr.ecl.len() > MAX_ECL {
                return Err(REG_ESPACE);
            }
            b.es[node as usize] = b.data.len() as u32;
            b.el[node as usize] = fr.ecl.len() as u32;
            b.data.extend_from_slice(&fr.ecl);
            b.st[node as usize] = 1;
        } else {
            b.st[node as usize] = 0;
        }
        if b.data.oom {
            return Err(REG_ESPACE);
        }
        let n = stack.len();
        if n > 0 {
            let mut e = core::mem::take(&mut stack[n - 1].ecl);
            merge_sorted(&mut e, &fr.ecl);
            stack[n - 1].ecl = e;
            if b.st[node as usize] == 0 {
                stack[n - 1].incomplete = true;
            }
        }
        if stack.oom {
            return Err(REG_ESPACE);
        }
    }
    Ok(())
}

/// The states of the multibyte sets (`K_MB`, `K_U8`) after their first: nodes of their own appended to `out`, and each
/// such node's place. (Not inlined: a pattern without such sets, every one of the C locale, keeps a small `build`.)
#[inline(never)]
#[allow(clippy::type_complexity)]
fn expand_sets(out: &mut V<NNode>, frags: &V<crate::mbset::Frag>, has_plural: &mut bool) -> Result<(V<MbRef>, V<U8Ref>), i32> {
    // the states of each multibyte automaton after the first: nodes of their own after the tree's (each use of an automaton
    // gets its own, as their `next` is the node after that use)
    let mut mbrefs: V<MbRef> = V::new();
    let ntree = out.len();
    for id in 0..ntree {
        if out[id].kind != K_MB {
            continue;
        }
        let fi = out[id].arg;
        let f = &frags[fi as usize];
        *has_plural |= f.plural;
        let base = out.len() as u32;
        out[id].arg = mbrefs.len() as u32;
        mbrefs.push(MbRef { frag: fi, local: 0, base });
        let mut n = out[id];
        n.opt = false;
        n.dup = false;
        for d in 1..f.nodes() as u32 {
            n.arg = mbrefs.len() as u32;
            mbrefs.push(MbRef { frag: fi, local: d, base });
            out.push(n);
        }
        if out.len() >= MAX_NNODES {
            return Err(REG_ESPACE);
        }
    }
    // the nodes of depth 1 to 3 of each UTF-8 set (the set's tree would have had alternations: has_plural)
    let mut u8refs: V<U8Ref> = V::new();
    for id in 0..ntree {
        if out[id].kind != K_U8 {
            continue;
        }
        *has_plural = true;
        let spec = out[id].arg;
        let base = out.len() as u32;
        out[id].arg = u8refs.len() as u32;
        u8refs.push(U8Ref { spec, depth: 0, base });
        let mut n = out[id];
        n.opt = false;
        n.dup = false;
        for depth in 1..=3 {
            n.arg = u8refs.len() as u32;
            u8refs.push(U8Ref { spec, depth, base });
            out.push(n);
        }
        if out.len() >= MAX_NNODES {
            return Err(REG_ESPACE);
        }
    }
    if out.oom || mbrefs.oom || u8refs.oom {
        return Err(REG_ESPACE);
    }
    Ok((mbrefs, u8refs))

}

pub fn build(parsed: Parsed, syntax: u64) -> Result<Nfa, i32> {
    let Parsed { mut nodes, root, sets, nsub, nbackref, guards, mb, frags, u8specs } = parsed;

    // optimize_subexps
    let mut map: V<u32> = V::new();
    for i in 0..nsub {
        map.push(i);
    }
    if map.oom {
        return Err(REG_ESPACE);
    }
    let mut changed = false;
    let walk_oom = preorder_mut(&mut nodes, root, |nodes, n| {
        let nd = nodes[n as usize];
        if nd.kind == NK::BackRef && !map.is_empty() {
            nodes[n as usize].idx = map[nd.idx as usize];
        } else if nd.kind == NK::Subexp && nd.left != NONE && nodes[nd.left as usize].kind == NK::Subexp {
            let inner = nodes[nd.left as usize];
            nodes[n as usize].left = inner.left;
            if inner.left != NONE {
                nodes[inner.left as usize].parent = n;
            }
            map[inner.idx as usize] = map[nd.idx as usize];
            changed = true;
        }
    });
    if walk_oom {
        return Err(REG_ESPACE);
    }
    if !changed {
        map.clear();
    }

    // lower_subexps: SUBEXP(body) becomes CONCAT(OPEN, CONCAT(body, CLOSE)) in place.
    let count = nodes.len();
    for n in 0..count as u32 {
        if nodes[n as usize].kind != NK::Subexp {
            continue;
        }
        let nd = nodes[n as usize];
        let mk = |nodes: &mut V<TNode>, kind: NK, left: u32, right: u32, idx: u32, opt: bool| -> u32 {
            let id = nodes.len() as u32;
            nodes.push(TNode { kind, left, right, parent: NONE, c: 0, idx, ctx: 0, opt, dup: false, first: NONE, next: NONE, nidx: NONE });
            id
        };
        let op = mk(&mut nodes, NK::Open, NONE, NONE, nd.idx, nd.opt);
        let cls = mk(&mut nodes, NK::Close, NONE, NONE, nd.idx, nd.opt);
        let tree1 = if nd.left != NONE { mk(&mut nodes, NK::Concat, nd.left, cls, 0, false) } else { cls };
        if nodes.oom {
            return Err(REG_ESPACE);
        }
        if nd.left != NONE {
            nodes[nd.left as usize].parent = tree1;
        }
        if tree1 != cls {
            nodes[cls as usize].parent = tree1;
        }
        nodes[op as usize].parent = n;
        nodes[tree1 as usize].parent = n;
        let me = &mut nodes[n as usize];
        me.kind = NK::Concat;
        me.left = op;
        me.right = tree1;
    }

    // calc_first: number the nodes in post order.
    let post = postorder_list(&nodes, root);
    if post.oom {
        return Err(REG_ESPACE);
    }
    let mut out: V<NNode> = V::new();
    let mut has_plural = false;
    for &n in post.iter() {
        let nd = nodes[n as usize];
        if nd.kind == NK::Concat {
            let l = nodes[nd.left as usize];
            nodes[n as usize].first = l.first;
            nodes[n as usize].nidx = l.nidx;
        } else {
            let id = out.len() as u32;
            nodes[n as usize].first = n;
            nodes[n as usize].nidx = id;
            let (kind, arg, constraint) = match nd.kind {
                NK::Char => (K_CHAR, 0, 0),
                NK::Set => (K_SET, nd.idx, 0),
                NK::Period => (K_ANY, 0, 0),
                NK::Anchor => (K_ANCHOR, 0, nd.ctx),
                NK::BackRef => (K_BACKREF, nd.idx, 0),
                NK::End => (K_END, 0, 0),
                NK::Open => (K_OPEN, nd.idx, 0),
                NK::Close => (K_CLOSE, nd.idx, 0),
                NK::Guard => (K_GUARD, nd.idx, 0),
                NK::Mb => (K_MB, nd.idx, 0),
                NK::U8 => (K_U8, nd.idx, 0),
                NK::Alt | NK::Star => {
                    has_plural = true;
                    (K_ALT, 0, 0)
                }
                NK::Concat | NK::Subexp => (K_END, 0, 0),
            };
            out.push(NNode { kind, c: nd.c, opt: nd.opt, dup: nd.dup, arg, constraint, e: [NONE, NONE], ne: 0, next: NONE, org: NONE });
        }
    }
    if out.oom {
        return Err(REG_ESPACE);
    }

    // calc_next
    let pre = preorder_list(&nodes, root);
    if pre.oom {
        return Err(REG_ESPACE);
    }
    for &n in pre.iter() {
        let nd = nodes[n as usize];
        match nd.kind {
            NK::Star => {
                nodes[nd.left as usize].next = n;
            }
            NK::Concat => {
                let rf = nodes[nd.right as usize].first;
                nodes[nd.left as usize].next = rf;
                nodes[nd.right as usize].next = nd.next;
            }
            _ => {
                if nd.left != NONE {
                    nodes[nd.left as usize].next = nd.next;
                }
                if nd.right != NONE {
                    nodes[nd.right as usize].next = nd.next;
                }
            }
        }
    }

    // link_nfa_nodes
    let nidx_of = |nodes: &V<TNode>, t: u32| -> u32 { nodes[t as usize].nidx };
    for &n in post.iter() {
        let nd = nodes[n as usize];
        if nd.kind == NK::Concat {
            continue;
        }
        let id = nd.nidx as usize;
        match nd.kind {
            NK::End => {}
            NK::Alt | NK::Star => {
                let left = if nd.left != NONE { nidx_of(&nodes, nodes[nd.left as usize].first) } else { nidx_of(&nodes, nd.next) };
                let right = if nd.right != NONE { nidx_of(&nodes, nodes[nd.right as usize].first) } else { nidx_of(&nodes, nd.next) };
                out[id].insert_edest(left);
                out[id].insert_edest(right);
            }
            NK::Anchor | NK::Open | NK::Close | NK::Guard => {
                out[id].insert_edest(nidx_of(&nodes, nd.next));
            }
            NK::BackRef => {
                let nx = nidx_of(&nodes, nd.next);
                out[id].next = nx;
                out[id].insert_edest(nx);
            }
            _ => {
                out[id].next = nidx_of(&nodes, nd.next);
            }
        }
    }
    let init = nodes[nodes[root as usize].first as usize].nidx;
    drop(post);
    drop(pre);
    drop(nodes);

    let mut mbsets: V<SetTables> = V::new();
    if !frags.is_empty() || !u8specs.is_empty() {
        let (mbrefs, u8refs) = expand_sets(&mut out, &frags, &mut has_plural)?;
        mbsets.push(SetTables { frags, mbrefs, u8specs, u8refs });
        if mbsets.oom {
            return Err(REG_ESPACE);
        }
    }

    let m = out.len();
    let mut b = B { nodes: out, st: V::from_elem(0, m), es: V::from_elem(0, m), el: V::from_elem(0, m), data: V::new() };
    if b.st.oom || b.es.oom || b.el.oom {
        return Err(REG_ESPACE);
    }
    // calc_eclosure
    let mut idx = 0usize;
    while idx < b.nodes.len() {
        if b.st[idx] != 0 {
            idx += 1;
            continue;
        }
        let nd = b.nodes[idx];
        if !nd.is_eps() && !(nd.constraint != 0 && nd.ne > 0) {
            // a consumer or end node: its closure is itself (what `calc_eclosure_iter` finds, without its frame)
            b.es[idx] = b.data.len() as u32;
            b.el[idx] = 1;
            b.data.push(idx as u32);
            b.st[idx] = 1;
            if b.data.oom || b.data.len() > MAX_ECL {
                return Err(REG_ESPACE);
            }
            idx += 1;
            continue;
        }
        calc_eclosure_iter(&mut b, idx as u32, true)?;
        idx += 1;
    }

    let mut ref_groups = 0u64;
    for n in b.nodes.iter() {
        if n.kind == K_BACKREF && n.arg < 64 {
            ref_groups |= 1 << n.arg;
        }
    }

    // create_initial_state: the closure of the start node; back-references in it may match the
    // empty string, so what follows them joins the set
    let mut init_nodes: V<u32> = V::new();
    init_nodes.extend_from_slice(b.slice(init));
    if nbackref > 0 {
        'restart: loop {
            for i in 0..init_nodes.len() {
                let n = init_nodes[i];
                let nd = b.nodes[n as usize];
                if nd.kind != K_BACKREF {
                    continue;
                }
                let has_close = init_nodes.iter().any(|&x| b.nodes[x as usize].kind == K_CLOSE && b.nodes[x as usize].arg == nd.arg);
                if !has_close {
                    continue;
                }
                let dest = nd.e[0];
                if init_nodes.binary_search(&dest).is_err() {
                    let mut tmp: V<u32> = V::new();
                    tmp.extend_from_slice(b.slice(dest));
                    merge_sorted(&mut init_nodes, &tmp);
                    continue 'restart;
                }
            }
            break;
        }
    }
    if init_nodes.oom || b.data.oom {
        return Err(REG_ESPACE);
    }

    let B { nodes: out, es, el, data, .. } = b;
    let word_ctx = out.iter().any(|n| n.constraint & (ctxbits::PREV_WORD | ctxbits::PREV_NOTWORD | ctxbits::NEXT_WORD | ctxbits::NEXT_NOTWORD) != 0);
    Ok(Nfa { nodes: out, sets, init, nsub, nbackref, guards, has_plural, subexp_map: map, ref_groups, syntax, mb, word_ctx, ascii_starts: mb == Mb::Other && crate::starts::ascii_always_starts(), ecl_start: es, ecl_len: el, ecl: data, init_nodes, dfa: crate::dfa::Dfa::new(), mbsets })
}

impl Nfa {
    /// The initial node set for a position whose previous character has context `ctx`: the start
    /// closure without the nodes whose "previous" constraint fails.
    pub fn init_state(&self, ctx: u8, out: &mut V<u32>) {
        out.clear();
        for &n in self.init_nodes.iter() {
            let c = self.nodes[n as usize].constraint;
            if c != 0 && prev_bad(c, ctx) {
                continue;
            }
            out.push(n);
        }
    }

    /// glibc's fastmap, from the initial states of the four contexts: the bytes a match can begin
    /// with (upper-case pattern letters also marked lower case when `icase`), and whether the
    /// pattern can match the empty string. Like glibc's, the scan of a state stops at its first `.`
    /// or end node.
    pub fn fastmap(&self, icase: bool, fastmap: &mut [u8; 256], can_be_null: &mut bool) {
        *fastmap = [0; 256];
        *can_be_null = false;
        // (in a multibyte locale the case variants are nodes of their own)
        let icase = icase && self.mb == Mb::None;
        let contexts: [u8; 4] = [0, CTX_WORD, CTX_NEWLINE, CTX_NEWLINE | CTX_BEGBUF];
        let mut st: V<u32> = V::new();
        let mut sets_done: V<u32> = V::new();
        for &cx in contexts.iter() {
            self.init_state(cx, &mut st);
            for &n in st.iter() {
                let nd = &self.nodes[n as usize];
                let set = |c: u8, fm: &mut [u8; 256]| {
                    fm[c as usize] = 1;
                    if icase {
                        fm[crate::charset::to_lower(c) as usize] = 1;
                    }
                };
                match nd.kind {
                    K_CHAR => set(nd.c, fastmap),
                    K_SET => {
                        // a set already merged from an earlier context adds nothing
                        if !sets_done.contains(&nd.arg) {
                            sets_done.push(nd.arg);
                            let s = &self.sets[nd.arg as usize];
                            for (w, &word) in s.iter().enumerate() {
                                let mut b = word;
                                while b != 0 {
                                    set((w * 64) as u8 + b.trailing_zeros() as u8, fastmap);
                                    b &= b - 1;
                                }
                            }
                        }
                    }
                    K_MB | K_U8 => {
                        let s = if nd.kind == K_MB {
                            let r = &self.mbrefs()[nd.arg as usize];
                            &self.frags()[r.frag as usize].union[r.local as usize]
                        } else {
                            &self.u8specs()[self.u8refs()[nd.arg as usize].spec as usize].root
                        };
                        for (w, &word) in s.iter().enumerate() {
                            let mut b = word;
                            while b != 0 {
                                set((w * 64) as u8 + b.trailing_zeros() as u8, fastmap);
                                b &= b - 1;
                            }
                        }
                    }
                    K_ANY | K_END => {
                        *fastmap = [1; 256];
                        if nd.kind == K_END {
                            *can_be_null = true;
                        }
                        break;
                    }
                    _ => {}
                }
            }
        }
    }
}
