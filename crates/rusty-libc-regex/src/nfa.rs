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
pub const K_GUARD: u8 = 20;
pub const K_BACKREF: u8 = 7;
pub const K_END: u8 = 8;

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
    pub dup: bool,
    pub arg: u32,
    pub constraint: u16,
    pub e: [u32; 2],
    pub ne: u8,
    pub next: u32,
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
    pub guards: V<crate::parse::Rest>,
    pub has_plural: bool,
    pub subexp_map: V<u32>,
    pub ref_groups: u64,
    pub syntax: u64,
    pub mb: Mb,
    pub word_ctx: bool,
    ecl_start: V<u32>,
    ecl_len: V<u32>,
    ecl: V<u32>,
    pub init_nodes: V<u32>,
    pub dfa: crate::dfa::Dfa,
}

impl Nfa {
    pub fn eclosure(&self, n: u32) -> &[u32] {
        let s = self.ecl_start[n as usize] as usize;
        let l = self.ecl_len[n as usize] as usize;
        &self.ecl[s..s + l]
    }
}

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

const MAX_ECL: usize = 160_000_000;
const MAX_NNODES: usize = 8_000_000;

struct B {
    nodes: V<NNode>,
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

pub fn build(parsed: Parsed, syntax: u64) -> Result<Nfa, i32> {
    let Parsed { mut nodes, root, sets, nsub, nbackref, guards, mb } = parsed;

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

    let m = out.len();
    let mut b = B { nodes: out, st: V::from_elem(0, m), es: V::from_elem(0, m), el: V::from_elem(0, m), data: V::new() };
    if b.st.oom || b.es.oom || b.el.oom {
        return Err(REG_ESPACE);
    }
    let mut idx = 0usize;
    while idx < b.nodes.len() {
        if b.st[idx] != 0 {
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
    Ok(Nfa { nodes: out, sets, init, nsub, nbackref, guards, has_plural, subexp_map: map, ref_groups, syntax, mb, word_ctx, ecl_start: es, ecl_len: el, ecl: data, init_nodes, dfa: crate::dfa::Dfa::new() })
}

impl Nfa {
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

    pub fn fastmap(&self, icase: bool, fastmap: &mut [u8; 256], can_be_null: &mut bool) {
        *fastmap = [0; 256];
        *can_be_null = false;
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
