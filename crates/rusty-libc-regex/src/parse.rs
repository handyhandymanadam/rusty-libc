use crate::charset::{self, Mb};
use crate::consts::*;
use crate::mbset::{self, Canon, Seq, Trie};
use crate::vec::V;

pub const NONE: u32 = u32::MAX;
pub const MAX_NODES: usize = 3_000_000;
pub const MAX_NEST: u32 = 3000;

pub type Rest = ([u8; 6], u8);

pub mod ctxbits {
    pub const PREV_WORD: u16 = 0x0001;
    pub const PREV_NOTWORD: u16 = 0x0002;
    pub const NEXT_WORD: u16 = 0x0004;
    pub const NEXT_NOTWORD: u16 = 0x0008;
    pub const PREV_NEWLINE: u16 = 0x0010;
    pub const NEXT_NEWLINE: u16 = 0x0020;
    pub const PREV_BEGBUF: u16 = 0x0040;
    pub const NEXT_ENDBUF: u16 = 0x0080;
    pub const WORD_DELIM: u16 = 0x0100;
    pub const NOT_WORD_DELIM: u16 = 0x0200;
    pub const INSIDE_WORD: u16 = PREV_WORD | NEXT_WORD;
    pub const WORD_FIRST: u16 = PREV_NOTWORD | NEXT_WORD;
    pub const WORD_LAST: u16 = PREV_WORD | NEXT_NOTWORD;
    pub const INSIDE_NOTWORD: u16 = PREV_NOTWORD | NEXT_NOTWORD;
    pub const LINE_FIRST: u16 = PREV_NEWLINE;
    pub const LINE_LAST: u16 = NEXT_NEWLINE;
    pub const BUF_FIRST: u16 = PREV_BEGBUF;
    pub const BUF_LAST: u16 = NEXT_ENDBUF;
}
use ctxbits::*;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NK {
    Concat,
    Alt,
    Star,
    Subexp,
    Char,
    Set,
    Period,
    Anchor,
    BackRef,
    End,
    Open,
    Close,
    Guard,
}

#[derive(Clone, Copy)]
pub struct TNode {
    pub kind: NK,
    pub left: u32,
    pub right: u32,
    pub parent: u32,
    pub c: u8,
    pub idx: u32,
    pub ctx: u16,
    pub opt: bool,
    pub dup: bool,
    pub first: u32,
    pub next: u32,
    pub nidx: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum T {
    Character,
    OpAlt,
    OpBackRef,
    Anchor,
    OpOpenSubexp,
    OpCloseSubexp,
    OpDupPlus,
    OpDupQuestion,
    OpDupAsterisk,
    OpOpenDupNum,
    OpCloseDupNum,
    OpOpenBracket,
    OpPeriod,
    OpWord,
    OpNotWord,
    OpSpace,
    OpNotSpace,
    BackSlash,
    EndOfRe,
    OpCharsetRange,
    OpCloseBracket,
    OpNonMatchList,
    OpOpenCollElem,
    OpOpenEquivClass,
    OpOpenCharClass,
}

#[derive(Clone, Copy)]
struct Tok {
    ty: T,
    c: u8,
    idx: u32,
    ctx: u16,
    mb: u8,
    wc: u32,
}

type Res = Result<u32, i32>;
pub type Set = [u64; 4];

pub struct Parsed {
    pub nodes: V<TNode>,
    pub root: u32,
    pub sets: V<Set>,
    pub nsub: u32,
    pub nbackref: u32,
    pub guards: V<Rest>,
    pub mb: Mb,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ET {
    SbChar,
    MbChar,
    CollSym,
    EquivClass,
    CharClass,
}

struct Elem {
    ty: ET,
    ch: u8,
    wch: u32,
    name: [u8; 33],
}

impl Elem {
    fn new() -> Elem {
        Elem { ty: ET::CollSym, ch: 0, wch: 0, name: [0; 33] }
    }
    fn name_len(&self) -> usize {
        self.name.iter().position(|&b| b == 0).unwrap_or(33)
    }
    fn name(&self) -> &[u8] {
        &self.name[..self.name_len()]
    }
}

struct Parser<'a> {
    up: &'a [u8],
    raw: &'a [u8],
    idx: usize,
    syntax: u64,
    trans: Option<&'a [u8; 256]>,
    nodes: V<TNode>,
    sets: V<Set>,
    nsub: u32,
    completed: u32,
    nbackref: u32,
    guards: V<Rest>,
    mb: Mb,
    sbc: Set,
    icase: bool,
    ucache: V<(u32, V<Seq>)>,
    cased: Option<mbset::Cased>,
    cased_own: Option<(V<(u32, u32)>, mbset::Ranges)>,
}

fn set_bit(s: &mut Set, c: u8) {
    s[(c >> 6) as usize] |= 1u64 << (c & 63);
}

pub fn set_has(s: &Set, c: u8) -> bool {
    s[(c >> 6) as usize] >> (c & 63) & 1 != 0
}

impl<'a> Parser<'a> {
    fn mk_raw(&mut self, kind: NK, left: u32, right: u32) -> Res {
        if self.nodes.len() >= MAX_NODES {
            return Err(REG_ESPACE);
        }
        let id = self.nodes.len() as u32;
        self.nodes.push(TNode {
            kind,
            left,
            right,
            parent: NONE,
            c: 0,
            idx: 0,
            ctx: 0,
            opt: false,
            dup: false,
            first: NONE,
            next: NONE,
            nidx: NONE,
        });
        if self.nodes.oom {
            return Err(REG_ESPACE);
        }
        if left != NONE {
            self.nodes[left as usize].parent = id;
        }
        if right != NONE {
            self.nodes[right as usize].parent = id;
        }
        Ok(id)
    }

    fn mk_tok(&mut self, t: &Tok) -> Res {
        let kind = match t.ty {
            T::Anchor => NK::Anchor,
            T::OpBackRef => NK::BackRef,
            T::OpPeriod => NK::Period,
            _ => NK::Char,
        };
        let id = self.mk_raw(kind, NONE, NONE)?;
        let n = &mut self.nodes[id as usize];
        n.c = t.c;
        n.idx = t.idx;
        n.ctx = t.ctx;
        Ok(id)
    }

    fn mk_set(&mut self, s: Set) -> Res {
        let id = self.mk_raw(NK::Set, NONE, NONE)?;
        self.nodes[id as usize].idx = self.sets.len() as u32;
        self.sets.push(s);
        if self.sets.oom {
            return Err(REG_ESPACE);
        }
        Ok(id)
    }

    fn eoi(&self) -> bool {
        self.idx >= self.up.len()
    }

    fn char_at(&self, i: usize) -> Option<(u32, usize)> {
        match charset::decode(self.mb, &self.raw[i..]) {
            Some((wc, n)) if n > 1 => Some((wc, n)),
            _ => None,
        }
    }

    fn fetch_token(&mut self, syntax: u64) -> Tok {
        let (t, n) = self.peek_token(syntax);
        self.idx += n;
        t
    }

    fn peek_at(&self, i: usize, syntax: u64) -> (Tok, usize) {
        let mut t = Tok { ty: T::Character, c: 0, idx: 0, ctx: 0, mb: 0, wc: 0 };
        if self.eoi() {
            t.ty = T::EndOfRe;
            return (t, 0);
        }
        let c = self.up[i];
        t.c = c;
        if self.mb != Mb::None
            && c >= 0x80
            && let Some((wc, n)) = self.char_at(i)
        {
            t.ty = T::Character;
            t.mb = n as u8;
            t.wc = wc;
            return (t, n);
        }
        if c == b'\\' {
            if i + 1 >= self.up.len() {
                t.ty = T::BackSlash;
                return (t, 1);
            }
            let c2 = self.raw[i + 1];
            t.c = c2;
            t.ty = T::Character;
            if self.mb != Mb::None
                && c2 >= 0x80
                && let Some((wc, n)) = self.char_at(i + 1)
            {
                t.mb = n as u8;
                t.wc = wc;
                return (t, 1 + n);
            }
            match c2 {
                b'|' if syntax & RE_LIMITED_OPS == 0 && syntax & RE_NO_BK_VBAR == 0 => t.ty = T::OpAlt,
                b'1'..=b'9' => {
                    if syntax & RE_NO_BK_REFS == 0 {
                        t.ty = T::OpBackRef;
                        t.idx = (c2 - b'1') as u32;
                    }
                }
                b'<' => {
                    if syntax & RE_NO_GNU_OPS == 0 {
                        t.ty = T::Anchor;
                        t.ctx = WORD_FIRST;
                    }
                }
                b'>' => {
                    if syntax & RE_NO_GNU_OPS == 0 {
                        t.ty = T::Anchor;
                        t.ctx = WORD_LAST;
                    }
                }
                b'b' => {
                    if syntax & RE_NO_GNU_OPS == 0 {
                        t.ty = T::Anchor;
                        t.ctx = WORD_DELIM;
                    }
                }
                b'B' => {
                    if syntax & RE_NO_GNU_OPS == 0 {
                        t.ty = T::Anchor;
                        t.ctx = NOT_WORD_DELIM;
                    }
                }
                b'w' if syntax & RE_NO_GNU_OPS == 0 => t.ty = T::OpWord,
                b'W' if syntax & RE_NO_GNU_OPS == 0 => t.ty = T::OpNotWord,
                b's' if syntax & RE_NO_GNU_OPS == 0 => t.ty = T::OpSpace,
                b'S' if syntax & RE_NO_GNU_OPS == 0 => t.ty = T::OpNotSpace,
                b'`' => {
                    if syntax & RE_NO_GNU_OPS == 0 {
                        t.ty = T::Anchor;
                        t.ctx = BUF_FIRST;
                    }
                }
                b'\'' => {
                    if syntax & RE_NO_GNU_OPS == 0 {
                        t.ty = T::Anchor;
                        t.ctx = BUF_LAST;
                    }
                }
                b'(' if syntax & RE_NO_BK_PARENS == 0 => t.ty = T::OpOpenSubexp,
                b')' if syntax & RE_NO_BK_PARENS == 0 => t.ty = T::OpCloseSubexp,
                b'+' if syntax & RE_LIMITED_OPS == 0 && syntax & RE_BK_PLUS_QM != 0 => t.ty = T::OpDupPlus,
                b'?' if syntax & RE_LIMITED_OPS == 0 && syntax & RE_BK_PLUS_QM != 0 => t.ty = T::OpDupQuestion,
                b'{' if syntax & RE_INTERVALS != 0 && syntax & RE_NO_BK_BRACES == 0 => t.ty = T::OpOpenDupNum,
                b'}' if syntax & RE_INTERVALS != 0 && syntax & RE_NO_BK_BRACES == 0 => t.ty = T::OpCloseDupNum,
                _ => {}
            }
            return (t, 2);
        }
        t.ty = T::Character;
        match c {
            b'\n' if syntax & RE_NEWLINE_ALT != 0 => t.ty = T::OpAlt,
            b'|' if syntax & RE_LIMITED_OPS == 0 && syntax & RE_NO_BK_VBAR != 0 => t.ty = T::OpAlt,
            b'*' => t.ty = T::OpDupAsterisk,
            b'+' if syntax & RE_LIMITED_OPS == 0 && syntax & RE_BK_PLUS_QM == 0 => t.ty = T::OpDupPlus,
            b'?' if syntax & RE_LIMITED_OPS == 0 && syntax & RE_BK_PLUS_QM == 0 => t.ty = T::OpDupQuestion,
            b'{' if syntax & RE_INTERVALS != 0 && syntax & RE_NO_BK_BRACES != 0 => t.ty = T::OpOpenDupNum,
            b'}' if syntax & RE_INTERVALS != 0 && syntax & RE_NO_BK_BRACES != 0 => t.ty = T::OpCloseDupNum,
            b'(' if syntax & RE_NO_BK_PARENS != 0 => t.ty = T::OpOpenSubexp,
            b')' if syntax & RE_NO_BK_PARENS != 0 => t.ty = T::OpCloseSubexp,
            b'[' => t.ty = T::OpOpenBracket,
            b'.' => t.ty = T::OpPeriod,
            b'^' => {
                let mut anchor = true;
                if syntax & (RE_CONTEXT_INDEP_ANCHORS | RE_CARET_ANCHORS_HERE) == 0 && i != 0 {
                    let prev = self.up[i - 1];
                    if syntax & RE_NEWLINE_ALT == 0 || prev != b'\n' {
                        anchor = false;
                    }
                }
                if anchor {
                    t.ty = T::Anchor;
                    t.ctx = LINE_FIRST;
                }
            }
            b'$' => {
                let mut anchor = true;
                if syntax & RE_CONTEXT_INDEP_ANCHORS == 0 && i + 1 != self.up.len() {
                    let (next, _) = self.peek_at(i + 1, syntax);
                    if next.ty != T::OpAlt && next.ty != T::OpCloseSubexp {
                        anchor = false;
                    }
                }
                if anchor {
                    t.ty = T::Anchor;
                    t.ctx = LINE_LAST;
                }
            }
            _ => {}
        }
        (t, 1)
    }

    fn peek_token(&self, syntax: u64) -> (Tok, usize) {
        self.peek_at(self.idx, syntax)
    }

    fn peek_token_bracket(&mut self) -> (Tok, usize) {
        let syntax = self.syntax;
        let mut t = Tok { ty: T::Character, c: 0, idx: 0, ctx: 0, mb: 0, wc: 0 };
        if self.eoi() {
            t.ty = T::EndOfRe;
            return (t, 0);
        }
        let c = self.up[self.idx];
        t.c = c;
        if c == b'\\' && syntax & RE_BACKSLASH_ESCAPE_IN_LISTS != 0 && self.idx + 1 < self.up.len() {
            self.idx += 1;
            t.c = self.up[self.idx];
            t.ty = T::Character;
            return (t, 1);
        }
        if c == b'[' {
            let c2 = if self.idx + 1 < self.up.len() { self.up[self.idx + 1] } else { 0 };
            t.c = c2;
            let mut len = 2;
            match c2 {
                b'.' => t.ty = T::OpOpenCollElem,
                b'=' => t.ty = T::OpOpenEquivClass,
                b':' if syntax & RE_CHAR_CLASSES != 0 => t.ty = T::OpOpenCharClass,
                _ => {
                    t.ty = T::Character;
                    t.c = c;
                    len = 1;
                }
            }
            return (t, len);
        }
        match c {
            b'-' => t.ty = T::OpCharsetRange,
            b']' => t.ty = T::OpCloseBracket,
            b'^' => t.ty = T::OpNonMatchList,
            _ => t.ty = T::Character,
        }
        (t, 1)
    }

    fn parse_reg_exp(&mut self, tok: &mut Tok, nest: u32) -> Res {
        let syntax = self.syntax;
        let initial_map = self.completed;
        let mut tree = self.parse_branch(tok, nest)?;
        while tok.ty == T::OpAlt {
            *tok = self.fetch_token(syntax | RE_CARET_ANCHORS_HERE);
            let branch;
            if tok.ty != T::OpAlt && tok.ty != T::EndOfRe && (nest == 0 || tok.ty != T::OpCloseSubexp) {
                let accumulated = self.completed;
                self.completed = initial_map;
                branch = self.parse_branch(tok, nest)?;
                self.completed |= accumulated;
            } else {
                branch = NONE;
            }
            tree = self.mk_raw(NK::Alt, tree, branch)?;
        }
        Ok(tree)
    }

    fn parse_branch(&mut self, tok: &mut Tok, nest: u32) -> Res {
        let mut tree = self.parse_expression(tok, nest)?;
        while tok.ty != T::OpAlt && tok.ty != T::EndOfRe && (nest == 0 || tok.ty != T::OpCloseSubexp) {
            let expr = self.parse_expression(tok, nest)?;
            if tree != NONE && expr != NONE {
                tree = self.mk_raw(NK::Concat, tree, expr)?;
            } else if tree == NONE {
                tree = expr;
            }
        }
        Ok(tree)
    }

    fn parse_expression(&mut self, tok: &mut Tok, nest: u32) -> Res {
        let syntax = self.syntax;
        let tree: u32;
        match tok.ty {
            T::Character => {
                tree = self.mk_character(tok)?;
            }
            T::OpOpenSubexp => {
                tree = self.parse_sub_exp(tok, nest + 1)?;
            }
            T::OpOpenBracket => {
                tree = self.parse_bracket_exp(tok)?;
            }
            T::OpBackRef => {
                if self.completed & (1u32 << tok.idx) == 0 {
                    return Err(REG_ESUBREG);
                }
                tree = self.mk_tok(tok)?;
                self.nbackref += 1;
            }
            T::OpOpenDupNum | T::OpDupAsterisk | T::OpDupPlus | T::OpDupQuestion | T::OpCloseSubexp | T::OpCloseDupNum => {
                if tok.ty == T::OpOpenDupNum && syntax & RE_CONTEXT_INVALID_DUP != 0 {
                    return Err(REG_BADRPT);
                }
                if matches!(tok.ty, T::OpOpenDupNum | T::OpDupAsterisk | T::OpDupPlus | T::OpDupQuestion) {
                    if syntax & RE_CONTEXT_INVALID_OPS != 0 {
                        return Err(REG_BADRPT);
                    } else if syntax & RE_CONTEXT_INDEP_OPS != 0 {
                        *tok = self.fetch_token(syntax);
                        return self.parse_expression(tok, nest);
                    }
                }
                if tok.ty == T::OpCloseSubexp && syntax & RE_UNMATCHED_RIGHT_PAREN_ORD == 0 {
                    return Err(REG_ERPAREN);
                }
                tok.ty = T::Character;
                tree = self.mk_tok(tok)?;
            }
            T::Anchor => {
                let t = if tok.ctx == WORD_DELIM || tok.ctx == NOT_WORD_DELIM {
                    let (a, b) = if tok.ctx == WORD_DELIM { (WORD_FIRST, WORD_LAST) } else { (INSIDE_WORD, INSIDE_NOTWORD) };
                    let mut tk = *tok;
                    tk.ctx = a;
                    let first = self.mk_tok(&tk)?;
                    tk.ctx = b;
                    let last = self.mk_tok(&tk)?;
                    self.mk_raw(NK::Alt, first, last)?
                } else {
                    self.mk_tok(tok)?
                };
                *tok = self.fetch_token(syntax);
                return Ok(t);
            }
            T::OpPeriod => {
                tree = self.mk_period(tok)?;
            }
            T::OpWord | T::OpNotWord => {
                tree = self.build_charclass_op(b"alnum", b"_", tok.ty == T::OpNotWord)?;
            }
            T::OpSpace | T::OpNotSpace => {
                tree = self.build_charclass_op(b"space", b"", tok.ty == T::OpNotSpace)?;
            }
            T::OpAlt | T::EndOfRe => return Ok(NONE),
            T::BackSlash => return Err(REG_EESCAPE),
            _ => return Ok(NONE),
        }
        *tok = self.fetch_token(syntax);
        let mut tree = tree;
        while matches!(tok.ty, T::OpDupAsterisk | T::OpDupPlus | T::OpDupQuestion | T::OpOpenDupNum) {
            tree = self.parse_dup_op(tree, tok)?;
            if syntax & RE_CONTEXT_INVALID_DUP != 0 && matches!(tok.ty, T::OpDupAsterisk | T::OpOpenDupNum) {
                return Err(REG_BADRPT);
            }
        }
        Ok(tree)
    }

    fn parse_sub_exp(&mut self, tok: &mut Tok, nest: u32) -> Res {
        if nest > MAX_NEST {
            return Err(REG_ESPACE);
        }
        let syntax = self.syntax;
        let cur_nsub = self.nsub;
        self.nsub += 1;
        *tok = self.fetch_token(syntax | RE_CARET_ANCHORS_HERE);
        let tree;
        if tok.ty == T::OpCloseSubexp {
            tree = NONE;
        } else {
            tree = self.parse_reg_exp(tok, nest)?;
            if tok.ty != T::OpCloseSubexp {
                return Err(REG_EPAREN);
            }
        }
        if cur_nsub <= 8 {
            self.completed |= 1 << cur_nsub;
        }
        let n = self.mk_raw(NK::Subexp, tree, NONE)?;
        self.nodes[n as usize].idx = cur_nsub;
        Ok(n)
    }

    fn fetch_number(&mut self, tok: &mut Tok) -> i64 {
        let mut num: i64 = -1;
        loop {
            *tok = self.fetch_token(self.syntax);
            let c = tok.c;
            if tok.ty == T::EndOfRe {
                return -2;
            }
            if tok.ty == T::OpCloseDupNum || c == b',' {
                break;
            }
            num = if tok.ty != T::Character || !c.is_ascii_digit() || num == -2 {
                -2
            } else if num == -1 {
                (c - b'0') as i64
            } else {
                core::cmp::min(RE_DUP_MAX + 1, num * 10 + (c - b'0') as i64)
            };
        }
        num
    }

    fn parse_dup_op(&mut self, elem: u32, tok: &mut Tok) -> Res {
        let syntax = self.syntax;
        let start_idx = self.idx;
        let start_token = *tok;
        let start: i64;
        let end: i64;
        if tok.ty == T::OpOpenDupNum {
            let mut e = 0i64;
            let mut s = self.fetch_number(tok);
            if s == -1 {
                if tok.ty == T::Character && tok.c == b',' {
                    s = 0;
                } else {
                    return Err(REG_BADBR);
                }
            }
            if s != -2 {
                e = if tok.ty == T::OpCloseDupNum {
                    s
                } else if tok.ty == T::Character && tok.c == b',' {
                    self.fetch_number(tok)
                } else {
                    -2
                };
            }
            if s == -2 || e == -2 {
                if syntax & RE_INVALID_INTERVAL_ORD == 0 {
                    return Err(if tok.ty == T::EndOfRe { REG_EBRACE } else { REG_BADBR });
                }
                self.idx = start_idx;
                *tok = start_token;
                tok.ty = T::Character;
                return Ok(elem);
            }
            if (e != -1 && s > e) || tok.ty != T::OpCloseDupNum {
                return Err(REG_BADBR);
            }
            if RE_DUP_MAX < (if e == -1 { s } else { e }) {
                return Err(REG_ESIZE);
            }
            start = s;
            end = e;
        } else {
            start = if tok.ty == T::OpDupPlus { 1 } else { 0 };
            end = if tok.ty == T::OpDupQuestion { 1 } else { -1 };
        }
        *tok = self.fetch_token(syntax);
        if elem == NONE {
            return Ok(NONE);
        }
        if start == 0 && end == 0 {
            return Ok(NONE);
        }
        let mut elem = elem;
        let old_tree;
        let mut tree;
        if start > 0 {
            tree = elem;
            for _ in 2..=start {
                elem = self.duplicate_tree(elem)?;
                tree = self.mk_raw(NK::Concat, tree, elem)?;
            }
            if start == end {
                return Ok(tree);
            }
            elem = self.duplicate_tree(elem)?;
            old_tree = tree;
        } else {
            old_tree = NONE;
        }
        if self.nodes[elem as usize].kind == NK::Subexp {
            let subidx = self.nodes[elem as usize].idx;
            self.mark_opt_subexp(elem, subidx);
        }
        tree = self.mk_raw(if end == -1 { NK::Star } else { NK::Alt }, elem, NONE)?;
        if end != -1 {
            for _ in (start + 2)..=end {
                elem = self.duplicate_tree(elem)?;
                tree = self.mk_raw(NK::Concat, tree, elem)?;
                tree = self.mk_raw(NK::Alt, tree, NONE)?;
            }
        }
        if old_tree != NONE {
            tree = self.mk_raw(NK::Concat, old_tree, tree)?;
        }
        Ok(tree)
    }

    fn mark_opt_subexp(&mut self, root: u32, subidx: u32) {
        let mut stack: V<u32> = V::new();
        stack.push(root);
        while let Some(n) = stack.pop() {
            let nd = self.nodes[n as usize];
            if nd.kind == NK::Subexp && nd.idx == subidx {
                self.nodes[n as usize].opt = true;
            }
            if nd.right != NONE {
                stack.push(nd.right);
            }
            if nd.left != NONE {
                stack.push(nd.left);
            }
        }
    }

    fn duplicate_tree(&mut self, root: u32) -> Res {
        let mut stack: V<(u32, u32, bool)> = V::new();
        stack.push((root, NONE, false));
        if stack.oom {
            return Err(REG_ESPACE);
        }
        let mut new_root = NONE;
        while let Some((src, dparent, is_left)) = stack.pop() {
            let s = self.nodes[src as usize];
            let id = self.mk_raw(s.kind, NONE, NONE)?;
            {
                let n = &mut self.nodes[id as usize];
                n.c = s.c;
                n.idx = s.idx;
                n.ctx = s.ctx;
                n.opt = false;
                n.dup = true;
                n.parent = dparent;
            }
            if dparent == NONE {
                new_root = id;
            } else if is_left {
                self.nodes[dparent as usize].left = id;
            } else {
                self.nodes[dparent as usize].right = id;
            }
            if s.right != NONE {
                stack.push((s.right, id, false));
            }
            if s.left != NONE {
                stack.push((s.left, id, true));
            }
            if stack.oom {
                return Err(REG_ESPACE);
            }
        }
        Ok(new_root)
    }

    fn mk_character(&mut self, tok: &Tok) -> Res {
        if self.mb == Mb::None {
            return self.mk_tok(tok);
        }
        let wc = if tok.mb > 1 {
            tok.wc
        } else if tok.c < 0x80 {
            tok.c as u32
        } else {
            return self.mk_tok(tok);
        };
        if !self.icase {
            if tok.mb > 1 {
                let mut b = [0u8; 6];
                let n = charset::encode(self.mb, wc, &mut b).unwrap_or(0);
                let mut seq = Seq { r: [(0, 0); 6], n: n as u8 };
                for i in 0..n {
                    seq.r[i] = (b[i], b[i]);
                }
                if n > 1 {
                    return self.tree_of_seq(&seq);
                }
            }
            return self.mk_tok(tok);
        }
        if wc < 0x80 && !rusty_libc_wchar::wctype::is_alpha(wc) {
            return self.mk_tok(tok);
        }
        let want = charset::upper_wc(wc);
        let mut seqs: V<Seq> = V::new();
        match self.ucache.iter().position(|(w, _)| *w == want) {
            Some(i) => seqs.extend_from_slice(&self.ucache[i].1),
            None => {
                self.same_upper(want, &mut seqs);
                if seqs.oom {
                    return Err(REG_ESPACE);
                }
                let mut keep: V<Seq> = V::new();
                keep.extend_from_slice(&seqs);
                self.ucache.push((want, keep));
            }
        }
        if seqs.len() <= 1 {
            return match mbset::seq_of(self.mb, wc) {
                Some(seq) if seq.n > 1 => self.tree_of_seq(&seq),
                _ => self.mk_tok(tok),
            };
        }
        self.tree_of_seqs(&seqs)
    }

    fn cased(&mut self) -> (&[(u32, u32)], &[(u32, u32)]) {
        if self.cased.is_none() && self.cased_own.is_none() {
            self.cased = mbset::cased_cached();
            if self.cased.is_none() {
                let (mut v, mut k): (V<(u32, u32)>, mbset::Ranges) = (V::new(), V::new());
                mbset::cased_compute(&mut v, &mut k);
                self.cased_own = Some((v, k));
            }
        }
        match (&self.cased, &self.cased_own) {
            (Some(c), _) => (c.pairs, c.kept),
            (None, Some((v, k))) => (&v[..], &k[..]),
            (None, None) => (&[], &[]),
        }
    }

    fn same_upper(&mut self, want: u32, out: &mut V<Seq>) {
        let mb = self.mb;
        if mb == Mb::Utf8 {
            if charset::upper_wc(want) == want
                && let Some(s) = mbset::seq_of(mb, want)
            {
                out.push(s);
            }
            for &(t, u) in self.cased().0 {
                if u == want
                    && let Some(s) = mbset::seq_of(mb, t)
                {
                    out.push(s);
                }
            }
            return;
        }
        if mb != Mb::Utf8 {
            mbset::collect_folded(mb, &mut |_, up, _| up == want, out);
            return;
        }
        let mut pred = |c: u32, _n: usize| charset::upper_wc(c) == want;
        mbset::collect(mb, true, 0x10ffff, &mut pred, out);
    }

    fn tree_of_seq(&mut self, s: &Seq) -> Res {
        let mut tree = NONE;
        for &(lo, hi) in s.r.iter().take(s.n as usize) {
            let node = if lo == hi {
                let mut t = Tok { ty: T::Character, c: lo, idx: 0, ctx: 0, mb: 0, wc: 0 };
                t.c = lo;
                self.mk_tok(&t)?
            } else {
                let mut set: Set = [0; 4];
                for b in lo..=hi {
                    set_bit(&mut set, b);
                }
                self.mk_set(set)?
            };
            tree = if tree == NONE { node } else { self.mk_raw(NK::Concat, tree, node)? };
        }
        Ok(tree)
    }

    fn cached_tree(&mut self, key: &[u8], build: &mut dyn FnMut(&mut V<Seq>)) -> Res {
        if let Some(r) = mbset::canon_with(key, |c| if c.root == u32::MAX { Ok(NONE) } else { self.emit_canon(c, c.root) }) {
            return r;
        }
        let mut seqs: V<Seq> = V::new();
        build(&mut seqs);
        if seqs.oom {
            return Err(REG_ESPACE);
        }
        let mut trie = Trie::new();
        for s in seqs.iter() {
            trie.insert(s);
        }
        if trie.oom() {
            return Err(REG_ESPACE);
        }
        if trie.is_empty() {
            mbset::canon_put(key, Canon::none());
            return Ok(NONE);
        }
        let canon = trie.canon();
        if canon.oom {
            return Err(REG_ESPACE);
        }
        let r = self.emit_canon(&canon, canon.root)?;
        mbset::canon_put(key, canon);
        Ok(r)
    }

    fn tree_of_seqs(&mut self, seqs: &V<Seq>) -> Res {
        let mut trie = Trie::new();
        for s in seqs.iter() {
            trie.insert(s);
        }
        if trie.oom() {
            return Err(REG_ESPACE);
        }
        if trie.is_empty() {
            return Ok(NONE);
        }
        let canon = trie.canon();
        if canon.oom {
            return Err(REG_ESPACE);
        }
        self.emit_canon(&canon, canon.root)
    }

    fn emit_canon(&mut self, c: &Canon, id: u32) -> Res {
        let mut groups: V<(u32, Set)> = V::new();
        groups.extend_from_slice(c.groups(id));
        if groups.oom {
            return Err(REG_ESPACE);
        }
        let mut alt = NONE;
        for &(child, set) in groups.iter() {
            let mut t = self.mk_set(set)?;
            if child != 0 {
                let sub = self.emit_canon(c, child)?;
                t = self.mk_raw(NK::Concat, t, sub)?;
            }
            alt = if alt == NONE { t } else { self.mk_raw(NK::Alt, alt, t)? };
        }
        Ok(alt)
    }

    fn mk_period(&mut self, tok: &Tok) -> Res {
        if self.mb == Mb::None {
            return self.mk_tok(tok);
        }
        let mut sb: Set = if self.mb == Mb::Utf8 { [!0, !0, 0, 0] } else { self.sbc };
        if self.syntax & RE_DOT_NEWLINE == 0 {
            sb[0] &= !(1u64 << b'\n');
        }
        if self.syntax & RE_DOT_NOT_NULL != 0 {
            sb[0] &= !1;
        }
        let mb = self.mb;
        let mut key: V<u8> = V::new();
        key.extend_from_slice(b"period");
        key.push(mb as u8);
        key.extend_from_slice(&(rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE) as usize).to_ne_bytes());
        let mut build = |seqs: &mut V<Seq>| {
            if mb == Mb::Utf8 {
                let c = (0x80u8, 0xbfu8);
                let z = (0, 0);
                seqs.push(Seq { r: [(0xc2, 0xdf), c, z, z, z, z], n: 2 });
                seqs.push(Seq { r: [(0xe0, 0xe0), (0xa0, 0xbf), c, z, z, z], n: 3 });
                seqs.push(Seq { r: [(0xe1, 0xef), c, c, z, z, z], n: 3 });
                seqs.push(Seq { r: [(0xf0, 0xf0), (0x90, 0xbf), c, c, z, z], n: 4 });
                seqs.push(Seq { r: [(0xf1, 0xf7), c, c, c, z, z], n: 4 });
                seqs.push(Seq { r: [(0xf8, 0xf8), (0x88, 0xbf), c, c, c, z], n: 5 });
                seqs.push(Seq { r: [(0xf9, 0xfb), c, c, c, c, z], n: 5 });
                seqs.push(Seq { r: [(0xfc, 0xfc), (0x84, 0xbf), c, c, c, c], n: 6 });
                seqs.push(Seq { r: [(0xfd, 0xfd), c, c, c, c, c], n: 6 });
            } else {
                mbset::collect(mb, false, 0x10ffff, &mut |_, _| true, seqs);
            }
        };
        let s = self.mk_set(sb)?;
        let m = self.cached_tree(&key, &mut build)?;
        if m == NONE {
            return Ok(s);
        }
        self.mk_raw(NK::Alt, s, m)
    }

    fn complex_member(acc: &Acc, coll: &charset::Collation, wc: u32) -> bool {
        let mut hit = acc.mbchars.contains(&wc) || acc.classes.iter().any(|&c| charset::in_class_wc(c as usize, wc));
        if !hit {
            if coll.nrules() != 0 {
                if !acc.ranges.is_empty() {
                    let seq = coll.seq_wc(wc);
                    hit = acc.ranges.iter().any(|&(s, e)| s <= seq && seq <= e);
                }
                if !hit && !acc.equivs.is_empty() {
                    let pat = [wc, 0u32];
                    if let Some((rule, w, _)) = unsafe { rusty_libc_locale::primary_wc(pat.as_ptr()) } {
                        hit = acc.equivs.iter().any(|&(r2, w2)| r2 == rule && w2 == w);
                    }
                }
            } else {
                hit = acc.ranges.iter().any(|&(s, e)| s <= wc && wc <= e);
            }
        }
        hit != acc.non_match
    }

    fn units_tree(&mut self, acc: &Acc) -> Res {
        let mut all: V<Seq> = V::new();
        self.contraction_seqs(acc, &mut all);
        if all.oom {
            return Err(REG_ESPACE);
        }
        let mut elems: V<Rest> = V::new();
        if !all.is_empty() {
            charset::Collation::current().each_element(&mut |elem, _| {
                if (2..=6).contains(&elem.len()) && !self.element_unseen(elem) {
                    let mut b = [0u8; 6];
                    b[..elem.len()].copy_from_slice(elem);
                    elems.push((b, elem.len() as u8));
                }
            });
        }
        let fold = |b: u8| if self.icase { b.to_ascii_uppercase() } else { b };
        let mut units: V<Seq> = V::new();
        let mut guarded: V<(Seq, V<Rest>)> = V::new();
        for u in all.iter() {
            let n = u.n as usize;
            let mut rests: V<Rest> = V::new();
            for (e, el) in elems.iter() {
                let el = *el as usize;
                if el > n && (0..n).all(|i| fold(u.r[i].0) == e[i]) {
                    let mut r = [0u8; 6];
                    r[..el - n].copy_from_slice(&e[n..el]);
                    rests.push((r, (el - n) as u8));
                }
            }
            if rests.is_empty() {
                units.push(*u);
            } else {
                guarded.push((*u, rests));
            }
        }
        if units.oom || guarded.oom || elems.oom {
            return Err(REG_ESPACE);
        }
        let n = units.len();
        let mut done: V<bool> = V::from_elem(false, n);
        let mut result = NONE;
        let mut left = n;
        while left > 0 {
            let mut group: V<Seq> = V::new();
            for i in 0..n {
                if done[i] {
                    continue;
                }
                let a = units[i];
                let clash = group.iter().any(|b| {
                    let k = a.n.min(b.n) as usize;
                    a.r[..k] == b.r[..k]
                });
                if !clash {
                    group.push(a);
                    done[i] = true;
                    left -= 1;
                }
            }
            if group.oom || done.oom {
                return Err(REG_ESPACE);
            }
            let t = self.tree_of_seqs(&group)?;
            if t == NONE {
                continue;
            }
            result = if result == NONE { t } else { self.mk_raw(NK::Alt, result, t)? };
        }
        for (u, rests) in guarded.iter() {
            let mut one: V<Seq> = V::new();
            one.push(*u);
            let mut t = self.tree_of_seqs(&one)?;
            if t == NONE {
                continue;
            }
            for (r, rl) in rests.iter() {
                let gid = self.guards.len() as u32;
                self.guards.push((*r, *rl));
                let g = self.mk_raw(NK::Guard, NONE, NONE)?;
                self.nodes[g as usize].idx = gid;
                self.nbackref += 1;
                t = self.mk_raw(NK::Concat, t, g)?;
            }
            result = if result == NONE { t } else { self.mk_raw(NK::Alt, result, t)? };
        }
        if self.guards.oom {
            return Err(REG_ESPACE);
        }
        Ok(result)
    }

    fn add_units(&mut self, m: u32, acc: &Acc) -> Res {
        let u = self.units_tree(acc)?;
        if u == NONE {
            return Ok(m);
        }
        if m == NONE {
            return Ok(u);
        }
        self.mk_raw(NK::Alt, m, u)
    }

    fn is_complex_bracket(&self, acc: &Acc) -> bool {
        !acc.mbchars.is_empty()
            || !acc.colls.is_empty()
            || !acc.equivs.is_empty()
            || !acc.equivs_mb.is_empty()
            || !acc.ranges.is_empty()
            || (self.mb != Mb::None && (!acc.classes.is_empty() || acc.non_match))
    }

    fn element_unseen(&self, elem: &[u8]) -> bool {
        self.icase && self.mb == Mb::None && elem.len() >= 4
    }

    fn symbol_unseen(&self, elem: &[u8]) -> bool {
        self.element_unseen(elem)
    }

    fn contraction_seqs(&self, acc: &Acc, out: &mut V<Seq>) {
        if !self.is_complex_bracket(acc) {
            return;
        }
        let coll = charset::Collation::current();
        if coll.nrules() == 0 {
            return;
        }
        coll.each_element(&mut |elem, seq| {
            if elem.is_empty() || elem.len() > 6 {
                return;
            }
            let (mut chars, mut n, mut i) = ([0u32; 6], 0usize, 0usize);
            while i < elem.len() {
                let (wc, l) = if self.mb == Mb::None { (elem[i] as u32, 1) } else { charset::decode(self.mb, &elem[i..]).unwrap_or((elem[i] as u32, 1)) };
                chars[n] = wc;
                n += 1;
                i += l;
            }
            if n < 2 {
                return;
            }
            let up = |wc: u32| if self.mb == Mb::None { u32::from(charset::to_upper(wc as u8)) } else { charset::upper_wc(wc) };
            if self.icase && chars[..n].iter().any(|&c| up(c) != c) {
                return;
            }
            let first_hit = acc.mbchars.contains(&chars[0])
                || acc.classes.iter().any(|&c| if self.mb == Mb::None { charset::in_class(c as usize, elem[0]) } else { charset::in_class_wc(c as usize, chars[0]) });
            let coll_hit = !self.symbol_unseen(elem) && acc.colls.iter().any(|s| s.n as usize == elem.len() && s.r[..elem.len()].iter().zip(elem).all(|(r, &b)| *r == (b, b)));
            let range_hit = acc.ranges.iter().any(|&(s, e)| s <= seq && seq <= e);
            let equiv_hit = !acc.equivs_mb.is_empty() && {
                let mut buf = [0u8; 8];
                buf[..elem.len()].copy_from_slice(elem);
                unsafe { rusty_libc_locale::primary_mb(buf.as_ptr()) }
                    .is_some_and(|(r, w, used)| used == elem.len() && acc.equivs_mb.iter().any(|&(r2, w2)| r2 == r && w2 == w))
            };
            let hit = coll_hit || range_hit || equiv_hit;
            let accepted = if acc.non_match { !(first_hit || hit) } else { !first_hit && hit };
            if accepted {
                self.push_element(&chars[..n], elem, out);
            }
        });
    }

    fn push_element(&self, chars: &[u32], elem: &[u8], out: &mut V<Seq>) {
        if !self.icase {
            let mut s = Seq { r: [(0, 0); 6], n: elem.len() as u8 };
            for (i, &b) in elem.iter().enumerate() {
                s.r[i] = (b, b);
            }
            out.push(s);
            return;
        }
        let lower = |c: u32| if self.mb == Mb::None { u32::from(charset::to_lower(c as u8)) } else { charset::lower_wc(c) };
        let up = |c: u32| if self.mb == Mb::None { u32::from(charset::to_upper(c as u8)) } else { charset::upper_wc(c) };
        let n = chars.len();
        for mask in 0u32..(1 << n) {
            let mut bytes = [0u8; 6];
            let mut len = 0usize;
            let mut ok = true;
            for (i, &c) in chars.iter().enumerate() {
                let mut x = c;
                if mask & (1 << i) != 0 {
                    let l = lower(c);
                    if l == c || up(l) != c {
                        ok = false;
                        break;
                    }
                    x = l;
                }
                let mut b = [0u8; 6];
                let m = if self.mb == Mb::None {
                    b[0] = x as u8;
                    Some(1)
                } else {
                    charset::encode(self.mb, x, &mut b)
                };
                match m {
                    Some(m) if len + m <= 6 => {
                        bytes[len..len + m].copy_from_slice(&b[..m]);
                        len += m;
                    }
                    _ => {
                        ok = false;
                        break;
                    }
                }
            }
            if ok {
                let mut s = Seq { r: [(0, 0); 6], n: len as u8 };
                for (i, &b) in bytes[..len].iter().enumerate() {
                    s.r[i] = (b, b);
                }
                out.push(s);
            }
        }
    }

    fn finish_bracket(&mut self, mut acc: Acc, always_alt: bool) -> Res {
        if self.mb == Mb::None {
            if acc.non_match {
                for w in acc.sb.iter_mut() {
                    *w = !*w;
                }
            }
            let set = self.mk_set(acc.sb)?;
            let m = self.units_tree(&acc)?;
            return if m == NONE { Ok(set) } else { self.mk_raw(NK::Alt, set, m) };
        }
        if acc.non_match {
            for w in acc.sb.iter_mut() {
                *w = !*w;
            }
        }
        for (w, m) in acc.sb.iter_mut().zip(self.sbc.iter()) {
            *w &= *m;
        }
        let has_complex = !acc.mbchars.is_empty() || !acc.equivs.is_empty() || !acc.ranges.is_empty() || !acc.classes.is_empty() || acc.non_match;
        let coll = charset::Collation::current();
        if self.mb == Mb::Utf8 && !FORCE_SCAN.load(core::sync::atomic::Ordering::Relaxed) {
            return self.finish_utf8(acc, always_alt, has_complex, &coll);
        }
        let key = self.bracket_key(&acc, has_complex);
        let (mb, icase, sbc) = (self.mb, self.icase, self.sbc);
        let sb = acc.sb;
        let mut build = |seqs: &mut V<Seq>| {
            if icase && mb != Mb::Utf8 {
                mbset::collect_folded(
                    mb,
                    &mut |_, x, single| {
                        if single >= 0 && set_has(&sbc, single as u8) {
                            return set_has(&sb, single as u8);
                        }
                        has_complex && Self::complex_member(&acc, &coll, x)
                    },
                    seqs,
                );
            } else if icase {
                let mut pred = |c: u32, _n: usize| -> bool {
                    let x = charset::upper_wc(c);
                    let mut b = [0u8; 6];
                    if let Some(1) = charset::encode(mb, x, &mut b)
                        && set_has(&sbc, b[0])
                    {
                        return set_has(&sb, b[0]);
                    }
                    has_complex && Self::complex_member(&acc, &coll, x)
                };
                mbset::collect(mb, true, if has_complex { 0x10ffff } else { 0x3000 }, &mut pred, seqs);
            } else if has_complex {
                let mut pred = |c: u32, n: usize| -> bool { n > 1 && Self::complex_member(&acc, &coll, c) };
                mbset::collect(mb, false, 0x10ffff, &mut pred, seqs);
            }
        };
        let sb_any = acc.sb.iter().any(|&w| w != 0);
        let m = self.cached_tree(&key, &mut build)?;
        let m = self.add_units(m, &acc)?;
        if self.icase {
            return if m == NONE { self.mk_set([0; 4]) } else { Ok(m) };
        }
        if m == NONE {
            return self.mk_set(acc.sb);
        }
        if !sb_any && !always_alt {
            return Ok(m);
        }
        let s = self.mk_set(acc.sb)?;
        self.mk_raw(NK::Alt, s, m)
    }

    fn finish_utf8(&mut self, acc: Acc, always_alt: bool, has_complex: bool, coll: &charset::Collation) -> Res {
        const WBIT: [u32; 12] = [0, 3, 6, 9, 1, 4, 7, 10, 2, 5, 8, 11];
        let mut m: mbset::Ranges = V::new();
        if has_complex {
            let mut h: mbset::Ranges = V::new();
            for &wc in acc.mbchars.iter() {
                h.push((wc, wc));
            }
            for &c in acc.classes.iter() {
                rusty_libc_wchar::wctype::class_runs(WBIT[c as usize], &mut |lo, hi| h.push((lo, hi)));
            }
            if coll.nrules() != 0 {
                for &(s, e) in acc.ranges.iter() {
                    coll.seq_runs(s, e, &mut |lo, hi| h.push((lo, hi)));
                }
                for &(r, w) in acc.equivs.iter() {
                    rusty_libc_locale::equiv_runs_wc(r, w, &mut |lo, hi| h.push((lo, hi)));
                }
            } else {
                for &(s, e) in acc.ranges.iter() {
                    if e >= 0x80 {
                        h.push((s.max(0x80), e));
                    }
                }
            }
            mbset::normalize(&mut h);
            h = mbset::clip(&h, &mbset::UTF8_DOMAIN);
            m = if acc.non_match { mbset::complement(&h, &mbset::UTF8_DOMAIN) } else { h };
        }
        if h_oom(&m) || acc.colls.oom {
            return Err(REG_ESPACE);
        }
        let mut seqs: V<Seq> = V::new();
        if self.icase {
            let mut s_set: mbset::Ranges = V::new();
            for b in 0..0x80u32 {
                if set_has(&acc.sb, b as u8) {
                    s_set.push((b, b));
                }
            }
            for &r in m.iter() {
                s_set.push(r);
            }
            mbset::normalize(&mut s_set);
            let mut res: mbset::Ranges = V::new();
            let (pairs, kept) = self.cased();
            res.extend_from_slice(&mbset::clip(&s_set, kept));
            for &(t, u) in pairs {
                if mbset::contains(&s_set, u) {
                    res.push((t, t));
                }
            }
            mbset::normalize(&mut res);
            mbset::utf8_seqs(&res, &mut seqs);
        } else {
            mbset::utf8_seqs(&m, &mut seqs);
        }
        if seqs.oom {
            return Err(REG_ESPACE);
        }
        let sb_any = acc.sb.iter().any(|&w| w != 0);
        let t = self.tree_of_seqs(&seqs)?;
        let t = self.add_units(t, &acc)?;
        if self.icase {
            return if t == NONE { self.mk_set([0; 4]) } else { Ok(t) };
        }
        if t == NONE {
            return self.mk_set(acc.sb);
        }
        if !sb_any && !always_alt {
            return Ok(t);
        }
        let s = self.mk_set(acc.sb)?;
        self.mk_raw(NK::Alt, s, t)
    }

    fn bracket_key(&self, acc: &Acc, has_complex: bool) -> V<u8> {
        let mut k: V<u8> = V::new();
        k.push(self.icase as u8);
        k.push(self.mb as u8);
        k.push(acc.non_match as u8);
        k.push(has_complex as u8);
        let loc = |cat: usize| rusty_libc_core::locale::current(cat) as usize;
        k.extend_from_slice(&loc(rusty_libc_core::locale::LC_CTYPE).to_ne_bytes());
        k.extend_from_slice(&loc(rusty_libc_core::locale::LC_COLLATE).to_ne_bytes());
        for w in acc.sb.iter() {
            k.extend_from_slice(&w.to_ne_bytes());
        }
        k.extend_from_slice(&(acc.mbchars.len() as u32).to_ne_bytes());
        for c in acc.mbchars.iter() {
            k.extend_from_slice(&c.to_ne_bytes());
        }
        k.extend_from_slice(&(acc.classes.len() as u32).to_ne_bytes());
        k.extend_from_slice(&acc.classes);
        k.extend_from_slice(&(acc.ranges.len() as u32).to_ne_bytes());
        for (a, b) in acc.ranges.iter() {
            k.extend_from_slice(&a.to_ne_bytes());
            k.extend_from_slice(&b.to_ne_bytes());
        }
        k.extend_from_slice(&(acc.equivs.len() as u32).to_ne_bytes());
        for (r, w) in acc.equivs.iter() {
            k.push(*r);
            k.extend_from_slice(&(w.len() as u32).to_ne_bytes());
            for x in w.iter() {
                k.extend_from_slice(&x.to_ne_bytes());
            }
        }
        k
    }

    fn parse_bracket_exp(&mut self, tok: &mut Tok) -> Res {
        let syntax = self.syntax;
        let mut acc = Acc::new();
        let mut non_match = false;
        let mut first_round = true;
        let (t, mut token_len) = self.peek_token_bracket();
        *tok = t;
        if tok.ty == T::EndOfRe {
            return Err(REG_BADPAT);
        }
        if tok.ty == T::OpNonMatchList {
            non_match = true;
            acc.non_match = true;
            if syntax & RE_HAT_LISTS_NOT_NEWLINE != 0 {
                set_bit(&mut acc.sb, b'\n');
            }
            self.idx += token_len;
            let (t, l) = self.peek_token_bracket();
            *tok = t;
            token_len = l;
            if tok.ty == T::EndOfRe {
                return Err(REG_BADPAT);
            }
        }
        let _ = non_match;
        if tok.ty == T::OpCloseBracket {
            tok.ty = T::Character;
        }
        loop {
            let mut start_elem = Elem::new();
            self.parse_bracket_element(&mut start_elem, tok, token_len, first_round)?;
            first_round = false;
            let (t, l) = self.peek_token_bracket();
            *tok = t;
            token_len = l;
            let mut is_range = false;
            let mut tok2 = Tok { ty: T::Character, c: 0, idx: 0, ctx: 0, mb: 0, wc: 0 };
            let mut token_len2 = 0;
            if start_elem.ty != ET::CharClass && start_elem.ty != ET::EquivClass {
                if tok.ty == T::EndOfRe {
                    return Err(REG_EBRACK);
                }
                if tok.ty == T::OpCharsetRange {
                    self.idx += token_len;
                    let (t2, l2) = self.peek_token_bracket();
                    tok2 = t2;
                    token_len2 = l2;
                    if tok2.ty == T::EndOfRe {
                        return Err(REG_EBRACK);
                    }
                    if tok2.ty == T::OpCloseBracket {
                        self.idx -= token_len;
                        tok.ty = T::Character;
                    } else {
                        is_range = true;
                    }
                }
            }
            if is_range {
                let mut end_elem = Elem::new();
                self.parse_bracket_element(&mut end_elem, &mut tok2, token_len2, true)?;
                let (t, l) = self.peek_token_bracket();
                *tok = t;
                token_len = l;
                self.build_range_exp(&mut acc, &start_elem, &end_elem)?;
            } else {
                match start_elem.ty {
                    ET::SbChar => set_bit(&mut acc.sb, start_elem.ch),
                    ET::MbChar => acc.mbchars.push(start_elem.wch),
                    ET::EquivClass => self.build_equiv_class(&mut acc, start_elem.name())?,
                    ET::CollSym => self.build_collating_symbol(&mut acc, start_elem.name())?,
                    ET::CharClass => self.build_charclass(&mut acc, start_elem.name())?,
                }
            }
            if tok.ty == T::EndOfRe {
                return Err(REG_EBRACK);
            }
            if tok.ty == T::OpCloseBracket {
                break;
            }
        }
        self.idx += token_len;
        if acc.mbchars.oom || acc.classes.oom || acc.ranges.oom || acc.equivs.oom || acc.colls.oom {
            return Err(REG_ESPACE);
        }
        self.finish_bracket(acc, false)
    }

    fn set_char_elem(&self, elem: &mut Elem, wc: u32) {
        let x = if self.icase { charset::upper_wc(wc) } else { wc };
        let mut b = [0u8; 6];
        if let Some(1) = charset::encode(self.mb, x, &mut b)
            && set_has(&self.sbc, b[0])
        {
            elem.ty = ET::SbChar;
            elem.ch = b[0];
        } else {
            elem.ty = ET::MbChar;
            elem.wch = x;
        }
    }

    fn parse_bracket_element(&mut self, elem: &mut Elem, tok: &mut Tok, token_len: usize, accept_hyphen: bool) -> Result<(), i32> {
        if self.mb != Mb::None
            && self.idx < self.raw.len()
            && self.raw[self.idx] >= 0x80
            && let Some((wc, n)) = self.char_at(self.idx)
        {
            self.idx += n;
            self.set_char_elem(elem, wc);
            return Ok(());
        }
        self.idx += token_len;
        if matches!(tok.ty, T::OpOpenCollElem | T::OpOpenCharClass | T::OpOpenEquivClass) {
            return self.parse_bracket_symbol(elem, tok);
        }
        if tok.ty == T::OpCharsetRange && !accept_hyphen {
            let (t2, _) = self.peek_token_bracket();
            if t2.ty != T::OpCloseBracket {
                return Err(REG_ERANGE);
            }
        }
        elem.ty = ET::SbChar;
        elem.ch = tok.c;
        if self.mb != Mb::None && self.icase && tok.c < 0x80 {
            self.set_char_elem(elem, tok.c as u32);
        }
        Ok(())
    }

    fn parse_bracket_symbol(&mut self, elem: &mut Elem, tok: &Tok) -> Result<(), i32> {
        let delim = tok.c;
        if self.eoi() {
            return Err(REG_EBRACK);
        }
        let mut i = 0usize;
        loop {
            if i >= 32 {
                return Err(REG_EBRACK);
            }
            let ch = if tok.ty == T::OpOpenCharClass { self.raw[self.idx] } else { self.up[self.idx] };
            self.idx += 1;
            if self.eoi() {
                return Err(REG_EBRACK);
            }
            if ch == delim && self.up[self.idx] == b']' {
                break;
            }
            elem.name[i] = ch;
            i += 1;
        }
        self.idx += 1;
        elem.name[i] = 0;
        elem.ty = match tok.ty {
            T::OpOpenCollElem => ET::CollSym,
            T::OpOpenEquivClass => ET::EquivClass,
            _ => ET::CharClass,
        };
        if self.mb != Mb::None && self.icase && elem.ty != ET::CharClass {
            self.upcase_name(&mut elem.name);
        }
        Ok(())
    }

    fn upcase_name(&self, name: &mut [u8; 33]) {
        let len = name.iter().position(|&b| b == 0).unwrap_or(33);
        let mut out = [0u8; 33];
        let (mut i, mut o) = (0usize, 0usize);
        while i < len {
            let (wc, n) = charset::decode(self.mb, &name[i..len]).unwrap_or((name[i] as u32, 1));
            let x = charset::upper_wc(wc);
            let mut b = [0u8; 6];
            match charset::encode(self.mb, x, &mut b) {
                Some(m) if o + m <= 32 && (m == n || x != wc) => {
                    out[o..o + m].copy_from_slice(&b[..m]);
                    o += m;
                }
                _ => {
                    if o + n <= 32 {
                        out[o..o + n].copy_from_slice(&name[i..i + n]);
                        o += n;
                    }
                }
            }
            i += n;
        }
        *name = out;
    }

    fn seq_value(&self, coll: &charset::Collation, x: &Elem) -> u32 {
        match x.ty {
            ET::SbChar => coll.seq_of_byte(x.ch),
            ET::MbChar => {
                if coll.nrules() != 0 {
                    coll.seq_wc(x.wch)
                } else {
                    charset::NO_SEQ
                }
            }
            ET::CollSym => match coll.symbol_seq(x.name()) {
                Some(v) => v,
                None if x.name_len() == 1 => coll.seq_mb(x.name[0]),
                _ => charset::NO_SEQ,
            },
            _ => charset::NO_SEQ,
        }
    }

    fn build_range_exp(&self, acc: &mut Acc, s: &Elem, e: &Elem) -> Result<(), i32> {
        if matches!(s.ty, ET::EquivClass | ET::CharClass) || matches!(e.ty, ET::EquivClass | ET::CharClass) {
            return Err(REG_ERANGE);
        }
        let coll = charset::Collation::current();
        let sv = self.seq_value(&coll, s);
        let ev = self.seq_value(&coll, e);
        if sv == charset::NO_SEQ || ev == charset::NO_SEQ {
            return Err(REG_ECOLLATE);
        }
        if self.syntax & RE_NO_EMPTY_RANGES != 0 && sv > ev {
            return Err(REG_ERANGE);
        }
        if coll.nrules() > 0 || self.mb != Mb::None {
            acc.ranges.push((sv, ev));
        }
        for ch in 0..=255u32 {
            let c = coll.seq_of_byte(ch as u8);
            if sv <= c && c <= ev {
                set_bit(&mut acc.sb, ch as u8);
            }
        }
        Ok(())
    }

    fn build_equiv_class(&self, acc: &mut Acc, name: &[u8]) -> Result<(), i32> {
        let coll = charset::Collation::current();
        if coll.nrules() == 0 {
            if name.len() != 1 {
                return Err(REG_ECOLLATE);
            }
            set_bit(&mut acc.sb, name[0]);
            return Ok(());
        }
        let mut buf = [0u8; 34];
        buf[..name.len()].copy_from_slice(name);
        let Some((rule, w1, used)) = (unsafe { rusty_libc_locale::primary_mb(buf.as_ptr()) }) else { return Err(REG_ECOLLATE) };
        if used != name.len() {
            return Err(REG_ECOLLATE);
        }
        for ch in 0..=255u32 {
            let b = [ch as u8, 0];
            if let Some((r2, w2, _)) = unsafe { rusty_libc_locale::primary_mb(b.as_ptr()) }
                && r2 == rule
                && w2 == w1
            {
                set_bit(&mut acc.sb, ch as u8);
            }
        }
        acc.equivs_mb.push((rule, w1));
        if self.mb != Mb::None {
            let mut wide = [0u32; 34];
            let (mut i, mut n) = (0usize, 0usize);
            while i < name.len() {
                let (wc, l) = charset::decode(self.mb, &name[i..]).unwrap_or((name[i] as u32, 1));
                wide[n] = wc;
                n += 1;
                i += l;
            }
            if let Some((r, w, _)) = unsafe { rusty_libc_locale::primary_wc(wide.as_ptr()) } {
                acc.equivs.push((r, w));
            }
        }
        Ok(())
    }

    fn build_collating_symbol(&self, acc: &mut Acc, name: &[u8]) -> Result<(), i32> {
        let coll = charset::Collation::current();
        let mut upper = [0u8; 40];
        let mut name = name;
        if self.icase && self.mb != Mb::None && name.len() <= 32 {
            let (mut i, mut n) = (0usize, 0usize);
            while i < name.len() && n + 6 <= upper.len() {
                let (wc, l) = charset::decode(self.mb, &name[i..]).unwrap_or((name[i] as u32, 1));
                let mut b = [0u8; 6];
                match charset::encode(self.mb, charset::upper_wc(wc), &mut b) {
                    Some(m) => {
                        upper[n..n + m].copy_from_slice(&b[..m]);
                        n += m;
                    }
                    None => {
                        upper[n..n + l].copy_from_slice(&name[i..i + l]);
                        n += l;
                    }
                }
                i += l;
            }
            if i == name.len() {
                name = &upper[..n];
            }
        }
        if coll.nrules() != 0 {
            if let Some(elem) = coll.symbol_elem(name) {
                if self.mb != Mb::None
                    && let Some((wc, n)) = charset::decode(self.mb, elem)
                    && n == elem.len()
                {
                    if n > 1 {
                        acc.mbchars.push(wc);
                    }
                    return Ok(());
                }
                if elem.len() > 1 && elem.len() <= 6 {
                    let mut s = Seq { r: [(0, 0); 6], n: elem.len() as u8 };
                    for (i, &b) in elem.iter().enumerate() {
                        s.r[i] = (b, b);
                    }
                    acc.colls.push(s);
                }
                return Ok(());
            }
            if name.len() == 1 {
                set_bit(&mut acc.sb, name[0]);
                return Ok(());
            }
            return Err(REG_ECOLLATE);
        }
        if name.len() != 1 {
            return Err(REG_ECOLLATE);
        }
        set_bit(&mut acc.sb, name[0]);
        Ok(())
    }

    fn build_charclass(&self, acc: &mut Acc, class_name: &[u8]) -> Result<(), i32> {
        let mut name = class_name;
        if self.syntax & RE_ICASE != 0 && (name == b"upper" || name == b"lower") {
            name = b"alpha";
        }
        let cls = match charset::class_by_name(name) {
            Some(c) => c,
            None => return Err(REG_ECTYPE),
        };
        acc.classes.push(cls as u8);
        for i in 0..=255u32 {
            if charset::in_class(cls, i as u8) {
                match self.trans {
                    Some(t) => set_bit(&mut acc.sb, t[i as usize]),
                    None => set_bit(&mut acc.sb, i as u8),
                }
            }
        }
        Ok(())
    }

    fn build_charclass_op(&mut self, class_name: &[u8], extra: &[u8], non_match: bool) -> Res {
        let mut acc = Acc::new();
        acc.non_match = non_match;
        let saved = self.syntax;
        self.syntax = 0;
        let r = self.build_charclass(&mut acc, class_name);
        self.syntax = saved;
        r?;
        for &c in extra {
            set_bit(&mut acc.sb, c);
        }
        if acc.classes.oom {
            return Err(REG_ESPACE);
        }
        self.finish_bracket(acc, true)
    }
}

fn h_oom(r: &mbset::Ranges) -> bool {
    r.oom
}

pub static FORCE_SCAN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

struct Acc {
    sb: Set,
    mbchars: V<u32>,
    classes: V<u8>,
    ranges: V<(u32, u32)>,
    equivs: V<(u8, &'static [u32])>,
    equivs_mb: V<(u8, &'static [u8])>,
    colls: V<Seq>,
    non_match: bool,
}

impl Acc {
    fn new() -> Acc {
        Acc { sb: [0; 4], mbchars: V::new(), classes: V::new(), ranges: V::new(), equivs: V::new(), equivs_mb: V::new(), colls: V::new(), non_match: false }
    }
}

pub fn parse(pattern: &[u8], syntax: u64, trans: Option<&[u8; 256]>) -> Result<Parsed, i32> {
    let icase = syntax & RE_ICASE != 0;
    let mb = charset::mb_kind();
    let mut up: V<u8> = V::new();
    if (icase && mb == Mb::None) || trans.is_some() {
        up.reserve(pattern.len());
        for &b in pattern {
            let mut c = b;
            if let Some(t) = trans {
                c = t[c as usize];
            }
            if icase && mb == Mb::None {
                c = charset::to_upper(c);
            }
            up.push(c);
        }
        if up.oom {
            return Err(REG_ESPACE);
        }
    } else {
        up.extend_from_slice(pattern);
    }
    let sbc = if mb == Mb::None { [!0u64; 4] } else { charset::sb_chars(mb) };
    let mut p = Parser {
        up: &up,
        raw: pattern,
        idx: 0,
        syntax,
        trans,
        nodes: V::new(),
        sets: V::new(),
        nsub: 0,
        completed: 0,
        nbackref: 0,
        guards: V::new(),
        mb,
        sbc,
        icase,
        ucache: V::new(),
        cased: None,
        cased_own: None,
    };
    let mut tok = p.fetch_token(syntax | RE_CARET_ANCHORS_HERE);
    let tree = p.parse_reg_exp(&mut tok, 0)?;
    let eor = p.mk_raw(NK::End, NONE, NONE)?;
    let root = if tree != NONE { p.mk_raw(NK::Concat, tree, eor)? } else { eor };
    Ok(Parsed { nodes: p.nodes, root, sets: p.sets, nsub: p.nsub, nbackref: p.nbackref, guards: p.guards, mb })
}
