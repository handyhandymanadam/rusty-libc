//! Pattern parser: the same token rules, grammar and tree shapes as glibc's regcomp.c (the parse
//! functions follow its structure on purpose: the order of alternatives, the way `{n,m}` is
//! expanded into copies and where subexpressions are marked optional decide which submatch glibc
//! reports). C locale only: one byte is one character.
use crate::charset::{self, Mb};
use crate::consts::*;
use crate::mbset::{self, Frag, Seq, Trie};
use crate::vec::V;

pub const NONE: u32 = u32::MAX;
/// Largest tree the parser builds before giving up with REG_ESPACE.
pub const MAX_NODES: usize = 3_000_000;
/// Deepest nesting of parentheses.
pub const MAX_NEST: u32 = 3000;

/// Context constraints (glibc's PREV_*/NEXT_* bits) carried by anchor nodes.
/// Bytes and their count: the text a `Guard` forbids, or a collating element.
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
    /// Zero width check that the text after a collating element does not go on as a longer element (see `units_tree`).
    Guard,
    /// A set of multibyte characters as an automaton over bytes (`idx`: index into `Parsed::frags`; see `nfa::K_MB`).
    Mb,
    /// A bracket set of a UTF-8 locale matched from its description (`idx`: index into `Parsed::u8specs`; see `u8set`).
    U8,
}

#[derive(Clone, Copy)]
pub struct TNode {
    pub kind: NK,
    pub left: u32,
    pub right: u32,
    pub parent: u32,
    pub c: u8,
    /// Subexpression number (Subexp, Open, Close), group number - 1 (BackRef) or set index (Set).
    pub idx: u32,
    pub ctx: u16,
    pub opt: bool,
    /// Copy made by `{n,m}` expansion (glibc's token.duplicated).
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
    /// A multibyte character: its length in bytes (0 for an ordinary token) and its value.
    mb: u8,
    wc: u32,
}

type Res = Result<u32, i32>;
/// Inclusive code point ranges.
type Ranges = [(u32, u32)];
pub type Set = [u64; 4];

pub struct Parsed {
    pub nodes: V<TNode>,
    pub root: u32,
    pub sets: V<Set>,
    pub nsub: u32,
    pub nbackref: u32,
    /// The texts a `Guard` node forbids after it: (bytes, length), indexed by the node's `idx`.
    pub guards: V<Rest>,
    /// The multibyte kind of the locale the pattern was compiled in.
    pub mb: Mb,
    /// The automata of the `Mb` nodes.
    pub frags: V<Frag>,
    /// The sets of the `U8` nodes.
    pub u8specs: V<crate::u8set::U8Spec>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ET {
    SbChar,
    /// A multibyte character (more than one byte).
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
    /// The pattern after translation and (for REG_ICASE) conversion to upper case.
    up: &'a [u8],
    /// The pattern as given.
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
    /// Multibyte locale (the pattern is then handled character by character).
    mb: Mb,
    /// The bytes that are complete characters on their own (`sb_char`).
    sbc: Set,
    icase: bool,
    /// Per upper case form: the sequences of the characters that have it (REG_ICASE in a multibyte locale).
    ucache: V<(u32, V<Seq>)>,
    /// The characters the upper case mapping changes (see `cased`): the table kept for the locale, or this pattern's own
    /// copy when it could not be kept.
    cased: Option<mbset::Cased>,
    cased_own: Option<(V<(u32, u32)>, mbset::Ranges)>,
    frags: V<Frag>,
    u8specs: V<crate::u8set::U8Spec>,
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

    /// The multibyte character (more than one byte) that starts at `raw[i]`, if the bytes there form one.
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

    /// glibc's peek_token: the token at the current position and its length in bytes.
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
            // a multibyte character is one token
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

    /// glibc's peek_token_bracket. Note: for a backslash escape inside a list it advances the
    /// input by one byte itself (as glibc does) and returns length 1.
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
                // Anchors cannot be followed by repetition operators: "^*" is ANCHOR, CHAR(*).
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

    // ---- characters, `.` and bracket expressions ----

    /// A literal character (glibc's CHARACTER token, with the bytes of a multibyte character joined).
    fn mk_character(&mut self, tok: &Tok) -> Res {
        if self.mb == Mb::None {
            return self.mk_tok(tok);
        }
        // the character, when the token is one (an invalid byte stands for itself)
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
        // REG_ICASE: glibc compares upper case forms, so every character with the same upper case form matches
        if wc < 0x80 && !rusty_libc_wchar::wctype::is_alpha(wc) {
            // no other character has an ASCII non-letter as its upper case form
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
            // only the character itself (one byte, or the bytes in a row)
            return match mbset::seq_of(self.mb, wc) {
                Some(seq) if seq.n > 1 => self.tree_of_seq(&seq),
                _ => self.mk_tok(tok),
            };
        }
        self.tree_of_seqs(&seqs)
    }

    /// The characters the upper case mapping changes, with their upper case forms, and every other code point as ranges
    /// (the table is read once per locale, not per pattern).
    fn cased(&mut self) -> (&Ranges, &Ranges) {
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

    /// The sequences of all characters whose upper case form is `want`.
    fn same_upper(&mut self, want: u32, out: &mut V<Seq>) {
        let mb = self.mb;
        if mb == Mb::Utf8 {
            // the characters the mapping changes, plus `want` itself when it has no other form
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
            let runs = mbset::other_runs();
            if runs.is_empty() {
                if !mbset::same_upper_listed(mb, want, out) {
                    mbset::collect_folded(mb, &mut |_, up, _| up == want, out);
                }
                return;
            }
            if !mbset::same_upper_listed(mb, want, out) {
                mbset::collect_folded_listed(mb, &mut |_, up, _| up == want, out);
            }
            // GB18030's four-byte codes: `want` itself when it has no other form, and the characters the mapping changes to it
            let mut set: mbset::Ranges = V::new();
            if charset::upper_wc(want) == want {
                set.push((want, want));
            }
            for &(t, u) in self.cased().0 {
                if u == want {
                    set.push((t, t));
                }
            }
            mbset::normalize(&mut set);
            mbset::runs_in(runs, &set, out);
            if set.oom {
                out.oom = true;
            }
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

    /// An alternation over the sequences (NONE when there are none).
    /// The tree of the sequences `build` makes, from the cache of canonical forms when `key` (which must describe the
    /// set, the syntax-independent part of it and the locale) is there.
    fn cached_tree(&mut self, key: &[u8], build: &mut dyn FnMut(&mut V<Seq>)) -> Res {
        if let Some(r) = mbset::canon_with(key, |f| self.emit_frag(f)) {
            return r;
        }
        let mut seqs: V<Seq> = V::new();
        build(&mut seqs);
        self.tree_put(key, &seqs)
    }

    /// The tree of the sequences `seqs`, whose canonical form is kept in the cache under `key` (see `cached_tree`).
    fn tree_put(&mut self, key: &[u8], seqs: &V<Seq>) -> Res {
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
            mbset::canon_put(key, Frag::empty());
            return Ok(NONE);
        }
        let canon = trie.canon();
        self.canon_put_tree(key, canon)
    }

    /// The tree of the canonical automaton `canon`, kept in the cache under `key` (see `tree_put`).
    fn canon_put_tree(&mut self, key: &[u8], canon: mbset::Canon) -> Res {
        if canon.oom {
            return Err(REG_ESPACE);
        }
        let frag = Frag::from_canon(&canon);
        drop(canon);
        if frag.nodes() == 0 {
            mbset::canon_put(key, Frag::empty());
            return Ok(NONE);
        }
        let r = self.emit_frag(&frag)?;
        mbset::canon_put(key, frag);
        Ok(r)
    }

    /// The tree of the multibyte characters of a charset with rows (not GB18030, which has four-byte codes) whose value is in
    /// `ranges` (all of them for `None`), from the cache under `key` or made from the rows (FIXLIST #148); `None` when the
    /// charset has no rows.
    fn rows_tree(&mut self, key: &[u8], ranges: Option<&[(u32, u32)]>) -> Result<Option<u32>, i32> {
        if let Some(r) = mbset::canon_with(key, |f| self.emit_frag(f)) {
            return r.map(Some);
        }
        match if mbset::other_runs().is_empty() { mbset::rows_canon(ranges) } else { mbset::rows_gb_canon(ranges) } {
            Some(canon) => self.canon_put_tree(key, canon).map(Some),
            None => Ok(None),
        }
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
        let frag = Frag::from_canon(&canon);
        drop(canon);
        self.emit_frag(&frag)
    }

    /// The tree of an automaton (`NONE` for the empty set): one `Mb` node that holds it, or, when a byte may have two
    /// successors in it, the tree of alternatives (`emit_tree`).
    fn emit_frag(&mut self, f: &Frag) -> Res {
        if f.oom {
            return Err(REG_ESPACE);
        }
        match f.nodes() {
            0 => Ok(NONE),
            // one node: a set of single bytes (the same tree as before)
            1 if f.det => self.emit_tree(f, 0),
            _ if f.det => {
                let copy = f.duplicate();
                if copy.oom {
                    return Err(REG_ESPACE);
                }
                let id = self.mk_raw(NK::Mb, NONE, NONE)?;
                self.nodes[id as usize].idx = self.frags.len() as u32;
                self.frags.push(copy);
                if self.frags.oom {
                    return Err(REG_ESPACE);
                }
                Ok(id)
            }
            _ => self.emit_tree(f, 0),
        }
    }

    /// The tree of node `d` of an automaton: per group, its set of bytes followed by the tree of its target, joined by
    /// alternation (a state reached by several paths is copied for each of them).
    fn emit_tree(&mut self, f: &Frag, d: u32) -> Res {
        let mut groups: V<(Set, u32)> = V::new();
        groups.extend_from_slice(f.groups(d));
        if groups.oom {
            return Err(REG_ESPACE);
        }
        let mut alt = NONE;
        for &(set, child) in groups.iter() {
            let mut t = self.mk_set(set)?;
            if child != mbset::EXIT {
                let sub = self.emit_tree(f, child)?;
                t = self.mk_raw(NK::Concat, t, sub)?;
            }
            alt = if alt == NONE { t } else { self.mk_raw(NK::Alt, alt, t)? };
        }
        Ok(alt)
    }

    /// `.`: one character. In a multibyte locale a single byte (minus the newline and NUL the syntax excludes), or
    /// a multibyte character.
    fn mk_period(&mut self, tok: &Tok) -> Res {
        if self.mb == Mb::None {
            return self.mk_tok(tok);
        }
        // (for UTF-8 glibc's own map of the single bytes: 0..0x7f)
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
        let icase = self.icase;
        key.push(u8::from(icase));
        key.extend_from_slice(&(rusty_libc_core::locale::current_key(rusty_libc_core::locale::LC_CTYPE)).to_ne_bytes());
        let mut build = |seqs: &mut V<Seq>| {
            if mb == Mb::Utf8 {
                // what glibc's OP_UTF8_PERIOD accepts: lead byte, then continuation bytes, with its overlong checks
                let c = (0x80u8, 0xbfu8);
                let z = (0, 0);
                seqs.push(Seq { r: [(0xc2, 0xdf), c, z, z, z, z], n: 2 });
                seqs.push(Seq { r: [(0xe0, 0xe0), (0xa0, 0xbf), c, z, z, z], n: 3 });
                if icase {
                    // REG_ICASE: glibc reads the text through mbrtowc, which refuses the surrogates (ED A0..BF xx)
                    seqs.push(Seq { r: [(0xe1, 0xec), c, c, z, z, z], n: 3 });
                    seqs.push(Seq { r: [(0xed, 0xed), (0x80, 0x9f), c, z, z, z], n: 3 });
                    seqs.push(Seq { r: [(0xee, 0xef), c, c, z, z, z], n: 3 });
                } else {
                    seqs.push(Seq { r: [(0xe1, 0xef), c, c, z, z, z], n: 3 });
                }
                seqs.push(Seq { r: [(0xf0, 0xf0), (0x90, 0xbf), c, c, z, z], n: 4 });
                seqs.push(Seq { r: [(0xf1, 0xf7), c, c, c, z, z], n: 4 });
                seqs.push(Seq { r: [(0xf8, 0xf8), (0x88, 0xbf), c, c, c, z], n: 5 });
                seqs.push(Seq { r: [(0xf9, 0xfb), c, c, c, c, z], n: 5 });
                seqs.push(Seq { r: [(0xfc, 0xfc), (0x84, 0xbf), c, c, c, c], n: 6 });
                seqs.push(Seq { r: [(0xfd, 0xfd), c, c, c, c, c], n: 6 });
            } else {
                // (GB18030's runs of four-byte codes whole, not character by character)
                // (from the charset's rows when it has them: no question per character)
                if !mbset::rows_seqs(None, seqs) {
                    mbset::collect_listed(mb, false, 0x10ffff, &mut |_, _| true, seqs);
                }
                let mut all: mbset::Ranges = V::new();
                all.push((0, u32::MAX));
                mbset::runs_in(mbset::other_runs(), &all, seqs);
            }
        };
        let s = self.mk_set(sb)?;
        let rows = if mb == Mb::Other { self.rows_tree(&key, None)? } else { None };
        let m = match rows {
            Some(r) => r,
            None => self.cached_tree(&key, &mut build)?,
        };
        if m == NONE {
            return Ok(s);
        }
        self.mk_raw(NK::Alt, s, m)
    }

    /// Does the multibyte character `wc` match the complex part of a bracket expression (glibc's
    /// `check_node_accept_bytes` for COMPLEX_BRACKET)?
    fn complex_member(acc: &Acc, coll: &charset::Collation, wc: u32) -> bool {
        let mut hit = acc.mbchars.contains(&wc) || acc.classes.iter().any(|&c| charset::in_class_wc(c as usize, wc));
        if !hit {
            if coll.nrules() != 0 {
                if !acc.ranges.is_empty() {
                    let seq = coll.seq_wc(wc);
                    hit = acc.ranges.iter().any(|&(s, e)| s <= seq && seq <= e);
                }
                if !hit
                    && !acc.equivs.is_empty()
                    && let Some((rule, w, _)) = rusty_libc_locale::primary_wide(through_nul(&[wc, 0u32]))
                {
                    hit = acc.equivs.iter().any(|&(r2, w2)| r2 == rule && w2 == w);
                }
            } else {
                hit = acc.ranges.iter().any(|&(s, e)| s <= wc && wc <= e);
            }
        }
        hit != acc.non_match
    }

    /// The tree of the collating elements of several characters that the bracket accepts as a unit (`NONE` if there are
    /// none). The sequences are not prefix free (Hungarian "dz" and "dzs"): a trie cannot hold both, so they go into
    /// groups in which none is a prefix of another, one tree per group, as alternatives.
    fn units_tree(&mut self, acc: &Acc) -> Res {
        // (`contraction_seqs` finds none otherwise)
        if !self.is_complex_bracket(acc) || charset::Collation::current().nrules() == 0 {
            return Ok(NONE);
        }
        // the units depend on the bracket, case ignoring, the charset and the collation (the key of the bracket's set plus its
        // collating symbols and multi-character equivalence classes); they are kept for later patterns
        let mut key = self.bracket_key(acc, true);
        key[0] += 2;
        for c in acc.colls.iter() {
            key.push(c.n);
            for &(lo, hi) in c.r.iter() {
                key.push(lo);
                key.push(hi);
            }
        }
        key.push(0xff);
        for &(r, w) in acc.equivs_mb.iter() {
            key.push(r);
            key.extend_from_slice(&(w.len() as u32).to_ne_bytes());
            key.extend_from_slice(w);
        }
        if key.oom {
            return Err(REG_ESPACE);
        }
        if let Some(r) = mbset::units_with(&key, |units| self.emit_units(units)) {
            return r;
        }
        let units = self.units_build(acc)?;
        let r = self.emit_units(&units);
        mbset::units_put(&key, units);
        r
    }

    /// The tree of the units: the groups, then each element that needs its `Guard` nodes, as alternatives.
    fn emit_units(&mut self, units: &[mbset::Unit]) -> Res {
        let mut result = NONE;
        for u in units {
            let mut t = self.emit_frag(&u.frag)?;
            if t == NONE {
                continue;
            }
            for (r, rl) in u.rests.iter() {
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

    /// The units of `units_tree`, made from the collation tables.
    fn units_build(&mut self, acc: &Acc) -> Result<V<mbset::Unit>, i32> {
        let mut out: V<mbset::Unit> = V::new();
        let mut all: V<Seq> = V::new();
        self.contraction_seqs(acc, &mut all);
        if all.oom {
            return Err(REG_ESPACE);
        }
        // glibc sees only the longest collating element that starts at a position (Hungarian "dzs" is one element, not
        // "dz" and "s"): a unit that is the start of a longer element of the locale is accepted only where the text does
        // not go on like that element. Such a unit gets a `Guard` node per longer element after it (the matcher then
        // takes the exact path, as for back-references); the other units form the prefix free groups below.
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
        // the elements sorted by their bytes: those that start with a unit's bytes are one run of it, found by binary search
        // instead of a scan of every element for every unit. An element is packed as its bytes left-aligned in the top 48
        // bits (zero after its end) and its length in the low byte: the order of these numbers is the order of the byte
        // strings (a string before the longer ones it starts), so the run is a range of the numbers.
        let pack = |b: &[u8]| -> u64 {
            let mut k = b.len() as u64;
            for (i, &x) in b.iter().enumerate() {
                k |= u64::from(x) << (56 - 8 * i);
            }
            k
        };
        let mut by_bytes: V<(u64, u32)> = V::new();
        if !all.is_empty() {
            by_bytes.reserve(elems.len());
            for (i, (b, l)) in elems.iter().enumerate() {
                by_bytes.push((pack(&b[..*l as usize]), i as u32));
            }
            by_bytes.sort_unstable();
        }
        let mut hits: V<u32> = V::new();
        for u in all.iter() {
            let n = u.n as usize;
            let mut rests: V<Rest> = V::new();
            if n < 6 {
                let mut key = [0u8; 6];
                for (i, k) in key.iter_mut().enumerate().take(n) {
                    *k = fold(u.r[i].0);
                }
                let kp = pack(&key[..n]);
                // (the bits of the first n bytes)
                let top = if n == 0 { 0 } else { !0u64 << (64 - 8 * n) };
                let lo = by_bytes.partition_point(|&(e, _)| e < kp);
                let hi = lo + by_bytes[lo..].partition_point(|&(e, _)| e & top == kp & top);
                hits.clear();
                for &(e, i) in by_bytes[lo..hi].iter() {
                    if (e & 0xff) as usize > n {
                        hits.push(i);
                    }
                }
                // (in the order of the elements, as the scan found them)
                hits.sort_unstable();
                for &i in hits.iter() {
                    let (e, el) = &elems[i as usize];
                    let el = *el as usize;
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
        if units.oom || guarded.oom || elems.oom || by_bytes.oom || hits.oom {
            return Err(REG_ESPACE);
        }
        let n = units.len();
        let mut done: V<bool> = V::from_elem(false, n);
        let mut left = n;
        // each pass builds a group from the sequences left that are not a prefix of, nor have as a prefix, one already in it
        // (the group's sequences by their prefixes: "is one a prefix of this one, or this one a prefix of one" in a few lookups)
        let mut in_group = mbset::PrefixSet::new();
        // when no unit is a prefix of another (nor equal to one) the first pass takes them all: in byte order, a prefix
        // relation between any two shows between neighbours (a prefix of c and b between them is a prefix of b too)
        if n > 0 {
            let mut sorted: V<Seq> = V::new();
            sorted.extend_from_slice(&units);
            mbset::sort_seqs(&mut sorted);
            let starts = |a: &Seq, b: &Seq| a.n <= b.n && a.r[..a.n as usize] == b.r[..a.n as usize];
            let clash = sorted.windows(2).any(|w| starts(&w[0], &w[1]));
            if sorted.oom {
                return Err(REG_ESPACE);
            }
            if !clash {
                out.push(mbset::Unit { frag: frag_of(&sorted, false)?, rests: V::new() });
                left = 0;
            }
        }
        while left > 0 {
            let mut group: V<Seq> = V::new();
            in_group.clear();
            for i in 0..n {
                if done[i] {
                    continue;
                }
                let a = units[i];
                if !in_group.clashes(&a) {
                    group.push(a);
                    in_group.add(&a);
                    done[i] = true;
                    left -= 1;
                }
            }
            if group.oom || done.oom || in_group.oom {
                return Err(REG_ESPACE);
            }
            out.push(mbset::Unit { frag: frag_of(&group, true)?, rests: V::new() });
        }
        for (u, rests) in guarded.iter() {
            let mut one: V<Seq> = V::new();
            one.push(*u);
            out.push(mbset::Unit { frag: frag_of(&one, false)?, rests: rests.duplicate() });
        }
        if out.oom {
            return Err(REG_ESPACE);
        }
        Ok(out)
    }

    /// `m` (a tree, or `NONE`) or the collating elements the bracket accepts as a unit.
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

    /// glibc's matcher treats a bracket expression with multibyte characters, collating symbols, equivalence classes or
    /// ranges (and, in a multibyte locale, one with character classes or a negation) as a COMPLEX_BRACKET node: besides the
    /// single characters it asks at every position which collating element of the locale starts there.
    fn is_complex_bracket(&self, acc: &Acc) -> bool {
        !acc.mbchars.is_empty()
            || !acc.colls.is_empty()
            || !acc.equivs.is_empty()
            || !acc.equivs_mb.is_empty()
            || !acc.ranges.is_empty()
            || (self.mb != Mb::None && (!acc.classes.is_empty() || acc.non_match))
    }

    /// glibc, single-byte locale, case ignored: collating elements of 4 or more characters are not seen by the longest-element
    /// rule, and a collating symbol of that many characters matches nothing (Hungarian "ddzs": `[[.ddzs.]]` matches nothing,
    /// `[[.ddz.]]` matches the start of "ddzs", `[c-h]` still takes "ddzs" whole; found by tests/c/regex_coll_diff.c).
    fn element_unseen(&self, elem: &[u8]) -> bool {
        self.icase && self.mb == Mb::None && elem.len() >= 4
    }

    fn symbol_unseen(&self, elem: &[u8]) -> bool {
        self.element_unseen(elem)
    }

    /// The collating elements of several characters (a contraction, Czech "ch") that the bracket accepts as ONE unit, as
    /// byte sequences. glibc's `check_node_accept_bytes` looks at the element that starts at the position: a class or a
    /// listed character matching its first character accepts that character only (the ordinary single-character path
    /// already does); otherwise the element is accepted whole when it is a named collating symbol of the bracket, lies in
    /// one of its ranges (by the element's collation sequence value) or is in one of its equivalence classes; a negated
    /// bracket accepts the whole element when none of these holds. (The element is the longest the tables find at the
    /// position: with contractions of different lengths starting alike, such as Hungarian "dz" and "dzs", the shorter one
    /// is accepted here even where the longer one is what glibc sees.)
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
            // with case ignored glibc compares the text in upper case: only upper case elements can occur
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
                rusty_libc_locale::primary_bytes(until_nul(&buf))
                    .is_some_and(|(r, w, used)| used == elem.len() && acc.equivs_mb.iter().any(|&(r2, w2)| r2 == r && w2 == w))
            };
            let hit = coll_hit || range_hit || equiv_hit;
            let accepted = if acc.non_match { !(first_hit || hit) } else { !first_hit && hit };
            if accepted {
                self.push_element(&chars[..n], elem, out);
            }
        });
    }

    /// The sequence of a collating element; with case ignored every combination of the characters and their lower case
    /// forms (the text is read in upper case, so "cH" is the element "CH").
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

    /// The tree for the finished bracket expression (or `\w`-like class): `acc.sb` is the single-byte set before
    /// the optional negation.
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
        // (a collating element of several characters is a sequence of its own: it needs no scan)
        let has_complex = !acc.mbchars.is_empty() || !acc.equivs.is_empty() || !acc.ranges.is_empty() || !acc.classes.is_empty() || acc.non_match;
        let coll = charset::Collation::current();
        if self.mb == Mb::Utf8 && !FORCE_SCAN.load(core::sync::atomic::Ordering::Relaxed) {
            return self.finish_utf8(acc, always_alt, has_complex, &coll);
        }
        let key = self.bracket_key(&acc, has_complex);
        let (mb, icase, sbc) = (self.mb, self.icase, self.sbc);
        let sb = acc.sb;
        // GB18030's runs of four-byte codes (1,100,000 characters) are not asked one by one: `runs_set_seqs` takes them
        // from the set as ranges of characters, and `build` then sees only the listed characters (`listed`)
        let build = |seqs: &mut V<Seq>, listed: bool| {
            let collect = if listed { mbset::collect_listed } else { mbset::collect };
            if icase && mb != Mb::Utf8 {
                // the text is compared in upper case: a character is in the set when its upper case form is
                let collect_folded = if listed { mbset::collect_folded_listed } else { mbset::collect_folded };
                collect_folded(
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
                // the text is compared in upper case: a character is in the set when its upper case form is
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
                collect(mb, true, if has_complex { 0x10ffff } else { 0x3000 }, &mut pred, seqs);
            } else if has_complex {
                let mut pred = |c: u32, n: usize| -> bool { n > 1 && Self::complex_member(&acc, &coll, c) };
                collect(mb, false, 0x10ffff, &mut pred, seqs);
            }
        };
        let sb_any = acc.sb.iter().any(|&w| w != 0);
        let m = match mbset::canon_with(&key, |f| self.emit_frag(f)) {
            Some(r) => r?,
            None => {
                let mut seqs: V<Seq> = V::new();
                // a set without case ignoring: its characters as ranges of values (as for UTF-8), taken from the charset's
                // rows (the same sequences the scan below finds: FIXLIST #148)
                let by_rows = if mb == Mb::Other && !icase && has_complex {
                    let m = self.set_ranges(&acc, true, &coll)?;
                    let canon = if mbset::other_runs().is_empty() { mbset::rows_canon(Some(&m)) } else { mbset::rows_gb_canon(Some(&m)) };
                    if let Some(canon) = canon {
                        Some(self.canon_put_tree(&key, canon)?)
                    } else if self.rows_bracket_seqs(&m, &mut seqs)? {
                        Some(self.tree_put(&key, &seqs)?)
                    } else {
                        None
                    }
                } else {
                    None
                };
                if let Some(t) = by_rows {
                    t
                } else {
                    seqs.clear();
                    // (the list of the charset is made only for a set that looks at it: `build` does nothing otherwise)
                    let runs: &[mbset::Run] = if mb == Mb::Other && (icase || has_complex) { mbset::other_runs() } else { &[] };
                    build(&mut seqs, !runs.is_empty());
                    if !runs.is_empty() {
                        self.runs_set_seqs(&acc, has_complex, &coll, runs, &mut seqs)?;
                    }
                    self.tree_put(&key, &seqs)?
                }
            }
        };
        let m = self.add_units(m, &acc)?;
        if self.icase {
            // the single bytes are inside `seqs` already
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

    /// The bracket set of a UTF-8 locale as ranges of code points, built from the tables by blocks (no question per
    /// character), then written as byte sequences.
    fn finish_utf8(&mut self, acc: Acc, always_alt: bool, has_complex: bool, coll: &charset::Collation) -> Res {
        // a set of listed characters and code-point ranges only (no classes, equivalence classes, collation order, negation or
        // case ignoring) costs less to build than to look up
        let cheap = acc.classes.is_empty() && acc.equivs.is_empty() && !acc.non_match && (coll.nrules() == 0 || acc.ranges.is_empty()) && !self.icase;
        if cheap {
            let r = self.utf8_set_ranges(&acc, has_complex, coll)?;
            let f = utf8_frag(&r)?;
            let t = self.emit_frag(&f)?;
            return self.finish_utf8_tree(t, acc, always_alt);
        }
        // otherwise the set is kept as its description and matched against the tables (`u8set`), when its characters have
        // two lengths or more (its automaton then has a state with two groups, so has_plural holds as before)
        let runs = match self.u8_node(&acc, has_complex, coll)? {
            Ok(t) => return self.finish_utf8_tree(t, acc, always_alt),
            Err(runs) => runs,
        };
        // else the tree of the set's sequences comes from the cache of canonical forms when the same set was compiled
        // before in the same locale (the key holds the set, case ignoring, the charset and the identities of LC_CTYPE and
        // LC_COLLATE)
        let mut key = self.bracket_key(&acc, has_complex);
        // (the scan of every character, FORCE_SCAN, keeps its own entries: a test compares the two; so does NO_U8)
        key.push(if NO_U8.load(core::sync::atomic::Ordering::Relaxed) { b'U' } else { b'u' });
        if key.oom {
            return Err(REG_ESPACE);
        }
        let t = match mbset::canon_with(&key, |f| self.emit_frag(f)) {
            Some(r) => r?,
            None => {
                // (the runs `u8_node` read already are this set)
                let r = match runs {
                    Some(r) => r,
                    None => self.utf8_set_ranges(&acc, has_complex, coll)?,
                };
                let f = utf8_frag(&r)?;
                let t = self.emit_frag(&f)?;
                mbset::canon_put(&key, f);
                t
            }
        };
        self.finish_utf8_tree(t, acc, always_alt)
    }

    /// The `U8` node of a bracket set (UTF-8, not one of the cheap sets), or `Err` when its automaton is to be built (the
    /// characters of the set have one length only, or the case table could not be kept), with the set's runs when they
    /// were read whole (`U8Spec::compute_root`).
    #[allow(clippy::type_complexity)]
    fn u8_node(&mut self, acc: &Acc, has_complex: bool, coll: &charset::Collation) -> Result<Result<u32, Option<mbset::Ranges>>, i32> {
        if NO_U8.load(core::sync::atomic::Ordering::Relaxed) {
            return Ok(Err(None));
        }
        let cased = if self.icase {
            match mbset::cased_cached() {
                Some(c) => Some(c),
                None => return Ok(Err(None)),
            }
        } else {
            None
        };
        let mut spec = crate::u8set::U8Spec {
            sb: acc.sb,
            mbchars: acc.mbchars.duplicate(),
            classes: acc.classes.duplicate(),
            ranges: acc.ranges.duplicate(),
            equivs: acc.equivs.duplicate(),
            non_match: acc.non_match,
            has_complex,
            icase: self.icase,
            coll: *coll,
            ctype: rusty_libc_core::locale::current(rusty_libc_core::locale::LC_CTYPE),
            cs: rusty_libc_wchar::charset(),
            collate: rusty_libc_core::locale::current(rusty_libc_core::locale::LC_COLLATE),
            cased,
            root: [0; 4],
            memo: [const { core::sync::atomic::AtomicU64::new(0) }; crate::u8set::MEMO_WORDS],
            blocks: [const { core::sync::atomic::AtomicU64::new(0) }; 2 * crate::u8set::BLOCK_SLOTS],
        };
        if spec.mbchars.oom || spec.classes.oom || spec.ranges.oom || spec.equivs.oom {
            return Err(REG_ESPACE);
        }
        // (the first bytes cost about fifty questions to the tables: kept for later patterns under the set's key)
        let mut key = self.bracket_key(acc, has_complex);
        key.push(b'r');
        if key.oom {
            return Err(REG_ESPACE);
        }
        let mut runs = None;
        match mbset::root_get(&key) {
            Some(r) => spec.root = r,
            None => {
                runs = spec.compute_root();
                mbset::root_put(&key, spec.root);
            }
        }
        if spec.lengths() < 2 {
            if runs.as_ref().is_some_and(|r| r.oom) {
                return Err(REG_ESPACE);
            }
            return Ok(Err(runs));
        }
        let id = self.mk_raw(NK::U8, NONE, NONE)?;
        self.nodes[id as usize].idx = self.u8specs.len() as u32;
        self.u8specs.push(spec);
        if self.u8specs.oom {
            return Err(REG_ESPACE);
        }
        Ok(Ok(id))
    }

    /// The rest of `finish_utf8` once the tree `t` of the set's sequences is made: the collating elements of several
    /// characters and the single bytes.
    fn finish_utf8_tree(&mut self, t: u32, acc: Acc, always_alt: bool) -> Res {
        let non_match = acc.non_match;
        let t = self.finish_utf8_set(t, acc, always_alt)?;
        if non_match { self.add_high_forms(t) } else { Ok(t) }
    }

    /// A negated bracket also takes the characters glibc's `mbrtowc` reads above U+10FFFF (the four to six byte forms up to
    /// U+7FFFFFFF, not overlong): none of them is in any class or range, so they are outside every set that is not negated
    /// (FIXLIST #143). The tables of the sets stop at U+10FFFF; these forms are a tree of their own.
    fn add_high_forms(&mut self, t: u32) -> Res {
        let mut key: V<u8> = V::new();
        key.extend_from_slice(b"u8high");
        if key.oom {
            return Err(REG_ESPACE);
        }
        let mut build = |seqs: &mut V<Seq>| {
            let c = (0x80u8, 0xbfu8);
            let z = (0, 0);
            seqs.push(Seq { r: [(0xf4, 0xf4), (0x90, 0xbf), c, c, z, z], n: 4 });
            seqs.push(Seq { r: [(0xf5, 0xf7), c, c, c, z, z], n: 4 });
            seqs.push(Seq { r: [(0xf8, 0xf8), (0x88, 0xbf), c, c, c, z], n: 5 });
            seqs.push(Seq { r: [(0xf9, 0xfb), c, c, c, c, z], n: 5 });
            seqs.push(Seq { r: [(0xfc, 0xfc), (0x84, 0xbf), c, c, c, c], n: 6 });
            seqs.push(Seq { r: [(0xfd, 0xfd), c, c, c, c, c], n: 6 });
        };
        let h = self.cached_tree(&key, &mut build)?;
        if t == NONE || h == NONE {
            return Ok(if t == NONE { h } else { t });
        }
        self.mk_raw(NK::Alt, t, h)
    }

    fn finish_utf8_set(&mut self, t: u32, acc: Acc, always_alt: bool) -> Res {
        let sb_any = acc.sb.iter().any(|&w| w != 0);
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

    /// The characters of a bracket set (UTF-8) beyond its single bytes (with case ignored, all of them), as ranges.
    fn utf8_set_ranges(&mut self, acc: &Acc, has_complex: bool, coll: &charset::Collation) -> Result<mbset::Ranges, i32> {
        let m = self.set_ranges(acc, has_complex, coll)?;
        if self.icase {
            // S, the set of upper case forms: the ASCII bytes of the set and `m`
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
            let res = self.upper_preimage(&s_set);
            if h_oom(&s_set) || h_oom(&res) {
                return Err(REG_ESPACE);
            }
            Ok(res)
        } else {
            Ok(m)
        }
    }

    /// The characters from 0x80 up that a bracket set holds, as ranges, read from the tables by blocks (no question per
    /// character): what `complex_member` answers for each of them (case not ignored).
    fn set_ranges(&mut self, acc: &Acc, has_complex: bool, coll: &charset::Collation) -> Result<mbset::Ranges, i32> {
        // the class numbers of `CLASS_NAMES` as bit numbers of rusty-libc-wchar's classes
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
                // no collation rules: a range is by character value
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
        Ok(m)
    }

    /// The characters whose upper case form is in `s_set` (normalized ranges): `s_set` without the characters the mapping
    /// changes, plus the changed characters whose upper case form is in it (the text is compared in upper case).
    fn upper_preimage(&mut self, s_set: &mbset::Ranges) -> mbset::Ranges {
        let mut res: mbset::Ranges = V::new();
        let (pairs, kept) = self.cased();
        res.extend_from_slice(&mbset::clip(s_set, kept));
        for &(t, u) in pairs {
            if mbset::contains(s_set, u) {
                res.push((t, t));
            }
        }
        mbset::normalize(&mut res);
        res
    }

    /// The sequences of the multibyte characters of a bracket set (case not ignored, a complex part) of a charset with rows:
    /// the set as ranges of values (`set_ranges`), then the rows' characters with a value in them, and GB18030's four-byte
    /// codes as ranges. False (nothing added) when the charset has no rows.
    fn rows_bracket_seqs(&mut self, m: &mbset::Ranges, seqs: &mut V<Seq>) -> Result<bool, i32> {
        if !mbset::rows_seqs(Some(m), seqs) {
            return Ok(false);
        }
        mbset::runs_in(mbset::other_runs(), m, seqs);
        if seqs.oom {
            return Err(REG_ESPACE);
        }
        Ok(true)
    }

    /// The sequences of GB18030's four-byte codes (`runs`) of a bracket set, from the set as ranges of characters (as for
    /// UTF-8) instead of a question per character: what the scan of `finish_bracket` accepts of them.
    fn runs_set_seqs(&mut self, acc: &Acc, has_complex: bool, coll: &charset::Collation, runs: &[mbset::Run], seqs: &mut V<Seq>) -> Result<(), i32> {
        // (every four-byte character is from 0x80 up and has no form of one byte)
        let m = self.set_ranges(acc, has_complex, coll)?;
        let res = if self.icase {
            // the scan's question for a character with upper case form x: the set's single byte when x is one, else
            // `complex_member`
            let mut s_set: mbset::Ranges = V::new();
            let mut b = [0u8; 6];
            for x in 0..0x80u32 {
                let hit = match charset::encode(self.mb, x, &mut b) {
                    Some(1) if set_has(&self.sbc, b[0]) => set_has(&acc.sb, b[0]),
                    _ => has_complex && Self::complex_member(acc, coll, x),
                };
                if hit {
                    s_set.push((x, x));
                }
            }
            for &r in m.iter() {
                s_set.push(r);
            }
            mbset::normalize(&mut s_set);
            if h_oom(&s_set) {
                return Err(REG_ESPACE);
            }
            self.upper_preimage(&s_set)
        } else if has_complex {
            m
        } else {
            V::new()
        };
        if h_oom(&res) {
            return Err(REG_ESPACE);
        }
        mbset::runs_in(runs, &res, seqs);
        if seqs.oom {
            return Err(REG_ESPACE);
        }
        Ok(())
    }

    /// A byte string that describes a bracket set and the locale it is read in (the key of the scan cache).
    fn bracket_key(&self, acc: &Acc, has_complex: bool) -> V<u8> {
        let mut k: V<u8> = V::new();
        k.push(self.icase as u8);
        k.push(self.mb as u8);
        k.push(acc.non_match as u8);
        k.push(has_complex as u8);
        let loc = rusty_libc_core::locale::current_key;
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
        // The first ']' is a normal character.
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
                        // The last '-' is a normal character.
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

    /// An element that is one character: a single-byte element when the character is one byte that is a complete
    /// character, else a multibyte one (REG_ICASE: the upper case form, as glibc parses the upper-cased pattern).
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
        // REG_ICASE in a multibyte locale: glibc reads names from the upper-cased pattern
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

    /// The collation sequence value glibc's `lookup_collation_sequence_value` gives an element (`NO_SEQ`: none).
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
        if coll.is_byte_identity() {
            // sequence value = byte value: the bytes of sv..=ev
            for ch in sv..=ev.min(255) {
                set_bit(&mut acc.sb, ch as u8);
            }
        } else {
            for ch in 0..=255u32 {
                let c = coll.seq_of_byte(ch as u8);
                if sv <= c && c <= ev {
                    set_bit(&mut acc.sb, ch as u8);
                }
            }
        }
        Ok(())
    }

    /// `[=name=]`: glibc's `build_equiv_class`.
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
        let Some((rule, w1, used)) = rusty_libc_locale::primary_bytes(until_nul(&buf)) else { return Err(REG_ECOLLATE) };
        if used != name.len() {
            return Err(REG_ECOLLATE);
        }
        for ch in 0..=255u32 {
            let b = [ch as u8];
            if let Some((r2, w2, _)) = rusty_libc_locale::primary_bytes(until_nul(&b))
                && r2 == rule
                && w2 == w1
            {
                set_bit(&mut acc.sb, ch as u8);
            }
        }
        // (the weights are also kept for the collating elements of several characters, see `contraction_seqs`)
        acc.equivs_mb.push((rule, w1));
        if self.mb != Mb::None {
            // the multibyte characters of the class: compared through the wide table
            let mut wide = [0u32; 34];
            let (mut i, mut n) = (0usize, 0usize);
            while i < name.len() {
                let (wc, l) = charset::decode(self.mb, &name[i..]).unwrap_or((name[i] as u32, 1));
                wide[n] = wc;
                n += 1;
                i += l;
            }
            if let Some((r, w, _)) = rusty_libc_locale::primary_wide(through_nul(&wide)) {
                acc.equivs.push((r, w));
            }
        }
        Ok(())
    }

    /// `[.name.]`: glibc's `build_collating_symbol`.
    fn build_collating_symbol(&self, acc: &mut Acc, name: &[u8]) -> Result<(), i32> {
        let coll = charset::Collation::current();
        // glibc reads the pattern through its translation table: when case is ignored the name is in upper case (in a
        // single-byte locale `parse` has translated the pattern already)
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
                // the element's bytes: several characters are a sequence to match; one multibyte character joins the set
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
        // The syntax does not matter here (glibc passes 0).
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

/// Test hook: build the sets of a UTF-8 locale by asking every character (the slow, plain way) instead of walking the
/// tables; the tests compare the two.
pub static FORCE_SCAN: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Test hook: build the automaton of every UTF-8 bracket set (no `U8` nodes); the tests compare the two.
pub static NO_U8: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// What a bracket expression collects: glibc's `sbcset` and `re_charset_t`.
struct Acc {
    sb: Set,
    mbchars: V<u32>,
    classes: V<u8>,
    ranges: V<(u32, u32)>,
    equivs: V<(u8, &'static [u32])>,
    /// the weights of the equivalence classes as the byte tables give them (a collating element of several characters is
    /// compared with these)
    equivs_mb: V<(u8, &'static [u8])>,
    /// the collating elements of several characters named by `[.xy.]` (in upper case when the match ignores case)
    colls: V<Seq>,
    non_match: bool,
}

impl Acc {
    fn new() -> Acc {
        Acc { sb: [0; 4], mbchars: V::new(), classes: V::new(), ranges: V::new(), equivs: V::new(), equivs_mb: V::new(), colls: V::new(), non_match: false }
    }
}

/// Parses `pattern` under `syntax`; `trans` is the optional translation table of the pattern
/// buffer. The result is glibc's parse tree: CONCAT(tree, END), or END alone for an empty pattern.
pub fn parse(pattern: &[u8], syntax: u64, trans: Option<&[u8; 256]>) -> Result<Parsed, i32> {
    let icase = syntax & RE_ICASE != 0;
    let mb = charset::mb_kind();
    let mut up: V<u8> = V::new();
    // in a multibyte locale the case is handled per character (see `mk_character`, `finish_bracket`): the pattern
    // text stays as it is
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
        frags: V::new(),
        u8specs: V::new(),
    };
    let mut tok = p.fetch_token(syntax | RE_CARET_ANCHORS_HERE);
    let tree = p.parse_reg_exp(&mut tok, 0)?;
    let eor = p.mk_raw(NK::End, NONE, NONE)?;
    let root = if tree != NONE { p.mk_raw(NK::Concat, tree, eor)? } else { eor };
    Ok(Parsed { nodes: p.nodes, root, sets: p.sets, nsub: p.nsub, nbackref: p.nbackref, guards: p.guards, mb, frags: p.frags, u8specs: p.u8specs })
}

/// The automaton of the UTF-8 sequences of the characters in the normalized `r`.
fn utf8_frag(r: &mbset::Ranges) -> Result<Frag, i32> {
    let canon = mbset::utf8_canon(r);
    if canon.oom {
        return Err(REG_ESPACE);
    }
    let f = Frag::from_canon(&canon);
    if f.oom {
        return Err(REG_ESPACE);
    }
    Ok(f)
}

/// The automaton of the sequences `seqs` (inserted in order when `sort`: the trie is then built without scans).
fn frag_of(seqs: &V<Seq>, sort: bool) -> Result<Frag, i32> {
    if seqs.oom {
        return Err(REG_ESPACE);
    }
    let mut trie = Trie::new();
    if sort {
        let mut v: V<Seq> = V::new();
        v.extend_from_slice(seqs);
        if v.oom {
            return Err(REG_ESPACE);
        }
        mbset::sort_seqs(&mut v);
        for s in v.iter() {
            trie.insert(s);
        }
    } else {
        for s in seqs.iter() {
            trie.insert(s);
        }
    }
    if trie.oom() {
        return Err(REG_ESPACE);
    }
    if trie.is_empty() {
        return Ok(Frag::empty());
    }
    let canon = trie.canon();
    if canon.oom {
        return Err(REG_ESPACE);
    }
    let f = Frag::from_canon(&canon);
    if f.oom {
        return Err(REG_ESPACE);
    }
    Ok(f)
}

/// The bytes of `s` before its first NUL (all of `s` if it has none): what the C-string form of the collation lookup saw.
fn until_nul(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |n| &s[..n])
}

/// The wide characters of `s` up to and including its first 0 (all of `s` if it has none).
fn through_nul(s: &[u32]) -> &[u32] {
    s.iter().position(|&c| c == 0).map_or(s, |n| &s[..=n])
}
