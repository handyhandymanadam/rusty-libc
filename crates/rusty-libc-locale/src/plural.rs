#[derive(Clone, Copy)]
enum Node {
    Var,
    Num(u64),
    Not(u8),
    Bin(Op, u8, u8),
    Cond(u8, u8, u8),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Mul,
    Div,
    Mod,
    Add,
    Sub,
    Lt,
    Gt,
    Le,
    Ge,
    Eq,
    Ne,
    And,
    Or,
}

const MAX_NODES: usize = 96;

#[derive(Clone, Copy)]
pub struct Plural {
    nodes: [Node; MAX_NODES],
    root: u8,
    n: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tok {
    End,
    Num(u64),
    Var,
    Mul,
    Div,
    Mod,
    Add,
    Sub,
    Lt,
    Gt,
    Le,
    Ge,
    Eq,
    Ne,
    And,
    Or,
    Not,
    Q,
    Colon,
    LP,
    RP,
    Err,
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    tok: Tok,
    p: Plural,
}

impl<'a> Parser<'a> {
    fn lex(&mut self) {
        let s = self.s;
        while self.i < s.len() && (s[self.i] == b' ' || s[self.i] == b'\t') {
            self.i += 1;
        }
        let Some(&c) = s.get(self.i) else {
            self.tok = Tok::End;
            return;
        };
        self.i += 1;
        let next = s.get(self.i).copied();
        self.tok = match c {
            b'0'..=b'9' => {
                let mut v = u64::from(c - b'0');
                while let Some(&d @ b'0'..=b'9') = s.get(self.i) {
                    v = v.wrapping_mul(10).wrapping_add(u64::from(d - b'0'));
                    self.i += 1;
                }
                Tok::Num(v)
            }
            b'=' => {
                if next == Some(b'=') {
                    self.i += 1;
                    Tok::Eq
                } else {
                    Tok::Err
                }
            }
            b'!' => {
                if next == Some(b'=') {
                    self.i += 1;
                    Tok::Ne
                } else {
                    Tok::Not
                }
            }
            b'&' => {
                if next == Some(b'&') {
                    self.i += 1;
                    Tok::And
                } else {
                    Tok::Err
                }
            }
            b'|' => {
                if next == Some(b'|') {
                    self.i += 1;
                    Tok::Or
                } else {
                    Tok::Err
                }
            }
            b'<' => {
                if next == Some(b'=') {
                    self.i += 1;
                    Tok::Le
                } else {
                    Tok::Lt
                }
            }
            b'>' => {
                if next == Some(b'=') {
                    self.i += 1;
                    Tok::Ge
                } else {
                    Tok::Gt
                }
            }
            b'*' => Tok::Mul,
            b'/' => Tok::Div,
            b'%' => Tok::Mod,
            b'+' => Tok::Add,
            b'-' => Tok::Sub,
            b'n' => Tok::Var,
            b'?' => Tok::Q,
            b':' => Tok::Colon,
            b'(' => Tok::LP,
            b')' => Tok::RP,
            b';' | b'\n' | 0 => {
                self.i -= 1;
                Tok::End
            }
            _ => Tok::Err,
        };
    }

    fn push(&mut self, n: Node) -> Option<u8> {
        if self.p.n >= MAX_NODES {
            return None;
        }
        self.p.nodes[self.p.n] = n;
        self.p.n += 1;
        Some((self.p.n - 1) as u8)
    }

    fn primary(&mut self) -> Option<u8> {
        match self.tok {
            Tok::Num(v) => {
                self.lex();
                self.push(Node::Num(v))
            }
            Tok::Var => {
                self.lex();
                self.push(Node::Var)
            }
            Tok::Not => {
                self.lex();
                let e = self.primary()?;
                self.push(Node::Not(e))
            }
            Tok::LP => {
                self.lex();
                let e = self.cond()?;
                if self.tok != Tok::RP {
                    return None;
                }
                self.lex();
                Some(e)
            }
            _ => None,
        }
    }

    fn binary(&mut self, level: u8) -> Option<u8> {
        if level > 5 {
            return self.primary();
        }
        let mut lhs = self.binary(level + 1)?;
        loop {
            let op = match (level, self.tok) {
                (0, Tok::Or) => Op::Or,
                (1, Tok::And) => Op::And,
                (2, Tok::Eq) => Op::Eq,
                (2, Tok::Ne) => Op::Ne,
                (3, Tok::Lt) => Op::Lt,
                (3, Tok::Gt) => Op::Gt,
                (3, Tok::Le) => Op::Le,
                (3, Tok::Ge) => Op::Ge,
                (4, Tok::Add) => Op::Add,
                (4, Tok::Sub) => Op::Sub,
                (5, Tok::Mul) => Op::Mul,
                (5, Tok::Div) => Op::Div,
                (5, Tok::Mod) => Op::Mod,
                _ => return Some(lhs),
            };
            self.lex();
            let rhs = self.binary(level + 1)?;
            lhs = self.push(Node::Bin(op, lhs, rhs))?;
        }
    }

    fn cond(&mut self) -> Option<u8> {
        let c = self.binary(0)?;
        if self.tok != Tok::Q {
            return Some(c);
        }
        self.lex();
        let t = self.cond()?;
        if self.tok != Tok::Colon {
            return None;
        }
        self.lex();
        let f = self.cond()?;
        self.push(Node::Cond(c, t, f))
    }
}

impl Plural {
    pub fn germanic() -> Plural {
        let mut p = Plural { nodes: [Node::Var; MAX_NODES], root: 2, n: 3 };
        p.nodes[0] = Node::Var;
        p.nodes[1] = Node::Num(1);
        p.nodes[2] = Node::Bin(Op::Ne, 0, 1);
        p
    }

    pub fn parse(text: &[u8]) -> Option<Plural> {
        let mut ps = Parser { s: text, i: 0, tok: Tok::End, p: Plural { nodes: [Node::Var; MAX_NODES], root: 0, n: 0 } };
        ps.lex();
        let root = ps.cond()?;
        if ps.tok != Tok::End {
            return None;
        }
        ps.p.root = root;
        Some(ps.p)
    }

    fn eval_node(&self, i: u8, n: u64) -> u64 {
        match self.nodes[i as usize] {
            Node::Var => n,
            Node::Num(v) => v,
            Node::Not(a) => u64::from(self.eval_node(a, n) == 0),
            Node::Cond(c, t, f) => {
                if self.eval_node(c, n) != 0 {
                    self.eval_node(t, n)
                } else {
                    self.eval_node(f, n)
                }
            }
            Node::Bin(op, a, b) => {
                let l = self.eval_node(a, n);
                match op {
                    Op::Or => return u64::from(l != 0 || self.eval_node(b, n) != 0),
                    Op::And => return u64::from(l != 0 && self.eval_node(b, n) != 0),
                    _ => {}
                }
                let r = self.eval_node(b, n);
                match op {
                    Op::Mul => l.wrapping_mul(r),
                    Op::Div => l.checked_div(r).unwrap_or(0),
                    Op::Mod => l.checked_rem(r).unwrap_or(0),
                    Op::Add => l.wrapping_add(r),
                    Op::Sub => l.wrapping_sub(r),
                    Op::Lt => u64::from(l < r),
                    Op::Gt => u64::from(l > r),
                    Op::Le => u64::from(l <= r),
                    Op::Ge => u64::from(l >= r),
                    Op::Eq => u64::from(l == r),
                    Op::Ne => u64::from(l != r),
                    Op::And | Op::Or => 0,
                }
            }
        }
    }

    pub fn eval(&self, n: u64) -> u64 {
        self.eval_node(self.root, n)
    }
}

pub fn extract(header: &[u8]) -> (Plural, u64) {
    let find = |pat: &[u8]| header.windows(pat.len()).position(|w| w == pat);
    if let (Some(pl), Some(npl)) = (find(b"plural="), find(b"nplurals=")) {
        let mut i = npl + 9;
        while i < header.len() && matches!(header[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
            i += 1;
        }
        if i < header.len() && header[i].is_ascii_digit() {
            let mut n: u64 = 0;
            while i < header.len() && header[i].is_ascii_digit() {
                n = n.wrapping_mul(10).wrapping_add(u64::from(header[i] - b'0'));
                i += 1;
            }
            if let Some(p) = Plural::parse(&header[pl + 7..]) {
                return (p, n);
            }
        }
    }
    (Plural::germanic(), 2)
}
