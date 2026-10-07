pub type RegSyntax = u64;

pub const RE_BACKSLASH_ESCAPE_IN_LISTS: RegSyntax = 1;
pub const RE_BK_PLUS_QM: RegSyntax = RE_BACKSLASH_ESCAPE_IN_LISTS << 1;
pub const RE_CHAR_CLASSES: RegSyntax = RE_BK_PLUS_QM << 1;
pub const RE_CONTEXT_INDEP_ANCHORS: RegSyntax = RE_CHAR_CLASSES << 1;
pub const RE_CONTEXT_INDEP_OPS: RegSyntax = RE_CONTEXT_INDEP_ANCHORS << 1;
pub const RE_CONTEXT_INVALID_OPS: RegSyntax = RE_CONTEXT_INDEP_OPS << 1;
pub const RE_DOT_NEWLINE: RegSyntax = RE_CONTEXT_INVALID_OPS << 1;
pub const RE_DOT_NOT_NULL: RegSyntax = RE_DOT_NEWLINE << 1;
pub const RE_HAT_LISTS_NOT_NEWLINE: RegSyntax = RE_DOT_NOT_NULL << 1;
pub const RE_INTERVALS: RegSyntax = RE_HAT_LISTS_NOT_NEWLINE << 1;
pub const RE_LIMITED_OPS: RegSyntax = RE_INTERVALS << 1;
pub const RE_NEWLINE_ALT: RegSyntax = RE_LIMITED_OPS << 1;
pub const RE_NO_BK_BRACES: RegSyntax = RE_NEWLINE_ALT << 1;
pub const RE_NO_BK_PARENS: RegSyntax = RE_NO_BK_BRACES << 1;
pub const RE_NO_BK_REFS: RegSyntax = RE_NO_BK_PARENS << 1;
pub const RE_NO_BK_VBAR: RegSyntax = RE_NO_BK_REFS << 1;
pub const RE_NO_EMPTY_RANGES: RegSyntax = RE_NO_BK_VBAR << 1;
pub const RE_UNMATCHED_RIGHT_PAREN_ORD: RegSyntax = RE_NO_EMPTY_RANGES << 1;
pub const RE_NO_POSIX_BACKTRACKING: RegSyntax = RE_UNMATCHED_RIGHT_PAREN_ORD << 1;
pub const RE_NO_GNU_OPS: RegSyntax = RE_NO_POSIX_BACKTRACKING << 1;
pub const RE_DEBUG: RegSyntax = RE_NO_GNU_OPS << 1;
pub const RE_INVALID_INTERVAL_ORD: RegSyntax = RE_DEBUG << 1;
pub const RE_ICASE: RegSyntax = RE_INVALID_INTERVAL_ORD << 1;
pub const RE_CARET_ANCHORS_HERE: RegSyntax = RE_ICASE << 1;
pub const RE_CONTEXT_INVALID_DUP: RegSyntax = RE_CARET_ANCHORS_HERE << 1;
pub const RE_NO_SUB: RegSyntax = RE_CONTEXT_INVALID_DUP << 1;

pub const RE_SYNTAX_EMACS: RegSyntax = 0;
const POSIX_COMMON: RegSyntax = RE_CHAR_CLASSES | RE_DOT_NEWLINE | RE_DOT_NOT_NULL | RE_INTERVALS | RE_NO_EMPTY_RANGES;
pub const RE_SYNTAX_POSIX_BASIC: RegSyntax = POSIX_COMMON | RE_BK_PLUS_QM | RE_CONTEXT_INVALID_DUP;
pub const RE_SYNTAX_POSIX_MINIMAL_BASIC: RegSyntax = POSIX_COMMON | RE_LIMITED_OPS;
pub const RE_SYNTAX_POSIX_EXTENDED: RegSyntax = POSIX_COMMON
    | RE_CONTEXT_INDEP_ANCHORS
    | RE_CONTEXT_INDEP_OPS
    | RE_NO_BK_BRACES
    | RE_NO_BK_PARENS
    | RE_NO_BK_VBAR
    | RE_CONTEXT_INVALID_OPS
    | RE_UNMATCHED_RIGHT_PAREN_ORD;
pub const RE_SYNTAX_POSIX_MINIMAL_EXTENDED: RegSyntax = POSIX_COMMON
    | RE_CONTEXT_INDEP_ANCHORS
    | RE_CONTEXT_INVALID_OPS
    | RE_NO_BK_BRACES
    | RE_NO_BK_PARENS
    | RE_NO_BK_REFS
    | RE_NO_BK_VBAR
    | RE_UNMATCHED_RIGHT_PAREN_ORD;
pub const RE_SYNTAX_AWK: RegSyntax = RE_BACKSLASH_ESCAPE_IN_LISTS
    | RE_DOT_NOT_NULL
    | RE_NO_BK_PARENS
    | RE_NO_BK_REFS
    | RE_NO_BK_VBAR
    | RE_NO_EMPTY_RANGES
    | RE_DOT_NEWLINE
    | RE_CONTEXT_INDEP_ANCHORS
    | RE_CHAR_CLASSES
    | RE_UNMATCHED_RIGHT_PAREN_ORD
    | RE_NO_GNU_OPS;
pub const RE_SYNTAX_GNU_AWK: RegSyntax = (RE_SYNTAX_POSIX_EXTENDED | RE_BACKSLASH_ESCAPE_IN_LISTS | RE_INVALID_INTERVAL_ORD)
    & !(RE_DOT_NOT_NULL | RE_CONTEXT_INDEP_OPS | RE_CONTEXT_INVALID_OPS);
pub const RE_SYNTAX_POSIX_AWK: RegSyntax =
    RE_SYNTAX_POSIX_EXTENDED | RE_BACKSLASH_ESCAPE_IN_LISTS | RE_INTERVALS | RE_NO_GNU_OPS | RE_INVALID_INTERVAL_ORD;
pub const RE_SYNTAX_GREP: RegSyntax = (RE_SYNTAX_POSIX_BASIC | RE_NEWLINE_ALT) & !(RE_CONTEXT_INVALID_DUP | RE_DOT_NOT_NULL);
pub const RE_SYNTAX_EGREP: RegSyntax =
    (RE_SYNTAX_POSIX_EXTENDED | RE_INVALID_INTERVAL_ORD | RE_NEWLINE_ALT) & !(RE_CONTEXT_INVALID_OPS | RE_DOT_NOT_NULL);
pub const RE_SYNTAX_POSIX_EGREP: RegSyntax = RE_SYNTAX_EGREP;
pub const RE_SYNTAX_ED: RegSyntax = RE_SYNTAX_POSIX_BASIC;
pub const RE_SYNTAX_SED: RegSyntax = RE_SYNTAX_POSIX_BASIC;

pub const RE_DUP_MAX: i64 = 0x7fff;

pub const REG_EXTENDED: i32 = 1;
pub const REG_ICASE: i32 = 1 << 1;
pub const REG_NEWLINE: i32 = 1 << 2;
pub const REG_NOSUB: i32 = 1 << 3;
pub const REG_NOTBOL: i32 = 1;
pub const REG_NOTEOL: i32 = 1 << 1;
pub const REG_STARTEND: i32 = 1 << 2;

pub const REG_ENOSYS: i32 = -1;
pub const REG_NOERROR: i32 = 0;
pub const REG_NOMATCH: i32 = 1;
pub const REG_BADPAT: i32 = 2;
pub const REG_ECOLLATE: i32 = 3;
pub const REG_ECTYPE: i32 = 4;
pub const REG_EESCAPE: i32 = 5;
pub const REG_ESUBREG: i32 = 6;
pub const REG_EBRACK: i32 = 7;
pub const REG_EPAREN: i32 = 8;
pub const REG_EBRACE: i32 = 9;
pub const REG_BADBR: i32 = 10;
pub const REG_ERANGE: i32 = 11;
pub const REG_ESPACE: i32 = 12;
pub const REG_BADRPT: i32 = 13;
pub const REG_EEND: i32 = 14;
pub const REG_ESIZE: i32 = 15;
pub const REG_ERPAREN: i32 = 16;

pub const REGS_UNALLOCATED: u32 = 0;
pub const REGS_REALLOCATE: u32 = 1;
pub const REGS_FIXED: u32 = 2;
pub const RE_NREGS: usize = 30;

pub static ERROR_MSGS: [&[u8]; 17] = [
    b"Success\0",
    b"No match\0",
    b"Invalid regular expression\0",
    b"Invalid collation character\0",
    b"Invalid character class name\0",
    b"Trailing backslash\0",
    b"Invalid back reference\0",
    b"Unmatched [, [^, [:, [., or [=\0",
    b"Unmatched ( or \\(\0",
    b"Unmatched \\{\0",
    b"Invalid content of \\{\\}\0",
    b"Invalid range end\0",
    b"Memory exhausted\0",
    b"Invalid preceding regular expression\0",
    b"Premature end of regular expression\0",
    b"Regular expression too big\0",
    b"Unmatched ) or \\)\0",
];

pub fn error_message(code: i32) -> Option<&'static [u8]> {
    if code < 0 || code as usize >= ERROR_MSGS.len() {
        return None;
    }
    let m = ERROR_MSGS[code as usize];
    Some(&m[..m.len() - 1])
}
