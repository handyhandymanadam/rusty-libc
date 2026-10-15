#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::cmem;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{errno, ffi};

const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;
const ESRCH: i32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Entry {
    pub key: *mut c_char,
    pub data: *mut c_void,
}

pub type Action = c_int;
pub const FIND: Action = 0;
pub const ENTER: Action = 1;

#[repr(C)]
pub struct HsearchData {
    table: *mut Slot,
    size: u32,
    filled: u32,
}

#[repr(C)]
struct Slot {
    used: u32,
    entry: Entry,
}

fn isprime(n: u32) -> bool {
    let mut d = 3u32;
    while d <= n / d {
        if n.is_multiple_of(d) {
            return false;
        }
        d += 2;
    }
    true
}

pub fn hcreate_in(nel: usize, htab: &mut HsearchData) -> bool {
    if !htab.table.is_null() {
        return false;
    }
    let mut nel = nel.max(3);
    nel |= 1;
    loop {
        if (u32::MAX as usize) - 2 < nel {
            errno::set(ENOMEM);
            return false;
        }
        if isprime(nel as u32) {
            break;
        }
        nel += 2;
    }
    htab.size = nel as u32;
    htab.filled = 0;
    let t = cmem::calloc(nel + 1, core::mem::size_of::<Slot>()).cast::<Slot>();
    htab.table = t;
    !t.is_null()
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hcreate_r(nel: usize, htab: *mut HsearchData) -> c_int {
    match unsafe { ffi::out(htab) } {
        None => {
            errno::set(EINVAL);
            0
        }
        Some(h) => hcreate_in(nel, h) as c_int,
    }
}

pub fn hdestroy_in(htab: &mut HsearchData) {
    unsafe { cmem::free(htab.table) };
    htab.table = null_mut();
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hdestroy_r(htab: *mut HsearchData) {
    match unsafe { ffi::out(htab) } {
        None => errno::set(EINVAL),
        Some(h) => hdestroy_in(h),
    }
}

#[inline]
fn hash(key: &[u8]) -> u32 {
    let mut hval = key.len() as u32;
    let mut count = key.len();
    while count > 0 {
        count -= 1;
        hval <<= 4;
        hval = hval.wrapping_add(key[count] as i8 as i32 as u32);
    }
    if hval == 0 { 1 } else { hval }
}

fn hsearch_slots(table: &mut [Slot], filled: &mut u32, item: Entry, key: &[u8], enter: bool, same: impl Fn(*const c_char) -> bool) -> Result<usize, i32> {
    let size = (table.len() - 1) as u32;
    let hval = hash(key);
    let mut idx = hval % size + 1;
    let hit = |s: &Slot| s.used == hval && same(s.entry.key);
    if table[idx as usize].used != 0 {
        if hit(&table[idx as usize]) {
            return Ok(idx as usize);
        }
        let hval2 = 1 + hval % (size - 2);
        let first = idx;
        loop {
            if idx <= hval2 {
                idx = size + idx - hval2;
            } else {
                idx -= hval2;
            }
            if idx == first {
                break;
            }
            if hit(&table[idx as usize]) {
                return Ok(idx as usize);
            }
            if table[idx as usize].used == 0 {
                break;
            }
        }
    }
    if enter {
        if *filled == size {
            return Err(ENOMEM);
        }
        let s = &mut table[idx as usize];
        s.used = hval;
        s.entry = item;
        *filled += 1;
        return Ok(idx as usize);
    }
    Err(ESRCH)
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch_r(item: Entry, action: Action, retval: *mut *mut Entry, htab: *mut HsearchData) -> c_int {
    let h = unsafe { &mut *htab };
    let retval = unsafe { &mut *retval };
    if h.table.is_null() {
        errno::set(ESRCH);
        *retval = null_mut();
        return 0;
    }
    let table = unsafe { ffi::slice_mut(h.table, h.size as usize + 1) };
    let key = unsafe { ffi::cstr_bytes(item.key) };
    let same = |k: *const c_char| unsafe { ffi::cstr_eq(item.key.cast_const(), k) };
    match hsearch_slots(table, &mut h.filled, item, key, action == ENTER, same) {
        Ok(i) => {
            *retval = &raw mut table[i].entry;
            1
        }
        Err(e) => {
            errno::set(e);
            *retval = null_mut();
            0
        }
    }
}

static GLOBAL_TABLE: rusty_libc_core::sync_cell::SyncCell<HsearchData> = rusty_libc_core::sync_cell::SyncCell::new(HsearchData { table: null_mut(), size: 0, filled: 0 });

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hcreate(nel: usize) -> c_int {
    unsafe { hcreate_r(nel, GLOBAL_TABLE.as_ptr()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hdestroy() {
    unsafe { hdestroy_r(GLOBAL_TABLE.as_ptr()) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch(item: Entry, action: Action) -> *mut Entry {
    let mut r: *mut Entry = null_mut();
    unsafe { hsearch_r(item, action, &mut r, GLOBAL_TABLE.as_ptr()) };
    r
}

#[repr(C)]
pub struct Node {
    key: *const c_void,
    left: usize,
    right: usize,
}

mod node {
    use super::Node;
    use core::ffi::c_void;
    use core::mem::offset_of;

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) struct N(*mut Node);

    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) struct Link(*mut usize);

    impl N {
        pub(super) const NULL: N = N(core::ptr::null_mut());

        pub(super) unsafe fn from_raw(p: *const c_void) -> N {
            N(p as *mut Node)
        }

        #[inline]
        pub(super) fn alloc(key: *const c_void) -> N {
            let q = crate::cmem::malloc(core::mem::size_of::<Node>()).cast::<Node>();
            if !q.is_null() {
                unsafe { q.write(Node { key, left: 1, right: 0 }) };
            }
            N(q)
        }

        pub(super) unsafe fn free(self) {
            unsafe { crate::cmem::free(self.0) }
        }

        #[inline]
        pub(super) fn is_null(self) -> bool {
            self.0.is_null()
        }

        #[inline]
        pub(super) fn as_ptr(self) -> *mut c_void {
            self.0.cast()
        }

        #[inline]
        fn field(self, off: usize) -> *mut usize {
            debug_assert!(!self.0.is_null());
            self.0.cast::<u8>().wrapping_add(off).cast::<usize>()
        }

        #[inline]
        fn get(self, off: usize) -> usize {
            unsafe { *self.field(off) }
        }

        #[inline]
        fn put(self, off: usize, v: usize) {
            unsafe { *self.field(off) = v }
        }

        #[inline]
        pub(super) fn key(self) -> *const c_void {
            self.get(offset_of!(Node, key)) as *const c_void
        }
        #[inline]
        pub(super) fn set_key(self, k: *const c_void) {
            self.put(offset_of!(Node, key), k as usize)
        }
        #[inline]
        pub(super) fn red(self) -> bool {
            self.get(offset_of!(Node, left)) & 1 != 0
        }
        #[inline]
        pub(super) fn set_red(self) {
            self.put(offset_of!(Node, left), self.get(offset_of!(Node, left)) | 1)
        }
        #[inline]
        pub(super) fn set_black(self) {
            self.put(offset_of!(Node, left), self.get(offset_of!(Node, left)) & !1)
        }
        #[inline]
        pub(super) fn left(self) -> N {
            N((self.get(offset_of!(Node, left)) & !1) as *mut Node)
        }
        #[inline]
        pub(super) fn right(self) -> N {
            N(self.get(offset_of!(Node, right)) as *mut Node)
        }
        #[inline]
        pub(super) fn leftp(self) -> Link {
            Link(self.field(offset_of!(Node, left)))
        }
        #[inline]
        pub(super) fn rightp(self) -> Link {
            Link(self.field(offset_of!(Node, right)))
        }
        #[inline]
        pub(super) fn set_left(self, l: N) {
            self.put(offset_of!(Node, left), (self.get(offset_of!(Node, left)) & 1) | l.0 as usize)
        }
        #[inline]
        pub(super) fn set_right(self, r: N) {
            self.put(offset_of!(Node, right), r.0 as usize)
        }
    }

    impl Link {
        pub(super) const NULL: Link = Link(core::ptr::null_mut());

        pub(super) unsafe fn root(p: *mut *mut c_void) -> Link {
            Link(p.cast())
        }

        #[inline]
        pub(super) fn is_null(self) -> bool {
            self.0.is_null()
        }

        #[inline]
        fn word(self) -> usize {
            debug_assert!(!self.0.is_null());
            unsafe { *self.0 }
        }

        #[inline]
        pub(super) fn get(self) -> N {
            N((self.word() & !1) as *mut Node)
        }

        #[inline]
        pub(super) fn set(self, p: N) {
            let w = (self.word() & 1) | p.0 as usize;
            unsafe { *self.0 = w }
        }
    }
}

use node::{Link, N};

type Compar = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

unsafe fn tree_args(vrootp: *mut *mut c_void, compar: Compar) -> Option<(Link, Cmp)> {
    if vrootp.is_null() {
        return None;
    }
    let l = unsafe { Link::root(vrootp) };
    Some((l, unsafe { Cmp::new(compar) }))
}

#[derive(Clone, Copy)]
struct Cmp(Compar);

impl Cmp {
    unsafe fn new(f: Compar) -> Cmp {
        Cmp(f)
    }
    #[inline]
    fn call(self, a: *const c_void, b: *const c_void) -> c_int {
        unsafe { (self.0)(a, b) }
    }
}

#[inline]
fn maybe_split_for_insert(rootp: Link, parentp: Link, gparentp: Link, p_r: c_int, gp_r: c_int, mode: c_int) {
    let root = rootp.get();
    let rp = root.rightp();
    let rpn = root.right();
    let lp = root.leftp();
    let lpn = root.left();
    if mode == 1 || (!rpn.is_null() && !lpn.is_null() && rpn.red() && lpn.red()) {
        root.set_red();
        if !rpn.is_null() {
            rpn.set_black();
        }
        if !lpn.is_null() {
            lpn.set_black();
        }
        if !parentp.is_null() && parentp.get().red() {
            let gp = gparentp.get();
            let p = parentp.get();
            if (p_r > 0) != (gp_r > 0) {
                p.set_red();
                gp.set_red();
                root.set_black();
                if p_r < 0 {
                    p.set_left(rpn);
                    rp.set(p);
                    gp.set_right(lpn);
                    lp.set(gp);
                } else {
                    p.set_right(lpn);
                    lp.set(p);
                    gp.set_left(rpn);
                    rp.set(gp);
                }
                gparentp.set(root);
            } else {
                gparentp.set(p);
                p.set_black();
                gp.set_red();
                if p_r < 0 {
                    gp.set_left(p.right());
                    p.set_right(gp);
                } else {
                    gp.set_right(p.left());
                    p.set_left(gp);
                }
            }
        }
    }
}

fn tsearch_in(key: *const c_void, mut rootp: Link, cmp: Cmp) -> N {
    let mut parentp = Link::NULL;
    let mut gparentp = Link::NULL;
    let (mut r, mut p_r, mut gp_r) = (0, 0, 0);
    let root = rootp.get();
    if !root.is_null() {
        root.set_black();
    }
    let mut nextp = rootp;
    while !nextp.get().is_null() {
        let root = rootp.get();
        r = cmp.call(key, root.key());
        if r == 0 {
            return root;
        }
        maybe_split_for_insert(rootp, parentp, gparentp, p_r, gp_r, 0);
        nextp = if r < 0 { root.leftp() } else { root.rightp() };
        if nextp.get().is_null() {
            break;
        }
        gparentp = parentp;
        parentp = rootp;
        rootp = nextp;
        gp_r = p_r;
        p_r = r;
    }
    let q = N::alloc(key);
    if !q.is_null() {
        nextp.set(q);
        if nextp != rootp {
            maybe_split_for_insert(nextp, rootp, parentp, r, p_r, 1);
        }
    }
    q
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tsearch(key: *const c_void, vrootp: *mut *mut c_void, compar: Compar) -> *mut c_void {
    let Some((rootp, cmp)) = (unsafe { tree_args(vrootp, compar) }) else { return null_mut() };
    tsearch_in(key, rootp, cmp).as_ptr()
}

fn tfind_in(key: *const c_void, mut rootp: Link, cmp: Cmp) -> N {
    while !rootp.get().is_null() {
        let root = rootp.get();
        let r = cmp.call(key, root.key());
        if r == 0 {
            return root;
        }
        rootp = if r < 0 { root.leftp() } else { root.rightp() };
    }
    N::NULL
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tfind(key: *const c_void, vrootp: *const *mut c_void, compar: Compar) -> *mut c_void {
    let Some((rootp, cmp)) = (unsafe { tree_args(vrootp.cast_mut(), compar) }) else { return null_mut() };
    tfind_in(key, rootp, cmp).as_ptr()
}

#[inline]
fn is_red(n: N) -> bool {
    !n.is_null() && n.red()
}

fn tdelete_in(key: *const c_void, mut rootp: Link, cmp: Cmp) -> N {
    let mut p = rootp.get();
    if p.is_null() {
        return N::NULL;
    }
    let mut stack: [Link; 130] = [Link::NULL; 130];
    let mut sp = 0usize;
    let mut root = rootp.get();
    loop {
        let c = cmp.call(key, root.key());
        if c == 0 {
            break;
        }
        stack[sp] = rootp;
        sp += 1;
        p = rootp.get();
        if c < 0 {
            rootp = p.leftp();
            root = p.left();
        } else {
            rootp = p.rightp();
            root = p.right();
        }
        if root.is_null() {
            return N::NULL;
        }
    }
    let retval = p;
    root = rootp.get();
    let mut r = root.right();
    let mut q = root.left();
    let unchained: N = if q.is_null() || r.is_null() {
        root
    } else {
        let mut parentp = rootp;
        let mut up = root.rightp();
        loop {
            stack[sp] = parentp;
            sp += 1;
            parentp = up;
            let upn = up.get();
            if upn.left().is_null() {
                break;
            }
            up = upn.leftp();
        }
        up.get()
    };
    r = unchained.left();
    if r.is_null() {
        r = unchained.right();
    }
    if sp == 0 {
        rootp.set(r);
    } else {
        q = stack[sp - 1].get();
        if unchained == q.right() {
            q.set_right(r);
        } else {
            q.set_left(r);
        }
    }
    if unchained != root {
        root.set_key(unchained.key());
    }
    if !unchained.red() {
        while sp > 0 && !is_red(r) {
            let mut pp = stack[sp - 1];
            p = pp.get();
            if r == p.left() {
                q = p.right();
                if q.red() {
                    q.set_black();
                    p.set_red();
                    p.set_right(q.left());
                    q.set_left(p);
                    pp.set(q);
                    pp = q.leftp();
                    stack[sp] = pp;
                    sp += 1;
                    q = p.right();
                }
                if !is_red(q.left()) && !is_red(q.right()) {
                    q.set_red();
                    r = p;
                } else {
                    if !is_red(q.right()) {
                        let q2 = q.left();
                        if p.red() {
                            q2.set_red();
                        } else {
                            q2.set_black();
                        }
                        p.set_right(q2.left());
                        q.set_left(q2.right());
                        q2.set_right(q);
                        q2.set_left(p);
                        pp.set(q2);
                        p.set_black();
                    } else {
                        if p.red() {
                            q.set_red();
                        } else {
                            q.set_black();
                        }
                        p.set_black();
                        q.right().set_black();
                        p.set_right(q.left());
                        q.set_left(p);
                        pp.set(q);
                    }
                    sp = 1;
                    r = N::NULL;
                }
            } else {
                q = p.left();
                if q.red() {
                    q.set_black();
                    p.set_red();
                    p.set_left(q.right());
                    q.set_right(p);
                    pp.set(q);
                    pp = q.rightp();
                    stack[sp] = pp;
                    sp += 1;
                    q = p.left();
                }
                if !is_red(q.right()) && !is_red(q.left()) {
                    q.set_red();
                    r = p;
                } else {
                    if !is_red(q.left()) {
                        let q2 = q.right();
                        if p.red() {
                            q2.set_red();
                        } else {
                            q2.set_black();
                        }
                        p.set_left(q2.right());
                        q.set_right(q2.left());
                        q2.set_left(q);
                        q2.set_right(p);
                        pp.set(q2);
                        p.set_black();
                    } else {
                        if p.red() {
                            q.set_red();
                        } else {
                            q.set_black();
                        }
                        p.set_black();
                        q.left().set_black();
                        p.set_left(q.right());
                        q.set_right(p);
                        pp.set(q);
                    }
                    sp = 1;
                    r = N::NULL;
                }
            }
            sp -= 1;
        }
        if !r.is_null() {
            r.set_black();
        }
    }
    unsafe { unchained.free() };
    retval
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tdelete(key: *const c_void, vrootp: *mut *mut c_void, compar: Compar) -> *mut c_void {
    let Some((rootp, cmp)) = (unsafe { tree_args(vrootp, compar) }) else { return null_mut() };
    tdelete_in(key, rootp, cmp).as_ptr()
}

pub const PREORDER: c_int = 0;
pub const POSTORDER: c_int = 1;
pub const ENDORDER: c_int = 2;
pub const LEAF: c_int = 3;

type WalkFn = unsafe extern "C" fn(*const c_void, c_int, c_int);
type WalkRFn = unsafe extern "C" fn(*const c_void, c_int, *mut c_void);

fn trecurse(root: N, action: &impl Fn(N, c_int, c_int), level: c_int) {
    let (l, r) = (root.left(), root.right());
    if l.is_null() && r.is_null() {
        action(root, LEAF, level);
    } else {
        action(root, PREORDER, level);
        let l = root.left();
        if !l.is_null() {
            trecurse(l, action, level + 1);
        }
        action(root, POSTORDER, level);
        let r = root.right();
        if !r.is_null() {
            trecurse(r, action, level + 1);
        }
        action(root, ENDORDER, level);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn twalk(root: *const c_void, action: Option<WalkFn>) {
    if let Some(a) = action
        && !root.is_null()
    {
        let act = |n: N, which, level| unsafe { a(n.as_ptr(), which, level) };
        trecurse(unsafe { N::from_raw(root) }, &act, 0);
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn twalk_r(root: *const c_void, action: Option<WalkRFn>, closure: *mut c_void) {
    if let Some(a) = action
        && !root.is_null()
    {
        let act = |n: N, which, _level| unsafe { a(n.as_ptr(), which, closure) };
        trecurse(unsafe { N::from_raw(root) }, &act, 0);
    }
}

fn tdestroy_recurse(root: N, freefct: unsafe extern "C" fn(*mut c_void)) {
    if !root.left().is_null() {
        tdestroy_recurse(root.left(), freefct);
    }
    if !root.right().is_null() {
        tdestroy_recurse(root.right(), freefct);
    }
    unsafe { freefct(root.key() as *mut c_void) };
    unsafe { root.free() };
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tdestroy(root: *mut c_void, freefct: unsafe extern "C" fn(*mut c_void)) {
    if !root.is_null() {
        tdestroy_recurse(unsafe { N::from_raw(root) }, freefct);
    }
}

fn lfind_in(key: *const c_void, base: *const u8, nmemb: usize, size: usize, cmp: Cmp) -> *mut c_void {
    let mut result = base;
    let mut cnt = 0usize;
    while cnt < nmemb && cmp.call(key, result.cast()) != 0 {
        result = result.wrapping_add(size);
        cnt += 1;
    }
    if cnt < nmemb { result as *mut c_void } else { null_mut() }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lfind(key: *const c_void, base: *const c_void, nmemb: *mut usize, size: usize, compar: Compar) -> *mut c_void {
    let n = unsafe { *nmemb };
    lfind_in(key, base.cast(), n, size, unsafe { Cmp::new(compar) })
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lsearch(key: *const c_void, base: *mut c_void, nmemb: *mut usize, size: usize, compar: Compar) -> *mut c_void {
    let n = unsafe { &mut *nmemb };
    let r = lfind_in(key, base.cast(), *n, size, unsafe { Cmp::new(compar) });
    if !r.is_null() {
        return r;
    }
    let dst = base.cast::<u8>().wrapping_add(*n * size);
    unsafe { rusty_libc_mem::memcpy(dst.cast(), key, size) };
    *n += 1;
    dst.cast()
}

#[repr(C)]
pub struct Qelem {
    pub q_forw: *mut Qelem,
    pub q_back: *mut Qelem,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn insque(elem: *mut c_void, prev: *mut c_void) {
    let e = elem as *mut Qelem;
    let p = prev as *mut Qelem;
    if p.is_null() {
        unsafe { e.write(Qelem { q_forw: null_mut(), q_back: null_mut() }) };
    } else {
        let next = unsafe { (*p).q_forw };
        unsafe { (*p).q_forw = e };
        if !next.is_null() {
            unsafe { (*next).q_back = e };
        }
        unsafe { e.write(Qelem { q_forw: next, q_back: p }) };
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remque(elem: *mut c_void) {
    let e = elem as *mut Qelem;
    let Qelem { q_forw: next, q_back: prev } = unsafe { e.read() };
    if !next.is_null() {
        unsafe { (*next).q_back = prev };
    }
    if !prev.is_null() {
        unsafe { (*prev).q_forw = next };
    }
}
