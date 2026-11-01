//! search.h: the hash table (hcreate, hsearch, hdestroy and the `_r` forms), binary trees (tsearch,
//! tfind, tdelete, twalk, twalk_r, tdestroy), lsearch/lfind and the queue functions insque/remque.
//!
//! These follow glibc's layouts so that results which depend on them match:
//! * The hash table has a prime number of slots (at least the requested count, at least 3, rounded
//!   up to the next prime), slot 0 is never used, the hash is `len` plus the key bytes folded in
//!   4 bits at a time from the last byte (as signed `char`), and collisions use double hashing with
//!   the second step `1 + hash % (size - 2)`. The full-table error is `ENOMEM`, a failed lookup
//!   `ESRCH`.
//! * The trees are red-black trees using the classic top-down insertion (split nodes with two red
//!   children on the way down) and the CLRS-style deletion that copies the successor's key into the
//!   deleted node; the colour lives in the low bit of the left pointer. The shape visible through
//!   `twalk` (order, levels, which nodes are leaves) and the pointer returned by `tdelete` (the
//!   parent, or the old root when the root went) therefore match glibc's.
//!
//! Unsafe code (BRIEF-UNSAFE U2): the hash table is a slice once its pointer is converted; the trees belong to the C caller
//! (it holds the root variable and sees the nodes), so the node accesses stay raw, but only inside the small `node` module,
//! whose handles can only be made from the caller's root or from links of nodes already reached (see its invariant). The
//! tree algorithms are safe code over those handles. Calling the caller's comparison, action and free functions is unsafe
//! once each, in `Cmp`, the twalk closures and `tdestroy`.
#![deny(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block, unsafe_op_in_unsafe_fn)]
use crate::cmem;
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::{errno, ffi};

const ENOMEM: i32 = 12;
const EINVAL: i32 = 22;
const ESRCH: i32 = 3;

/// `ENTRY` from search.h.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Entry {
    pub key: *mut c_char,
    pub data: *mut c_void,
}

/// `ACTION`: FIND = 0, ENTER = 1.
pub type Action = c_int;
pub const FIND: Action = 0;
pub const ENTER: Action = 1;

/// `struct hsearch_data`.
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
    // n is odd here
    let mut d = 3u32;
    while d <= n / d {
        if n.is_multiple_of(d) {
            return false;
        }
        d += 2;
    }
    true
}

/// `hcreate_r` on a table that exists: allocate `nel` slots (rounded up to a prime). False when the table already has
/// slots (no errno, as glibc), when the request is too large (ENOMEM) or when memory ran out.
pub fn hcreate_in(nel: usize, htab: &mut HsearchData) -> bool {
    if !htab.table.is_null() {
        return false;
    }
    let mut nel = nel.max(3);
    // first prime in [nel, UINT_MAX - 2]; the size field is 32 bits, like glibc's (nel is `size_t`
    // but the loop compares it against UINT_MAX - 2, so a larger request fails with ENOMEM)
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

/// # Safety
/// `htab` must be NULL or point to a zero-initialised `struct hsearch_data` (or one that was destroyed).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hcreate_r(nel: usize, htab: *mut HsearchData) -> c_int {
    // SAFETY: `htab` is NULL or a valid, exclusively ours `struct hsearch_data` (caller's contract).
    match unsafe { ffi::out(htab) } {
        None => {
            errno::set(EINVAL);
            0
        }
        Some(h) => hcreate_in(nel, h) as c_int,
    }
}

/// `hdestroy_r` on a table that exists: free its slots (not the keys).
pub fn hdestroy_in(htab: &mut HsearchData) {
    // SAFETY: `table` is NULL or the block hcreate_in allocated; it is cleared right after, so it is not used again.
    unsafe { cmem::free(htab.table) };
    htab.table = null_mut();
}

/// # Safety
/// `htab` must be NULL or a table made by `hcreate_r`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hdestroy_r(htab: *mut HsearchData) {
    // SAFETY: `htab` is NULL or a valid table (caller's contract).
    match unsafe { ffi::out(htab) } {
        None => errno::set(EINVAL),
        Some(h) => hdestroy_in(h),
    }
}

/// glibc's hash of a key: its length plus its bytes (as signed `char`) folded in from the last one; never 0.
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

/// The search of `hsearch_r` over the slots (`table.len()` is at least `size + 1`): the entry of the slot holding `key`
/// (or of the new slot when `enter`), or `Err(errno)`. `same(k)` says whether the stored key `k` equals `key`.
/// Indexes stay u32 as in glibc; `table` is cut to `size + 1` slots first, so every index (1..=size) needs no bounds check.
fn hsearch_slots<'t>(table: &'t mut [Slot], size: u32, filled: &mut u32, item: Entry, key: &[u8], enter: bool, same: impl Fn(*const c_char) -> bool) -> Result<&'t mut Entry, i32> {
    let table = &mut table[..=size as usize];
    let hval = hash(key);
    let mut idx = hval % size + 1;
    let hit = |s: &Slot| s.used == hval && same(s.entry.key);
    if table[idx as usize].used != 0 {
        if hit(&table[idx as usize]) {
            return Ok(&mut table[idx as usize].entry);
        }
        let hval2 = 1 + hval % (size - 2);
        let first = idx;
        loop {
            idx = if idx <= hval2 { size + idx - hval2 } else { idx - hval2 };
            if idx == first {
                break;
            }
            let s = &table[idx as usize];
            if hit(s) {
                return Ok(&mut table[idx as usize].entry);
            }
            if s.used == 0 {
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
        return Ok(&mut s.entry);
    }
    Err(ESRCH)
}

/// # Safety
/// `item.key` must be a C string; `retval` and `htab` valid; the table must have been created.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch_r(item: Entry, action: Action, retval: *mut *mut Entry, htab: *mut HsearchData) -> c_int {
    // SAFETY: `htab` points to a valid table and `retval` to a writable pointer, neither aliased during the call
    // (caller's contract; NULL faults as in glibc).
    let h = unsafe { &mut *htab };
    // SAFETY: as above.
    let retval = unsafe { &mut *retval };
    if h.table.is_null() {
        // glibc would fault here; fail the lookup instead
        errno::set(ESRCH);
        *retval = null_mut();
        return 0;
    }
    // SAFETY: a created table has `size + 1` slots, owned by the table and only reached through it during the call.
    let table = unsafe { ffi::slice_mut(h.table, h.size as usize + 1) };
    // SAFETY: `item.key` is a C string (caller's contract), unchanged during the call.
    let key = unsafe { ffi::cstr_bytes(item.key) };
    // SAFETY: both are C strings: `item.key` by the caller's contract, a stored key because it was such a key when entered.
    let same = |k: *const c_char| unsafe { ffi::cstr_eq(item.key.cast_const(), k) };
    match hsearch_slots(table, h.size, &mut h.filled, item, key, action == ENTER, same) {
        Ok(e) => {
            *retval = e;
            1
        }
        Err(e) => {
            errno::set(e);
            *retval = null_mut();
            0
        }
    }
}

/// The table of `hcreate`/`hsearch`/`hdestroy`. Rule: as glibc's (`MT-Unsafe race:hsearch`), the caller does not use these
/// three functions from two threads at once, so each call has the table to itself.
static GLOBAL_TABLE: rusty_libc_core::sync_cell::SyncCell<HsearchData> = rusty_libc_core::sync_cell::SyncCell::new(HsearchData { table: null_mut(), size: 0, filled: 0 });

/// # Safety
/// As `hcreate_r`; not called at the same time as `hsearch` or `hdestroy` (glibc: race:hsearch).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hcreate(nel: usize) -> c_int {
    // SAFETY: the global table is valid; no concurrent use (contract above).
    unsafe { hcreate_r(nel, GLOBAL_TABLE.as_ptr()) }
}

/// # Safety
/// As `hdestroy_r`; not concurrent with the other two.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hdestroy() {
    // SAFETY: the global table is valid; no concurrent use (contract above).
    unsafe { hdestroy_r(GLOBAL_TABLE.as_ptr()) }
}

/// # Safety
/// As `hsearch_r`; `hcreate` must have been called; not concurrent with the other two.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch(item: Entry, action: Action) -> *mut Entry {
    let mut r: *mut Entry = null_mut();
    // SAFETY: the global table is valid and `r` writable; no concurrent use (contract above).
    unsafe { hsearch_r(item, action, &mut r, GLOBAL_TABLE.as_ptr()) };
    r
}

// ------------------------------------------------------------------------------------ trees

/// A tree node: the key first (callers cast the node pointer to `void **`), then the left link with
/// the colour in bit 0, then the right link.
#[repr(C)]
pub struct Node {
    key: *const c_void,
    left: usize,
    right: usize,
}

/// Raw node access, the only unsafe part of the trees.
///
/// Invariant: every non-NULL [`N`] and every non-NULL [`Link`] handled during an exported call was obtained in that call
/// from the tree the C caller passed in ([`Link::root`], [`N::from_raw`]) or from links of nodes reached that way, or from
/// [`N::alloc`]. The C contract (glibc: `MT-Safe race:rootp`) gives the call exclusive use of that tree, so these point to
/// live nodes (or the caller's root variable) that nothing else touches meanwhile; a node given to [`N::free`] is not used
/// again. The handles are not public, so code outside this file cannot make one.
mod node {
    use super::Node;
    use core::ffi::c_void;
    use core::mem::offset_of;

    /// A node pointer (maybe NULL).
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) struct N(*mut Node);

    /// A pointer to a link: the caller's root variable, or a node's left (colour in bit 0) or right field (maybe NULL).
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(super) struct Link(*mut usize);

    impl N {
        pub(super) const NULL: N = N(core::ptr::null_mut());

        /// The node at `p` (a tree's root as `twalk` and `tdestroy` get it).
        ///
        /// # Safety
        /// `p` is NULL or the root node of a tree made by tsearch, used only by this call (the module invariant).
        pub(super) unsafe fn from_raw(p: *const c_void) -> N {
            N(p as *mut Node)
        }

        /// A new red leaf holding `key`; NULL when memory ran out.
        #[inline]
        pub(super) fn alloc(key: *const c_void) -> N {
            let q = crate::cmem::malloc(core::mem::size_of::<Node>()).cast::<Node>();
            if !q.is_null() {
                // SAFETY: fresh, suitably aligned memory for one Node (malloc's alignment), owned by this call.
                unsafe { q.write(Node { key, left: 1, right: 0 }) };
            }
            N(q)
        }

        /// Free the node.
        ///
        /// # Safety
        /// The node was unlinked from the tree and no handle to it is used afterwards.
        pub(super) unsafe fn free(self) {
            // SAFETY: a node block from `alloc`, not used again (caller's contract).
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
            // SAFETY: a live node of this call's tree (module invariant); `off` is a field offset of Node.
            unsafe { *self.field(off) }
        }

        #[inline]
        fn put(self, off: usize, v: usize) {
            // SAFETY: as in `get`; the call has the tree to itself.
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

        /// The caller's root variable.
        ///
        /// # Safety
        /// `p` is NULL or points to the root variable of a tree made by tsearch (or NULL for an empty tree), used only by
        /// this call (the module invariant).
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
            // SAFETY: the root variable or a link field of a live node (module invariant).
            unsafe { *self.0 }
        }

        /// The node the link points to (the colour bit a left link carries is masked).
        #[inline]
        pub(super) fn get(self) -> N {
            N((self.word() & !1) as *mut Node)
        }

        /// Store `p` in the link, keeping the colour bit that a left link carries.
        #[inline]
        pub(super) fn set(self, p: N) {
            let w = (self.word() & 1) | p.0 as usize;
            // SAFETY: as in `word`; the call has the tree to itself.
            unsafe { *self.0 = w }
        }
    }
}

use node::{Link, N};

type Compar = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

/// The arguments of tsearch/tfind/tdelete: the root link (None for a NULL `vrootp`) and the comparison function.
///
/// # Safety
/// `vrootp` is NULL or points to the root variable of a tree made by tsearch, used only by this call; `compar` compares
/// the key with the tree's keys.
unsafe fn tree_args(vrootp: *mut *mut c_void, compar: Compar) -> Option<(Link, Cmp)> {
    if vrootp.is_null() {
        return None;
    }
    // SAFETY: forwarded contract.
    let l = unsafe { Link::root(vrootp) };
    // SAFETY: forwarded contract.
    Some((l, unsafe { Cmp::new(compar) }))
}

/// The caller's comparison function.
#[derive(Clone, Copy)]
struct Cmp(Compar);

impl Cmp {
    /// # Safety
    /// `f` can be called with the search key and with every key stored in the tree (the C contract of compar).
    unsafe fn new(f: Compar) -> Cmp {
        Cmp(f)
    }
    #[inline]
    fn call(self, a: *const c_void, b: *const c_void) -> c_int {
        // SAFETY: the keys passed are the caller's key and stored keys, which `new`'s contract covers.
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

/// # Safety
/// `vrootp` points to the tree's root pointer; `compar` compares keys.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tsearch(key: *const c_void, vrootp: *mut *mut c_void, compar: Compar) -> *mut c_void {
    // SAFETY: the caller's tree and comparison function (caller's contract).
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

/// # Safety
/// As `tsearch`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tfind(key: *const c_void, vrootp: *const *mut c_void, compar: Compar) -> *mut c_void {
    // SAFETY: the caller's tree and comparison function (caller's contract); tfind only reads through the link.
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
    // stack of link pointers from the root down to the parent of the node being worked on; the
    // red-black height bound keeps it short (a tree needs far more than 2^64 nodes to exceed it)
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
    // SAFETY: `unchained` was unlinked above and is not used after this (only `retval`'s address is returned, which is
    // the old root itself when the root went: glibc returns that dangling pointer too).
    unsafe { unchained.free() };
    retval
}

/// # Safety
/// As `tsearch`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tdelete(key: *const c_void, vrootp: *mut *mut c_void, compar: Compar) -> *mut c_void {
    // SAFETY: the caller's tree and comparison function (caller's contract).
    let Some((rootp, cmp)) = (unsafe { tree_args(vrootp, compar) }) else { return null_mut() };
    tdelete_in(key, rootp, cmp).as_ptr()
}

/// `VISIT` values.
pub const PREORDER: c_int = 0;
pub const POSTORDER: c_int = 1;
pub const ENDORDER: c_int = 2;
pub const LEAF: c_int = 3;

type WalkFn = unsafe extern "C" fn(*const c_void, c_int, c_int);
type WalkRFn = unsafe extern "C" fn(*const c_void, c_int, *mut c_void);

/// Visit the subtree at `root` (not NULL) in glibc's order, calling `action(node, which, level)`.
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

/// # Safety
/// `root` is a tree root (or NULL); `action` may be NULL.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn twalk(root: *const c_void, action: Option<WalkFn>) {
    if let Some(a) = action
        && !root.is_null()
    {
        // SAFETY: the action can be called with every node of the tree (C contract of twalk).
        let act = |n: N, which, level| unsafe { a(n.as_ptr(), which, level) };
        // SAFETY: the caller's tree (caller's contract).
        trecurse(unsafe { N::from_raw(root) }, &act, 0);
    }
}

/// # Safety
/// As `twalk`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn twalk_r(root: *const c_void, action: Option<WalkRFn>, closure: *mut c_void) {
    if let Some(a) = action
        && !root.is_null()
    {
        // SAFETY: the action can be called with every node of the tree and the caller's closure (C contract of twalk_r).
        let act = |n: N, which, _level| unsafe { a(n.as_ptr(), which, closure) };
        // SAFETY: the caller's tree (caller's contract); the depth argument is unused for twalk_r.
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
    // SAFETY: the caller's free function takes every key of the tree (C contract of tdestroy).
    unsafe { freefct(root.key() as *mut c_void) };
    // SAFETY: both subtrees are gone and the caller hands the whole tree over, so the node is not used again.
    unsafe { root.free() };
}

/// # Safety
/// `root` is a tree root (or NULL); `freefct` is called on every key (post-order).
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tdestroy(root: *mut c_void, freefct: unsafe extern "C" fn(*mut c_void)) {
    if !root.is_null() {
        // SAFETY: the caller's tree, handed over for destruction (caller's contract).
        tdestroy_recurse(unsafe { N::from_raw(root) }, freefct);
    }
}

// ------------------------------------------------------------------------- lsearch, queues

/// `lfind` over `nmemb` elements of `size` bytes from `base`: the first one `cmp` says equals `key`, or NULL.
fn lfind_in(key: *const c_void, base: *const u8, nmemb: usize, size: usize, cmp: Cmp) -> *mut c_void {
    let mut result = base;
    let mut cnt = 0usize;
    while cnt < nmemb && cmp.call(key, result.cast()) != 0 {
        result = result.wrapping_add(size);
        cnt += 1;
    }
    if cnt < nmemb { result as *mut c_void } else { null_mut() }
}

/// # Safety
/// `base` holds `*nmemb` elements of `size` bytes.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lfind(key: *const c_void, base: *const c_void, nmemb: *mut usize, size: usize, compar: Compar) -> *mut c_void {
    // SAFETY: `nmemb` points to the element count (caller's contract).
    let n = unsafe { *nmemb };
    // SAFETY: `compar` compares `key` with the elements of the array (caller's contract).
    lfind_in(key, base.cast(), n, size, unsafe { Cmp::new(compar) })
}

/// # Safety
/// As `lfind`; the array must have room for one more element.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lsearch(key: *const c_void, base: *mut c_void, nmemb: *mut usize, size: usize, compar: Compar) -> *mut c_void {
    // SAFETY: `nmemb` points to the element count, writable, not aliased by the array (caller's contract).
    let n = unsafe { &mut *nmemb };
    // SAFETY: `compar` compares `key` with the elements of the array (caller's contract).
    let r = lfind_in(key, base.cast(), *n, size, unsafe { Cmp::new(compar) });
    if !r.is_null() {
        return r;
    }
    let dst = base.cast::<u8>().wrapping_add(*n * size);
    // SAFETY: the array has room for element `*n` (caller's contract) and `key` points to `size` readable bytes.
    unsafe { rusty_libc_mem::memcpy(dst.cast(), key, size) };
    *n += 1;
    dst.cast()
}

/// `struct qelem`.
#[repr(C)]
pub struct Qelem {
    pub q_forw: *mut Qelem,
    pub q_back: *mut Qelem,
}

/// # Safety
/// `elem` points to a `struct qelem` (at least); `prev` is NULL or in a list.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn insque(elem: *mut c_void, prev: *mut c_void) {
    let e = elem as *mut Qelem;
    let p = prev as *mut Qelem;
    if p.is_null() {
        // SAFETY: `elem` is a writable element (caller's contract).
        unsafe { e.write(Qelem { q_forw: null_mut(), q_back: null_mut() }) };
    } else {
        // SAFETY: `prev` is an element of a list (caller's contract).
        let next = unsafe { (*p).q_forw };
        // SAFETY: as above.
        unsafe { (*p).q_forw = e };
        if !next.is_null() {
            // SAFETY: `next` is `prev`'s successor in the same list.
            unsafe { (*next).q_back = e };
        }
        // SAFETY: `elem` is a writable element (caller's contract).
        unsafe { e.write(Qelem { q_forw: next, q_back: p }) };
    }
}

/// # Safety
/// `elem` is an element of a list made with `insque`.
#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remque(elem: *mut c_void) {
    let e = elem as *mut Qelem;
    // SAFETY: `elem` is an element of a list (caller's contract).
    let Qelem { q_forw: next, q_back: prev } = unsafe { e.read() };
    if !next.is_null() {
        // SAFETY: `next` is `elem`'s successor in the same list.
        unsafe { (*next).q_back = prev };
    }
    if !prev.is_null() {
        // SAFETY: `prev` is `elem`'s predecessor in the same list.
        unsafe { (*prev).q_forw = next };
    }
}
