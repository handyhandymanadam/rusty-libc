use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use rusty_libc_core::errno;

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

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hcreate_r(nel: usize, htab: *mut HsearchData) -> c_int {
    unsafe {
        if htab.is_null() {
            errno::set(EINVAL);
            return 0;
        }
        if !(*htab).table.is_null() {
            return 0;
        }
        let mut nel = nel.max(3);
        nel |= 1;
        loop {
            if (u32::MAX as usize) - 2 < nel {
                errno::set(ENOMEM);
                return 0;
            }
            if isprime(nel as u32) {
                break;
            }
            nel += 2;
        }
        (*htab).size = nel as u32;
        (*htab).filled = 0;
        let t = rusty_libc_malloc::calloc(nel + 1, core::mem::size_of::<Slot>()) as *mut Slot;
        (*htab).table = t;
        if t.is_null() {
            return 0;
        }
        1
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hdestroy_r(htab: *mut HsearchData) {
    unsafe {
        if htab.is_null() {
            errno::set(EINVAL);
            return;
        }
        rusty_libc_malloc::free((*htab).table.cast());
        (*htab).table = null_mut();
    }
}

unsafe fn key_eq(a: *const c_char, b: *const c_char) -> bool {
    unsafe { rusty_libc_mem::strcmp(a.cast(), b.cast()) == 0 }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch_r(item: Entry, action: Action, retval: *mut *mut Entry, htab: *mut HsearchData) -> c_int {
    unsafe {
        let t = (*htab).table;
        if t.is_null() {
            errno::set(ESRCH);
            *retval = null_mut();
            return 0;
        }
        let size = (*htab).size;
        let len = rusty_libc_mem::strlen(item.key.cast()) as u32;
        let mut hval = len;
        let mut count = len;
        while count > 0 {
            count -= 1;
            hval <<= 4;
            hval = hval.wrapping_add(*item.key.add(count as usize) as i32 as u32);
        }
        if hval == 0 {
            hval += 1;
        }
        let mut idx = hval % size + 1;
        let slot = |i: u32| t.add(i as usize);
        if (*slot(idx)).used != 0 {
            if (*slot(idx)).used == hval && key_eq(item.key, (*slot(idx)).entry.key) {
                *retval = &raw mut (*slot(idx)).entry;
                return 1;
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
                if (*slot(idx)).used == hval && key_eq(item.key, (*slot(idx)).entry.key) {
                    *retval = &raw mut (*slot(idx)).entry;
                    return 1;
                }
                if (*slot(idx)).used == 0 {
                    break;
                }
            }
        }
        if action == ENTER {
            if (*htab).filled == size {
                errno::set(ENOMEM);
                *retval = null_mut();
                return 0;
            }
            (*slot(idx)).used = hval;
            (*slot(idx)).entry = item;
            (*htab).filled += 1;
            *retval = &raw mut (*slot(idx)).entry;
            return 1;
        }
        errno::set(ESRCH);
        *retval = null_mut();
        0
    }
}

static mut GLOBAL_TABLE: HsearchData = HsearchData { table: null_mut(), size: 0, filled: 0 };

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hcreate(nel: usize) -> c_int {
    unsafe { hcreate_r(nel, &raw mut GLOBAL_TABLE) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hdestroy() {
    unsafe { hdestroy_r(&raw mut GLOBAL_TABLE) }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn hsearch(item: Entry, action: Action) -> *mut Entry {
    unsafe {
        let mut r: *mut Entry = null_mut();
        hsearch_r(item, action, &mut r, &raw mut GLOBAL_TABLE);
        r
    }
}

#[repr(C)]
pub struct Node {
    key: *const c_void,
    left: usize,
    right: usize,
}

type N = *mut Node;
type NP = *mut N;

unsafe fn red(n: N) -> bool {
    unsafe { (*n).left & 1 != 0 }
}
unsafe fn set_red(n: N) {
    unsafe { (*n).left |= 1 }
}
unsafe fn set_black(n: N) {
    unsafe { (*n).left &= !1 }
}
unsafe fn left(n: N) -> N {
    unsafe { ((*n).left & !1) as N }
}
unsafe fn right(n: N) -> N {
    unsafe { (*n).right as N }
}
unsafe fn leftp(n: N) -> NP {
    unsafe { &raw mut (*n).left as NP }
}
unsafe fn rightp(n: N) -> NP {
    unsafe { &raw mut (*n).right as NP }
}
unsafe fn set_left(n: N, l: N) {
    unsafe { (*n).left = ((*n).left & 1) | l as usize }
}
unsafe fn set_right(n: N, r: N) {
    unsafe { (*n).right = r as usize }
}
unsafe fn set_ptr(np: NP, p: N) {
    unsafe { *np = (((*np) as usize & 1) | p as usize) as N }
}
unsafe fn deref(np: NP) -> N {
    unsafe { ((*np) as usize & !1) as N }
}

type Compar = unsafe extern "C" fn(*const c_void, *const c_void) -> c_int;

unsafe fn maybe_split_for_insert(rootp: NP, parentp: NP, gparentp: NP, p_r: c_int, gp_r: c_int, mode: c_int) {
    unsafe {
        let root = deref(rootp);
        let rp = rightp(root);
        let rpn = right(root);
        let lp = leftp(root);
        let lpn = left(root);
        if mode == 1 || (!rpn.is_null() && !lpn.is_null() && red(rpn) && red(lpn)) {
            set_red(root);
            if !rpn.is_null() {
                set_black(rpn);
            }
            if !lpn.is_null() {
                set_black(lpn);
            }
            if !parentp.is_null() && red(deref(parentp)) {
                let gp = deref(gparentp);
                let p = deref(parentp);
                if (p_r > 0) != (gp_r > 0) {
                    set_red(p);
                    set_red(gp);
                    set_black(root);
                    if p_r < 0 {
                        set_left(p, rpn);
                        set_ptr(rp, p);
                        set_right(gp, lpn);
                        set_ptr(lp, gp);
                    } else {
                        set_right(p, lpn);
                        set_ptr(lp, p);
                        set_left(gp, rpn);
                        set_ptr(rp, gp);
                    }
                    set_ptr(gparentp, root);
                } else {
                    set_ptr(gparentp, p);
                    set_black(p);
                    set_red(gp);
                    if p_r < 0 {
                        set_left(gp, right(p));
                        set_right(p, gp);
                    } else {
                        set_right(gp, left(p));
                        set_left(p, gp);
                    }
                }
            }
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tsearch(key: *const c_void, vrootp: *mut *mut c_void, compar: Compar) -> *mut c_void {
    unsafe {
        let mut rootp = vrootp as NP;
        if rootp.is_null() {
            return null_mut();
        }
        let mut parentp: NP = null_mut();
        let mut gparentp: NP = null_mut();
        let (mut r, mut p_r, mut gp_r) = (0, 0, 0);
        let root = deref(rootp);
        if !root.is_null() {
            set_black(root);
        }
        let mut nextp = rootp;
        while !deref(nextp).is_null() {
            let root = deref(rootp);
            r = compar(key, (*root).key);
            if r == 0 {
                return root.cast();
            }
            maybe_split_for_insert(rootp, parentp, gparentp, p_r, gp_r, 0);
            nextp = if r < 0 { leftp(root) } else { rightp(root) };
            if deref(nextp).is_null() {
                break;
            }
            gparentp = parentp;
            parentp = rootp;
            rootp = nextp;
            gp_r = p_r;
            p_r = r;
        }
        let q = rusty_libc_malloc::malloc(core::mem::size_of::<Node>()) as N;
        if !q.is_null() {
            set_ptr(nextp, q);
            (*q).key = key;
            (*q).left = 0;
            (*q).right = 0;
            set_red(q);
            if nextp != rootp {
                maybe_split_for_insert(nextp, rootp, parentp, r, p_r, 1);
            }
        }
        q.cast()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tfind(key: *const c_void, vrootp: *const *mut c_void, compar: Compar) -> *mut c_void {
    unsafe {
        let mut rootp = vrootp as NP;
        if rootp.is_null() {
            return null_mut();
        }
        while !deref(rootp).is_null() {
            let root = deref(rootp);
            let r = compar(key, (*root).key);
            if r == 0 {
                return root.cast();
            }
            rootp = if r < 0 { leftp(root) } else { rightp(root) };
        }
        null_mut()
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tdelete(key: *const c_void, vrootp: *mut *mut c_void, compar: Compar) -> *mut c_void {
    unsafe {
        let mut rootp = vrootp as NP;
        if rootp.is_null() {
            return null_mut();
        }
        let mut p = deref(rootp);
        if p.is_null() {
            return null_mut();
        }
        let mut stack: [NP; 130] = [null_mut(); 130];
        let mut sp = 0usize;
        let mut root = deref(rootp);
        loop {
            let cmp = compar(key, (*root).key);
            if cmp == 0 {
                break;
            }
            stack[sp] = rootp;
            sp += 1;
            p = deref(rootp);
            if cmp < 0 {
                rootp = leftp(p);
                root = left(p);
            } else {
                rootp = rightp(p);
                root = right(p);
            }
            if root.is_null() {
                return null_mut();
            }
        }
        let retval = p;
        root = deref(rootp);
        let mut r = right(root);
        let mut q = left(root);
        let unchained: N = if q.is_null() || r.is_null() {
            root
        } else {
            let mut parentp = rootp;
            let mut up = rightp(root);
            loop {
                stack[sp] = parentp;
                sp += 1;
                parentp = up;
                let upn = deref(up);
                if left(upn).is_null() {
                    break;
                }
                up = leftp(upn);
            }
            deref(up)
        };
        r = left(unchained);
        if r.is_null() {
            r = right(unchained);
        }
        if sp == 0 {
            set_ptr(rootp, r);
        } else {
            q = deref(stack[sp - 1]);
            if unchained == right(q) {
                set_right(q, r);
            } else {
                set_left(q, r);
            }
        }
        if unchained != root {
            (*root).key = (*unchained).key;
        }
        if !red(unchained) {
            while sp > 0 && (r.is_null() || !red(r)) {
                let mut pp = stack[sp - 1];
                p = deref(pp);
                if r == left(p) {
                    q = right(p);
                    if red(q) {
                        set_black(q);
                        set_red(p);
                        set_right(p, left(q));
                        set_left(q, p);
                        set_ptr(pp, q);
                        pp = leftp(q);
                        stack[sp] = pp;
                        sp += 1;
                        q = right(p);
                    }
                    if (left(q).is_null() || !red(left(q))) && (right(q).is_null() || !red(right(q))) {
                        set_red(q);
                        r = p;
                    } else {
                        if right(q).is_null() || !red(right(q)) {
                            let q2 = left(q);
                            if red(p) {
                                set_red(q2);
                            } else {
                                set_black(q2);
                            }
                            set_right(p, left(q2));
                            set_left(q, right(q2));
                            set_right(q2, q);
                            set_left(q2, p);
                            set_ptr(pp, q2);
                            set_black(p);
                        } else {
                            if red(p) {
                                set_red(q);
                            } else {
                                set_black(q);
                            }
                            set_black(p);
                            set_black(right(q));
                            set_right(p, left(q));
                            set_left(q, p);
                            set_ptr(pp, q);
                        }
                        sp = 1;
                        r = null_mut();
                    }
                } else {
                    q = left(p);
                    if red(q) {
                        set_black(q);
                        set_red(p);
                        set_left(p, right(q));
                        set_right(q, p);
                        set_ptr(pp, q);
                        pp = rightp(q);
                        stack[sp] = pp;
                        sp += 1;
                        q = left(p);
                    }
                    if (right(q).is_null() || !red(right(q))) && (left(q).is_null() || !red(left(q))) {
                        set_red(q);
                        r = p;
                    } else {
                        if left(q).is_null() || !red(left(q)) {
                            let q2 = right(q);
                            if red(p) {
                                set_red(q2);
                            } else {
                                set_black(q2);
                            }
                            set_left(p, right(q2));
                            set_right(q, left(q2));
                            set_left(q2, q);
                            set_right(q2, p);
                            set_ptr(pp, q2);
                            set_black(p);
                        } else {
                            if red(p) {
                                set_red(q);
                            } else {
                                set_black(q);
                            }
                            set_black(p);
                            set_black(left(q));
                            set_left(p, right(q));
                            set_right(q, p);
                            set_ptr(pp, q);
                        }
                        sp = 1;
                        r = null_mut();
                    }
                }
                sp -= 1;
            }
            if !r.is_null() {
                set_black(r);
            }
        }
        rusty_libc_malloc::free(unchained.cast());
        retval.cast()
    }
}

pub const PREORDER: c_int = 0;
pub const POSTORDER: c_int = 1;
pub const ENDORDER: c_int = 2;
pub const LEAF: c_int = 3;

type WalkFn = unsafe extern "C" fn(*const c_void, c_int, c_int);
type WalkRFn = unsafe extern "C" fn(*const c_void, c_int, *mut c_void);

unsafe fn trecurse(root: N, action: WalkFn, level: c_int) {
    unsafe {
        if left(root).is_null() && right(root).is_null() {
            action(root.cast(), LEAF, level);
        } else {
            action(root.cast(), PREORDER, level);
            if !left(root).is_null() {
                trecurse(left(root), action, level + 1);
            }
            action(root.cast(), POSTORDER, level);
            if !right(root).is_null() {
                trecurse(right(root), action, level + 1);
            }
            action(root.cast(), ENDORDER, level);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn twalk(root: *const c_void, action: Option<WalkFn>) {
    unsafe {
        if let Some(a) = action
            && !root.is_null()
        {
            trecurse(root as N, a, 0);
        }
    }
}

unsafe fn trecurse_r(root: N, action: WalkRFn, closure: *mut c_void) {
    unsafe {
        if left(root).is_null() && right(root).is_null() {
            action(root.cast(), LEAF, closure);
        } else {
            action(root.cast(), PREORDER, closure);
            if !left(root).is_null() {
                trecurse_r(left(root), action, closure);
            }
            action(root.cast(), POSTORDER, closure);
            if !right(root).is_null() {
                trecurse_r(right(root), action, closure);
            }
            action(root.cast(), ENDORDER, closure);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn twalk_r(root: *const c_void, action: Option<WalkRFn>, closure: *mut c_void) {
    unsafe {
        if let Some(a) = action
            && !root.is_null()
        {
            trecurse_r(root as N, a, closure);
        }
    }
}

unsafe fn tdestroy_recurse(root: N, freefct: unsafe extern "C" fn(*mut c_void)) {
    unsafe {
        if !left(root).is_null() {
            tdestroy_recurse(left(root), freefct);
        }
        if !right(root).is_null() {
            tdestroy_recurse(right(root), freefct);
        }
        freefct((*root).key as *mut c_void);
        rusty_libc_malloc::free(root.cast());
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn tdestroy(root: *mut c_void, freefct: unsafe extern "C" fn(*mut c_void)) {
    unsafe {
        if !root.is_null() {
            tdestroy_recurse(root as N, freefct);
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lfind(key: *const c_void, base: *const c_void, nmemb: *mut usize, size: usize, compar: Compar) -> *mut c_void {
    unsafe {
        let mut result = base as *const u8;
        let mut cnt = 0usize;
        while cnt < *nmemb && compar(key, result.cast()) != 0 {
            result = result.wrapping_add(size);
            cnt += 1;
        }
        if cnt < *nmemb { result as *mut c_void } else { null_mut() }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn lsearch(key: *const c_void, base: *mut c_void, nmemb: *mut usize, size: usize, compar: Compar) -> *mut c_void {
    unsafe {
        let r = lfind(key, base, nmemb, size, compar);
        if !r.is_null() {
            return r;
        }
        let dst = (base as *mut u8).add(*nmemb * size);
        rusty_libc_mem::memcpy(dst.cast(), key.cast(), size);
        *nmemb += 1;
        dst.cast()
    }
}

#[repr(C)]
pub struct Qelem {
    pub q_forw: *mut Qelem,
    pub q_back: *mut Qelem,
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn insque(elem: *mut c_void, prev: *mut c_void) {
    unsafe {
        let e = elem as *mut Qelem;
        let p = prev as *mut Qelem;
        if p.is_null() {
            (*e).q_forw = null_mut();
            (*e).q_back = null_mut();
        } else {
            let next = (*p).q_forw;
            (*p).q_forw = e;
            if !next.is_null() {
                (*next).q_back = e;
            }
            (*e).q_forw = next;
            (*e).q_back = p;
        }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn remque(elem: *mut c_void) {
    unsafe {
        let e = elem as *mut Qelem;
        let next = (*e).q_forw;
        let prev = (*e).q_back;
        if !next.is_null() {
            (*next).q_back = prev;
        }
        if !prev.is_null() {
            (*prev).q_forw = next;
        }
    }
}
