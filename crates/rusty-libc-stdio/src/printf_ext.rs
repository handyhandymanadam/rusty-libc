#![allow(clippy::deref_addrof, clippy::manual_range_contains, clippy::needless_late_init)]
use crate::file::File;
use crate::fmt::{self, Args, FmtChar, Kind, Sink, Val};
use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};
use rusty_libc_core::errno;

pub const PA_INT: c_int = 0;
pub const PA_CHAR: c_int = 1;
pub const PA_WCHAR: c_int = 2;
pub const PA_STRING: c_int = 3;
pub const PA_WSTRING: c_int = 4;
pub const PA_POINTER: c_int = 5;
pub const PA_FLOAT: c_int = 6;
pub const PA_DOUBLE: c_int = 7;
pub const PA_LAST: c_int = 8;
pub const PA_FLAG_MASK: c_int = 0xff00;
pub const PA_FLAG_LONG_LONG: c_int = 1 << 8;
pub const PA_FLAG_LONG_DOUBLE: c_int = PA_FLAG_LONG_LONG;
pub const PA_FLAG_LONG: c_int = 1 << 9;
pub const PA_FLAG_SHORT: c_int = 1 << 10;
pub const PA_FLAG_PTR: c_int = 1 << 11;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PrintfInfo {
    pub prec: c_int,
    pub width: c_int,
    pub spec: i32,
    pub flags: u16,
    pub user: u16,
    pub pad: i32,
}
const _: () = assert!(size_of::<PrintfInfo>() == 20);

pub const INFO_LONG_DOUBLE: u16 = 1 << 0;
pub const INFO_SHORT: u16 = 1 << 1;
pub const INFO_LONG: u16 = 1 << 2;
pub const INFO_ALT: u16 = 1 << 3;
pub const INFO_SPACE: u16 = 1 << 4;
pub const INFO_LEFT: u16 = 1 << 5;
pub const INFO_SHOWSIGN: u16 = 1 << 6;
pub const INFO_GROUP: u16 = 1 << 7;
pub const INFO_EXTRA: u16 = 1 << 8;
pub const INFO_CHAR: u16 = 1 << 9;
pub const INFO_WIDE: u16 = 1 << 10;
pub const INFO_I18N: u16 = 1 << 11;
pub const INFO_BINARY128: u16 = 1 << 12;

impl PrintfInfo {
    fn has(&self, bit: u16) -> bool {
        self.flags & bit != 0
    }
    fn set(&mut self, bit: u16) {
        self.flags |= bit;
    }
    const fn zero() -> PrintfInfo {
        PrintfInfo { prec: -1, width: 0, spec: 0, flags: 0, user: 0, pad: b' ' as i32 }
    }
}

pub type PrintfFunction = unsafe extern "C" fn(*mut File, *const PrintfInfo, *const *const c_void) -> c_int;
pub type ArginfoSizeFunction = unsafe extern "C" fn(*const PrintfInfo, usize, *mut c_int, *mut c_int) -> c_int;
pub type ArginfoFunction = unsafe extern "C" fn(*const PrintfInfo, usize, *mut c_int) -> c_int;
pub type VaArgFunction = unsafe extern "C" fn(*mut c_void, *mut c_void);

static ACTIVE: AtomicU8 = AtomicU8::new(0);
static LOCK: AtomicU32 = AtomicU32::new(0);

static mut FUNC_TABLE: *mut Option<PrintfFunction> = null_mut();
static mut ARGINFO_TABLE: *mut Option<ArginfoSizeFunction> = null_mut();
static mut VAARG_TABLE: *mut Option<VaArgFunction> = null_mut();
static mut MOD_TABLE: *mut *mut ModRecord = null_mut();
static mut NEXT_BIT: c_int = 0;
static mut NEXT_TYPE: c_int = PA_LAST;

struct ModRecord {
    next: *mut ModRecord,
    bit: c_int,
    len: usize,
    text: *mut u8,
}

#[inline(always)]
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed) != 0
}

fn lock() {
    while LOCK.compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
}

fn unlock() {
    LOCK.store(0, Ordering::Release);
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn register_printf_specifier(spec: c_int, converter: Option<PrintfFunction>, arginfo: Option<ArginfoSizeFunction>) -> c_int {
    unsafe {
        if !(0..=255).contains(&spec) {
            errno::set(22);
            return -1;
        }
        lock();
        let mut result = 0;
        if (*(&raw const FUNC_TABLE)).is_null() {
            let f = rusty_libc_malloc::calloc(256, size_of::<Option<PrintfFunction>>()) as *mut Option<PrintfFunction>;
            let a = rusty_libc_malloc::calloc(256, size_of::<Option<ArginfoSizeFunction>>()) as *mut Option<ArginfoSizeFunction>;
            if f.is_null() || a.is_null() {
                rusty_libc_malloc::free(f.cast());
                rusty_libc_malloc::free(a.cast());
                result = -1;
            } else {
                ARGINFO_TABLE = a;
                FUNC_TABLE = f;
            }
        }
        if result == 0 {
            *FUNC_TABLE.add(spec as usize) = converter;
            *ARGINFO_TABLE.add(spec as usize) = arginfo;
            ACTIVE.store(1, Ordering::Release);
        }
        unlock();
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn register_printf_function(spec: c_int, converter: Option<PrintfFunction>, arginfo: Option<ArginfoFunction>) -> c_int {
    unsafe {
        let a = core::mem::transmute::<Option<ArginfoFunction>, Option<ArginfoSizeFunction>>(arginfo);
        register_printf_specifier(spec, converter, a)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn register_printf_modifier(s: *const i32) -> c_int {
    unsafe {
        if *s == 0 {
            errno::set(22);
            return -1;
        }
        let mut n = 0;
        while *s.add(n) != 0 {
            if !(0..=255).contains(&*s.add(n)) {
                errno::set(22);
                return -1;
            }
            n += 1;
        }
        if NEXT_BIT / 8 == size_of::<u16>() as c_int {
            errno::set(28);
            return -1;
        }
        lock();
        let mut result = -1;
        'out: {
            if (*(&raw const MOD_TABLE)).is_null() {
                MOD_TABLE = rusty_libc_malloc::calloc(256, size_of::<*mut ModRecord>()) as *mut *mut ModRecord;
                if MOD_TABLE.is_null() {
                    break 'out;
                }
            }
            let rec = rusty_libc_malloc::malloc(size_of::<ModRecord>()) as *mut ModRecord;
            if rec.is_null() {
                break 'out;
            }
            let text = rusty_libc_malloc::malloc(n) as *mut u8;
            if text.is_null() {
                rusty_libc_malloc::free(rec.cast());
                break 'out;
            }
            for i in 1..n {
                *text.add(i - 1) = *s.add(i) as u8;
            }
            let first = *s as u8 as usize;
            (*rec).next = *MOD_TABLE.add(first);
            (*rec).bit = 1 << NEXT_BIT;
            NEXT_BIT += 1;
            (*rec).len = n - 1;
            (*rec).text = text;
            *MOD_TABLE.add(first) = rec;
            result = (*rec).bit;
            ACTIVE.store(1, Ordering::Release);
        }
        unlock();
        result
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn register_printf_type(fct: Option<VaArgFunction>) -> c_int {
    unsafe {
        lock();
        let mut result = -1;
        if (*(&raw const VAARG_TABLE)).is_null() {
            VAARG_TABLE = rusty_libc_malloc::calloc((0x100 - PA_LAST) as usize, size_of::<Option<VaArgFunction>>()) as *mut Option<VaArgFunction>;
        }
        if !(*(&raw const VAARG_TABLE)).is_null() {
            if NEXT_TYPE == 0x100 {
                errno::set(28);
            } else {
                result = NEXT_TYPE;
                NEXT_TYPE += 1;
                *VAARG_TABLE.add((result - PA_LAST) as usize) = fct;
                ACTIVE.store(1, Ordering::Release);
            }
        }
        unlock();
        result
    }
}

unsafe fn func_for(spec: i32) -> Option<PrintfFunction> {
    unsafe {
        if (*(&raw const FUNC_TABLE)).is_null() || !(0..=255).contains(&spec) { None } else { *FUNC_TABLE.add(spec as usize) }
    }
}

unsafe fn arginfo_for(spec: i32) -> Option<ArginfoSizeFunction> {
    unsafe {
        if (*(&raw const ARGINFO_TABLE)).is_null() || !(0..=255).contains(&spec) { None } else { *ARGINFO_TABLE.add(spec as usize) }
    }
}

unsafe fn vaarg_for(ty: c_int) -> Option<VaArgFunction> {
    unsafe {
        if (*(&raw const VAARG_TABLE)).is_null() || ty < PA_LAST || ty >= 0x100 { None } else { *VAARG_TABLE.add((ty - PA_LAST) as usize) }
    }
}

#[derive(Clone, Copy)]
struct SpecRec {
    info: PrintfInfo,
    end_of_fmt: usize,
    next_fmt: usize,
    prec_arg: i32,
    width_arg: i32,
    data_arg: i32,
    data_arg_type: c_int,
    ndata_args: usize,
    size: c_int,
}

impl SpecRec {
    const fn zero() -> SpecRec {
        SpecRec { info: PrintfInfo::zero(), end_of_fmt: 0, next_fmt: 0, prec_arg: -1, width_arg: -1, data_arg: -1, data_arg_type: 0, ndata_args: 0, size: -1 }
    }
}

fn is_digit(c: u8) -> bool {
    c.is_ascii_digit()
}

unsafe fn read_int<F: FmtChar>(p: *const F, i: &mut usize) -> i32 {
    unsafe {
        let mut retval = i32::from(F::at(p, *i)) - i32::from(b'0');
        loop {
            *i += 1;
            let c = F::at(p, *i);
            if !is_digit(c) {
                break;
            }
            if retval >= 0 {
                if i32::MAX / 10 < retval {
                    retval = -1;
                } else {
                    let digit = i32::from(c) - i32::from(b'0');
                    retval *= 10;
                    if i32::MAX - digit < retval {
                        retval = -1;
                    } else {
                        retval += digit;
                    }
                }
            }
        }
        retval
    }
}

unsafe fn handle_registered_modifier<F: FmtChar>(p: *const F, i: &mut usize, info: &mut PrintfInfo) -> bool {
    unsafe {
        if (*(&raw const MOD_TABLE)).is_null() {
            return false;
        }
        let first = F::raw(p, *i);
        if first > 255 {
            return false;
        }
        let mut runp = *MOD_TABLE.add(first as usize);
        let mut best_bit = 0;
        let mut best_len = 0usize;
        while !runp.is_null() {
            let r = &*runp;
            let mut k = 0;
            while F::raw(p, *i + 1 + k) != 0 && k < r.len && F::raw(p, *i + 1 + k) == u32::from(*r.text.add(k)) {
                k += 1;
            }
            if k == r.len && k + 1 > best_len {
                best_len = k + 1;
                best_bit = r.bit;
            }
            runp = r.next;
        }
        if best_bit != 0 {
            info.user |= best_bit as u16;
            *i += best_len;
            return true;
        }
        false
    }
}

unsafe fn parse_one<F: FmtChar>(p: *const F, start: usize, posn: usize, max_ref_arg: &mut usize, spec: &mut SpecRec) -> (usize, bool) {
    unsafe {
        let mut posn = posn;
        let mut nargs = 0usize;
        let mut failed = false;
        let mut i = start + 1;
        *spec = SpecRec::zero();
        spec.info = PrintfInfo::zero();
        if F::WIDE {
            spec.info.set(INFO_WIDE);
        }
        if is_digit(F::at(p, i)) {
            let begin = i;
            let n = read_int::<F>(p, &mut i);
            if n != 0 && F::at(p, i) == b'$' {
                i += 1;
                if n != -1 {
                    spec.data_arg = n - 1;
                    *max_ref_arg = (*max_ref_arg).max(n as usize);
                }
            } else {
                i = begin;
            }
        }
        loop {
            match F::at(p, i) {
                b' ' => spec.info.set(INFO_SPACE),
                b'+' => spec.info.set(INFO_SHOWSIGN),
                b'-' => spec.info.set(INFO_LEFT),
                b'#' => spec.info.set(INFO_ALT),
                b'0' => spec.info.pad = i32::from(b'0'),
                b'\'' => spec.info.set(INFO_GROUP),
                b'I' => spec.info.set(INFO_I18N),
                _ => break,
            }
            i += 1;
            if F::at(p, i) == 0 {
                break;
            }
        }
        if spec.info.has(INFO_LEFT) {
            spec.info.pad = i32::from(b' ');
        }
        spec.width_arg = -1;
        spec.info.width = 0;
        if F::at(p, i) == b'*' {
            i += 1;
            let begin = i;
            if is_digit(F::at(p, i)) {
                let n = read_int::<F>(p, &mut i);
                if n != 0 && F::at(p, i) == b'$' {
                    if n != -1 {
                        spec.width_arg = n - 1;
                        *max_ref_arg = (*max_ref_arg).max(n as usize);
                    }
                    i += 1;
                }
            }
            if spec.width_arg < 0 {
                spec.width_arg = posn as i32;
                posn += 1;
                nargs += 1;
                i = begin;
            }
        } else if is_digit(F::at(p, i)) {
            let n = read_int::<F>(p, &mut i);
            if n != -1 {
                spec.info.width = n;
            }
        }
        spec.prec_arg = -1;
        spec.info.prec = -1;
        if F::at(p, i) == b'.' {
            i += 1;
            if F::at(p, i) == b'*' {
                i += 1;
                let begin = i;
                if is_digit(F::at(p, i)) {
                    let n = read_int::<F>(p, &mut i);
                    if n != 0 && F::at(p, i) == b'$' {
                        if n != -1 {
                            spec.prec_arg = n - 1;
                            *max_ref_arg = (*max_ref_arg).max(n as usize);
                        }
                        i += 1;
                    }
                }
                if spec.prec_arg < 0 {
                    spec.prec_arg = posn as i32;
                    posn += 1;
                    nargs += 1;
                    i = begin;
                }
            } else if is_digit(F::at(p, i)) {
                let n = read_int::<F>(p, &mut i);
                if n != -1 {
                    spec.info.prec = n;
                }
            } else {
                spec.info.prec = 0;
            }
        }
        spec.info.user = 0;
        if !handle_registered_modifier(p, &mut i, &mut spec.info) {
            let c = F::at(p, i);
            i += 1;
            match c {
                b'h' => {
                    if F::at(p, i) != b'h' {
                        spec.info.set(INFO_SHORT);
                    } else {
                        i += 1;
                        spec.info.set(INFO_CHAR);
                    }
                }
                b'l' => {
                    spec.info.set(INFO_LONG);
                    if F::at(p, i) == b'l' {
                        i += 1;
                        spec.info.set(INFO_LONG_DOUBLE);
                    }
                }
                b'L' | b'q' => spec.info.set(INFO_LONG_DOUBLE),
                b'z' | b'Z' | b't' | b'j' => spec.info.set(INFO_LONG),
                b'w' => {
                    let mut is_fast = false;
                    if F::at(p, i) == b'f' {
                        i += 1;
                        is_fast = true;
                    }
                    let mut bitwidth = 0;
                    if is_digit(F::at(p, i)) {
                        bitwidth = read_int::<F>(p, &mut i);
                    }
                    if is_fast {
                        bitwidth = match bitwidth {
                            8 => 8,
                            16 => 64,
                            32 => 64,
                            64 => 64,
                            b => b,
                        };
                    }
                    match bitwidth {
                        8 => spec.info.set(INFO_CHAR),
                        16 => spec.info.set(INFO_SHORT),
                        32 => {}
                        64 => {
                            spec.info.set(INFO_LONG_DOUBLE);
                            spec.info.set(INFO_LONG);
                        }
                        _ => {
                            errno::set(22);
                            failed = true;
                        }
                    }
                }
                _ => i -= 1,
            }
        }
        let craw = F::raw(p, i);
        let c = F::at(p, i);
        i += 1;
        spec.info.spec = craw as i32;
        spec.size = -1;
        let mut ndata: Option<usize> = None;
        if let Some(ai) = arginfo_for(spec.info.spec) {
            let mut ty = 0;
            let mut size = -1;
            let r = ai(&spec.info, 1, &mut ty, &mut size) as c_int;
            if r >= 0 {
                spec.data_arg_type = ty;
                spec.size = size;
                ndata = Some(r as usize);
            }
        }
        match ndata {
            Some(n) => spec.ndata_args = n,
            None => {
                spec.ndata_args = 1;
                let i_ = &spec.info;
                match c {
                    b'i' | b'd' | b'u' | b'o' | b'X' | b'x' | b'B' | b'b' => {
                        spec.data_arg_type = if i_.has(INFO_LONG) {
                            PA_INT | PA_FLAG_LONG
                        } else if i_.has(INFO_SHORT) {
                            PA_INT | PA_FLAG_SHORT
                        } else if i_.has(INFO_CHAR) {
                            PA_CHAR
                        } else {
                            PA_INT
                        };
                    }
                    b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' => {
                        spec.data_arg_type = if i_.has(INFO_LONG_DOUBLE) { PA_DOUBLE | PA_FLAG_LONG_DOUBLE } else { PA_DOUBLE };
                    }
                    b'c' => spec.data_arg_type = PA_CHAR,
                    b'C' => spec.data_arg_type = PA_WCHAR,
                    b's' => spec.data_arg_type = PA_STRING,
                    b'S' => spec.data_arg_type = PA_WSTRING,
                    b'p' => spec.data_arg_type = PA_POINTER,
                    b'n' => spec.data_arg_type = PA_INT | PA_FLAG_PTR,
                    _ => spec.ndata_args = 0,
                }
            }
        }
        if spec.data_arg == -1 && spec.ndata_args > 0 {
            spec.data_arg = posn as i32;
            nargs += spec.ndata_args;
        }
        if c == 0 {
            spec.end_of_fmt = i - 1;
            spec.next_fmt = i - 1;
        } else {
            spec.end_of_fmt = i;
            let mut j = i;
            while F::at(p, j) != 0 && F::at(p, j) != b'%' {
                j += 1;
            }
            spec.next_fmt = j;
        }
        (nargs, failed)
    }
}

struct Arr<T: Copy> {
    p: *mut T,
    len: usize,
    cap: usize,
}

impl<T: Copy> Arr<T> {
    const fn new() -> Arr<T> {
        Arr { p: null_mut(), len: 0, cap: 0 }
    }
    unsafe fn push(&mut self, v: T) -> bool {
        unsafe {
            if self.len == self.cap {
                let ncap = if self.cap == 0 { 8 } else { self.cap * 2 };
                let np = rusty_libc_malloc::realloc(self.p.cast(), ncap * size_of::<T>()) as *mut T;
                if np.is_null() {
                    return false;
                }
                self.p = np;
                self.cap = ncap;
            }
            self.p.add(self.len).write(v);
            self.len += 1;
            true
        }
    }
    unsafe fn free(&mut self) {
        unsafe { rusty_libc_malloc::free(self.p.cast()) };
        self.p = null_mut();
        self.len = 0;
        self.cap = 0;
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct Slot([u8; 16]);

struct OneArg(Val);

impl Args for OneArg {
    fn get(&mut self, _kind: Kind, _pos: Option<usize>) -> Val {
        self.0
    }
}

unsafe fn read_slot<A: Args>(args: &mut A, ty: c_int, pos: usize, user: &mut Arr<*mut c_void>, size: c_int) -> Option<Slot> {
    unsafe {
        let mut s = Slot([0; 16]);
        let put64 = |s: &mut Slot, v: u64| s.0[..8].copy_from_slice(&v.to_le_bytes());
        if ty == PA_WCHAR || ty == PA_CHAR || ty == PA_INT || ty == PA_INT | PA_FLAG_SHORT {
            if let Val::I(v) = args.get(Kind::Int, Some(pos)) {
                s.0[..4].copy_from_slice(&(v as u32).to_le_bytes());
            }
        } else if ty == PA_INT | PA_FLAG_LONG_LONG || ty == PA_INT | PA_FLAG_LONG {
            if let Val::I(v) = args.get(Kind::Long, Some(pos)) {
                put64(&mut s, v);
            }
        } else if ty == PA_FLOAT || ty == PA_DOUBLE {
            if let Val::D(d) = args.get(Kind::Double, Some(pos)) {
                put64(&mut s, d.to_bits());
            }
        } else if ty == PA_DOUBLE | PA_FLAG_LONG_DOUBLE {
            if let Val::LD(b) = args.get(Kind::LongDouble, Some(pos)) {
                s.0 = b;
            }
        } else if ty == PA_STRING || ty == PA_WSTRING || ty == PA_POINTER || ty & PA_FLAG_PTR != 0 {
            if let Val::I(v) = args.get(Kind::Ptr, Some(pos)) {
                put64(&mut s, v);
            }
        } else if let Some(f) = vaarg_for(ty) {
            let mem = rusty_libc_malloc::calloc(1, (size.max(1)) as usize);
            if mem.is_null() {
                return None;
            }
            if !user.push(mem) {
                rusty_libc_malloc::free(mem);
                return None;
            }
            put64(&mut s, mem as usize as u64);
            let va = args.raw_va();
            if !va.is_null() {
                f(mem, va);
            }
        }
        Some(s)
    }
}

fn slot_val(ty: c_int, s: &Slot) -> Val {
    let u32v = u32::from_le_bytes([s.0[0], s.0[1], s.0[2], s.0[3]]);
    let u64v = u64::from_le_bytes([s.0[0], s.0[1], s.0[2], s.0[3], s.0[4], s.0[5], s.0[6], s.0[7]]);
    match ty {
        PA_FLOAT | PA_DOUBLE => Val::D(f64::from_bits(u64v)),
        x if x == PA_DOUBLE | PA_FLAG_LONG_DOUBLE => Val::LD(s.0),
        x if x == PA_INT | PA_FLAG_LONG_LONG || x == PA_INT | PA_FLAG_LONG => Val::I(u64v),
        PA_STRING | PA_WSTRING | PA_POINTER => Val::I(u64v),
        x if x & PA_FLAG_PTR != 0 => Val::I(u64v),
        _ => Val::I(u64::from(u32v)),
    }
}

struct Mini {
    buf: [u8; 80],
    len: usize,
}

impl Mini {
    fn push(&mut self, b: u8) {
        if self.len < self.buf.len() - 1 {
            self.buf[self.len] = b;
            self.len += 1;
        }
    }
    fn push_num(&mut self, mut v: u64) {
        let mut tmp = [0u8; 20];
        let mut k = tmp.len();
        loop {
            k -= 1;
            tmp[k] = b'0' + (v % 10) as u8;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        for &d in &tmp[k..] {
            self.push(d);
        }
    }
}

fn build_mini(info: &PrintfInfo, conv: u8) -> Mini {
    let mut m = Mini { buf: [0; 80], len: 0 };
    m.push(b'%');
    if info.has(INFO_ALT) {
        m.push(b'#');
    }
    if info.has(INFO_GROUP) {
        m.push(b'\'');
    }
    if info.has(INFO_SHOWSIGN) {
        m.push(b'+');
    } else if info.has(INFO_SPACE) {
        m.push(b' ');
    }
    if info.has(INFO_LEFT) {
        m.push(b'-');
    }
    if info.pad == i32::from(b'0') && !info.has(INFO_LEFT) {
        m.push(b'0');
    }
    if info.has(INFO_I18N) {
        m.push(b'I');
    }
    if info.width > 0 {
        m.push_num(info.width as u64);
    }
    if info.prec >= 0 {
        m.push(b'.');
        m.push_num(info.prec as u64);
    }
    let is_float = matches!(conv, b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A');
    if is_float {
        if info.has(INFO_LONG_DOUBLE) {
            m.push(b'L');
        }
    } else if info.has(INFO_CHAR) {
        m.push(b'h');
        m.push(b'h');
    } else if info.has(INFO_SHORT) {
        m.push(b'h');
    } else if info.has(INFO_LONG_DOUBLE) {
        m.push(b'l');
        m.push(b'l');
    } else if info.has(INFO_LONG) {
        m.push(b'l');
    }
    m.push(conv);
    m
}

fn print_unknown<S: Sink>(sink: &mut S, info: &PrintfInfo) -> Option<usize> {
    let mut m = Mini { buf: [0; 80], len: 0 };
    m.push(b'%');
    if info.has(INFO_ALT) {
        m.push(b'#');
    }
    if info.has(INFO_GROUP) {
        m.push(b'\'');
    }
    if info.has(INFO_SHOWSIGN) {
        m.push(b'+');
    } else if info.has(INFO_SPACE) {
        m.push(b' ');
    }
    if info.has(INFO_LEFT) {
        m.push(b'-');
    }
    if info.pad == i32::from(b'0') {
        m.push(b'0');
    }
    if info.has(INFO_I18N) {
        m.push(b'I');
    }
    if info.width != 0 {
        m.push_num(i64::from(info.width).unsigned_abs());
    }
    if info.prec != -1 {
        m.push(b'.');
        m.push_num(i64::from(info.prec).unsigned_abs());
    }
    if info.spec != 0 {
        m.push(info.spec as u8);
    }
    if sink.put(&m.buf[..m.len]) { Some(m.len) } else { None }
}

pub(crate) unsafe fn format_ext<S: Sink, A: Args, F: FmtChar>(sink: &mut S, fmt: *const F, args: &mut A) -> i32 {
    unsafe {
        if sink.partial_output_on_error() {
            return format_ext_to::<S, A, F>(sink, fmt, args);
        }
        if F::WIDE {
            let mut hold = HoldSinkW { buf: Arr::new() };
            let r = format_ext_to::<HoldSinkW, A, F>(&mut hold, fmt, args);
            let ok = r >= 0 && (hold.buf.len == 0 || sink.put_wide(core::slice::from_raw_parts(hold.buf.p, hold.buf.len)));
            hold.buf.free();
            return if ok { r } else { -1 };
        }
        let mut hold = HoldSink { buf: Arr::new() };
        let r = format_ext_to::<HoldSink, A, F>(&mut hold, fmt, args);
        let ok = r >= 0 && (hold.buf.len == 0 || sink.put(core::slice::from_raw_parts(hold.buf.p, hold.buf.len)));
        hold.buf.free();
        if ok { r } else { -1 }
    }
}

struct HoldSink {
    buf: Arr<u8>,
}

impl Sink for HoldSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        unsafe {
            for &b in bytes {
                if !self.buf.push(b) {
                    errno::set(12);
                    return false;
                }
            }
        }
        true
    }
}

struct HoldSinkW {
    buf: Arr<u32>,
}

impl Sink for HoldSinkW {
    const WIDE: bool = true;
    fn put_wide(&mut self, w: &[u32]) -> bool {
        unsafe {
            for &c in w {
                if !self.buf.push(c) {
                    errno::set(12);
                    return false;
                }
            }
        }
        true
    }
    fn put(&mut self, bytes: &[u8]) -> bool {
        unsafe {
            for &b in bytes {
                if !self.buf.push(u32::from(b)) {
                    errno::set(12);
                    return false;
                }
            }
        }
        true
    }
}

unsafe fn emit_lit<S: Sink, F: FmtChar>(sink: &mut S, fmt: *const F, start: usize, len: usize) -> bool {
    unsafe {
        if !F::WIDE {
            return sink.put(core::slice::from_raw_parts(fmt.add(start) as *const u8, len));
        }
        let mut chunk = [0u32; 64];
        let mut i = 0usize;
        while i < len {
            let k = (len - i).min(64);
            for (j, c) in chunk.iter_mut().enumerate().take(k) {
                *c = F::raw(fmt, start + i + j);
            }
            if !sink.put_wide(&chunk[..k]) {
                return false;
            }
            i += k;
        }
        true
    }
}

unsafe fn format_ext_to<S: Sink, A: Args, F: FmtChar>(sink: &mut S, fmt: *const F, args: &mut A) -> i32 {
    unsafe {
        let saved_errno = errno::get();
        let mut total: usize = 0;
        let mut f = 0usize;
        while F::raw(fmt, f) != 0 && F::raw(fmt, f) != u32::from(b'%') {
            f += 1;
        }
        if f > 0 {
            if !emit_lit::<S, F>(sink, fmt, 0, f) {
                return -1;
            }
            total += f;
        }
        if F::raw(fmt, f) == 0 {
            return total.min(i32::MAX as usize) as i32;
        }
        let mut specs: Arr<SpecRec> = Arr::new();
        let mut types: Arr<c_int> = Arr::new();
        let mut sizes: Arr<c_int> = Arr::new();
        let mut slots: Arr<Slot> = Arr::new();
        let mut user_mem: Arr<*mut c_void> = Arr::new();
        let r = format_ext_inner::<S, A, F>(sink, fmt, f, args, saved_errno, &mut total, &mut specs, &mut types, &mut sizes, &mut slots, &mut user_mem);
        for i in 0..user_mem.len {
            rusty_libc_malloc::free(*user_mem.p.add(i));
        }
        specs.free();
        types.free();
        sizes.free();
        slots.free();
        user_mem.free();
        if !r {
            return -1;
        }
        if total > i32::MAX as usize {
            errno::set(75);
            return -1;
        }
        total as i32
    }
}

#[allow(clippy::too_many_arguments)]
unsafe fn format_ext_inner<S: Sink, A: Args, F: FmtChar>(
    sink: &mut S,
    fmt: *const F,
    first: usize,
    args: &mut A,
    saved_errno: i32,
    total: &mut usize,
    specs: &mut Arr<SpecRec>,
    types: &mut Arr<c_int>,
    sizes: &mut Arr<c_int>,
    slots: &mut Arr<Slot>,
    user_mem: &mut Arr<*mut c_void>,
) -> bool {
    unsafe {
        let mut nargs = 0usize;
        let mut max_ref_arg = 0usize;
        let mut f = first;
        while F::raw(fmt, f) != 0 {
            let mut spec = SpecRec::zero();
            let (n, failed) = parse_one::<F>(fmt, f, nargs, &mut max_ref_arg, &mut spec);
            if failed {
                return false;
            }
            nargs += n;
            f = spec.next_fmt;
            if !specs.push(spec) {
                errno::set(12);
                return false;
            }
        }
        nargs = nargs.max(max_ref_arg);
        for _ in 0..nargs {
            if !types.push(PA_INT) || !sizes.push(0) || !slots.push(Slot([0; 16])) {
                errno::set(12);
                return false;
            }
        }
        for k in 0..specs.len {
            let s = *specs.p.add(k);
            if s.width_arg != -1 && (s.width_arg as usize) < nargs {
                *types.p.add(s.width_arg as usize) = PA_INT;
            }
            if s.prec_arg != -1 && (s.prec_arg as usize) < nargs {
                *types.p.add(s.prec_arg as usize) = PA_INT;
            }
            match s.ndata_args {
                0 => {}
                1 => {
                    if s.data_arg >= 0 && (s.data_arg as usize) < nargs {
                        *types.p.add(s.data_arg as usize) = s.data_arg_type;
                        *sizes.p.add(s.data_arg as usize) = s.size;
                    }
                }
                n => {
                    if let Some(ai) = arginfo_for(s.info.spec)
                        && s.data_arg >= 0
                        && (s.data_arg as usize) < nargs
                    {
                        let room = nargs - s.data_arg as usize;
                        ai(&s.info, n.min(room), types.p.add(s.data_arg as usize), sizes.p.add(s.data_arg as usize));
                    }
                }
            }
        }
        for cnt in 0..nargs {
            match read_slot(args, *types.p.add(cnt), cnt + 1, user_mem, *sizes.p.add(cnt)) {
                Some(s) => *slots.p.add(cnt) = s,
                None => {
                    errno::set(12);
                    return false;
                }
            }
        }
        for k in 0..specs.len {
            let mut s = *specs.p.add(k);
            if s.width_arg != -1 && (s.width_arg as usize) < nargs {
                let b = &(*slots.p.add(s.width_arg as usize)).0;
                s.info.width = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                if s.info.width < 0 {
                    s.info.width = s.info.width.wrapping_neg();
                    s.info.set(INFO_LEFT);
                }
            }
            if s.prec_arg != -1 && (s.prec_arg as usize) < nargs {
                let b = &(*slots.p.add(s.prec_arg as usize)).0;
                s.info.prec = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                if s.info.prec < 0 {
                    s.info.prec = -1;
                }
            }
            *specs.p.add(k) = s;
            let mut handled = false;
            if let Some(func) = func_for(s.info.spec) {
                match call_handler::<S, F>(sink, func, &s, slots, total) {
                    Ok(true) => handled = true,
                    Ok(false) => {}
                    Err(()) => return false,
                }
            }
            if !handled {
                let spec = s.info.spec;
                let ty = if s.data_arg >= 0 && (s.data_arg as usize) < nargs { *types.p.add(s.data_arg as usize) } else { PA_INT };
                let slot = if s.data_arg >= 0 && (s.data_arg as usize) < nargs { *slots.p.add(s.data_arg as usize) } else { Slot([0; 16]) };
                match spec as u8 {
                    b'%' if spec < 256 => {
                        if !sink.put(b"%") {
                            return false;
                        }
                        *total += 1;
                    }
                    b'n' if spec < 256 => {
                        let p = u64::from_le_bytes([slot.0[0], slot.0[1], slot.0[2], slot.0[3], slot.0[4], slot.0[5], slot.0[6], slot.0[7]]) as *mut u8;
                        if !p.is_null() {
                            let n = *total;
                            if s.info.has(INFO_CHAR) {
                                *(p as *mut i8) = n as i8;
                            } else if s.info.has(INFO_SHORT) {
                                *(p as *mut i16) = n as i16;
                            } else if s.info.has(INFO_LONG) || s.info.has(INFO_LONG_DOUBLE) {
                                *(p as *mut i64) = n as i64;
                            } else {
                                *(p as *mut i32) = n as i32;
                            }
                        }
                    }
                    b'm' | b'i' | b'd' | b'u' | b'o' | b'X' | b'x' | b'B' | b'b' | b'e' | b'E' | b'f' | b'F' | b'g' | b'G' | b'a' | b'A' | b'c' | b'C' | b's' | b'S' | b'p' if spec < 256 => {
                        let mini = build_mini(&s.info, spec as u8);
                        let mut mf = [F::from_ascii(0); 80];
                        for (k, b) in mini.buf.iter().enumerate().take(mini.len) {
                            mf[k] = F::from_ascii(*b);
                        }
                        let mut v = OneArg(slot_val(ty, &slot));
                        errno::set(saved_errno);
                        let n = fmt::format_builtin::<S, OneArg, F>(sink, mf.as_ptr(), &mut v);
                        if n < 0 {
                            return false;
                        }
                        *total += n as usize;
                    }
                    _ => match print_unknown(sink, &s.info) {
                        Some(n) => *total += n,
                        None => return false,
                    },
                }
            }
            let (a, b) = (s.end_of_fmt, s.next_fmt);
            if b > a {
                if !emit_lit::<S, F>(sink, fmt, a, b - a) {
                    return false;
                }
                *total += b - a;
            }
        }
        true
    }
}

unsafe fn call_handler<S: Sink, F: FmtChar>(sink: &mut S, func: PrintfFunction, s: &SpecRec, slots: &Arr<Slot>, total: &mut usize) -> Result<bool, ()> {
    unsafe {
        let mut ptrs: [*const c_void; 4] = [core::ptr::null(); 4];
        let mut heap: *mut *const c_void = null_mut();
        let n = s.ndata_args;
        let pp: *mut *const c_void = if n <= ptrs.len() {
            ptrs.as_mut_ptr()
        } else {
            heap = rusty_libc_malloc::calloc(n, size_of::<*const c_void>()) as *mut *const c_void;
            if heap.is_null() {
                return Err(());
            }
            heap
        };
        for i in 0..n {
            let idx = s.data_arg + i as i32;
            *pp.add(i) = if idx >= 0 && (idx as usize) < slots.len { slots.p.add(idx as usize) as *const c_void } else { core::ptr::null() };
        }
        let mut buf: *mut c_char = null_mut();
        let mut size: usize = 0;
        let fp = crate::file_extra::open_memstream_unit(&mut buf, &mut size, if F::WIDE { 4 } else { 1 });
        if fp.is_null() {
            rusty_libc_malloc::free(heap.cast());
            return Err(());
        }
        let done = func(fp, &s.info, pp);
        crate::file_api::fflush(fp);
        crate::file_api::fclose(fp);
        rusty_libc_malloc::free(heap.cast());
        let ok = if buf.is_null() || size == 0 {
            true
        } else if F::WIDE {
            sink.put_wide(core::slice::from_raw_parts(buf as *const u32, size))
        } else {
            sink.put(core::slice::from_raw_parts(buf as *const u8, size))
        };
        let written = size;
        rusty_libc_malloc::free(buf.cast());
        if !ok {
            return Err(());
        }
        *total += written;
        if done == -2 {
            return Ok(false);
        }
        if done < 0 {
            return Err(());
        }
        Ok(true)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn parse_printf_format(fmt: *const c_char, n: usize, argtypes: *mut c_int) -> usize {
    unsafe {
        let p = fmt as *const u8;
        let mut nargs = 0usize;
        let mut max_ref_arg = 0usize;
        let mut f = 0usize;
        while *p.add(f) != 0 && *p.add(f) != b'%' {
            f += 1;
        }
        while *p.add(f) != 0 {
            let mut spec = SpecRec::zero();
            let (k, _failed) = parse_one(p, f, nargs, &mut max_ref_arg, &mut spec);
            nargs += k;
            if spec.width_arg != -1 && (spec.width_arg as usize) < n {
                *argtypes.add(spec.width_arg as usize) = PA_INT;
            }
            if spec.prec_arg != -1 && (spec.prec_arg as usize) < n {
                *argtypes.add(spec.prec_arg as usize) = PA_INT;
            }
            if spec.data_arg >= 0 && (spec.data_arg as usize) < n {
                match spec.ndata_args {
                    0 => {}
                    1 => *argtypes.add(spec.data_arg as usize) = spec.data_arg_type,
                    k => {
                        if let Some(ai) = arginfo_for(spec.info.spec) {
                            let room = rusty_libc_malloc::calloc(k.max(n), size_of::<c_int>()) as *mut c_int;
                            ai(&spec.info, n - spec.data_arg as usize, argtypes.add(spec.data_arg as usize), room);
                            rusty_libc_malloc::free(room.cast());
                        }
                    }
                }
            }
            f = spec.next_fmt;
        }
        nargs.max(max_ref_arg)
    }
}

mod x87 {
    use core::arch::asm;

    pub fn ge(v: &[u8; 16], d: i32) -> bool {
        let r: u8;
        unsafe {
            asm!(
                "fild dword ptr [{d}]",
                "fld tbyte ptr [{v}]",
                "fucomip st, st(1)",
                "fstp st(0)",
                "setae {r}",
                v = in(reg) v.as_ptr(),
                d = in(reg) &d,
                r = out(reg_byte) r,
                out("st(0)") _, out("st(1)") _, out("st(2)") _, out("st(3)") _, out("st(4)") _, out("st(5)") _, out("st(6)") _, out("st(7)") _,
                options(nostack)
            );
        }
        r != 0
    }

    pub fn div(v: &mut [u8; 16], d: i32) {
        unsafe {
            asm!(
                "fld tbyte ptr [{v}]",
                "fidiv dword ptr [{d}]",
                "fstp tbyte ptr [{v}]",
                v = in(reg) v.as_mut_ptr(),
                d = in(reg) &d,
                out("st(0)") _, out("st(1)") _, out("st(2)") _, out("st(3)") _, out("st(4)") _, out("st(5)") _, out("st(6)") _, out("st(7)") _,
                options(nostack)
            );
        }
    }
}

unsafe fn fput(fp: *mut File, s: &[u8]) -> bool {
    unsafe {
        if (*fp).flags & crate::file::F_WIDE != 0 {
            for &b in s {
                if crate::wfile::putwc_raw(fp, u32::from(b)) == rusty_libc_wchar::WEOF {
                    return false;
                }
            }
            return true;
        }
        crate::file_api::fwrite(s.as_ptr().cast(), 1, s.len(), fp) == s.len()
    }
}

unsafe fn fpad(fp: *mut File, n: usize) -> bool {
    unsafe {
        let chunk = [b' '; 64];
        let mut left = n;
        while left > 0 {
            let k = left.min(64);
            if !fput(fp, &chunk[..k]) {
                return false;
            }
            left -= k;
        }
        true
    }
}

struct VecSink {
    buf: [u8; 512],
    len: usize,
    more: *mut Arr<u8>,
}

impl Sink for VecSink {
    fn put(&mut self, bytes: &[u8]) -> bool {
        unsafe {
            for &b in bytes {
                if self.len < self.buf.len() {
                    self.buf[self.len] = b;
                    self.len += 1;
                } else if !(*self.more).push(b) {
                    return false;
                }
            }
        }
        true
    }
}

unsafe fn printf_fp_f(fp: *mut File, info: &PrintfInfo, val: Val) -> c_int {
    unsafe { printf_fp_conv(fp, info, val, b'f') }
}

unsafe fn printf_fp_conv(fp: *mut File, info: &PrintfInfo, val: Val, conv: u8) -> c_int {
    unsafe {
        let mini = build_mini(info, conv);
        let mut more: Arr<u8> = Arr::new();
        let mut sink = VecSink { buf: [0; 512], len: 0, more: &mut more };
        let mut a = OneArg(val);
        let n = fmt::format_builtin::<VecSink, OneArg, u8>(&mut sink, mini.buf.as_ptr(), &mut a);
        let mut ok = n >= 0 && fput(fp, &sink.buf[..sink.len]);
        if ok && more.len > 0 {
            ok = fput(fp, core::slice::from_raw_parts(more.p, more.len));
        }
        more.free();
        if ok { n } else { -1 }
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn __printf_fp(fp: *mut File, info: *const PrintfInfo, args: *const *const c_void) -> c_int {
    unsafe {
        let info = &*info;
        let a0 = *args;
        let val = if info.has(INFO_BINARY128) {
            Val::Q((a0 as *const u128).read_unaligned())
        } else if info.has(INFO_LONG_DOUBLE) {
            Val::LD(*(a0 as *const [u8; 16]))
        } else {
            Val::D(*(a0 as *const f64))
        };
        let sp = if (0..256).contains(&info.spec) { info.spec as u8 } else { b'g' };
        let conv = match sp {
            b'e' | b'E' | b'f' | b'F' | b'g' | b'G' => sp,
            c if c.is_ascii_uppercase() => b'G',
            _ => b'g',
        };
        let mut fi = *info;
        if fi.has(INFO_BINARY128) {
            fi.flags &= !INFO_LONG_DOUBLE;
        }
        printf_fp_conv(fp, &fi, val, conv)
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn printf_size(fp: *mut File, info: *const PrintfInfo, args: *const *const c_void) -> c_int {
    unsafe {
        let info = &*info;
        let upper = (info.spec as u8).is_ascii_uppercase() && info.spec < 256;
        let tag: &[u8] = if upper { b" KMGTPEZY" } else { b" kmgtpezy" };
        let divisor: i32 = if upper { 1000 } else { 1024 };
        let mut ti = 0usize;
        let mut is_neg = false;
        let mut special: Option<&[u8; 3]> = None;
        let a0 = *args;
        let val: Val;
        if info.has(INFO_LONG_DOUBLE) {
            let mut b = *(a0 as *const [u8; 16]);
            let exp = u16::from_le_bytes([b[8], b[9]]) & 0x7fff;
            let mant = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
            if exp == 0x7fff {
                if mant << 1 != 0 {
                    special = Some(b"nan");
                } else {
                    is_neg = b[9] & 0x80 != 0;
                    special = Some(b"inf");
                }
            } else {
                while x87::ge(&b, divisor) && ti + 1 < tag.len() {
                    x87::div(&mut b, divisor);
                    ti += 1;
                }
            }
            val = Val::LD(b);
        } else {
            let mut d = *(a0 as *const f64);
            if d.is_nan() {
                special = Some(b"nan");
            } else if d.is_infinite() {
                is_neg = d.is_sign_negative();
                special = Some(b"inf");
            } else {
                while d >= f64::from(divisor) && ti + 1 < tag.len() {
                    d /= f64::from(divisor);
                    ti += 1;
                }
            }
            val = Val::D(d);
        }
        let mut done: c_int = 0;
        if let Some(sp) = special {
            let mut width = if info.prec > info.width { info.prec } else { info.width };
            if is_neg || info.has(INFO_SHOWSIGN) || info.has(INFO_SPACE) {
                width -= 1;
            }
            width -= 3;
            if !info.has(INFO_LEFT) && width > 0 {
                if !fpad(fp, width as usize) {
                    return -1;
                }
                done += width;
            }
            let sign: &[u8] = if is_neg {
                b"-"
            } else if info.has(INFO_SHOWSIGN) {
                b"+"
            } else if info.has(INFO_SPACE) {
                b" "
            } else {
                b""
            };
            if !fput(fp, sign) || !fput(fp, sp) {
                return -1;
            }
            done += sign.len() as c_int + 3;
            if info.has(INFO_LEFT) && width > 0 {
                if !fpad(fp, width as usize) {
                    return -1;
                }
                done += width;
            }
            return done;
        }
        let mut fp_info = *info;
        fp_info.spec = i32::from(b'f');
        fp_info.prec = if info.prec < 0 { 3 } else { info.prec };
        if fp_info.has(INFO_LEFT) && fp_info.pad == i32::from(b' ') {
            fp_info.width = 0;
            done = printf_fp_f(fp, &fp_info, val);
            if done > 0 {
                if !fput(fp, &tag[ti..ti + 1]) {
                    return -1;
                }
                done += 1;
                if info.width > done {
                    if !fpad(fp, (info.width - done) as usize) {
                        return -1;
                    }
                    done = info.width;
                }
            }
        } else {
            fp_info.width = info.width - 1;
            done = printf_fp_f(fp, &fp_info, val);
            if done > 0 {
                if !fput(fp, &tag[ti..ti + 1]) {
                    return -1;
                }
                done += 1;
            }
        }
        done
    }
}

#[cfg_attr(feature = "export", unsafe(no_mangle))]
pub unsafe extern "C" fn printf_size_info(info: *const PrintfInfo, n: usize, argtypes: *mut c_int) -> c_int {
    unsafe {
        if n >= 1 {
            *argtypes = PA_DOUBLE | if (*info).has(INFO_LONG_DOUBLE) { PA_FLAG_LONG_DOUBLE } else { 0 };
        }
        1
    }
}
