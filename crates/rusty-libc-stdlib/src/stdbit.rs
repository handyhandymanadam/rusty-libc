//! stdbit.h (C23 bit utilities): the 14 families of `stdc_*` functions for unsigned char, short, int,
//! long and long long. Counts return `unsigned int`; `bit_floor` and `bit_ceil` return the argument's
//! type (`bit_ceil` of a value above the top power of two wraps to 0, like glibc's code).

macro_rules! paste_names {
    ($t:ty, uc) => { stdbit_fns!($t, stdc_leading_zeros_uc, stdc_leading_ones_uc, stdc_trailing_zeros_uc, stdc_trailing_ones_uc, stdc_first_leading_zero_uc, stdc_first_leading_one_uc, stdc_first_trailing_zero_uc, stdc_first_trailing_one_uc, stdc_count_zeros_uc, stdc_count_ones_uc, stdc_has_single_bit_uc, stdc_bit_width_uc, stdc_bit_floor_uc, stdc_bit_ceil_uc); };
    ($t:ty, us) => { stdbit_fns!($t, stdc_leading_zeros_us, stdc_leading_ones_us, stdc_trailing_zeros_us, stdc_trailing_ones_us, stdc_first_leading_zero_us, stdc_first_leading_one_us, stdc_first_trailing_zero_us, stdc_first_trailing_one_us, stdc_count_zeros_us, stdc_count_ones_us, stdc_has_single_bit_us, stdc_bit_width_us, stdc_bit_floor_us, stdc_bit_ceil_us); };
    ($t:ty, ui) => { stdbit_fns!($t, stdc_leading_zeros_ui, stdc_leading_ones_ui, stdc_trailing_zeros_ui, stdc_trailing_ones_ui, stdc_first_leading_zero_ui, stdc_first_leading_one_ui, stdc_first_trailing_zero_ui, stdc_first_trailing_one_ui, stdc_count_zeros_ui, stdc_count_ones_ui, stdc_has_single_bit_ui, stdc_bit_width_ui, stdc_bit_floor_ui, stdc_bit_ceil_ui); };
    ($t:ty, ul) => { stdbit_fns!($t, stdc_leading_zeros_ul, stdc_leading_ones_ul, stdc_trailing_zeros_ul, stdc_trailing_ones_ul, stdc_first_leading_zero_ul, stdc_first_leading_one_ul, stdc_first_trailing_zero_ul, stdc_first_trailing_one_ul, stdc_count_zeros_ul, stdc_count_ones_ul, stdc_has_single_bit_ul, stdc_bit_width_ul, stdc_bit_floor_ul, stdc_bit_ceil_ul); };
    ($t:ty, ull) => { stdbit_fns!($t, stdc_leading_zeros_ull, stdc_leading_ones_ull, stdc_trailing_zeros_ull, stdc_trailing_ones_ull, stdc_first_leading_zero_ull, stdc_first_leading_one_ull, stdc_first_trailing_zero_ull, stdc_first_trailing_one_ull, stdc_count_zeros_ull, stdc_count_ones_ull, stdc_has_single_bit_ull, stdc_bit_width_ull, stdc_bit_floor_ull, stdc_bit_ceil_ull); };
}

macro_rules! stdbit_fns {
    ($t:ty, $lz:ident, $lo:ident, $tz:ident, $to:ident, $flz:ident, $flo:ident, $ftz:ident, $fto:ident, $cz:ident, $co:ident, $hs:ident, $bw:ident, $bf:ident, $bc:ident) => {
        /// Leading zero bits (the width for 0).
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $lz(x: $t) -> u32 {
            x.leading_zeros()
        }
        /// Leading one bits.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $lo(x: $t) -> u32 {
            (!x).leading_zeros()
        }
        /// Trailing zero bits (the width for 0).
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $tz(x: $t) -> u32 {
            x.trailing_zeros()
        }
        /// Trailing one bits.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $to(x: $t) -> u32 {
            (!x).trailing_zeros()
        }
        /// 1-based position of the first zero bit counting from the top, 0 if there is none.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $flz(x: $t) -> u32 {
            if x == <$t>::MAX { 0 } else { (!x).leading_zeros() + 1 }
        }
        /// 1-based position of the first one bit counting from the top, 0 if there is none.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $flo(x: $t) -> u32 {
            if x == 0 { 0 } else { x.leading_zeros() + 1 }
        }
        /// 1-based position of the first zero bit counting from the bottom, 0 if there is none.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $ftz(x: $t) -> u32 {
            if x == <$t>::MAX { 0 } else { (!x).trailing_zeros() + 1 }
        }
        /// 1-based position of the first one bit counting from the bottom, 0 if there is none.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $fto(x: $t) -> u32 {
            if x == 0 { 0 } else { x.trailing_zeros() + 1 }
        }
        /// Number of zero bits.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $cz(x: $t) -> u32 {
            x.count_zeros()
        }
        /// Number of one bits.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $co(x: $t) -> u32 {
            x.count_ones()
        }
        /// True if exactly one bit is set.
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $hs(x: $t) -> bool {
            x.count_ones() == 1
        }
        /// Smallest number of bits that can represent `x` (0 for 0).
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $bw(x: $t) -> u32 {
            <$t>::BITS - x.leading_zeros()
        }
        /// Largest power of two not above `x` (0 for 0).
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $bf(x: $t) -> $t {
            if x == 0 { 0 } else { (1 as $t) << (<$t>::BITS - 1 - x.leading_zeros()) }
        }
        /// Smallest power of two not below `x` (1 for 0 and 1; 0 if it does not fit).
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $bc(x: $t) -> $t {
            if x <= 1 { 1 } else { (1 as $t).checked_shl(<$t>::BITS - (x - 1).leading_zeros()).unwrap_or(0) }
        }
    };
}

paste_names!(u8, uc);
paste_names!(u16, us);
paste_names!(u32, ui);
paste_names!(u64, ul);
paste_names!(u64, ull);

#[cfg(test)]
#[allow(clippy::undocumented_unsafe_blocks, clippy::multiple_unsafe_ops_per_block)]
mod tests {
    use super::*;

    macro_rules! host {
        ($($n:ident: $t:ty => $r:ty),* $(,)?) => {
            unsafe extern "C" { $(pub fn $n(x: $t) -> $r;)* }
        };
    }
    mod h {
        host!(
            stdc_leading_zeros_uc: u8 => u32, stdc_leading_zeros_ull: u64 => u32,
            stdc_leading_ones_us: u16 => u32, stdc_trailing_zeros_ui: u32 => u32, stdc_trailing_ones_ul: u64 => u32,
            stdc_first_leading_zero_uc: u8 => u32, stdc_first_leading_one_us: u16 => u32,
            stdc_first_trailing_zero_ui: u32 => u32, stdc_first_trailing_one_ull: u64 => u32,
            stdc_count_zeros_us: u16 => u32, stdc_count_ones_ull: u64 => u32,
            stdc_has_single_bit_uc: u8 => bool, stdc_has_single_bit_ul: u64 => bool,
            stdc_bit_width_ui: u32 => u32, stdc_bit_floor_us: u16 => u16, stdc_bit_floor_ull: u64 => u64,
            stdc_bit_ceil_uc: u8 => u8, stdc_bit_ceil_us: u16 => u16, stdc_bit_ceil_ui: u32 => u32,
        );
    }

    fn samples64() -> Vec<u64> {
        let mut v = vec![0, 1, 2, 3, u64::MAX, u64::MAX - 1, 1 << 63, (1 << 63) + 1, 0x8000_0000, 0x7fff_ffff];
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..20000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            v.push(x >> (x % 64));
        }
        v
    }

    #[test]
    fn eight_and_sixteen_bit_exhaustive_and_wide_samples_match_glibc() {
        unsafe {
            for x in 0..=u8::MAX {
                assert_eq!(stdc_leading_zeros_uc(x), h::stdc_leading_zeros_uc(x), "lz {x}");
                assert_eq!(stdc_first_leading_zero_uc(x), h::stdc_first_leading_zero_uc(x), "flz {x}");
                assert_eq!(stdc_has_single_bit_uc(x), h::stdc_has_single_bit_uc(x), "hs {x}");
                assert_eq!(stdc_bit_ceil_uc(x), h::stdc_bit_ceil_uc(x), "ceil {x}");
            }
            for x in 0..=u16::MAX {
                assert_eq!(stdc_leading_ones_us(x), h::stdc_leading_ones_us(x), "lo {x}");
                assert_eq!(stdc_first_leading_one_us(x), h::stdc_first_leading_one_us(x), "flo {x}");
                assert_eq!(stdc_count_zeros_us(x), h::stdc_count_zeros_us(x), "cz {x}");
                assert_eq!(stdc_bit_floor_us(x), h::stdc_bit_floor_us(x), "floor {x}");
                assert_eq!(stdc_bit_ceil_us(x), h::stdc_bit_ceil_us(x), "ceil {x}");
            }
            for x in samples64() {
                let (a, b) = (x as u32, x);
                assert_eq!(stdc_trailing_zeros_ui(a), h::stdc_trailing_zeros_ui(a), "tz {a}");
                assert_eq!(stdc_first_trailing_zero_ui(a), h::stdc_first_trailing_zero_ui(a), "ftz {a}");
                assert_eq!(stdc_bit_width_ui(a), h::stdc_bit_width_ui(a), "bw {a}");
                assert_eq!(stdc_bit_ceil_ui(a), h::stdc_bit_ceil_ui(a), "ceil {a}");
                assert_eq!(stdc_leading_zeros_ull(b), h::stdc_leading_zeros_ull(b), "lz {b}");
                assert_eq!(stdc_trailing_ones_ul(b), h::stdc_trailing_ones_ul(b), "to {b}");
                assert_eq!(stdc_first_trailing_one_ull(b), h::stdc_first_trailing_one_ull(b), "fto {b}");
                assert_eq!(stdc_count_ones_ull(b), h::stdc_count_ones_ull(b), "co {b}");
                assert_eq!(stdc_has_single_bit_ul(b), h::stdc_has_single_bit_ul(b), "hs {b}");
                assert_eq!(stdc_bit_floor_ull(b), h::stdc_bit_floor_ull(b), "floor {b}");
            }
        }
    }
}
