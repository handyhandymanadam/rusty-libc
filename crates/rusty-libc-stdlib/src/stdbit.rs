macro_rules! paste_names {
    ($t:ty, uc) => { stdbit_fns!($t, stdc_leading_zeros_uc, stdc_leading_ones_uc, stdc_trailing_zeros_uc, stdc_trailing_ones_uc, stdc_first_leading_zero_uc, stdc_first_leading_one_uc, stdc_first_trailing_zero_uc, stdc_first_trailing_one_uc, stdc_count_zeros_uc, stdc_count_ones_uc, stdc_has_single_bit_uc, stdc_bit_width_uc, stdc_bit_floor_uc, stdc_bit_ceil_uc); };
    ($t:ty, us) => { stdbit_fns!($t, stdc_leading_zeros_us, stdc_leading_ones_us, stdc_trailing_zeros_us, stdc_trailing_ones_us, stdc_first_leading_zero_us, stdc_first_leading_one_us, stdc_first_trailing_zero_us, stdc_first_trailing_one_us, stdc_count_zeros_us, stdc_count_ones_us, stdc_has_single_bit_us, stdc_bit_width_us, stdc_bit_floor_us, stdc_bit_ceil_us); };
    ($t:ty, ui) => { stdbit_fns!($t, stdc_leading_zeros_ui, stdc_leading_ones_ui, stdc_trailing_zeros_ui, stdc_trailing_ones_ui, stdc_first_leading_zero_ui, stdc_first_leading_one_ui, stdc_first_trailing_zero_ui, stdc_first_trailing_one_ui, stdc_count_zeros_ui, stdc_count_ones_ui, stdc_has_single_bit_ui, stdc_bit_width_ui, stdc_bit_floor_ui, stdc_bit_ceil_ui); };
    ($t:ty, ul) => { stdbit_fns!($t, stdc_leading_zeros_ul, stdc_leading_ones_ul, stdc_trailing_zeros_ul, stdc_trailing_ones_ul, stdc_first_leading_zero_ul, stdc_first_leading_one_ul, stdc_first_trailing_zero_ul, stdc_first_trailing_one_ul, stdc_count_zeros_ul, stdc_count_ones_ul, stdc_has_single_bit_ul, stdc_bit_width_ul, stdc_bit_floor_ul, stdc_bit_ceil_ul); };
    ($t:ty, ull) => { stdbit_fns!($t, stdc_leading_zeros_ull, stdc_leading_ones_ull, stdc_trailing_zeros_ull, stdc_trailing_ones_ull, stdc_first_leading_zero_ull, stdc_first_leading_one_ull, stdc_first_trailing_zero_ull, stdc_first_trailing_one_ull, stdc_count_zeros_ull, stdc_count_ones_ull, stdc_has_single_bit_ull, stdc_bit_width_ull, stdc_bit_floor_ull, stdc_bit_ceil_ull); };
}

macro_rules! stdbit_fns {
    ($t:ty, $lz:ident, $lo:ident, $tz:ident, $to:ident, $flz:ident, $flo:ident, $ftz:ident, $fto:ident, $cz:ident, $co:ident, $hs:ident, $bw:ident, $bf:ident, $bc:ident) => {
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $lz(x: $t) -> u32 {
            x.leading_zeros()
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $lo(x: $t) -> u32 {
            (!x).leading_zeros()
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $tz(x: $t) -> u32 {
            x.trailing_zeros()
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $to(x: $t) -> u32 {
            (!x).trailing_zeros()
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $flz(x: $t) -> u32 {
            if x == <$t>::MAX { 0 } else { (!x).leading_zeros() + 1 }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $flo(x: $t) -> u32 {
            if x == 0 { 0 } else { x.leading_zeros() + 1 }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $ftz(x: $t) -> u32 {
            if x == <$t>::MAX { 0 } else { (!x).trailing_zeros() + 1 }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $fto(x: $t) -> u32 {
            if x == 0 { 0 } else { x.trailing_zeros() + 1 }
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $cz(x: $t) -> u32 {
            x.count_zeros()
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $co(x: $t) -> u32 {
            x.count_ones()
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $hs(x: $t) -> bool {
            x.count_ones() == 1
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $bw(x: $t) -> u32 {
            <$t>::BITS - x.leading_zeros()
        }
        #[cfg_attr(feature = "export", unsafe(no_mangle))]
        pub extern "C" fn $bf(x: $t) -> $t {
            if x == 0 { 0 } else { (1 as $t) << (<$t>::BITS - 1 - x.leading_zeros()) }
        }
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

