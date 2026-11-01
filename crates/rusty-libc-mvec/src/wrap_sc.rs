//! The AVX (`c`) sincos entry points through the AVX2 entry point of `simd/sk.rs` (as `wrap.rs`): the vectors of pointers of
//! this ISA are xmm registers (AVX has no 256-bit integer instructions), which are joined into the ymm vectors of the AVX2 entry
//! point. (The SSE ones through the ymm entry point on repeated lanes measured 1.76x slower than the loop and stay loops.) `tools/gen_libmvec.py` writes the invocations.

/// The AVX double sincos (x in a ymm register, the 4 pointers of each result in two xmm registers) through the AVX2 entry point
/// `$d` (the pointers in ymm registers) after the AVX2 test.
macro_rules! sincosk_c2 {
    ($name:ident, $d:path, $f:ident) => {
        /// # Safety
        /// The vector ABI's contract: every lane of the four pointer vectors is a valid, aligned pointer to writable memory.
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx")]
        pub unsafe extern "C" fn $name(x: __m256d, sin_lo: __m128i, sin_hi: __m128i, cos_lo: __m128i, cos_hi: __m128i) {
            if simd::avx2_ok() {
                // SAFETY: `$d` needs AVX2, which `avx2_ok` found; its pointer contract is the caller's.
                return unsafe { $d(x, _mm256_set_m128i(sin_hi, sin_lo), _mm256_set_m128i(cos_hi, cos_lo)) };
            }
            let a: [f64; 4] = x.to_lanes();
            let (sl, sh): ([u64; 2], [u64; 2]) = (sin_lo.to_lanes(), sin_hi.to_lanes());
            let (cl, ch): ([u64; 2], [u64; 2]) = (cos_lo.to_lanes(), cos_hi.to_lanes());
            let mut i = 0;
            while i < 2 {
                // SAFETY: the caller's contract: every lane of the pointer vectors is a valid, aligned pointer.
                unsafe { $f(a[i], lane_ptr(sl[i]), lane_ptr(cl[i])) };
                // SAFETY: as above.
                unsafe { $f(a[i + 2], lane_ptr(sh[i]), lane_ptr(ch[i])) };
                i += 1;
            }
        }
    };
}

/// The AVX float sincos (x in a ymm register, 8 pointers of each result in four xmm registers) through the AVX2 entry point.
macro_rules! sincosk_c4 {
    ($name:ident, $d:path, $f:ident) => {
        /// # Safety
        /// The vector ABI's contract: every lane of the eight pointer vectors is a valid, aligned pointer to writable memory.
        #[unsafe(no_mangle)]
        #[target_feature(enable = "avx")]
        #[allow(clippy::too_many_arguments)]
        pub unsafe extern "C" fn $name(x: __m256, s0: __m128i, s1: __m128i, s2: __m128i, s3: __m128i, c0: __m128i, c1: __m128i, c2: __m128i, c3: __m128i) {
            if simd::avx2_ok() {
                // SAFETY: as in `sincosk_c2`.
                return unsafe { $d(x, _mm256_set_m128i(s1, s0), _mm256_set_m128i(s3, s2), _mm256_set_m128i(c1, c0), _mm256_set_m128i(c3, c2)) };
            }
            let a: [f32; 8] = x.to_lanes();
            let s: [[u64; 2]; 4] = [s0.to_lanes(), s1.to_lanes(), s2.to_lanes(), s3.to_lanes()];
            let c: [[u64; 2]; 4] = [c0.to_lanes(), c1.to_lanes(), c2.to_lanes(), c3.to_lanes()];
            let mut i = 0;
            while i < 8 {
                // SAFETY: the caller's contract: every lane of the pointer vectors is a valid, aligned pointer.
                unsafe { $f(a[i], lane_ptr(s[i / 2][i % 2]), lane_ptr(c[i / 2][i % 2])) };
                i += 1;
            }
        }
    };
}
