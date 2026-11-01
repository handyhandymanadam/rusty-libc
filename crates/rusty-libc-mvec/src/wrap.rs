//! The AVX (`c`) and SSE (`b`) entry points of the functions that have an AVX2 kernel: they call the AVX2 entry point
//! (`simd.rs`, the `_ZGVd` name of the same function) after a test for AVX2, so every lane is exactly what the scalar function
//! gives; on a CPU without AVX2 they loop over the scalar function as before. `tools/gen_libmvec.py` writes the invocations.
/// The AVX entry point of a function whose AVX2 entry point `$d` takes and returns the same ymm vectors.
macro_rules! vec1k {
    ($name:ident, $vt:ty, $et:ty, $n:expr, $feat:literal, $f:ident, $d:path) => {
        /// # Safety
        /// Safe to call from code with this entry point's instruction set (its target feature); from other code, only on a
        /// CPU that has it.
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub extern "C" fn $name(x: $vt) -> $vt {
            if simd::avx2_ok() {
                // SAFETY: `$d` needs AVX2, which `avx2_ok` found (with the OS saving the ymm state); it takes and returns plain
                // vectors.
                return unsafe { $d(x) };
            }
            let mut a: [$et; $n] = x.to_lanes();
            let mut i = 0;
            while i < $n {
                a[i] = $f(a[i]);
                i += 1;
            }
            <$vt>::from_lanes(a)
        }
    };
}

/// `vec1k` for two vector arguments.
macro_rules! vec2k {
    ($name:ident, $vt:ty, $et:ty, $n:expr, $feat:literal, $f:ident, $d:path) => {
        /// # Safety
        /// Safe to call from code with this entry point's instruction set (its target feature); from other code, only on a
        /// CPU that has it.
        #[unsafe(no_mangle)]
        #[target_feature(enable = $feat)]
        pub extern "C" fn $name(x: $vt, y: $vt) -> $vt {
            if simd::avx2_ok() {
                // SAFETY: as in `vec1k`.
                return unsafe { $d(x, y) };
            }
            let mut a: [$et; $n] = x.to_lanes();
            let b: [$et; $n] = y.to_lanes();
            let mut i = 0;
            while i < $n {
                a[i] = $f(a[i], b[i]);
                i += 1;
            }
            <$vt>::from_lanes(a)
        }
    };
}

/// The SSE entry point (`$vt` an xmm vector) of a function with an AVX2 kernel: the lanes go twice into the ymm vector (`$wt`)
/// of the AVX2 entry point `$d` (the upper half repeats the lower, so no extra special lane arises) and the lower half comes
/// back. `$wide(x, x)` and `$low(r)` convert.
macro_rules! vec1b {
    ($name:ident, $vt:ty, $wt:ty, $et:ty, $n:expr, $f:ident, $d:path, $wide:ident, $low:ident) => {
        /// # Safety
        /// Safe to call from code with this entry point's instruction set (its target feature); from other code, only on a
        /// CPU that has it.
        #[unsafe(no_mangle)]
        #[target_feature(enable = "sse2")]
        pub extern "C" fn $name(x: $vt) -> $vt {
            #[inline(never)]
            #[target_feature(enable = "avx2")]
            fn wide(x: $vt) -> $vt {
                // a safe call: this function has AVX2 as `$d` needs
                $low($d($wide(x, x)))
            }
            if simd::avx2_ok() {
                // SAFETY: `wide` needs AVX2, which `avx2_ok` found (with the OS saving the ymm state).
                return unsafe { wide(x) };
            }
            let mut a: [$et; $n] = x.to_lanes();
            let mut i = 0;
            while i < $n {
                a[i] = $f(a[i]);
                i += 1;
            }
            <$vt>::from_lanes(a)
        }
    };
}

/// `vec1b` for two vector arguments.
macro_rules! vec2b {
    ($name:ident, $vt:ty, $wt:ty, $et:ty, $n:expr, $f:ident, $d:path, $wide:ident, $low:ident) => {
        /// # Safety
        /// Safe to call from code with this entry point's instruction set (its target feature); from other code, only on a
        /// CPU that has it.
        #[unsafe(no_mangle)]
        #[target_feature(enable = "sse2")]
        pub extern "C" fn $name(x: $vt, y: $vt) -> $vt {
            #[inline(never)]
            #[target_feature(enable = "avx2")]
            fn wide(x: $vt, y: $vt) -> $vt {
                // a safe call: this function has AVX2 as `$d` needs
                $low($d($wide(x, x), $wide(y, y)))
            }
            if simd::avx2_ok() {
                // SAFETY: as in `vec1b`.
                return unsafe { wide(x, y) };
            }
            let mut a: [$et; $n] = x.to_lanes();
            let b: [$et; $n] = y.to_lanes();
            let mut i = 0;
            while i < $n {
                a[i] = $f(a[i], b[i]);
                i += 1;
            }
            <$vt>::from_lanes(a)
        }
    };
}
