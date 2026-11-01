//! The test kit (src/testkit, cfg(test) only) uses MPFR as its oracle. The machine has
//! libmpfr.so.6 but no headers and no libmpfr.so symlink, so the test targets are linked against
//! the versioned file by name. Normal builds (cargo build) link nothing and never need MPFR.
//! Override with LIBC_PORT_MPFR_LINK (for example "-lmpfr" where a development package exists).
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=LIBC_PORT_MPFR_LINK");
    let arg = std::env::var("LIBC_PORT_MPFR_LINK").unwrap_or_else(|_| "-l:libmpfr.so.6".to_string());
    // Applies to this package's own link steps only (its unit-test binary); the rlib has none and
    // dependent crates are not affected.
    println!("cargo:rustc-link-arg={arg}");
}
