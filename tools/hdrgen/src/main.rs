//! hdrgen: builds the C headers of the sysroot (and, in later subcommands, the other build-time generated
//! files) from the Rust library crates and from header data held in Rust source files.

mod check;
mod compat;
mod compat_table;
mod oldabi_table;
mod compare;
mod gen;
mod hdr;
mod hdr_cb;
mod layout;
mod hdr_tests;
mod model;
mod math;
mod specs;
mod sys;
mod text;
mod versions;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn default_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn write_tree(out: &Path, files: &BTreeMap<String, String>) {
    for (rel, text) in files {
        let p = out.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = arg(&args, "--root").map(PathBuf::from).unwrap_or_else(default_root);
    let root = fs::canonicalize(&root).unwrap_or(root);
    match args.first().map(|s| s.as_str()) {
        Some("headers") => {
            let out = PathBuf::from(arg(&args, "--out").expect("--out DIR"));
            let tmp = out.parent().unwrap_or(Path::new(".")).join("hdrgen-tmp");
            let files = gen::full_tree(&root, &tmp);
            write_tree(&out, &files);
            if let Some(t) = arg(&args, "--tests-out") {
                let tf: BTreeMap<String, String> = hdr_tests::TESTS.iter().map(|h| (h.path.to_string(), h.render())).collect();
                write_tree(Path::new(&t), &tf);
            }
            let _ = fs::remove_dir_all(&tmp);
            eprintln!("hdrgen: {} headers written to {}", files.len(), out.display());
        }
        Some("compare") => {
            let old = PathBuf::from(arg(&args, "--old").expect("--old DIR"));
            let new = PathBuf::from(arg(&args, "--new").expect("--new DIR"));
            let scratch = arg(&args, "--scratch").map(PathBuf::from).unwrap_or_else(|| compare::scratch_default(&root));
            let r = compare::compare(&old, &new, args.iter().any(|a| a == "--preprocess-all"), &scratch);
            compare::print(&r);
            if !r.different.is_empty() || !r.only_old.is_empty() || !r.only_new.is_empty() {
                std::process::exit(1);
            }
        }
        Some("check-consts") => {
            let cc = check::crate_consts(&root);
            let st = check::check_headers(check::sources(), &cc);
            check::print_report(&st);
            if st.values().any(|s| !s.mismatched.is_empty()) {
                std::process::exit(1);
            }
        }
        Some("check-glibc") => {
            let st = check::check_against_glibc(check::sources(), &compare::scratch_default(&root).join("glibc"));
            check::print_glibc_report(&st);
        }
        Some("check-layouts") => {
            let inc = PathBuf::from(arg(&args, "--inc").expect("--inc DIR (a generated include tree)"));
            let v = layout::check_layouts(&root, hdr::ALL, &inc, &compare::scratch_default(&root).join("layout"));
            layout::print_layouts(&v);
            if v.iter().any(|s| s.result.starts_with("DIFFER")) {
                std::process::exit(1);
            }
        }
        Some("versions") => {
            let libdir = arg(&args, "--libdir").unwrap_or_else(|| "/usr/lib64".into());
            versions::versions(&root, &libdir, arg(&args, "--out").map(PathBuf::from).as_deref());
        }
        Some("stubsrc") => {
            let lib = args.get(1).expect("stubsrc LIB BASE");
            let base = PathBuf::from(args.get(2).expect("stubsrc LIB BASE"));
            versions::stubsrc(&root, lib, &base);
        }
        Some("linkstubs") => {
            let out = PathBuf::from(args.get(1).expect("linkstubs OUTDIR"));
            versions::linkstubs(&root, &out);
        }
        Some("oldabi") => compat::oldabi(&root, arg(&args, "--defined").as_deref()),
        Some("svid") => compat::svid(&root),
        Some("svid-raw") => compat::svid_raw(args.get(1).expect("svid-raw REF OUR")),
        Some("compat-symver") => {
            if args.iter().any(|a| a == "--math") {
                compat::compat_symver_math(&root, arg(&args, "--defined").as_deref());
            } else {
                compat::compat_symver(&root, arg(&args, "--defined").as_deref());
            }
        }
        Some("methods") => methods(&root),
        Some("exceptions") => exceptions(args.iter().any(|a| a == "--list")),
        _ => {
            eprintln!("usage: hdrgen headers --out DIR [--tests-out DIR] [--root REPO] | versions [--libdir D] [--out D] | linkstubs OUTDIR | oldabi | svid | svid-raw REF | compat-symver [--math] [--defined FILE] | check-consts | check-glibc | check-layouts --inc DIR | compare --old DIR --new DIR [--preprocess-all] | methods | exceptions [--list]");
            std::process::exit(2);
        }
    }
}

/// Every piece of C text that has to stay text (macros, conditionals, _Generic, static inline), by header and reason.
fn exceptions(list: bool) {
    use model::Reason;
    let ex = model::exceptions(hdr::ALL);
    let mut by_reason: BTreeMap<Reason, usize> = BTreeMap::new();
    let mut by_header: BTreeMap<&str, BTreeMap<Reason, usize>> = BTreeMap::new();
    for e in &ex {
        *by_reason.entry(e.reason).or_default() += 1;
        *by_header.entry(e.header.as_str()).or_default().entry(e.reason).or_default() += 1;
    }
    if list {
        for e in &ex {
            println!("{}\t{}\t{}", e.header, e.reason.label(), e.what);
        }
        return;
    }
    let all = [Reason::StdMacro, Reason::FeatureTest, Reason::Generic, Reason::StaticInline, Reason::Attribute, Reason::GlibcMacro, Reason::Other];
    println!("raw-text blocks by reason ({} in {} headers):", ex.len(), by_header.len());
    for r in all {
        println!("  {:6} {}", by_reason.get(&r).copied().unwrap_or(0), r.label());
    }
    println!("\nper header (std-macro / feature-test / _Generic / static-inline / attribute / glibc-macro / other):");
    for (h, m) in &by_header {
        let c: Vec<String> = all.iter().map(|r| m.get(r).copied().unwrap_or(0).to_string()).collect();
        println!("  {:34} {}", h, c.join(" / "));
    }
}

/// Per header: where its content comes from, and how its constants are kept in step with the crates.
fn methods(root: &Path) {
    let specs = specs::build_specs();
    let mut paths: BTreeMap<String, (bool, bool, bool)> = BTreeMap::new(); // (cbindgen from crates, table data, table text in cbindgen config)
    let sys_like: Vec<String> = sys::sys_fns().iter().map(|(h, _)| h.to_string()).chain(sys::CONST_ONLY.iter().map(|s| s.to_string())).collect();
    for s in &specs {
        paths.entry(format!("{}.h", s.name)).or_default().0 = true;
    }
    for h in sys_like {
        paths.entry(format!("{h}.h")).or_default().0 = true;
    }
    for h in hdr::ALL {
        paths.entry(h.path.to_string()).or_default().1 = true;
    }
    for s in &specs {
        if hdr_cb::lookup(&s.config).is_some() {
            paths.entry(format!("{}.h", s.name)).or_default().2 = true;
        }
    }
    for p in ["bits/rlibc-mathaliases.h", "bits/rlibc-mathldcalls.h", "bits/rlibc-mathquadcalls.h", "complex.h"] {
        paths.entry(p.to_string()).or_default().0 = true;
    }
    let cc = check::crate_consts(root);
    let st = check::check_headers(check::sources(), &cc);
    println!("{:34} {:48} {:>9} {:>11}", "header", "method", "crate-eq", "table-only");
    let (mut a, mut b, mut c) = (0, 0, 0);
    for (p, (cb, table, cbt)) in &paths {
        let method = match (*cb, *table || *cbt) {
            (true, true) => {
                b += 1;
                "prototypes/types from crates (cbindgen) + Rust tables"
            }
            (true, false) => {
                a += 1;
                "from the crate sources (cbindgen) / generated tables"
            }
            _ => {
                c += 1;
                "Rust tables (constants checked, see columns)"
            }
        };
        let s = st.get(p.as_str());
        println!("{:34} {:48} {:>9} {:>11}", p, method, s.map_or(0, |s| s.checked), s.map_or(0, |s| s.table_only));
    }
    println!("{} headers: {} from the crates only, {} crates + tables, {} tables only", paths.len(), a, b, c);
    println!("constants: tables are cross-checked by `cargo test` (crate consts, struct layouts) and `hdrgen check-glibc` (host glibc values)");
}
