mod compat;
mod compat_table;
mod oldabi_table;
mod gen;
mod hdr;
mod hdr_cb;
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
            let _ = fs::remove_dir_all(&tmp);
            eprintln!("hdrgen: {} headers written to {}", files.len(), out.display());
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
        Some("compat-symver") => {
            if args.iter().any(|a| a == "--math") {
                compat::compat_symver_math(&root, arg(&args, "--defined").as_deref());
            } else {
                compat::compat_symver(&root, arg(&args, "--defined").as_deref());
            }
        }
        _ => {
            eprintln!("usage: hdrgen headers --out DIR [--root REPO] | versions [--libdir D] [--out D] | linkstubs OUTDIR | oldabi | svid | compat-symver [--math] [--defined FILE]");
            std::process::exit(2);
        }
    }
}
