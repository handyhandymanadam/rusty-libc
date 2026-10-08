use regex_lite::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const ORDER: [&str; 4] = ["misc", "gnu", "ext", "floatn"];

fn macro_of(t: &str) -> &'static str {
    match t {
        "misc" => "__RLIBC_MATH_MISC",
        "gnu" => "__RLIBC_MATH_GNU",
        "ext" => "__RLIBC_MATH_EXT",
        "floatn" => "__RLIBC_MATH_FLOATN",
        _ => panic!("tier {t}"),
    }
}

fn words(s: &str) -> Vec<&str> {
    s.split_whitespace().collect()
}

pub struct Math {
    src: PathBuf,
    tier: BTreeMap<String, &'static str>,
    floatn_re: Regex,
    lgamma_re: Regex,
}

fn order_idx(t: &str) -> usize {
    ORDER.iter().position(|x| *x == t).unwrap()
}

pub fn cond(tiers: &[&str]) -> String {
    tiers.iter().map(|t| format!("defined {}", macro_of(t))).collect::<Vec<_>>().join(" && ")
}

impl Math {
    pub fn new(root: &Path) -> Math {
        let mut base: BTreeMap<String, &'static str> = BTreeMap::new();
        for n in words("isinf isnan finite drem significand scalb gamma lgamma_r j0 j1 jn y0 y1 yn") {
            base.insert(n.into(), "misc");
        }
        base.insert("sincos".into(), "gnu");
        for n in words("acospi asinpi atanpi atan2pi cospi sinpi tanpi exp10 exp2m1 exp10m1 log2p1 log10p1 logp1 pown powr rootn compoundn rsqrt
        nextdown nextup llogb roundeven fromfp ufromfp fromfpx ufromfpx canonicalize fmaxmag fminmag
        fmaximum fminimum fmaximum_num fminimum_num fmaximum_mag fminimum_mag fmaximum_mag_num
        fminimum_mag_num totalorder totalordermag getpayload setpayload setpayloadsig") {
            base.insert(n.into(), "ext");
        }
        for n in words("feenableexcept fedisableexcept fegetexcept") {
            base.insert(n.into(), "gnu");
        }
        for n in words("fesetexcept fetestexceptflag fegetmode fesetmode") {
            base.insert(n.into(), "ext");
        }
        let mut tier = BTreeMap::new();
        for (b, t) in &base {
            tier.insert(b.clone(), *t);
            if !b.starts_with("fe") {
                tier.insert(format!("{b}f"), *t);
                tier.insert(format!("{b}l"), *t);
            }
        }
        Math {
            src: root.join("crates/rusty-libc-math/src"),
            tier,
            floatn_re: Regex::new(r"^(.+?)(f32x|f64x|f128|f64|f32)$").unwrap(),
            lgamma_re: Regex::new(r"^lgamma(f32x|f64|f32|f128)_r$").unwrap(),
        }
    }

    pub fn tiers_of(&self, name: &str) -> Vec<&'static str> {
        if self.lgamma_re.is_match(name) {
            return vec!["misc", "floatn"];
        }
        if let Some(m) = self.floatn_re.captures(name) {
            if !name.starts_with("fe") {
                let base = m.get(1).unwrap().as_str();
                let mut s: BTreeSet<usize> = BTreeSet::new();
                s.insert(order_idx("floatn"));
                if let Some(t) = self.tier.get(base) {
                    s.insert(order_idx(t));
                }
                return s.into_iter().map(|i| ORDER[i]).collect();
            }
        }
        match self.tier.get(name) {
            Some(t) => vec![t],
            None => vec![],
        }
    }

    pub fn inject_cfg(&self, src: &str) -> String {
        let re = Regex::new(r#"(?m)^(pub (?:unsafe )?extern "C" fn (\w+)\b)"#).unwrap();
        let mut out = String::with_capacity(src.len() + 1024);
        let mut last = 0;
        for m in re.captures_iter(src) {
            let whole = m.get(0).unwrap();
            let tiers = self.tiers_of(&m[2]);
            if tiers.is_empty() {
                continue;
            }
            out.push_str(&src[last..whole.start()]);
            let feats: Vec<String> = tiers.iter().map(|t| format!("feature = \"{t}\"")).collect();
            if feats.len() == 1 {
                out.push_str(&format!("#[cfg({})]\n", feats[0]));
            } else {
                out.push_str(&format!("#[cfg(all({}))]\n", feats.join(", ")));
            }
            last = whole.start();
        }
        out.push_str(&src[last..]);
        out
    }
}

fn ctype(t: &str, fl: (&str, &str)) -> String {
    let t = t.trim();
    let re = Regex::new(r"^\*(mut|const)\s+(.+)$").unwrap();
    if let Some(m) = re.captures(t) {
        let inner = ctype(&m[2], fl);
        return format!("{}{} *", if &m[1] == "const" { "const " } else { "" }, inner);
    }
    match t {
        "f64" => fl.0.to_string(),
        "f32" => fl.1.to_string(),
        "c_int" => "int".into(),
        "c_long" => "long".into(),
        "c_longlong" => "long long".into(),
        "u32" => "unsigned int".into(),
        "c_char" => "char".into(),
        "()" => "void".into(),
        _ => panic!("math ctype {t}"),
    }
}

fn suffix_types(name: &str) -> (&'static str, &'static str) {
    if name.ends_with("f32x") {
        ("_Float32x", "_Float32")
    } else if name.ends_with("f64") {
        ("_Float64", "_Float32")
    } else if name.ends_with("f32") {
        ("_Float32", "_Float32")
    } else {
        ("double", "float")
    }
}

fn proto(name: &str, ret: &str, params: &[(String, String)]) -> String {
    let fl = suffix_types(name);
    let mut args: Vec<String> = Vec::new();
    for (p, t) in params {
        let c = ctype(t, fl);
        if c.ends_with('*') {
            args.push(format!("{c}{p}"));
        } else {
            args.push(format!("{c} {p}"));
        }
    }
    let a = if args.is_empty() { "void".to_string() } else { args.join(", ") };
    format!("{} {}({});", ctype(ret, fl), name, a)
}

fn params(s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for p in s.split(',') {
        let p = p.trim();
        if !p.is_empty() {
            let (n, t) = p.split_once(':').unwrap();
            out.push((n.trim().to_string(), t.trim().to_string()));
        }
    }
    out
}

fn walk(dir: &Path, files: &mut Vec<PathBuf>) {
    let mut ents: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    ents.sort();
    for p in ents {
        if p.is_dir() {
            walk(&p, files);
        } else if p.extension().map_or(false, |e| e == "rs") {
            files.push(p);
        }
    }
}

impl Math {
    fn macro_functions(&self) -> BTreeMap<String, String> {
        let mut found: BTreeMap<String, String> = BTreeMap::new();
        let mut files = Vec::new();
        walk(&self.src, &mut files);
        files.sort();
        let export_alias = Regex::new(r"(?m)^export_alias!\((?:unsafe )?fn\(([^)]*)\) -> ([^;]+);\s*(\w+)\s*=>\s*([\w\s,]+)\);").unwrap();
        let alias_body = Regex::new(r"(?m)^alias_body!\((f64|f32);[^=]*=>\s*([\w\s,]+)\);").unwrap();
        let float_aliases = Regex::new(r"(?ms)^float_aliases! \{\n(.*?)^\}\n").unwrap();
        let blk_re = Regex::new(r"(?s)(f64|f32) => \{(.*?)\n    \}").unwrap();
        let ent_re = Regex::new(r"(\w+) = (\w+)\(([^)]*)\);").unwrap();
        let alias_ent = Regex::new(r"(\w+) => (\w+): (f64|f32);").unwrap();
        let fe_ent = Regex::new(r"(?m)^    (\w+), \w+, \w+;").unwrap();
        for f in files {
            let text = fs::read_to_string(&f).unwrap();
            for m in export_alias.captures_iter(&text) {
                let ps = params(&m[1]);
                let ret = m[2].trim().to_string();
                for a in m[4].replace('\n', " ").split(',') {
                    let a = a.trim();
                    if !a.is_empty() {
                        found.insert(a.to_string(), proto(a, &ret, &ps));
                    }
                }
            }
            for m in alias_body.captures_iter(&text) {
                let ty = m[1].to_string();
                let ps = vec![("x".to_string(), ty.clone()), ("y".to_string(), ty.clone())];
                for a in m[2].replace('\n', " ").split(',') {
                    let a = a.trim();
                    if !a.is_empty() {
                        found.insert(a.to_string(), proto(a, &ty, &ps));
                    }
                }
            }
            if let Some(mm) = float_aliases.captures(&text) {
                for blk in blk_re.captures_iter(&mm[1]) {
                    let ty = blk[1].to_string();
                    for e in ent_re.captures_iter(&blk[2]) {
                        let ps: Vec<(String, String)> = e[3].split(',').map(|a| (a.trim().to_string(), ty.clone())).collect();
                        found.insert(e[1].to_string(), proto(&e[1], &ty, &ps));
                    }
                }
            }
            for (mac, nargs) in [("alias1", 1), ("alias2", 2)] {
                let re = Regex::new(&format!(r"(?ms)^{mac}! \{{\n(.*?)^\}}\n")).unwrap();
                if let Some(mm) = re.captures(&text) {
                    for e in alias_ent.captures_iter(&mm[1]) {
                        let ty = e[3].to_string();
                        let ps = if nargs == 1 { vec![("x".to_string(), ty.clone())] } else { vec![("y".to_string(), ty.clone()), ("x".to_string(), ty.clone())] };
                        found.insert(e[1].to_string(), proto(&e[1], &ty, &ps));
                    }
                }
            }
            let fe = Regex::new(r"(?ms)^float_entry! \{\n(.*?)^\}\n").unwrap();
            if let Some(mm) = fe.captures(&text) {
                for e in fe_ent.captures_iter(&mm[1]) {
                    found.insert(e[1].to_string(), proto(&e[1], "f32", &[("x".into(), "f32".into())]));
                }
            }
        }
        for sfx in ["", "f", "f32", "f64", "f32x"] {
            let ty = match sfx {
                "" => "double",
                "f" => "float",
                "f32" => "_Float32",
                "f64" => "_Float64",
                _ => "_Float32x",
            };
            for func in words("erf erfc lgamma tgamma j0 j1 y0 y1 gamma") {
                if func == "gamma" && sfx != "" && sfx != "f" {
                    continue;
                }
                let n = format!("{func}{sfx}");
                found.insert(n.clone(), format!("{ty} {n}({ty} x);"));
            }
            for func in ["jn", "yn"] {
                let n = format!("{func}{sfx}");
                found.insert(n.clone(), format!("{ty} {n}(int n, {ty} x);"));
            }
            let n = format!("lgamma{sfx}_r");
            found.insert(n.clone(), format!("{ty} {n}({ty} x, int *signgamp);"));
        }
        for (n, ty) in [("sincosf32", "_Float32"), ("sincosf64", "_Float64"), ("sincosf32x", "_Float32x")] {
            found.insert(n.into(), format!("void {n}({ty} x, {ty} *s, {ty} *c);"));
        }
        found.insert("nexttoward".into(), "double nexttoward(double x, long double y);".into());
        found.insert("nexttowardf".into(), "float nexttowardf(float x, long double y);".into());
        found
    }

    pub fn alias_header(&self) -> String {
        let funcs = self.macro_functions();
        let mut groups: BTreeMap<Vec<&'static str>, Vec<String>> = BTreeMap::new();
        for (name, p) in &funcs {
            groups.entry(self.tiers_of(name)).or_default().push(p.clone());
        }
        let mut out: Vec<String> = vec![
            "#ifndef _RLIBC_MATH_ALIASES_H".into(), "#define _RLIBC_MATH_ALIASES_H".into(), "".into(),
            "#if defined __RLIBC_MATH_MISC".into(), "extern int signgam;".into(), "#endif".into(), "".into(),
        ];
        emit_groups(&mut out, groups, false);
        out.push("#endif".into());
        out.join("\n") + "\n"
    }
}

fn emit_groups(out: &mut Vec<String>, groups: BTreeMap<Vec<&'static str>, Vec<String>>, sort: bool) {
    let mut keys: Vec<_> = groups.keys().cloned().collect();
    keys.sort_by(|a, b| (a.len(), a.clone()).cmp(&(b.len(), b.clone())));
    for key in keys {
        let mut v = groups[&key].clone();
        if sort {
            v.sort();
        }
        if !key.is_empty() {
            out.push(format!("#if {}", cond(&key)));
        }
        out.extend(v);
        if !key.is_empty() {
            out.push("#endif".into());
        }
        out.push("".into());
    }
}

pub fn complex_header() -> String {
    let real_ret = ["cabs", "carg", "cimag", "creal"];
    let unary = words("cabs carg cimag creal conj cproj cexp clog clog10 csqrt csin ccos ctan casin cacos catan csinh ccosh ctanh casinh cacosh catanh");
    let kinds = [("", "double"), ("f", "float"), ("l", "long double"), ("f32", "_Float32"), ("f64", "_Float64"), ("f32x", "_Float32x"), ("f64x", "_Float64x"), ("f128", "_Float128")];
    let mut out: Vec<String> = [
        "#ifndef _RLIBC_COMPLEX_H", "#define _RLIBC_COMPLEX_H 1", "",
        "#define complex _Complex", "#define _Complex_I (__extension__ 1.0iF)", "#undef I", "#define I _Complex_I",
        "#if defined __STDC_VERSION__ && __STDC_VERSION__ > 201710L || defined _GNU_SOURCE",
        "# define CMPLX(x, y) __builtin_complex ((double) (x), (double) (y))",
        "# define CMPLXF(x, y) __builtin_complex ((float) (x), (float) (y))",
        "# define CMPLXL(x, y) __builtin_complex ((long double) (x), (long double) (y))",
        "#endif",
        "#if defined _GNU_SOURCE || defined __STDC_WANT_IEC_60559_TYPES_EXT__",
        "# define CMPLXF32(x, y) __builtin_complex ((_Float32) (x), (_Float32) (y))",
        "# define CMPLXF64(x, y) __builtin_complex ((_Float64) (x), (_Float64) (y))",
        "# define CMPLXF32X(x, y) __builtin_complex ((_Float32x) (x), (_Float32x) (y))",
        "# define CMPLXF64X(x, y) __builtin_complex ((_Float64x) (x), (_Float64x) (y))",
        "# define CMPLXF128(x, y) __builtin_complex ((_Float128) (x), (_Float128) (y))",
        "#endif", "", "#ifdef __cplusplus", "extern \"C\" {", "#endif", "",
    ].iter().map(|s| s.to_string()).collect();
    for (suffix, ty) in kinds {
        let guard = suffix.starts_with("f3") || suffix.starts_with("f6") || suffix.starts_with("f1");
        if guard {
            out.push("#if defined _GNU_SOURCE || defined __STDC_WANT_IEC_60559_TYPES_EXT__".into());
        }
        for name in &unary {
            let func = format!("{name}{suffix}");
            if *name == "clog10" {
                out.push("#ifdef _GNU_SOURCE".into());
            }
            let arg = format!("{ty} _Complex");
            let ret = if real_ret.contains(name) { ty.to_string() } else { arg.clone() };
            out.push(format!("extern {ret} {func} ({arg});"));
            if *name == "clog10" && suffix == "l" {
                out.push(format!("extern {ret} __clog10l ({arg});"));
            }
            if *name == "clog10" {
                out.push("#endif".into());
            }
        }
        out.push(format!("extern {ty} _Complex cpow{suffix} ({ty} _Complex, {ty} _Complex);"));
        if guard {
            out.push("#endif".into());
        }
        out.push("".into());
    }
    for s in ["#ifdef __cplusplus", "}", "#endif", "", "#endif", ""] {
        out.push(s.into());
    }
    out.join("\n")
}

const LD_UNARY: &str = "sinl cosl tanl asinl acosl atanl sinhl coshl tanhl asinhl acoshl atanhl expl exp2l exp10l expm1l
    exp2m1l exp10m1l logl log2l log10l log1pl log2p1l log10p1l logp1l sqrtl cbrtl rsqrtl fabsl ceill floorl
    truncl roundl roundevenl rintl nearbyintl logbl nextupl nextdownl significandl sinpil cospil tanpil asinpil
    acospil atanpil erfl erfcl lgammal tgammal gammal j0l j1l y0l y1l";
const LD_BINARY: &str = "atan2l atan2pil powl powrl fmodl remainderl dreml hypotl copysignl nextafterl nexttowardl fdiml fmaxl
    fminl fmaxmagl fminmagl fmaximuml fminimuml fmaximum_numl fminimum_numl fmaximum_magl fminimum_magl
    fmaximum_mag_numl fminimum_mag_numl scalbl";
const LD_OTHER: &[(&str, &str, &str)] = &[
    ("fmal", "L", "L L L"), ("sincosl", "void", "L LP LP"), ("frexpl", "L", "L IP"), ("modfl", "L", "L LP"),
    ("ldexpl", "L", "L I"), ("scalbnl", "L", "L I"), ("scalblnl", "L", "L J"), ("pownl", "L", "L K"),
    ("rootnl", "L", "L K"), ("compoundnl", "L", "L K"), ("remquol", "L", "L L IP"), ("lgammal_r", "L", "L IP"),
    ("jnl", "L", "I L"), ("ynl", "L", "I L"), ("ilogbl", "I", "L"), ("llogbl", "J", "L"), ("lrintl", "J", "L"),
    ("llrintl", "K", "L"), ("lroundl", "J", "L"), ("llroundl", "K", "L"), ("fromfpl", "L", "L I U"),
    ("ufromfpl", "L", "L I U"), ("fromfpxl", "L", "L I U"), ("ufromfpxl", "L", "L I U"), ("nanl", "L", "CS"),
    ("getpayloadl", "L", "CLP"), ("setpayloadl", "I", "LP L"), ("setpayloadsigl", "I", "LP L"),
    ("canonicalizel", "I", "LP CLP"), ("totalorderl", "I", "CLP CLP"), ("totalordermagl", "I", "CLP CLP"),
    ("__fpclassifyl", "I", "L"), ("__signbitl", "I", "L"), ("__isnanl", "I", "L"), ("__isinfl", "I", "L"),
    ("__finitel", "I", "L"), ("__issignalingl", "I", "L"), ("__iscanonicall", "I", "L"), ("__iseqsigl", "I", "L L"),
    ("isnanl", "I", "L"), ("isinfl", "I", "L"), ("finitel", "I", "L"),
    ("faddl", "F", "L L"), ("fsubl", "F", "L L"), ("fmull", "F", "L L"), ("fdivl", "F", "L L"),
    ("ffmal", "F", "L L L"), ("fsqrtl", "F", "L"),
    ("daddl", "D", "L L"), ("dsubl", "D", "L L"), ("dmull", "D", "L L"), ("ddivl", "D", "L L"),
    ("dfmal", "D", "L L L"), ("dsqrtl", "D", "L"),
];

fn ldt(t: &str) -> &'static str {
    match t {
        "L" => "long double", "F" => "float", "D" => "double", "I" => "int", "J" => "long", "K" => "long long",
        "U" => "unsigned int", "LP" => "long double *", "CLP" => "const long double *", "IP" => "int *",
        "CS" => "const char *", "void" => "void",
        _ => panic!("ldt {t}"),
    }
}

const NO_F64X: [&str; 15] = ["nexttowardl", "dreml", "scalbl", "significandl", "gammal", "isnanl", "isinfl", "finitel",
    "__fpclassifyl", "__signbitl", "__isnanl", "__isinfl", "__finitel", "__issignalingl", "__iscanonicall"];

type LdFn = (String, (String, Vec<String>), Vec<&'static str>);

impl Math {
    fn ld_functions(&self) -> Vec<LdFn> {
        let mut out: Vec<LdFn> = Vec::new();
        let mut protos: BTreeMap<String, (String, String)> = BTreeMap::new();
        for n in words(LD_UNARY) {
            protos.insert(n.into(), ("L".into(), "L".into()));
        }
        for n in words(LD_BINARY) {
            protos.insert(n.into(), ("L".into(), "L L".into()));
        }
        for (n, r, a) in LD_OTHER {
            protos.insert(n.to_string(), (r.to_string(), a.to_string()));
        }
        let narrow_names = ["addl", "subl", "mull", "divl", "fmal", "sqrtl"];
        for (name, (r, a)) in &protos {
            let args: Vec<String> = a.split_whitespace().map(|t| ldt(t).to_string()).collect();
            let mut t0 = if name.starts_with("__") { vec![] } else { self.tiers_of(name) };
            let base = &name[..name.len() - 1];
            if ["pown", "powr", "rootn", "compoundn", "rsqrt"].contains(&base) {
                t0 = vec!["ext"];
            }
            out.push((name.clone(), (ldt(r).to_string(), args.clone()), t0.clone()));
            if NO_F64X.contains(&name.as_str()) || name == "__iseqsigl" || name == "pow10l" || name.starts_with("__") {
                continue;
            }
            let c0 = name.as_bytes()[0];
            if (c0 == b'f' || c0 == b'd') && narrow_names.contains(&&name[1..]) && name != "fdiml" && name != "floorl" && name != "fabsl" {
                continue;
            }
            let alias = if name == "lgammal_r" { "lgammaf64x_r".to_string() } else { format!("{base}f64x") };
            let x = |t: &str| t.replace("long double", "_Float64x");
            let mut tiers: BTreeSet<usize> = t0.iter().map(|t| order_idx(t)).collect();
            tiers.insert(order_idx("floatn"));
            out.push((alias, (x(ldt(r)), args.iter().map(|t| x(t)).collect()), tiers.into_iter().map(|i| ORDER[i]).collect()));
        }
        for op in ["add", "sub", "mul", "div", "fma", "sqrt"] {
            let (_, a) = &protos[&format!("f{op}l")];
            let args: Vec<String> = a.split_whitespace().map(|_| "_Float64x".to_string()).collect();
            out.push((format!("f32{op}f64x"), ("_Float32".into(), args.clone()), vec!["ext", "floatn"]));
            out.push((format!("f32x{op}f64x"), ("_Float32x".into(), args.clone()), vec!["ext", "floatn"]));
            out.push((format!("f64{op}f64x"), ("_Float64".into(), args), vec!["ext", "floatn"]));
        }
        out
    }

    pub fn longdouble_header(&self) -> String {
        let mut groups: BTreeMap<Vec<&'static str>, Vec<String>> = BTreeMap::new();
        for (name, (ret, args), mut tiers) in self.ld_functions() {
            if words("faddl fsubl fmull fdivl ffmal fsqrtl daddl dsubl dmull ddivl dfmal dsqrtl").contains(&name.as_str()) {
                tiers = vec!["ext"];
            }
            let a = if args.is_empty() { "void".to_string() } else { args.join(", ") };
            groups.entry(tiers).or_default().push(format!("extern {ret} {name} ({a});"));
        }
        let mut out: Vec<String> = [
            "#ifndef _RLIBC_MATH_LDCALLS_H", "#define _RLIBC_MATH_LDCALLS_H", "",
        ].iter().map(|s| s.to_string()).collect();
        emit_groups(&mut out, groups, true);
        out.push("#endif".into());
        out.join("\n") + "\n"
    }
}

const Q_UNARY: &str = "acos acosh acospi asin asinh asinpi atan atanh atanpi cbrt ceil cos cosh cospi erf erfc exp exp10 exp10m1
    exp2 exp2m1 expm1 fabs floor j0 j1 lgamma log log10 log10p1 log1p log2 log2p1 logb logp1 nearbyint nextdown
    nextup rint round roundeven rsqrt sin sinh sinpi sqrt tan tanh tanpi tgamma trunc y0 y1";
const Q_BINARY: &str = "atan2 atan2pi copysign fdim fmax fmaxmag fmin fminmag fmaximum fmaximum_mag fmaximum_mag_num
    fmaximum_num fminimum fminimum_mag fminimum_mag_num fminimum_num fmod hypot nextafter pow powr remainder";
const Q_OTHER: &[(&str, &str, &str)] = &[
    ("fma", "Q", "Q Q Q"), ("sincos", "void", "Q QP QP"), ("frexp", "Q", "Q IP"), ("modf", "Q", "Q QP"),
    ("ldexp", "Q", "Q I"), ("scalbn", "Q", "Q I"), ("scalbln", "Q", "Q J"), ("pown", "Q", "Q K"),
    ("rootn", "Q", "Q K"), ("compoundn", "Q", "Q K"), ("remquo", "Q", "Q Q IP"), ("lgammaf128_r", "Q", "Q IP"),
    ("jn", "Q", "I Q"), ("yn", "Q", "I Q"), ("ilogb", "I", "Q"), ("llogb", "J", "Q"), ("lrint", "J", "Q"),
    ("llrint", "K", "Q"), ("lround", "J", "Q"), ("llround", "K", "Q"), ("fromfp", "Q", "Q I U"),
    ("ufromfp", "Q", "Q I U"), ("fromfpx", "Q", "Q I U"), ("ufromfpx", "Q", "Q I U"), ("nan", "Q", "CS"),
    ("getpayload", "Q", "CQP"), ("setpayload", "I", "QP Q"), ("setpayloadsig", "I", "QP Q"),
    ("canonicalize", "I", "QP CQP"), ("totalorder", "I", "CQP CQP"), ("totalordermag", "I", "CQP CQP"),
];
const Q_INTERNAL: &[(&str, &str, &str)] = &[
    ("__fpclassifyf128", "I", "Q"), ("__signbitf128", "I", "Q"), ("__isnanf128", "I", "Q"), ("__isinff128", "I", "Q"),
    ("__finitef128", "I", "Q"), ("__issignalingf128", "I", "Q"), ("__iseqsigf128", "I", "Q Q"),
];

fn qt(t: &str) -> &'static str {
    match t {
        "Q" => "_Float128", "QP" => "_Float128 *", "CQP" => "const _Float128 *", "I" => "int", "J" => "long", "K" => "long long",
        "U" => "unsigned int", "UJ" => "unsigned long", "IP" => "int *", "CS" => "const char *", "F" => "float", "D" => "double",
        "X" => "_Float64x", "F32" => "_Float32", "F32X" => "_Float32x", "F64" => "_Float64", "void" => "void",
        _ => panic!("qt {t}"),
    }
}

impl Math {
    fn q_defined(&self) -> BTreeSet<String> {
        let mut names = BTreeSet::new();
        let qdir = self.src.join("quad");
        let mut fs_: Vec<String> = fs::read_dir(&qdir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().to_string()).collect();
        fs_.sort();
        let r1 = Regex::new(r"\b(?:fn\s+|q\w*!\(\s*|q_fromfp!\s*\{\s*)((?:__)?[a-z0-9_]+f128(?:_r)?)\b").unwrap();
        let r2 = Regex::new(r"\b((?:f32|f32x|f64|f64x|f)[a-z0-9_]*f(?:128|64|32x))\s*,\s*to(?:32|64|80)_").unwrap();
        let r3 = Regex::new(r"\b((?:u?fromfpx?)f128)\s*,").unwrap();
        for f in fs_ {
            if !f.ends_with(".rs") || f == "abi.rs" {
                continue;
            }
            let text = fs::read_to_string(qdir.join(&f)).unwrap();
            for line in text.lines() {
                let t = line.trim();
                if t.starts_with("//") || t.starts_with("macro_rules") {
                    continue;
                }
                for m in r1.captures_iter(t) {
                    names.insert(m[1].to_string());
                }
                for m in r2.captures_iter(t) {
                    names.insert(m[1].to_string());
                }
                if t.starts_with("q_fromfp!") || t.starts_with("fromfpf128") || t.starts_with("ufromfp") {
                    for m in r3.captures_iter(t) {
                        names.insert(m[1].to_string());
                    }
                }
            }
        }
        names
    }

    pub fn quad_header(&self) -> String {
        let defined = self.q_defined();
        let mut narrow: Vec<(String, String, String)> = Vec::new();
        for (op, n) in [("add", 2), ("sub", 2), ("mul", 2), ("div", 2), ("fma", 3), ("sqrt", 1)] {
            for (res, rt) in [("f32", "F32"), ("f32x", "F32X"), ("f64", "F64"), ("f64x", "X")] {
                narrow.push((format!("{res}{op}f128"), rt.into(), vec!["Q"; n].join(" ")));
            }
            let d = vec!["D"; n].join(" ");
            narrow.push((format!("f32{op}f64"), "F32".into(), d.clone()));
            narrow.push((format!("f32{op}f32x"), "F32".into(), d.clone()));
            narrow.push((format!("f32x{op}f64"), "F32X".into(), d.clone()));
            let short = match op { "add" => "fadd", "sub" => "fsub", "mul" => "fmul", "div" => "fdiv", "fma" => "ffma", _ => "fsqrt" };
            narrow.push((short.into(), "F".into(), d));
        }
        let mut protos: BTreeMap<String, (String, String)> = BTreeMap::new();
        for n in words(Q_UNARY) {
            protos.insert(format!("{n}f128"), ("Q".into(), "Q".into()));
        }
        for n in words(Q_BINARY) {
            protos.insert(format!("{n}f128"), ("Q".into(), "Q Q".into()));
        }
        for (n, r, a) in Q_OTHER {
            let key = if n.ends_with("_r") { n.to_string() } else { format!("{n}f128") };
            protos.insert(key, (r.to_string(), a.to_string()));
        }
        for (n, r, a) in Q_INTERNAL {
            protos.insert(n.to_string(), (r.to_string(), a.to_string()));
        }
        for (n, r, a) in &narrow {
            protos.insert(n.clone(), (r.clone(), a.clone()));
        }
        let narrow_names: BTreeSet<&str> = narrow.iter().map(|x| x.0.as_str()).collect();
        let mut groups: BTreeMap<Vec<&'static str>, Vec<String>> = BTreeMap::new();
        for (name, (r, a)) in &protos {
            if (name.ends_with("f128") || name.ends_with("f128_r")) && !defined.contains(name) {
                continue;
            }
            let args: Vec<&str> = a.split_whitespace().map(qt).collect();
            let tiers: Vec<&'static str> = if name.starts_with("__") {
                vec!["floatn"]
            } else if narrow_names.contains(name.as_str()) {
                if ["fadd", "fsub", "fmul", "fdiv", "ffma", "fsqrt"].contains(&name.as_str()) { vec!["ext"] } else { vec!["ext", "floatn"] }
            } else {
                self.tiers_of(name)
            };
            let al = if args.is_empty() { "void".to_string() } else { args.join(", ") };
            groups.entry(tiers).or_default().push(format!("extern {} {} ({});", qt(r), name, al));
        }
        let mut out: Vec<String> = [
            "#ifndef _RLIBC_MATH_QUADCALLS_H", "#define _RLIBC_MATH_QUADCALLS_H", "",
        ].iter().map(|s| s.to_string()).collect();
        emit_groups(&mut out, groups, true);
        out.push("#endif".into());
        out.join("\n") + "\n"
    }
}
