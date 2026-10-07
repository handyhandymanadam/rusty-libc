#!/usr/bin/env python3
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

OVERRIDES = {
    ("regexec", "GLIBC_2.2.5"): "__rl_compat_regexec",
    ("realpath", "GLIBC_2.2.5"): "__rl_compat_realpath",
    ("nftw", "GLIBC_2.2.5"): "__rl_compat_nftw",
    ("nftw64", "GLIBC_2.2.5"): "__rl_compat_nftw64",
    ("memcpy", "GLIBC_2.2.5"): "memmove",
    ("sched_getaffinity", "GLIBC_2.3.3"): "__rl_compat_sched_getaffinity",
    ("sched_setaffinity", "GLIBC_2.3.3"): "__rl_compat_sched_setaffinity",
    ("pthread_getaffinity_np", "GLIBC_2.3.3"): "__rl_compat_pthread_getaffinity_np",
    ("pthread_setaffinity_np", "GLIBC_2.3.3"): "__rl_compat_pthread_setaffinity_np",
    ("pthread_attr_getaffinity_np", "GLIBC_2.3.3"): "__rl_compat_pthread_attr_getaffinity_np",
    ("pthread_attr_setaffinity_np", "GLIBC_2.3.3"): "__rl_compat_pthread_attr_setaffinity_np",
    ("quick_exit", "GLIBC_2.10"): "__rl_compat_quick_exit",
    ("cfgetospeed", "GLIBC_2.2.5"): "__rl_compat_cfgetospeed",
    ("cfgetispeed", "GLIBC_2.2.5"): "__rl_compat_cfgetispeed",
    ("cfsetospeed", "GLIBC_2.2.5"): "__rl_compat_cfsetospeed",
    ("cfsetispeed", "GLIBC_2.2.5"): "__rl_compat_cfsetispeed",
    ("cfsetspeed", "GLIBC_2.2.5"): "__rl_compat_cfsetspeed",
    ("timer_create", "GLIBC_2.2.5"): "__rl_compat_timer_create",
    ("timer_delete", "GLIBC_2.2.5"): "__rl_compat_timer_delete",
    ("timer_settime", "GLIBC_2.2.5"): "__rl_compat_timer_settime",
    ("timer_gettime", "GLIBC_2.2.5"): "__rl_compat_timer_gettime",
    ("timer_getoverrun", "GLIBC_2.2.5"): "__rl_compat_timer_getoverrun",
    ("pthread_cond_init", "GLIBC_2.2.5"): "__rl_compat_pthread_cond_init",
    ("pthread_cond_destroy", "GLIBC_2.2.5"): "__rl_compat_pthread_cond_destroy",
    ("pthread_cond_wait", "GLIBC_2.2.5"): "__rl_compat_pthread_cond_wait",
    ("pthread_cond_timedwait", "GLIBC_2.2.5"): "__rl_compat_pthread_cond_timedwait",
    ("pthread_cond_signal", "GLIBC_2.2.5"): "__rl_compat_pthread_cond_signal",
    ("pthread_cond_broadcast", "GLIBC_2.2.5"): "__rl_compat_pthread_cond_broadcast",
    ("glob", "GLIBC_2.2.5"): "__rl_compat_glob",
    ("glob64", "GLIBC_2.2.5"): "__rl_compat_glob",
    ("fmemopen", "GLIBC_2.2.5"): "__rl_compat_fmemopen",
    ("posix_spawn", "GLIBC_2.2.5"): "__rl_compat_posix_spawn",
    ("posix_spawnp", "GLIBC_2.2.5"): "__rl_compat_posix_spawnp",
    ("lio_listio", "GLIBC_2.2.5"): "__rl_compat_lio_listio",
    ("lio_listio64", "GLIBC_2.2.5"): "__rl_compat_lio_listio64",
    ("sigvec", "GLIBC_2.2.5"): "__rl_old_sigvec",
    ("vtimes", "GLIBC_2.2.5"): "__rl_old_vtimes",
    ("sstk", "GLIBC_2.2.5"): "__rl_old_sstk",
    ("sysctl", "GLIBC_2.2.5"): "__rl_old_sysctl",
    ("__sysctl", "GLIBC_2.2.5"): "__rl_old_sysctl",
    ("ustat", "GLIBC_2.2.5"): "__rl_old_ustat",
    ("uselib", "GLIBC_2.2.5"): "__rl_old_uselib",
    ("bdflush", "GLIBC_2.2.5"): "__rl_old_bdflush",
    ("create_module", "GLIBC_2.2.5"): "__rl_old_create_module",
    ("get_kernel_syms", "GLIBC_2.2.5"): "__rl_old_get_kernel_syms",
    ("query_module", "GLIBC_2.2.5"): "__rl_old_query_module",
    ("nfsservctl", "GLIBC_2.2.5"): "__rl_old_nfsservctl",
    ("fattach", "GLIBC_2.2.5"): "__rl_old_streams_enosys",
    ("fdetach", "GLIBC_2.2.5"): "__rl_old_streams_enosys",
    ("getmsg", "GLIBC_2.2.5"): "__rl_old_streams_enosys",
    ("getpmsg", "GLIBC_2.2.5"): "__rl_old_streams_enosys",
    ("putmsg", "GLIBC_2.2.5"): "__rl_old_streams_enosys",
    ("putpmsg", "GLIBC_2.2.5"): "__rl_old_streams_enosys",
    ("isastream", "GLIBC_2.2.5"): "__rl_old_isastream",
    ("step", "GLIBC_2.2.5"): "__rl_old_step",
    ("advance", "GLIBC_2.2.5"): "__rl_old_advance",
    ("tr_break", "GLIBC_2.2.5"): "__rl_old_tr_break",
    ("_dl_mcount_wrapper", "GLIBC_2.2.5"): "__rl_old_dl_mcount_wrapper",
    ("pthread_kill_other_threads_np", "GLIBC_2.2.5"): "__rl_old_pthread_kill_other_threads_np",
    ("__default_morecore", "GLIBC_2.2.5"): "__rl_old_default_morecore",
    ("__nss_passwd_lookup", "GLIBC_2.2.5"): "__rl_old_nss_lookup",
    ("__nss_group_lookup", "GLIBC_2.2.5"): "__rl_old_nss_lookup",
    ("__nss_hosts_lookup", "GLIBC_2.2.5"): "__rl_old_nss_lookup",
    ("__nss_next", "GLIBC_2.2.5"): "__rl_old_nss_next",
    ("__nss_database_lookup", "GLIBC_2.2.5"): "__rl_old_nss_database_lookup",
    ("_IO_vfscanf", "GLIBC_2.2.5"): "__rl_old_io_vfscanf",
    ("__ivaliduser", "GLIBC_2.2.5"): "__rl_old_ivaliduser",
    ("__sigismember", "GLIBC_2.2.5"): "__rl_old_sigismember",
    ("__sigaddset", "GLIBC_2.2.5"): "__rl_old_sigaddset",
    ("__sigdelset", "GLIBC_2.2.5"): "__rl_old_sigdelset",
    ("__strtok_r_1c", "GLIBC_2.2.5"): "__rl_old_strtok_r_1c",
    ("__strsep_1c", "GLIBC_2.2.5"): "__rl_old_strsep_1c",
    ("__strsep_2c", "GLIBC_2.2.5"): "__rl_old_strsep_2c",
    ("__strsep_3c", "GLIBC_2.2.5"): "__rl_old_strsep_3c",
    ("__strcspn_c1", "GLIBC_2.2.5"): "__rl_old_strcspn_c1",
    ("__strcspn_c2", "GLIBC_2.2.5"): "__rl_old_strcspn_c2",
    ("__strcspn_c3", "GLIBC_2.2.5"): "__rl_old_strcspn_c3",
    ("__strspn_c1", "GLIBC_2.2.5"): "__rl_old_strspn_c1",
    ("__strspn_c2", "GLIBC_2.2.5"): "__rl_old_strspn_c2",
    ("__strspn_c3", "GLIBC_2.2.5"): "__rl_old_strspn_c3",
    ("__strpbrk_c2", "GLIBC_2.2.5"): "__rl_old_strpbrk_c2",
    ("__strpbrk_c3", "GLIBC_2.2.5"): "__rl_old_strpbrk_c3",
    ("__mempcpy_small", "GLIBC_2.2.5"): "__rl_old_mempcpy_small",
    ("__strcpy_small", "GLIBC_2.2.5"): "__rl_old_strcpy_small",
    ("__stpcpy_small", "GLIBC_2.2.5"): "__rl_old_stpcpy_small",
    ("llseek", "GLIBC_2.2.5"): "lseek64",
    ("cfree", "GLIBC_2.2.5"): "free",
    ("__secure_getenv", "GLIBC_2.2.5"): "secure_getenv",
    ("__pthread_mutexattr_destroy", "GLIBC_2.2.5"): "pthread_mutexattr_destroy",
    ("__pthread_mutexattr_init", "GLIBC_2.2.5"): "pthread_mutexattr_init",
    ("__pthread_mutexattr_settype", "GLIBC_2.2.5"): "pthread_mutexattr_settype",
    ("pthread_mutexattr_getkind_np", "GLIBC_2.2.5"): "pthread_mutexattr_gettype",
    ("pthread_mutexattr_setkind_np", "GLIBC_2.2.5"): "pthread_mutexattr_settype",
    ("__pthread_rwlock_destroy", "GLIBC_2.2.5"): "pthread_rwlock_destroy",
    ("__pthread_rwlock_init", "GLIBC_2.2.5"): "pthread_rwlock_init",
    ("__pthread_rwlock_rdlock", "GLIBC_2.2.5"): "pthread_rwlock_rdlock",
    ("__pthread_rwlock_tryrdlock", "GLIBC_2.2.5"): "pthread_rwlock_tryrdlock",
    ("__pthread_rwlock_trywrlock", "GLIBC_2.2.5"): "pthread_rwlock_trywrlock",
    ("__pthread_rwlock_unlock", "GLIBC_2.2.5"): "pthread_rwlock_unlock",
    ("__pthread_rwlock_wrlock", "GLIBC_2.2.5"): "pthread_rwlock_wrlock",
    ("__dn_comp", "GLIBC_2.2.5"): "dn_comp",
    ("__dn_expand", "GLIBC_2.2.5"): "dn_expand",
    ("__dn_skipname", "GLIBC_2.2.5"): "dn_skipname",
    ("__res_dnok", "GLIBC_2.2.5"): "res_dnok",
    ("__res_hnok", "GLIBC_2.2.5"): "res_hnok",
    ("__res_mailok", "GLIBC_2.2.5"): "res_mailok",
    ("__res_mkquery", "GLIBC_2.2.5"): "res_mkquery",
    ("__res_nmkquery", "GLIBC_2.2.5"): "res_nmkquery",
    ("__res_nquery", "GLIBC_2.2.5"): "res_nquery",
    ("__res_nquerydomain", "GLIBC_2.2.5"): "res_nquerydomain",
    ("__res_nsearch", "GLIBC_2.2.5"): "res_nsearch",
    ("__res_nsend", "GLIBC_2.2.5"): "res_nsend",
    ("__res_ownok", "GLIBC_2.2.5"): "res_ownok",
    ("__res_query", "GLIBC_2.2.5"): "res_query",
    ("__res_querydomain", "GLIBC_2.2.5"): "res_querydomain",
    ("__res_search", "GLIBC_2.2.5"): "res_search",
    ("__res_send", "GLIBC_2.2.5"): "res_send",
}
extra = os.path.join(ROOT, "tools", "compat_overrides.txt")
if os.path.exists(extra):
    for line in open(extra):
        line = line.split("#")[0].split()
        if len(line) == 3:
            OVERRIDES[(line[0], line[1])] = line[2]

ALIASES = {}

GROUPS = [
    ("rpc", ("xdr", "clnt", "svc", "auth", "_auth", "key_", "__key", "pmap", "rpc", "__rpc", "_rpc", "callrpc", "registerrpc", "get_myaddress", "getnetname", "getrpcport",
             "host2netname", "netname2", "user2netname", "rtime", "cbc_crypt", "ecb_crypt", "des_setparity", "passwd2des", "xdecrypt", "xencrypt", "getpublickey", "getsecretkey", "_seterr_reply", "xprt_")),
    ("resolver", ("__res_", "__dn_", "ns_")),
    ("pthread", ("pthread", "__pthread", "_pthread", "sem_", "cnd_", "mtx_", "thrd_", "tss_", "call_once", "sched_")),
    ("dl", ("dl", "_dl_")),
    ("aio", ("aio_", "lio_", "gai_", "getaddrinfo_a", "mq_", "__mq_", "timer_", "clock_", "shm_")),
    ("string", ("__str", "__stp", "__mempcpy", "memcpy")),
]


def group_of(name):
    for g, prefixes in GROUPS:
        if name.startswith(prefixes):
            return g
    return "misc"


def defined_names():
    if "--defined" in sys.argv:
        return set(l.strip() for l in open(sys.argv[sys.argv.index("--defined") + 1]))
    libc_a = os.environ.get("COMPAT_LIBC_A") or os.path.join(ROOT, "target/sysroot/lib/libc.a")
    out = subprocess.run(["nm", "-g", "--defined-only", libc_a], capture_output=True, text=True).stdout
    names = set()
    for line in out.splitlines():
        p = line.split()
        if len(p) == 3:
            names.add(p[2])
    return names


ZERO_DATA = {
    "__after_morecore_hook", "__free_hook", "__malloc_hook", "__malloc_initialize_hook", "__memalign_hook", "__morecore", "__realloc_hook", "mallwatch",
    "_null_auth", "rpc_createerr", "svc_fdset", "svc_max_pollfd", "svc_pollfd", "svcauthdes_stats", "_obstack",
    "__key_decryptsession_pk_LOCAL", "__key_encryptsession_pk_LOCAL", "__key_gendes_LOCAL",
}
TABLE_DATA = {"sys_errlist", "_sys_errlist", "sys_siglist", "_sys_siglist", "sys_sigabbrev", "sys_nerr", "_sys_nerr"}
HAND_DATA = {"loc1", "loc2", "locs"}


def glibc_table(name, ver, size):
    import ctypes
    libc = ctypes.CDLL("libc.so.6")
    libc.dlvsym.restype = ctypes.c_void_p
    libc.dlvsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p]
    addr = libc.dlvsym(None, name.encode(), ver.encode())
    if not addr:
        raise SystemExit("dlvsym(%s, %s) failed" % (name, ver))
    return ctypes.string_at(addr, size), addr


CANON = {}
FAMILY = {"sys_errlist": "errlist", "_sys_errlist": "errlist", "sys_siglist": "siglist", "_sys_siglist": "siglist", "sys_sigabbrev": "sigabbrev"}


def sym_head(out, label, size):
    out.append('        ".globl %s",' % label)
    out.append('        ".type %s, @object",' % label)
    out.append('        ".size %s, %d",' % (label, size))


def data_block(name, ver, size, label, out):
    if name in ZERO_DATA:
        sym_head(out, label, size)
        out.append('        "%s:",' % label)
        out.append('        ".zero %d",' % size)
        out.append('        ".symver %s, %s@%s",' % (label, name, ver))
        return True
    if name in TABLE_DATA:
        import ctypes
        raw, addr = glibc_table(name, ver, size)
        if name in ("sys_nerr", "_sys_nerr"):
            sym_head(out, label, size)
            out.append('        "%s:",' % label)
            out.append('        ".long %d",' % int.from_bytes(raw[:4], "little", signed=True))
            out.append('        ".symver %s, %s@%s",' % (label, name, ver))
            return True
        n = size // 8
        ptrs = [int.from_bytes(raw[i * 8:i * 8 + 8], "little") for i in range(n)]
        strs = []
        for i, p in enumerate(ptrs):
            strs.append(ctypes.string_at(p).decode("latin1") if p else None)
        fam = FAMILY[name]
        for clabel, cstrs in CANON.get(fam, []):
            if cstrs[:len(strs)] == strs:
                sym_head(out, label, size)
                out.append('        ".set %s, %s",' % (label, clabel))
                out.append('        ".symver %s, %s@%s",' % (label, name, ver))
                return True
        CANON.setdefault(fam, []).append((label, strs))
        sym_head(out, label, size)
        out.append('        ".p2align 3",')
        out.append('        "%s:",' % label)
        for i, st in enumerate(strs):
            out.append('        ".quad %s",' % (("%s_s%d" % (label, i)) if st is not None else "0"))
        out.append('        ".symver %s, %s@%s",' % (label, name, ver))
        for i, st in enumerate(strs):
            if st is not None:
                esc = st.replace("\\", "\\\\").replace('"', '\\\\"')
                out.append('        "%s_s%d: .asciz \\"%s\\"",' % (label, i, esc))
        return True
    return False


def main():
    ours = defined_names()
    rows = []
    for line in open(os.path.join(ROOT, "tools", "compat_symbols.txt")):
        if line.startswith("#") or not line.strip():
            continue
        name, ver, kind, size = line.split()
        rows.append((name, ver, kind))
    skipped_data = []
    skipped_missing = []
    groups = {}
    for name, ver, kind in rows:
        if kind != "func":
            skipped_data.append("%s@%s" % (name, ver))
            continue
        target = OVERRIDES.get((name, ver)) or ALIASES.get(name) or name
        if target not in ours and (name, ver) not in OVERRIDES:
            skipped_missing.append("%s@%s" % (name, ver))
            continue
        groups.setdefault(group_of(name), []).append((name, ver, target))
    data_lines = []
    done_data = []
    sizes = {}
    for l in open(os.path.join(ROOT, "tools", "compat_symbols.txt")):
        if not l.startswith("#") and l.strip():
            f = l.split()
            sizes[(f[0], f[1])] = int(f[3])
    for name, ver, kind in sorted(rows, key=lambda r: -sizes[(r[0], r[1])]):
        if kind != "data" or name in HAND_DATA:
            continue
        size = sizes[(name, ver)]
        label = "__rl_cd_%s_%s" % (name, ver.replace("GLIBC_", "").replace(".", "_"))
        block = []
        if data_block(name, ver, size, label, block):
            data_lines += block
            done_data.append("%s@%s" % (name, ver))
        else:
            pass
    skipped_data = [d for d in skipped_data if d.split("@")[0] not in HAND_DATA and d not in done_data]
    out = []
    out.append("//! GENERATED by tools/gen_compat_symver.py from tools/compat_symbols.txt: do not edit.")
    out.append("//!")
    out.append("//! glibc 2.43's compat exports (`name@GLIBC_x.y`, the old versions of functions) as symbols of this library: each is a")
    out.append("//! `jmp` to the function that implements it (a plain alias where the old version behaves as the current one, a function of")
    out.append("//! compat_shims.rs where it does not). A static program that names an old version with `.symver` links against them.")
    out.append("//! One module per family so that using one of them does not pull in the others' targets.")
    out.append("//!")
    out.append("//! Not provided (data objects, and functions this library does not have): %d data symbols, %d functions:" % (len(skipped_data), len(skipped_missing)))
    for chunk in range(0, len(skipped_missing), 6):
        out.append("//!   " + " ".join(skipped_missing[chunk:chunk + 6]))
    out.append("//!   data objects not provided: " + " ".join(skipped_data))
    out.append("#![allow(missing_docs)]")
    out.append("")
    total = 0
    out.append("pub mod data {")
    out.append("    core::arch::global_asm!(")
    out.append('        ".pushsection .data.rl_compat,\\"aw\\",@progbits",')
    out += data_lines
    out.append('        ".popsection",')
    out.append("    );")
    out.append("}")
    out.append("")
    for g in sorted(groups):
        out.append("pub mod %s {" % g)
        out.append("    core::arch::global_asm!(")
        out.append('        ".pushsection .text.rl_compat,\\"ax\\",@progbits",')
        for name, ver, target in groups[g]:
            label = "__rl_cs_%s_%s" % (name, ver.replace("GLIBC_", "").replace(".", "_"))
            out.append('        ".p2align 3",')
            out.append('        ".globl %s",' % label)
            out.append('        "%s:",' % label)
            out.append('        "jmp %s",' % target)
            out.append('        ".symver %s, %s@%s",' % (label, name, ver))
            total += 1
        out.append('        ".popsection",')
        out.append("    );")
        out.append("}")
        out.append("")
    open(os.path.join(ROOT, "crates/rusty-libc-cabi/src/compat_symver.rs"), "w").write("\n".join(out))
    print("%d versioned function symbols in %d groups, %d data objects; %d functions skipped (not defined), %d data objects skipped" % (total, len(groups), len(done_data), len(skipped_missing), len(skipped_data)))
    for f in skipped_missing:
        pass


MATH_SKIP = ()
OLDFP_SUFFIX = {"": "d", "f": "f", "l": "l", "f32": "f", "f64": "d", "f32x": "d", "f64x": "l", "f128": "q"}
OLDFP_BASES = (("ufromfpx", "ofp3"), ("fromfpx", "ofp2"), ("ufromfp", "ofp1"), ("fromfp", "ofp0"), ("totalordermag", "otm"), ("totalorder", "oto"))


def oldfp_target(name):
    for base, kind in OLDFP_BASES:
        if name.startswith(base) and name[len(base):] in OLDFP_SUFFIX:
            t = OLDFP_SUFFIX[name[len(base):]]
            return "__rl_ofp_%s%s" % (t, kind[3]) if kind.startswith("ofp") else "__rl_%s_%s" % (kind, t)
    return None
MATH_TARGET = {
    ("pow10", "GLIBC_2.2.5"): "exp10", ("pow10f", "GLIBC_2.2.5"): "exp10f", ("pow10l", "GLIBC_2.2.5"): "exp10l",
    ("matherr", "GLIBC_2.2.5"): "__rl_old_matherr",
}
FINITE_TARGET = {"gamma_r": "lgamma_r", "gammaf_r": "lgammaf_r", "gammal_r": "lgammal_r", "gammaf128_r": "lgammaf128_r"}
MATH_DATA = {"_LIB_VERSION": 2}
MATH_PLAIN = {"__clog10": "clog10", "__clog10f": "clog10f"}


def math_main():
    import gen_svid_compat
    svid = {(n, v): label for (label, n, v, *_rest) in gen_svid_compat.entries()}
    ours = defined_names()
    funcs, data, skipped = [], [], []
    for line in open(os.path.join(ROOT, "tools", "compat_symbols_libm.txt")):
        if line.startswith("#") or not line.strip():
            continue
        name, ver, kind, size = line.split()
        size = int(size)
        if kind == "data":
            if name in MATH_DATA:
                data.append((name, ver, size))
            else:
                skipped.append("%s@%s" % (name, ver))
            continue
        if name.startswith(MATH_SKIP):
            skipped.append("%s@%s" % (name, ver))
            continue
        target = svid.get((name, ver)) or MATH_TARGET.get((name, ver))
        if target is None and ver in ("GLIBC_2.25", "GLIBC_2.26", "GLIBC_2.27"):
            target = oldfp_target(name)
        if target is None and name.startswith("__") and name.endswith("_finite"):
            base = name[2:-len("_finite")]
            target = FINITE_TARGET.get(base, base)
        if target is None:
            target = name
        if target not in ours and not target.startswith("__rl_"):
            skipped.append("%s@%s" % (name, ver))
            continue
        funcs.append((name, ver, target))
    out = ["//! GENERATED by tools/gen_compat_symver.py --math from tools/compat_symbols_libm.txt: do not edit.", "//!",
           "//! The old versions of libm functions (`exp@GLIBC_2.2.5`, `__exp_finite@GLIBC_2.15`, ...) that programs built against glibc older",
           "//! than 2.29 ask libm.so.6 for: each is a `jmp` to the current function (see the comment in tools/gen_compat_symver.py).",
           "//!", "//! Not provided: " + " ".join(skipped), "#![allow(missing_docs)]", "", "core::arch::global_asm!("]
    out.append('    ".pushsection .data.rl_compat,\\"aw\\",@progbits",')
    for name, ver, size in data:
        label = "__rl_cd_%s_%s" % (name, ver.replace("GLIBC_", "").replace(".", "_"))
        out.append('    ".globl %s",' % label)
        out.append('    ".type %s, @object",' % label)
        out.append('    ".size %s, %d",' % (label, size))
        out.append('    ".p2align 2",')
        out.append('    "%s:",' % label)
        out.append('    ".long %d",' % MATH_DATA[name])
        if size > 4:
            out.append('    ".zero %d",' % (size - 4))
        out.append('    ".symver %s, %s@%s",' % (label, name, ver))
    out.append('    ".popsection",')
    out.append('    ".pushsection .text.rl_compat,\\"ax\\",@progbits",')
    for name, target in sorted(MATH_PLAIN.items()):
        out.append('    ".p2align 3",')
        out.append('    ".globl %s",' % name)
        out.append('    ".type %s, @function",' % name)
        out.append('    "%s:",' % name)
        out.append('    "jmp %s",' % target)
    for name, ver, target in funcs:
        label = "__rl_cs_%s_%s" % (name, ver.replace("GLIBC_", "").replace(".", "_"))
        out.append('    ".p2align 3",')
        out.append('    ".globl %s",' % label)
        out.append('    "%s:",' % label)
        out.append('    "jmp %s",' % target)
        out.append('    ".symver %s, %s@%s",' % (label, name, ver))
    out.append('    ".popsection",')
    out.append(");")
    open(os.path.join(ROOT, "crates/rusty-libc-cabi/src/compat_symver_math.rs"), "w").write("\n".join(out) + "\n")
    print("math: %d versioned function symbols, %d data objects, %d skipped" % (len(funcs), len(data), len(skipped)))


if "--math" in sys.argv:
    math_main()
else:
    main()
