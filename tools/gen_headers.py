#!/usr/bin/env python3
import os, re, shutil, subprocess, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.dont_write_bytecode = True
import sys_headers, sys_types
import math_headers

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MEM_SRC = ["mem.rs", "str.rs", "search.rs"]
ITEM_SRC = [("rusty-libc-mem", n) for n in MEM_SRC] + [("rusty-libc-wchar", "mbyte.rs"), ("rusty-libc-wchar", "wctype.rs")]

TIME_SRC = ["crates/rusty-libc-time/src/" + f for f in ("clock.rs", "calendar.rs", "tz.rs", "strftime.rs")]
TIME_OTHER_FNS = "gettimeofday settimeofday adjtime getitimer setitimer utimes lutimes futimes futimesat ftime utime stime".split()

SIG_SRC = ["crates/rusty-libc-signal/src/" + f for f in ("sigset.rs", "action.rs", "send.rs", "wait.rs", "stack.rs", "names.rs")]
SIG_TIERS = {
    "posix": "raise kill sigemptyset sigfillset sigaddset sigdelset sigismember sigprocmask sigsuspend sigaction sigpending sigwait sigwaitinfo sigtimedwait sigqueue",
    "misc": "killpg siginterrupt sigaltstack",
    "miscx": "ssignal gsignal sigblock sigsetmask siggetmask sigreturn sigstack",
    "k8": "psignal psiginfo",
    "xopen": "sighold sigrelse sigignore sigset",
    "bsdsig": "bsd_signal",
    "gnu": "sigisemptyset sigandset sigorset sysv_signal tgkill",
}

HEADERS = {
    "sys/types": {"config": "types", "files": ["crates/rusty-libc-cabi/src/types.rs"]},
    "stdlib": {"config": "stdlib", "files": ["crates/rusty-libc-cabi/src/stdlib.rs", "crates/rusty-libc-malloc/src/stdlib_api.rs", "crates/rusty-libc-stdlib/src/num.rs", "crates/rusty-libc-stdlib/src/sort.rs", "crates/rusty-libc-stdlib/src/rand.rs", "crates/rusty-libc-stdlib/src/env.rs", "crates/rusty-libc-stdlib/src/misc.rs", "crates/rusty-libc-stdio/src/numconv.rs"], "fns": "mblen mbtowc wctomb mbstowcs wcstombs __ctype_get_mb_cur_max".split()},
    "stdio": {"config": "stdio", "files": ["crates/rusty-libc-stdio/src/file_api.rs", "crates/rusty-libc-stdio/src/file_extra.rs", "crates/rusty-libc-stdio/src/printf_api.rs"],
              "picks": {"crates/rusty-libc-extra/src/obstack.rs": ["obstack_printf", "obstack_vprintf"], "crates/rusty-libc-util/src/pwd.rs": ["cuserid"]}},
    "wchar": {"config": "wchar", "files": ["crates/rusty-libc-wchar/src/wstring.rs", "crates/rusty-libc-wchar/src/wconv.rs", "crates/rusty-libc-stdio/src/wfile.rs", "crates/rusty-libc-stdio/src/wprintf_api.rs", "crates/rusty-libc-stdio/src/wscan_api.rs"], "fns": """
        btowc wctob mbsinit mbrlen mbrtowc wcrtomb mbsrtowcs mbsnrtowcs wcsrtombs wcsnrtombs
        wcwidth wcswidth""".split()},
    "wctype": {"config": "wctype", "fns": """
        towlower towupper towlower_l towupper_l wctype wctype_l iswctype iswctype_l
        wctrans wctrans_l towctrans towctrans_l""".split()},
    "uchar": {"config": "uchar", "fns": "mbrtoc8 c8rtomb mbrtoc16 c16rtomb mbrtoc32 c32rtomb".split()},
    "stdio_ext": {"config": "stdio_ext", "files": ["crates/rusty-libc-stdio/src/stdio_ext.rs"]},
    "ctype": {"config": "ctype", "files": ["crates/rusty-libc-ctype/src/lib.rs"],
              "picks": {"crates/rusty-libc-extra/src/misc.rs": ["__isascii_l", "__toascii_l"]}},
    "errno": {"config": "errno", "files": ["crates/rusty-libc-cabi/src/errno.rs"]},
    "malloc": {"config": "malloc", "files": ["crates/rusty-libc-malloc/src/malloc_api.rs", "crates/rusty-libc-stdio/src/malloc_info.rs"]},
    "unistd": {"config": "unistd", "files": ["crates/rusty-libc-cabi/src/unistd.rs"], "fns": ["swab"], "picks": {"crates/rusty-libc-extra/src/gmon.rs": ["profil"]}},
    "string": {"config": "string", "files": ["crates/rusty-libc-malloc/src/string_alloc.rs", "crates/rusty-libc-cabi/src/strerror.rs"], "fns": """
        memcpy memmove memset memcmp memchr memrchr rawmemchr memccpy mempcpy memfrob memmem
        memset_explicit explicit_bzero strcpy stpcpy strncpy stpncpy strcat strncat strlcpy strlcat
        strcmp strncmp strcoll strcoll_l strxfrm strxfrm_l strchr strrchr strchrnul strspn strcspn
        strpbrk strstr strcasestr strtok strtok_r strsep strlen strnlen strverscmp basename""".split(),
        "picks": {"crates/rusty-libc-signal/src/names.rs": ["sigabbrev_np", "sigdescr_np"], "crates/rusty-libc-util/src/strfry.rs": ["strfry"]}},
    "sys/auxv": {"config": "auxv", "picks": {"crates/rusty-libc-util/src/auxv.rs": ["getauxval"]},
                 "subst": [(r"\bu64\b", "c_ulong")]},
    "libgen": {"config": "libgen", "picks": {"crates/rusty-libc-util/src/libgen.rs": ["__xpg_basename", "dirname"]}},
    "search": {"config": "search", "picks": {"crates/rusty-libc-util/src/search.rs": """
        hcreate_r hdestroy_r hsearch_r hcreate hdestroy hsearch tsearch tfind tdelete tdestroy lfind lsearch insque remque""".split()}},
    "err": {"config": "err", "picks": {"crates/rusty-libc-util/src/err.rs": "vwarn vwarnx verr verrx warn warnx err errx".split()}},
    "error": {"config": "error", "picks": {"crates/rusty-libc-util/src/err.rs": "error error_at_line error_print_progname error_message_count error_one_per_line".split()},
              "subst": [(r"\bu32\b", "c_uint")]},
    "bits/getopt_core": {"config": "getopt_core", "picks": {"crates/rusty-libc-util/src/getopt.rs": "optarg optind opterr optopt getopt".split()}},
    "bits/getopt_ext": {"config": "getopt_ext", "picks": {"crates/rusty-libc-util/src/getopt.rs": ["getopt_long", "getopt_long_only"]}},
    "fnmatch": {"config": "fnmatch", "picks": {"crates/rusty-libc-util/src/fnmatch.rs": ["fnmatch"]}},
    "iconv": {"config": "iconv", "picks": {"crates/rusty-libc-iconv/src/cabi.rs": ["iconv_open", "iconv", "iconv_close"]}},
    "glob": {"config": "glob", "picks": {"crates/rusty-libc-util/src/glob.rs": "glob globfree glob_pattern_p".split()},
             "subst": [(r"Option<ErrFn>", 'Option<unsafe extern "C" fn(*const c_char, c_int) -> c_int>')]},
    "bits/rlibc-wordexpcalls": {"config": "wordexpcalls", "picks": {"crates/rusty-libc-util/src/wordexp.rs": ["wordexp", "wordfree"]}},
    "pwd": {"config": "pwd", "picks": {"crates/rusty-libc-util/src/pwd.rs": """
        getpwnam_r getpwuid_r getpwnam getpwuid setpwent endpwent getpwent_r getpwent fgetpwent_r fgetpwent putpwent getpw""".split()}},
    "grp": {"config": "grp", "picks": {"crates/rusty-libc-util/src/pwd.rs": """
        getgrnam_r getgrgid_r getgrnam getgrgid setgrent endgrent getgrent_r getgrent fgetgrent_r fgetgrent putgrent
        getgrouplist initgroups""".split()}},
    "shadow": {"config": "shadow", "picks": {"crates/rusty-libc-util/src/pwd.rs": """
        getspnam_r getspnam setspent endspent getspent_r getspent fgetspent_r fgetspent sgetspent_r sgetspent putspent
        lckpwdf ulckpwdf""".split()}},
    "bits/rlibc_util_unistd": {"config": "util_unistd", "picks": {"crates/rusty-libc-util/src/pwd.rs": """
        getlogin getlogin_r getusershell setusershell endusershell""".split()}},
    "time": {"config": "time", "files": TIME_SRC, "skip": TIME_OTHER_FNS},
    "sys/time": {"config": "systime", "files": TIME_SRC, "only": "gettimeofday settimeofday adjtime getitimer setitimer utimes lutimes futimes futimesat".split()},
    "sys/timeb": {"config": "timeb", "files": TIME_SRC, "only": ["ftime"]},
    "utime": {"config": "utime", "files": TIME_SRC, "only": ["utime"]},
    "bits/rlibc-mathcalls": {"config": "mathcalls", "tiers": True, "files": ["crates/rusty-libc-math/src/" + f for f in
        ["exp.rs", "exp/c23.rs", "trig.rs", "rounding.rs", "rounding/fma_impl.rs", "rounding/cbrt_impl.rs",
         "rounding/fmod_impl.rs", "rounding/hypot_impl.rs", "rounding/minmax.rs", "rounding/fp.rs", "classify.rs", "quad/c23.rs"]]},
    "bits/rlibc-fenvcalls": {"config": "fenvcalls", "tiers": True, "files": ["crates/rusty-libc-math/src/fenv.rs"]},
    "bits/rlibc-pthreadcalls": {"config": "pthreadcalls", "files": ["crates/rusty-libc-pthread/src/" + f for f in
        ["attr.rs", "thread.rs", "cancel.rs", "mutex.rs", "cond.rs", "rwlock.rs", "key.rs", "sync.rs", "misc.rs", "atfork.rs"]],
        "subst": [(r"\*mut pthread_spinlock_t", "*mut pthread_spinlock_t")]},
    "bits/rlibc-semcalls": {"config": "semcalls", "files": ["crates/rusty-libc-pthread/src/sem.rs"]},
    "bits/rlibc-threadscalls": {"config": "threadscalls", "files": ["crates/rusty-libc-pthread/src/c11.rs"]},
    "strings": {"config": "strings", "fns": """
        bcmp bcopy bzero index rindex strcasecmp strncasecmp strcasecmp_l strncasecmp_l""".split(),
        "picks": {"crates/rusty-libc-extra/src/misc.rs": ["ffs", "ffsl", "ffsll"]}},
}

_NET = "crates/rusty-libc-net/src/"
HEADERS.update({
    "bits/rlibc-net-sock": {"config": "net_sock", "picks": {_NET + "sock.rs": """
        socket socketpair bind listen accept accept4 connect getsockname getpeername send recv sendto recvfrom
        sendmsg recvmsg sendmmsg recvmmsg shutdown getsockopt setsockopt isfdtype sockatmark __cmsg_nxthdr""".split()}},
    "bits/rlibc-net-in": {"config": "net_in", "picks": {
        _NET + "inet.rs": "htons ntohs htonl ntohl".split(),
        _NET + "misc.rs": """bindresvport inet6_opt_init inet6_opt_append inet6_opt_finish inet6_opt_set_val inet6_opt_next
        inet6_opt_find inet6_opt_get_val inet6_rth_space inet6_rth_init inet6_rth_add inet6_rth_reverse
        inet6_rth_segments inet6_rth_getaddr""".split(),
        _NET + "inetx.rs": """inet6_option_space inet6_option_init inet6_option_append inet6_option_alloc inet6_option_next inet6_option_find
        getsourcefilter setsourcefilter getipv4sourcefilter setipv4sourcefilter""".split()}},
    "bits/rlibc-net-inet": {"config": "net_inet", "picks": {_NET + "inet.rs": """
        inet_addr inet_aton inet_lnaof inet_makeaddr inet_netof inet_network inet_ntoa inet_ntop inet_pton
        inet_nsap_addr inet_nsap_ntoa""".split()}},
    "bits/rlibc-net-netdb": {"config": "net_netdb", "picks": {
        _NET + "netdb.rs": """
        gethostbyname gethostbyname2 gethostbyaddr gethostbyname_r gethostbyname2_r gethostbyaddr_r gethostent
        gethostent_r sethostent endhostent getservbyname getservbyport getservent getservbyname_r getservbyport_r
        getservent_r setservent endservent getprotobyname getprotobynumber getprotoent getprotobyname_r
        getprotobynumber_r getprotoent_r setprotoent endprotoent getnetbyname getnetbyaddr getnetent
        getnetbyname_r getnetbyaddr_r getnetent_r setnetent endnetent getrpcbyname getrpcbynumber getrpcent
        getrpcbyname_r getrpcbynumber_r getrpcent_r setrpcent endrpcent""".split(),
        _NET + "gai.rs": "getaddrinfo freeaddrinfo getnameinfo".split(),
        _NET + "netgrp.rs": "setnetgrent endnetgrent getnetgrent getnetgrent_r innetgr".split(),
        _NET + "gai_async.rs": "getaddrinfo_a gai_suspend gai_error gai_cancel".split(),
        _NET + "rcmd.rs": "rcmd rcmd_af rexec rexec_af rresvport rresvport_af ruserok ruserok_af iruserok iruserok_af".split(),
        _NET + "strerr.rs": "gai_strerror hstrerror herror __h_errno_location".split()}},
    "bits/rlibc-net-aliases": {"config": "net_aliases", "picks": {_NET + "netdb.rs": """
        getaliasent getaliasent_r getaliasbyname getaliasbyname_r setaliasent endaliasent""".split()}},
    "bits/rlibc-net-if": {"config": "net_if", "picks": {_NET + "ifaddrs.rs": "if_nametoindex if_indextoname if_nameindex if_freenameindex".split()}},
    "bits/rlibc-net-ifaddrs": {"config": "net_ifaddrs", "picks": {_NET + "ifaddrs.rs": "getifaddrs freeifaddrs".split()}},
    "bits/rlibc-net-ether": {"config": "net_ether", "picks": {_NET + "ether.rs": """
        ether_aton ether_aton_r ether_ntoa ether_ntoa_r ether_line ether_hostton ether_ntohost""".split()}},
    "bits/rlibc-net-nameser": {"config": "net_nameser", "picks": {_NET + "resolv.rs": """
        ns_name_uncompress ns_name_unpack ns_name_ntop ns_name_pton ns_name_skip ns_name_pack ns_name_compress""".split(),
        _NET + "nsparse.rs": """ns_msg_getflag ns_get16 ns_get32 ns_put16 ns_put32 ns_initparse ns_skiprr ns_parserr ns_sprintrr
        ns_sprintrrf ns_format_ttl ns_parse_ttl ns_datetosecs ns_name_ntol ns_name_rollback ns_samedomain ns_subdomain
        ns_makecanon ns_samename""".split()}},
    "bits/rlibc-net-resolv": {"config": "net_resolv", "picks": {_NET + "resolv.rs": """
        res_query res_search res_querydomain res_mkquery res_send res_nquery res_nsearch res_nquerydomain
        res_nmkquery res_nsend __res_init __res_ninit __res_nclose __res_state dn_comp dn_expand dn_skipname
        res_hnok res_dnok res_ownok res_mailok""".split(), _NET + "nsparse.rs": ["__loc_ntoa"]}},
})

_IPC = "crates/rusty-libc-ipc/src/"
HEADERS.update({
    "bits/rlibc-ipc-ipc": {"config": "ipc_ipc", "picks": {_IPC + "sysv.rs": ["ftok"]}},
    "bits/rlibc-ipc-msg": {"config": "ipc_msg", "picks": {_IPC + "sysv.rs": "msgctl msgget msgrcv msgsnd".split()}},
    "bits/rlibc-ipc-sem": {"config": "ipc_sem", "picks": {_IPC + "sysv.rs": "semctl semget semop".split()}},
    "bits/rlibc-ipc-semgnu": {"config": "ipc_semgnu", "picks": {_IPC + "sysv.rs": ["semtimedop"]}},
    "bits/rlibc-ipc-shm": {"config": "ipc_shm", "picks": {_IPC + "sysv.rs": "shmctl shmget shmat shmdt".split()}},
    "bits/rlibc-mq-calls": {"config": "ipc_mq_calls", "picks": {_IPC + "mq.rs": "mq_open __mq_open_2 mq_close mq_getattr mq_setattr mq_unlink mq_notify mq_receive mq_send".split()}},
    "bits/rlibc-mq-timed": {"config": "ipc_mq_timed", "picks": {_IPC + "mq.rs": "mq_timedreceive mq_timedsend".split()}},
    "bits/rlibc-aio-calls": {"config": "aio_calls", "picks": {_IPC + "aio.rs": "aio_read aio_write aio_fsync aio_error aio_return aio_cancel aio_suspend lio_listio".split()}},
    "bits/rlibc-aio-64": {"config": "aio_64", "picks": {_IPC + "aio.rs": "aio_read64 aio_write64 aio_fsync64 aio_error64 aio_return64 aio_cancel64 aio_suspend64 lio_listio64".split()}},
    "bits/rlibc-aio-gnu": {"config": "aio_gnu", "picks": {_IPC + "aio.rs": ["aio_init"]}},
})
_EXTRA = "crates/rusty-libc-extra/src/"
def _words(text):
    return text.split()
EXTRA_HEADERS = [
    {"name": "spawncalls", "files": ["spawn.rs"], "tiers": _words("""posix_spawn_file_actions_addchdir_np
        posix_spawn_file_actions_addfchdir_np posix_spawn_file_actions_addclosefrom_np
        posix_spawn_file_actions_addtcsetpgrp_np posix_spawnattr_getcgroup_np posix_spawnattr_setcgroup_np
        pidfd_spawn pidfd_spawnp""")},
    {"name": "mntentcalls", "files": ["mntent.rs"], "tiers": ["getmntent_r"]},
    {"name": "utmpcalls", "files": ["utmp.rs"], "only": _words("""utmpname setutent endutent getutent getutid getutline
        pututline updwtmp logwtmp login logout getutent_r getutid_r getutline_r"""),
     "tiers": _words("getutent_r getutid_r getutline_r")},
    {"name": "argzcalls", "files": ["argz.rs"], "only": _words("""argz_create argz_create_sep argz_count argz_extract
        argz_stringify argz_append argz_add argz_add_sep argz_delete argz_insert argz_next argz_replace""")},
    {"name": "envzcalls", "files": ["argz.rs"], "only": _words("envz_entry envz_get envz_add envz_merge envz_remove envz_strip")},
    {"name": "ftscalls", "files": ["fts.rs"], "only": _words("fts_open fts_read fts_children fts_close fts_set")},
    {"name": "fstabcalls", "files": ["fstab.rs"]},
    {"name": "ttyentcalls", "files": ["ttyent.rs"]},
    {"name": "syslogcalls", "files": ["syslog.rs"], "only": _words("openlog closelog setlogmask syslog vsyslog"),
     "subst": [(r"\bva_list\b", "__gnuc_va_list")]},
    {"name": "utmpxcalls", "files": ["utmp.rs"], "only": _words("""setutxent endutxent getutxent getutxid getutxline
        pututxline utmpxname updwtmpx getutmp getutmpx"""), "tiers": _words("utmpxname updwtmpx getutmp getutmpx")},
]
HEADERS["bits/rlibc-gshadowcalls"] = {"config": "gshadowcalls", "picks": {"crates/rusty-libc-util/src/pwd/sgrp.rs": _words("""
    getsgnam_r getsgnam setsgent endsgent getsgent_r getsgent fgetsgent_r fgetsgent sgetsgent_r sgetsgent putsgent""")}}
for _h in EXTRA_HEADERS:
    _src = [_EXTRA + f for f in _h["files"]]
    _tiers = _h.get("tiers", [])
    _base = {"config": _h["name"], "files": _src}
    if "subst" in _h:
        _base["subst"] = _h["subst"]
    if "only" in _h:
        _base["only"] = [n for n in _h["only"] if n not in _tiers]
    else:
        _base["skip"] = _tiers
    HEADERS["bits/rlibc-" + _h["name"]] = _base
    if _tiers:
        HEADERS["bits/rlibc-" + _h["name"] + "-misc"] = {"config": _h["name"] + "_misc", "files": _src, "only": _tiers, **({"subst": _h["subst"]} if "subst" in _h else {})}

_RPC = "crates/rusty-libc-rpc/src/"
_RPC_DECLS = {
    "xdr": {"files": [_RPC + "xdr.rs", _RPC + "xdrrec.rs", _RPC + "xdrstdio.rs"]},
    "auth": {"picks": {
        _RPC + "auth.rs": "authnone_create authunix_create authunix_create_default".split(),
        _RPC + "authdes.rs": "authdes_create authdes_pk_create".split(),
        _RPC + "msg.rs": "xdr_opaque_auth xdr_des_block".split(),
        _RPC + "key.rs": """getnetname host2netname user2netname netname2user netname2host key_decryptsession
            key_decryptsession_pk key_encryptsession key_encryptsession_pk key_gendes key_setsecret
            key_secretkey_is_set key_get_conv""".split()}},
    "auth_unix": {"picks": {_RPC + "auth.rs": ["xdr_authunix_parms"]}},
    "clnt": {"picks": {
        _RPC + "clnt.rs": "clnt_create clnt_pcreateerror clnt_spcreateerror clnt_perrno clnt_perror clnt_sperror clnt_sperrno callrpc".split(),
        _RPC + "clnt_raw.rs": ["clntraw_create"],
        _RPC + "clnt_tcp.rs": ["clnttcp_create"],
        _RPC + "clnt_udp.rs": ["clntudp_create", "clntudp_bufcreate"],
        _RPC + "clnt_unix.rs": ["clntunix_create"],
        _RPC + "vars.rs": ["_rpc_dtablesize"],
        _RPC + "pmap.rs": ["getrpcport", "get_myaddress"]}},
    "msg": {"picks": {_RPC + "msg.rs": "xdr_callmsg xdr_callhdr xdr_replymsg _seterr_reply xdr_accepted_reply xdr_rejected_reply".split()}},
    "svc": {"picks": {
        _RPC + "svc.rs": """svc_register svc_unregister xprt_register xprt_unregister svc_sendreply svcerr_decode
            svcerr_weakauth svcerr_noproc svcerr_progvers svcerr_auth svcerr_noprog svcerr_systemerr svc_getreq
            svc_getreq_common svc_getreqset svc_getreq_poll svc_exit svc_run registerrpc""".split(),
        _RPC + "svc_raw.rs": ["svcraw_create"],
        _RPC + "svc_udp.rs": ["svcudp_create", "svcudp_bufcreate", "svcudp_enablecache"],
        _RPC + "svc_tcp.rs": ["svctcp_create", "svcfd_create"],
        _RPC + "svc_unix.rs": ["svcunix_create", "svcunixfd_create"]}},
    "svc_auth": {"picks": {_RPC + "auth.rs": ["_authenticate"]}},
    "pmap_clnt": {"picks": {_RPC + "pmap.rs": "pmap_set pmap_unset pmap_getmaps pmap_rmtcall clnt_broadcast pmap_getport".split()}},
    "pmap_prot": {"picks": {_RPC + "pmap.rs": ["xdr_pmap", "xdr_pmaplist"]}},
    "pmap_rmt": {"picks": {_RPC + "pmap.rs": ["xdr_rmtcall_args", "xdr_rmtcallres"]}},
    "auth_des": {"picks": {
        _RPC + "authdes.rs": "authdes_getucred xdr_authdes_cred xdr_authdes_verf".split(),
        _RPC + "key.rs": ["getpublickey", "getsecretkey", "rtime"]}},
    "des_crypt": {"picks": {_RPC + "des.rs": "cbc_crypt ecb_crypt des_setparity passwd2des xencrypt xdecrypt".split()}},
    "key_prot": {"picks": {_RPC + "key.rs": """xdr_keystatus xdr_keybuf xdr_netnamestr xdr_cryptkeyarg xdr_cryptkeyarg2
        xdr_cryptkeyres xdr_unixcred xdr_getcredres xdr_key_netstarg xdr_key_netstres key_setnet""".split()}},
}
for _n, _spec in _RPC_DECLS.items():
    HEADERS["bits/rlibc-rpc-" + _n.replace("_", "-")] = {"config": "rpc_" + ("rpc_msg" if _n == "msg" else _n), **_spec}

for _tier, _names in SIG_TIERS.items():
    HEADERS["bits/rlibc-sigcalls-" + _tier] = {"config": "signalcalls_" + _tier, "files": SIG_SRC, "only": _names.split()}

for _h in list(sys_headers.SYS_FNS) + sys_headers.CONST_ONLY + ["sys/types"]:
    _spec = HEADERS.setdefault(_h, {"config": _h.replace("/", "_")})
    _spec["sys"] = True

def load_mem_items():
    items = {}
    for crate, name in ITEM_SRC:
        text = open(os.path.join(ROOT, "crates", crate, "src", name)).read()
        for m in re.finditer(r'((?:///[^\n]*\n|#\[[^\n]*\n)+)(pub unsafe extern "C" fn (\w+)\b.*?\n\}\n)', text, re.S):
            items[m.group(3)] = m.group(1) + m.group(2)
    return items

ITEM_RE = re.compile(
    r'((?:///[^\n]*\n|#\[[^\n]*\n)*)'
    r'(pub (?:unsafe )?extern "C" fn (\w+)\b.*?\n\}\n|pub static mut (\w+)\b[^\n]*;\n)', re.S)

def pick_items(path, names):
    text = open(os.path.join(ROOT, path)).read()
    found = {}
    for m in ITEM_RE.finditer(text):
        name = m.group(3) or m.group(4)
        if name in names and "not(feature" not in m.group(1):
            attrs = m.group(1)
            if "no_mangle" not in attrs and m.group(3):
                attrs += "#[unsafe(no_mangle)]\n"
            found[name] = attrs + m.group(2)
    missing = [n for n in names if n not in found]
    if missing:
        sys.exit("gen_headers: %s: not found: %s" % (path, " ".join(missing)))
    return [found[n] for n in names]

GUARD_RE = re.compile(r"^(#\s*ifndef\s+(\w+)[ \t]*\n#\s*define\s+\2\b[^\n]*\n)", re.M)

def add_features_include(out_dir):
    skip = {"features.h", "limits.h", "stdint.h", "gnu-versions.h"}
    for top, dirs, files in os.walk(out_dir):
        rel = os.path.relpath(top, out_dir)
        if rel == "bits" or rel.startswith("bits" + os.sep) or rel == "gnu":
            continue
        for name in files:
            if not name.endswith(".h") or (rel == "." and name in skip) or (rel == "sys" and name == "cdefs.h"):
                continue
            path = os.path.join(top, name)
            text = open(path).read()
            if "<features.h>" in text:
                continue
            m = GUARD_RE.search(text)
            if not m:
                print("gen_headers: no include guard, features.h not added: " + os.path.join(rel, name))
                continue
            rel_path = os.path.normpath(os.path.join(rel, name))
            glibc_guard = "_" + re.sub(r"[^A-Za-z0-9]", "_", rel_path).upper()
            extra = "" if re.search(r"#\s*define\s+%s\b" % glibc_guard, text) else "#ifndef %s\n# define %s 1\n#endif\n" % (glibc_guard, glibc_guard)
            text = text[:m.end()] + "#include <features.h>\n" + extra + text[m.end():]
            with open(path, "w") as f:
                f.write(text)


_P = "__THROW __attribute_pure__ __nonnull ((%s))"
_T = "__THROW __nonnull ((%s))"
ATTRS = {
    "string.h": {
        **{n: _T % "1, 2" for n in "memcpy memmove memccpy mempcpy strcpy stpcpy strncpy stpncpy strcat strncat strsep".split()},
        "memset": _T % "1", "strxfrm": _T % "2", "strtok": _T % "2", "strtok_r": _T % "2, 3",
        **{n: _P % "1, 2" for n in "memcmp strcmp strncmp strcoll strcspn strspn strpbrk strstr strverscmp".split()},
        **{n: _P % "1" for n in "memchr rawmemchr memrchr strchr strrchr strchrnul strlen strnlen".split()},
        "memmem": _P % "1, 3", "strdup": "__THROW __attribute_malloc__ __nonnull ((1))", "strndup": "__THROW __attribute_malloc__ __nonnull ((1))",
        "strerror": "__THROW",
    },
    "strings.h": {"bcmp": _P % "1, 2", "bcopy": _T % "1, 2", "bzero": _T % "1", "index": _P % "1", "rindex": _P % "1",
                  "strcasecmp": _P % "1, 2", "strncasecmp": _P % "1, 2", "ffs": "__THROW __attribute_const__", "ffsl": "__THROW __attribute_const__", "ffsll": "__THROW __attribute_const__"},
    "stdlib.h": {"atoi": _P % "1", "atol": _P % "1", "atoll": _P % "1", "atof": _P % "1",
                 "abs": "__THROW __attribute_const__", "labs": "__THROW __attribute_const__", "llabs": "__THROW __attribute_const__",
                 "strtol": _T % "1", "strtoul": _T % "1", "strtoll": _T % "1", "strtoull": _T % "1", "strtod": _T % "1", "strtof": _T % "1", "strtold": _T % "1",
                 "getenv": "__THROW __nonnull ((1))", "malloc": "__THROW __attribute_malloc__", "calloc": "__THROW __attribute_malloc__"},
}
CTYPE_NAMES = "isalnum isalpha iscntrl isdigit islower isgraph isprint ispunct isspace isupper isxdigit isblank tolower toupper isascii toascii".split()
ATTRS["ctype.h"] = {n: "__THROW" for n in CTYPE_NAMES}

def add_attributes(out_dir):
    for hdr, table in ATTRS.items():
        path = os.path.join(out_dir, hdr)
        if not os.path.exists(path):
            continue
        text = open(path).read()
        for name, attr in table.items():
            pat = re.compile(r"^(?![ \t]*[*/])([^\n;{}()]*[ *]%s[ \t]*\([^;{}]*\))[ \t]*;" % re.escape(name), re.M)
            text = pat.sub(lambda m: m.group(1) + " " + attr + ";", text, count=1)
        with open(path, "w") as f:
            f.write(text)

UNTYPEDEF = {"stdlib.h": ["random_data", "drand48_data"]}

def untypedef(out_dir):
    for hdr, names in UNTYPEDEF.items():
        path = os.path.join(out_dir, hdr)
        if not os.path.exists(path):
            continue
        text = open(path).read()
        for n in names:
            text = re.sub(r"typedef struct %s \{(.*?)\n\} %s;" % (n, n), r"struct %s {\1\n};" % n, text, count=1, flags=re.S)
        with open(path, "w") as f:
            f.write(text)

def main(out_dir):
    static_dir = os.path.join(ROOT, "include-static")
    if os.path.isdir(static_dir):
        for top, _dirs, files in os.walk(static_dir):
            rel = os.path.relpath(top, static_dir)
            os.makedirs(os.path.join(out_dir, rel), exist_ok=True)
            for name in files:
                subprocess.run(["cp", os.path.join(top, name), os.path.join(out_dir, rel, name)], check=True)
    items = load_mem_items()
    for hdr, spec in HEADERS.items():
        parts = []
        for f in spec.get("files", []):
            parts.append(open(os.path.join(ROOT, f)).read())
        for fn in spec.get("fns", []):
            parts.append(items[fn])
        for path, names in spec.get("picks", {}).items():
            parts.extend(pick_items(path, names))
        if spec.get("sys"):
            parts.append(sys_headers.header_source(hdr))
        src = "\n".join(parts).replace('#[cfg_attr(feature = "export", unsafe(no_mangle))]', "#[unsafe(no_mangle)]")
        if "only" in spec or "skip" in spec:
            def keep(m):
                name = m.group(2)
                ok = name in spec["only"] if "only" in spec else name not in spec["skip"]
                return m.group(0) if ok else m.group(0).replace("#[unsafe(no_mangle)]", "", 1)
            if "only" in spec:
                src = re.sub(r'#\[unsafe\(no_mangle\)\]\n((?:#\[[^\n]*\n)*pub static)', r'\1', src)
            src = re.sub(r'#\[unsafe\(no_mangle\)\]\n((?:#\[[^\n]*\n)*pub (?:unsafe )?extern "C" fn (\w+))', keep, src)
        src = re.sub(r"^//!.*\n", "", src, flags=re.M)
        src = re.sub(r"^#!\[.*\]\n", "", src, flags=re.M)
        src = re.sub(r"\bVaList\b", "va_list", src)
        for pat, repl in spec.get("subst", []):
            src = re.sub(pat, repl, src)
        if spec.get("tiers"):
            src = math_headers.inject_cfg(src)
        with tempfile.NamedTemporaryFile("w", suffix=".rs", delete=False) as t:
            t.write(src)
        dest = os.path.join(out_dir, hdr + ".h")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        subprocess.run(["cbindgen", "--config", os.path.join(ROOT, "cbindgen", spec["config"] + ".toml"),
                        "--output", dest, t.name], check=True, stderr=subprocess.DEVNULL)
        os.unlink(t.name)
        if spec.get("sys"):
            with open(dest) as f:
                text = f.read()
            with open(dest, "w") as f:
                f.write(sys_types.finish(text, hdr))
    os.makedirs(os.path.join(out_dir, "bits"), exist_ok=True)
    with open(os.path.join(out_dir, "bits/rlibc-mathaliases.h"), "w") as f:
        f.write(math_headers.alias_header())
    with open(os.path.join(out_dir, "bits/rlibc-mathldcalls.h"), "w") as f:
        f.write(math_headers.longdouble_header())
    with open(os.path.join(out_dir, "bits/rlibc-mathquadcalls.h"), "w") as f:
        f.write(math_headers.quad_header())
    with open(os.path.join(out_dir, "complex.h"), "w") as f:
        f.write(math_headers.complex_header())
    add_attributes(out_dir)
    untypedef(out_dir)
    add_features_include(out_dir)

if __name__ == "__main__":
    main(sys.argv[1])
