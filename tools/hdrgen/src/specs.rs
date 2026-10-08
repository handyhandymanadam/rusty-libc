#[derive(Clone, Default)]
pub enum Subst {
    #[default]
    None,
    Word(&'static str, &'static str),
    Lit(&'static str, &'static str),
}

#[derive(Clone, Default)]
pub struct Spec {
    pub name: String,
    pub config: String,
    pub files: Vec<String>,
    pub fns: Vec<String>,
    pub picks: Vec<(String, Vec<String>)>,
    pub only: Option<Vec<String>>,
    pub skip: Option<Vec<String>>,
    pub subst: Vec<Subst>,
    pub tiers: bool,
    pub sys: bool,
}

fn w(s: &str) -> Vec<String> {
    s.split_whitespace().map(String::from).collect()
}
fn fl(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| s.to_string()).collect()
}

fn spec(name: &str, config: &str) -> Spec {
    Spec { name: name.into(), config: config.into(), ..Default::default() }
}

impl Spec {
    fn files(mut self, f: &[&str]) -> Self {
        self.files = fl(f);
        self
    }
    fn fns(mut self, s: &str) -> Self {
        self.fns = w(s);
        self
    }
    fn pick(mut self, file: &str, names: &str) -> Self {
        self.picks.push((file.into(), w(names)));
        self
    }
    fn only(mut self, s: &str) -> Self {
        self.only = Some(w(s));
        self
    }
    fn skip(mut self, v: Vec<String>) -> Self {
        self.skip = Some(v);
        self
    }
    fn subst(mut self, s: Subst) -> Self {
        self.subst.push(s);
        self
    }
}

pub const MEM_SRC: [&str; 3] = ["mem.rs", "str.rs", "search.rs"];
pub fn item_src() -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = MEM_SRC.iter().map(|n| ("rusty-libc-mem".to_string(), n.to_string())).collect();
    v.push(("rusty-libc-wchar".into(), "mbyte.rs".into()));
    v.push(("rusty-libc-wchar".into(), "wctype.rs".into()));
    v
}

fn time_src() -> Vec<String> {
    ["clock.rs", "calendar.rs", "tz.rs", "strftime.rs"].iter().map(|f| format!("crates/rusty-libc-time/src/{f}")).collect()
}

pub fn build_specs() -> Vec<Spec> {
    let mut h: Vec<Spec> = Vec::new();
    let time_other = w("gettimeofday settimeofday adjtime getitimer setitimer utimes lutimes futimes futimesat ftime utime stime");
    let sig_src: Vec<String> = ["sigset.rs", "action.rs", "send.rs", "wait.rs", "stack.rs", "names.rs"].iter().map(|f| format!("crates/rusty-libc-signal/src/{f}")).collect();

    h.push(spec("sys/types", "types").files(&["crates/rusty-libc-cabi/src/types.rs"]));
    h.push(spec("stdlib", "stdlib")
        .files(&["crates/rusty-libc-cabi/src/stdlib.rs", "crates/rusty-libc-malloc/src/stdlib_api.rs", "crates/rusty-libc-stdlib/src/num.rs", "crates/rusty-libc-stdlib/src/sort.rs", "crates/rusty-libc-stdlib/src/rand.rs", "crates/rusty-libc-stdlib/src/env.rs", "crates/rusty-libc-stdlib/src/misc.rs", "crates/rusty-libc-stdio/src/numconv.rs"])
        .fns("mblen mbtowc wctomb mbstowcs wcstombs __ctype_get_mb_cur_max"));
    h.push(spec("stdio", "stdio")
        .files(&["crates/rusty-libc-stdio/src/file_api.rs", "crates/rusty-libc-stdio/src/file_extra.rs", "crates/rusty-libc-stdio/src/printf_api.rs"])
        .pick("crates/rusty-libc-extra/src/obstack.rs", "obstack_printf obstack_vprintf")
        .pick("crates/rusty-libc-util/src/pwd.rs", "cuserid"));
    h.push(spec("wchar", "wchar")
        .files(&["crates/rusty-libc-wchar/src/wstring.rs", "crates/rusty-libc-wchar/src/wconv.rs", "crates/rusty-libc-stdio/src/wfile.rs", "crates/rusty-libc-stdio/src/wprintf_api.rs", "crates/rusty-libc-stdio/src/wscan_api.rs"])
        .fns("btowc wctob mbsinit mbrlen mbrtowc wcrtomb mbsrtowcs mbsnrtowcs wcsrtombs wcsnrtombs wcwidth wcswidth"));
    h.push(spec("wctype", "wctype").fns("towlower towupper towlower_l towupper_l wctype wctype_l iswctype iswctype_l wctrans wctrans_l towctrans towctrans_l"));
    h.push(spec("uchar", "uchar").fns("mbrtoc8 c8rtomb mbrtoc16 c16rtomb mbrtoc32 c32rtomb"));
    h.push(spec("stdio_ext", "stdio_ext").files(&["crates/rusty-libc-stdio/src/stdio_ext.rs"]));
    h.push(spec("ctype", "ctype").files(&["crates/rusty-libc-ctype/src/lib.rs"]).pick("crates/rusty-libc-extra/src/misc.rs", "__isascii_l __toascii_l"));
    h.push(spec("errno", "errno").files(&["crates/rusty-libc-cabi/src/errno.rs"]));
    h.push(spec("malloc", "malloc").files(&["crates/rusty-libc-malloc/src/malloc_api.rs", "crates/rusty-libc-stdio/src/malloc_info.rs"]));
    h.push(spec("unistd", "unistd").files(&["crates/rusty-libc-cabi/src/unistd.rs"]).fns("swab").pick("crates/rusty-libc-extra/src/gmon.rs", "profil"));
    h.push(spec("string", "string")
        .files(&["crates/rusty-libc-malloc/src/string_alloc.rs", "crates/rusty-libc-cabi/src/strerror.rs"])
        .fns("memcpy memmove memset memcmp memchr memrchr rawmemchr memccpy mempcpy memfrob memmem memset_explicit explicit_bzero strcpy stpcpy strncpy stpncpy strcat strncat strlcpy strlcat strcmp strncmp strcoll strcoll_l strxfrm strxfrm_l strchr strrchr strchrnul strspn strcspn strpbrk strstr strcasestr strtok strtok_r strsep strlen strnlen strverscmp basename")
        .pick("crates/rusty-libc-signal/src/names.rs", "sigabbrev_np sigdescr_np")
        .pick("crates/rusty-libc-util/src/strfry.rs", "strfry"));
    h.push(spec("sys/auxv", "auxv").pick("crates/rusty-libc-util/src/auxv.rs", "getauxval").subst(Subst::Word("u64", "c_ulong")));
    h.push(spec("libgen", "libgen").pick("crates/rusty-libc-util/src/libgen.rs", "__xpg_basename dirname"));
    h.push(spec("search", "search").pick("crates/rusty-libc-util/src/search.rs", "hcreate_r hdestroy_r hsearch_r hcreate hdestroy hsearch tsearch tfind tdelete tdestroy lfind lsearch insque remque"));
    h.push(spec("err", "err").pick("crates/rusty-libc-util/src/err.rs", "vwarn vwarnx verr verrx warn warnx err errx"));
    h.push(spec("error", "error").pick("crates/rusty-libc-util/src/err.rs", "error error_at_line error_print_progname error_message_count error_one_per_line").subst(Subst::Word("u32", "c_uint")));
    h.push(spec("bits/getopt_core", "getopt_core").pick("crates/rusty-libc-util/src/getopt.rs", "optarg optind opterr optopt getopt"));
    h.push(spec("bits/getopt_ext", "getopt_ext").pick("crates/rusty-libc-util/src/getopt.rs", "getopt_long getopt_long_only"));
    h.push(spec("fnmatch", "fnmatch").pick("crates/rusty-libc-util/src/fnmatch.rs", "fnmatch"));
    h.push(spec("iconv", "iconv").pick("crates/rusty-libc-iconv/src/cabi.rs", "iconv_open iconv iconv_close"));
    h.push(spec("glob", "glob").pick("crates/rusty-libc-util/src/glob.rs", "glob globfree glob_pattern_p")
        .subst(Subst::Lit("Option<ErrFn>", "Option<unsafe extern \"C\" fn(*const c_char, c_int) -> c_int>")));
    h.push(spec("bits/rlibc-wordexpcalls", "wordexpcalls").pick("crates/rusty-libc-util/src/wordexp.rs", "wordexp wordfree"));
    h.push(spec("pwd", "pwd").pick("crates/rusty-libc-util/src/pwd.rs", "getpwnam_r getpwuid_r getpwnam getpwuid setpwent endpwent getpwent_r getpwent fgetpwent_r fgetpwent putpwent getpw"));
    h.push(spec("grp", "grp").pick("crates/rusty-libc-util/src/pwd.rs", "getgrnam_r getgrgid_r getgrnam getgrgid setgrent endgrent getgrent_r getgrent fgetgrent_r fgetgrent putgrent getgrouplist initgroups"));
    h.push(spec("shadow", "shadow").pick("crates/rusty-libc-util/src/pwd.rs", "getspnam_r getspnam setspent endspent getspent_r getspent fgetspent_r fgetspent sgetspent_r sgetspent putspent lckpwdf ulckpwdf"));
    h.push(spec("bits/rlibc_util_unistd", "util_unistd").pick("crates/rusty-libc-util/src/pwd.rs", "getlogin getlogin_r getusershell setusershell endusershell"));

    let mut t = spec("time", "time"); t.files = time_src(); t = t.skip(time_other.clone()); h.push(t);
    let mut t = spec("sys/time", "systime"); t.files = time_src(); t = t.only("gettimeofday settimeofday adjtime getitimer setitimer utimes lutimes futimes futimesat"); h.push(t);
    let mut t = spec("sys/timeb", "timeb"); t.files = time_src(); t = t.only("ftime"); h.push(t);
    let mut t = spec("utime", "utime"); t.files = time_src(); t = t.only("utime"); h.push(t);

    let mut m = spec("bits/rlibc-mathcalls", "mathcalls");
    m.tiers = true;
    m.files = ["exp.rs", "exp/c23.rs", "trig.rs", "rounding.rs", "rounding/fma_impl.rs", "rounding/cbrt_impl.rs", "rounding/fmod_impl.rs", "rounding/hypot_impl.rs", "rounding/minmax.rs", "rounding/fp.rs", "classify.rs", "quad/c23.rs"]
        .iter().map(|f| format!("crates/rusty-libc-math/src/{f}")).collect();
    h.push(m);
    let mut m = spec("bits/rlibc-fenvcalls", "fenvcalls");
    m.tiers = true;
    m.files = vec!["crates/rusty-libc-math/src/fenv.rs".into()];
    h.push(m);

    let mut p = spec("bits/rlibc-pthreadcalls", "pthreadcalls");
    p.files = ["attr.rs", "thread.rs", "cancel.rs", "mutex.rs", "cond.rs", "rwlock.rs", "key.rs", "sync.rs", "misc.rs", "atfork.rs"].iter().map(|f| format!("crates/rusty-libc-pthread/src/{f}")).collect();
    h.push(p);
    h.push(spec("bits/rlibc-semcalls", "semcalls").files(&["crates/rusty-libc-pthread/src/sem.rs"]));
    h.push(spec("bits/rlibc-threadscalls", "threadscalls").files(&["crates/rusty-libc-pthread/src/c11.rs"]));
    h.push(spec("strings", "strings").fns("bcmp bcopy bzero index rindex strcasecmp strncasecmp strcasecmp_l strncasecmp_l").pick("crates/rusty-libc-extra/src/misc.rs", "ffs ffsl ffsll"));

    let net = "crates/rusty-libc-net/src/";
    let n = |f: &str| format!("{net}{f}");
    h.push(spec("bits/rlibc-net-sock", "net_sock").pick(&n("sock.rs"), "socket socketpair bind listen accept accept4 connect getsockname getpeername send recv sendto recvfrom sendmsg recvmsg sendmmsg recvmmsg shutdown getsockopt setsockopt isfdtype sockatmark __cmsg_nxthdr"));
    h.push(spec("bits/rlibc-net-in", "net_in")
        .pick(&n("inet.rs"), "htons ntohs htonl ntohl")
        .pick(&n("misc.rs"), "bindresvport inet6_opt_init inet6_opt_append inet6_opt_finish inet6_opt_set_val inet6_opt_next inet6_opt_find inet6_opt_get_val inet6_rth_space inet6_rth_init inet6_rth_add inet6_rth_reverse inet6_rth_segments inet6_rth_getaddr")
        .pick(&n("inetx.rs"), "inet6_option_space inet6_option_init inet6_option_append inet6_option_alloc inet6_option_next inet6_option_find getsourcefilter setsourcefilter getipv4sourcefilter setipv4sourcefilter"));
    h.push(spec("bits/rlibc-net-inet", "net_inet").pick(&n("inet.rs"), "inet_addr inet_aton inet_lnaof inet_makeaddr inet_netof inet_network inet_ntoa inet_ntop inet_pton inet_nsap_addr inet_nsap_ntoa"));
    h.push(spec("bits/rlibc-net-netdb", "net_netdb")
        .pick(&n("netdb.rs"), "gethostbyname gethostbyname2 gethostbyaddr gethostbyname_r gethostbyname2_r gethostbyaddr_r gethostent gethostent_r sethostent endhostent getservbyname getservbyport getservent getservbyname_r getservbyport_r getservent_r setservent endservent getprotobyname getprotobynumber getprotoent getprotobyname_r getprotobynumber_r getprotoent_r setprotoent endprotoent getnetbyname getnetbyaddr getnetent getnetbyname_r getnetbyaddr_r getnetent_r setnetent endnetent getrpcbyname getrpcbynumber getrpcent getrpcbyname_r getrpcbynumber_r getrpcent_r setrpcent endrpcent")
        .pick(&n("gai.rs"), "getaddrinfo freeaddrinfo getnameinfo")
        .pick(&n("netgrp.rs"), "setnetgrent endnetgrent getnetgrent getnetgrent_r innetgr")
        .pick(&n("gai_async.rs"), "getaddrinfo_a gai_suspend gai_error gai_cancel")
        .pick(&n("rcmd.rs"), "rcmd rcmd_af rexec rexec_af rresvport rresvport_af ruserok ruserok_af iruserok iruserok_af")
        .pick(&n("strerr.rs"), "gai_strerror hstrerror herror __h_errno_location"));
    h.push(spec("bits/rlibc-net-aliases", "net_aliases").pick(&n("netdb.rs"), "getaliasent getaliasent_r getaliasbyname getaliasbyname_r setaliasent endaliasent"));
    h.push(spec("bits/rlibc-net-if", "net_if").pick(&n("ifaddrs.rs"), "if_nametoindex if_indextoname if_nameindex if_freenameindex"));
    h.push(spec("bits/rlibc-net-ifaddrs", "net_ifaddrs").pick(&n("ifaddrs.rs"), "getifaddrs freeifaddrs"));
    h.push(spec("bits/rlibc-net-ether", "net_ether").pick(&n("ether.rs"), "ether_aton ether_aton_r ether_ntoa ether_ntoa_r ether_line ether_hostton ether_ntohost"));
    h.push(spec("bits/rlibc-net-nameser", "net_nameser")
        .pick(&n("resolv.rs"), "ns_name_uncompress ns_name_unpack ns_name_ntop ns_name_pton ns_name_skip ns_name_pack ns_name_compress")
        .pick(&n("nsparse.rs"), "ns_msg_getflag ns_get16 ns_get32 ns_put16 ns_put32 ns_initparse ns_skiprr ns_parserr ns_sprintrr ns_sprintrrf ns_format_ttl ns_parse_ttl ns_datetosecs ns_name_ntol ns_name_rollback ns_samedomain ns_subdomain ns_makecanon ns_samename"));
    h.push(spec("bits/rlibc-net-resolv", "net_resolv")
        .pick(&n("resolv.rs"), "res_query res_search res_querydomain res_mkquery res_send res_nquery res_nsearch res_nquerydomain res_nmkquery res_nsend __res_init __res_ninit __res_nclose __res_state dn_comp dn_expand dn_skipname res_hnok res_dnok res_ownok res_mailok")
        .pick(&n("nsparse.rs"), "__loc_ntoa"));

    let ipc = "crates/rusty-libc-ipc/src/";
    let i = |f: &str| format!("{ipc}{f}");
    h.push(spec("bits/rlibc-ipc-ipc", "ipc_ipc").pick(&i("sysv.rs"), "ftok"));
    h.push(spec("bits/rlibc-ipc-msg", "ipc_msg").pick(&i("sysv.rs"), "msgctl msgget msgrcv msgsnd"));
    h.push(spec("bits/rlibc-ipc-sem", "ipc_sem").pick(&i("sysv.rs"), "semctl semget semop"));
    h.push(spec("bits/rlibc-ipc-semgnu", "ipc_semgnu").pick(&i("sysv.rs"), "semtimedop"));
    h.push(spec("bits/rlibc-ipc-shm", "ipc_shm").pick(&i("sysv.rs"), "shmctl shmget shmat shmdt"));
    h.push(spec("bits/rlibc-mq-calls", "ipc_mq_calls").pick(&i("mq.rs"), "mq_open __mq_open_2 mq_close mq_getattr mq_setattr mq_unlink mq_notify mq_receive mq_send"));
    h.push(spec("bits/rlibc-mq-timed", "ipc_mq_timed").pick(&i("mq.rs"), "mq_timedreceive mq_timedsend"));
    h.push(spec("bits/rlibc-aio-calls", "aio_calls").pick(&i("aio.rs"), "aio_read aio_write aio_fsync aio_error aio_return aio_cancel aio_suspend lio_listio"));
    h.push(spec("bits/rlibc-aio-64", "aio_64").pick(&i("aio.rs"), "aio_read64 aio_write64 aio_fsync64 aio_error64 aio_return64 aio_cancel64 aio_suspend64 lio_listio64"));
    h.push(spec("bits/rlibc-aio-gnu", "aio_gnu").pick(&i("aio.rs"), "aio_init"));

    struct Extra { name: &'static str, files: &'static [&'static str], only: Option<&'static str>, tiers: &'static str, subst: bool }
    let extras = [
        Extra { name: "spawncalls", files: &["spawn.rs"], only: None, tiers: "posix_spawn_file_actions_addchdir_np posix_spawn_file_actions_addfchdir_np posix_spawn_file_actions_addclosefrom_np posix_spawn_file_actions_addtcsetpgrp_np posix_spawnattr_getcgroup_np posix_spawnattr_setcgroup_np pidfd_spawn pidfd_spawnp", subst: false },
        Extra { name: "mntentcalls", files: &["mntent.rs"], only: None, tiers: "getmntent_r", subst: false },
        Extra { name: "utmpcalls", files: &["utmp.rs"], only: Some("utmpname setutent endutent getutent getutid getutline pututline updwtmp logwtmp login logout getutent_r getutid_r getutline_r"), tiers: "getutent_r getutid_r getutline_r", subst: false },
        Extra { name: "argzcalls", files: &["argz.rs"], only: Some("argz_create argz_create_sep argz_count argz_extract argz_stringify argz_append argz_add argz_add_sep argz_delete argz_insert argz_next argz_replace"), tiers: "", subst: false },
        Extra { name: "envzcalls", files: &["argz.rs"], only: Some("envz_entry envz_get envz_add envz_merge envz_remove envz_strip"), tiers: "", subst: false },
        Extra { name: "ftscalls", files: &["fts.rs"], only: Some("fts_open fts_read fts_children fts_close fts_set"), tiers: "", subst: false },
        Extra { name: "fstabcalls", files: &["fstab.rs"], only: None, tiers: "", subst: false },
        Extra { name: "ttyentcalls", files: &["ttyent.rs"], only: None, tiers: "", subst: false },
        Extra { name: "syslogcalls", files: &["syslog.rs"], only: Some("openlog closelog setlogmask syslog vsyslog"), tiers: "", subst: true },
        Extra { name: "utmpxcalls", files: &["utmp.rs"], only: Some("setutxent endutxent getutxent getutxid getutxline pututxline utmpxname updwtmpx getutmp getutmpx"), tiers: "utmpxname updwtmpx getutmp getutmpx", subst: false },
    ];
    h.push(spec("bits/rlibc-gshadowcalls", "gshadowcalls").pick("crates/rusty-libc-util/src/pwd/sgrp.rs", "getsgnam_r getsgnam setsgent endsgent getsgent_r getsgent fgetsgent_r fgetsgent sgetsgent_r sgetsgent putsgent"));
    for e in &extras {
        let src: Vec<String> = e.files.iter().map(|f| format!("crates/rusty-libc-extra/src/{f}")).collect();
        let tiers = w(e.tiers);
        let mut b = spec(&format!("bits/rlibc-{}", e.name), e.name);
        b.files = src.clone();
        if e.subst { b.subst.push(Subst::Word("va_list", "__gnuc_va_list")); }
        if let Some(o) = e.only {
            b.only = Some(w(o).into_iter().filter(|n| !tiers.contains(n)).collect());
        } else {
            b.skip = Some(tiers.clone());
        }
        h.push(b);
        if !tiers.is_empty() {
            let mut m = spec(&format!("bits/rlibc-{}-misc", e.name), &format!("{}_misc", e.name));
            m.files = src;
            m.only = Some(tiers);
            if e.subst { m.subst.push(Subst::Word("va_list", "__gnuc_va_list")); }
            h.push(m);
        }
    }

    let rpc = "crates/rusty-libc-rpc/src/";
    let r = |f: &str| format!("{rpc}{f}");
    let mut rp: Vec<(&str, Spec)> = Vec::new();
    rp.push(("xdr", { let mut s = spec("", ""); s.files = vec![r("xdr.rs"), r("xdrrec.rs"), r("xdrstdio.rs")]; s }));
    rp.push(("auth", spec("", "")
        .pick(&r("auth.rs"), "authnone_create authunix_create authunix_create_default")
        .pick(&r("authdes.rs"), "authdes_create authdes_pk_create")
        .pick(&r("msg.rs"), "xdr_opaque_auth xdr_des_block")
        .pick(&r("key.rs"), "getnetname host2netname user2netname netname2user netname2host key_decryptsession key_decryptsession_pk key_encryptsession key_encryptsession_pk key_gendes key_setsecret key_secretkey_is_set key_get_conv")));
    rp.push(("auth_unix", spec("", "").pick(&r("auth.rs"), "xdr_authunix_parms")));
    rp.push(("clnt", spec("", "")
        .pick(&r("clnt.rs"), "clnt_create clnt_pcreateerror clnt_spcreateerror clnt_perrno clnt_perror clnt_sperror clnt_sperrno callrpc")
        .pick(&r("clnt_raw.rs"), "clntraw_create").pick(&r("clnt_tcp.rs"), "clnttcp_create")
        .pick(&r("clnt_udp.rs"), "clntudp_create clntudp_bufcreate").pick(&r("clnt_unix.rs"), "clntunix_create")
        .pick(&r("vars.rs"), "_rpc_dtablesize").pick(&r("pmap.rs"), "getrpcport get_myaddress")));
    rp.push(("msg", spec("", "").pick(&r("msg.rs"), "xdr_callmsg xdr_callhdr xdr_replymsg _seterr_reply xdr_accepted_reply xdr_rejected_reply")));
    rp.push(("svc", spec("", "")
        .pick(&r("svc.rs"), "svc_register svc_unregister xprt_register xprt_unregister svc_sendreply svcerr_decode svcerr_weakauth svcerr_noproc svcerr_progvers svcerr_auth svcerr_noprog svcerr_systemerr svc_getreq svc_getreq_common svc_getreqset svc_getreq_poll svc_exit svc_run registerrpc")
        .pick(&r("svc_raw.rs"), "svcraw_create").pick(&r("svc_udp.rs"), "svcudp_create svcudp_bufcreate svcudp_enablecache")
        .pick(&r("svc_tcp.rs"), "svctcp_create svcfd_create").pick(&r("svc_unix.rs"), "svcunix_create svcunixfd_create")));
    rp.push(("svc_auth", spec("", "").pick(&r("auth.rs"), "_authenticate")));
    rp.push(("pmap_clnt", spec("", "").pick(&r("pmap.rs"), "pmap_set pmap_unset pmap_getmaps pmap_rmtcall clnt_broadcast pmap_getport")));
    rp.push(("pmap_prot", spec("", "").pick(&r("pmap.rs"), "xdr_pmap xdr_pmaplist")));
    rp.push(("pmap_rmt", spec("", "").pick(&r("pmap.rs"), "xdr_rmtcall_args xdr_rmtcallres")));
    rp.push(("auth_des", spec("", "").pick(&r("authdes.rs"), "authdes_getucred xdr_authdes_cred xdr_authdes_verf").pick(&r("key.rs"), "getpublickey getsecretkey rtime")));
    rp.push(("des_crypt", spec("", "").pick(&r("des.rs"), "cbc_crypt ecb_crypt des_setparity passwd2des xencrypt xdecrypt")));
    rp.push(("key_prot", spec("", "").pick(&r("key.rs"), "xdr_keystatus xdr_keybuf xdr_netnamestr xdr_cryptkeyarg xdr_cryptkeyarg2 xdr_cryptkeyres xdr_unixcred xdr_getcredres xdr_key_netstarg xdr_key_netstres key_setnet")));
    for (nm, mut s) in rp {
        s.name = format!("bits/rlibc-rpc-{}", nm.replace('_', "-"));
        s.config = format!("rpc_{}", if nm == "msg" { "rpc_msg" } else { nm });
        h.push(s);
    }

    let sigtiers = [
        ("posix", "raise kill sigemptyset sigfillset sigaddset sigdelset sigismember sigprocmask sigsuspend sigaction sigpending sigwait sigwaitinfo sigtimedwait sigqueue"),
        ("misc", "killpg siginterrupt sigaltstack"),
        ("miscx", "ssignal gsignal sigblock sigsetmask siggetmask sigreturn sigstack"),
        ("k8", "psignal psiginfo"),
        ("xopen", "sighold sigrelse sigignore sigset"),
        ("bsdsig", "bsd_signal"),
        ("gnu", "sigisemptyset sigandset sigorset sysv_signal tgkill"),
    ];
    for (tier, names) in sigtiers {
        let mut s = spec(&format!("bits/rlibc-sigcalls-{tier}"), &format!("signalcalls_{tier}"));
        s.files = sig_src.clone();
        s = s.only(names);
        h.push(s);
    }
    h
}
