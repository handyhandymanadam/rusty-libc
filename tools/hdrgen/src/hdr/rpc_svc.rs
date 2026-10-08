use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/svc.h",
    items: &[
        Item::Comment(r#"/*
 * Copyright (c) 2010, Oracle America, Inc.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above
 *       copyright notice, this list of conditions and the following
 *       disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the "Oracle America, Inc." nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 *   COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 *   INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 *   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 *   GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *   WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */"#),
        Item::Guard { name: "_RPC_SVC_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<sys/select.h>"),
            Item::Include("<poll.h>"),
            Item::Include("<rpc/rpc_msg.h>"),
            Item::Blank,
            Item::Block { head: "enum xprt_stat ", body: &["", r#"	XPRT_DIED,"#, r#"	XPRT_MOREREQS,"#, r#"	XPRT_IDLE"#, ""], tail: "" },
            Item::Blank,
            Item::Typedef("struct SVCXPRT", "SVCXPRT"),
            Item::Block { head: "struct SVCXPRT ", body: &["", "  int xp_sock;", r#"  u_short xp_port;"#, "  const struct xp_ops {", r#"    bool_t	(*xp_recv) (SVCXPRT *__xprt, struct rpc_msg *__msg);"#, "    enum xprt_stat (*xp_stat) (SVCXPRT *__xprt);", r#"    bool_t	(*xp_getargs) (SVCXPRT *__xprt, xdrproc_t __xdr_args,"#, r#"			       caddr_t __args_ptr);"#, r#"    bool_t	(*xp_reply) (SVCXPRT *__xprt, struct rpc_msg *__msg);"#, r#"    bool_t	(*xp_freeargs) (SVCXPRT *__xprt, xdrproc_t __xdr_args,"#, r#"				caddr_t __args_ptr);"#, r#"    void	(*xp_destroy) (SVCXPRT *__xprt);"#, "  } *xp_ops;", r#"  int		xp_addrlen;"#, r#"  struct sockaddr_in xp_raddr;"#, r#"  struct opaque_auth xp_verf;"#, r#"  caddr_t		xp_p1;"#, r#"  caddr_t		xp_p2;"#, r#"  char		xp_pad [256];"#, ""], tail: "" },
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define svc_getcaller(x) (&(x)->xp_raddr)"),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define SVC_RECV(xprt, msg)	(*(xprt)->xp_ops->xp_recv)((xprt), (msg))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define svc_recv(xprt, msg)	(*(xprt)->xp_ops->xp_recv)((xprt), (msg))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define SVC_STAT(xprt)		(*(xprt)->xp_ops->xp_stat)(xprt)"#),
            Item::Raw(Reason::GlibcMacro, r#"#define svc_stat(xprt)		(*(xprt)->xp_ops->xp_stat)(xprt)"#),
            Item::Raw(Reason::GlibcMacro, r#"#define SVC_GETARGS(xprt, xargs, argsp)	(*(xprt)->xp_ops->xp_getargs)((xprt), (xargs), (argsp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define svc_getargs(xprt, xargs, argsp)	(*(xprt)->xp_ops->xp_getargs)((xprt), (xargs), (argsp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define SVC_REPLY(xprt, msg)	(*(xprt)->xp_ops->xp_reply) ((xprt), (msg))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define svc_reply(xprt, msg)	(*(xprt)->xp_ops->xp_reply) ((xprt), (msg))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define SVC_FREEARGS(xprt, xargs, argsp)	(*(xprt)->xp_ops->xp_freeargs)((xprt), (xargs), (argsp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define svc_freeargs(xprt, xargs, argsp)	(*(xprt)->xp_ops->xp_freeargs)((xprt), (xargs), (argsp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define SVC_DESTROY(xprt)	(*(xprt)->xp_ops->xp_destroy)(xprt)"#),
            Item::Raw(Reason::GlibcMacro, r#"#define svc_destroy(xprt)	(*(xprt)->xp_ops->xp_destroy)(xprt)"#),
            Item::Blank,
            Item::Block { head: "struct svc_req ", body: &["", "  rpcprog_t rq_prog;", "  rpcvers_t rq_vers;", "  rpcproc_t rq_proc;", "  struct opaque_auth rq_cred;", "  caddr_t rq_clntcred;", "  SVCXPRT *rq_xprt;", ""], tail: "" },
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef __DISPATCH_FN_T", items: &[
                    Item::ConstsFlat(&[
                        ("__DISPATCH_FN_T", V::Txt("")),
                    ]),
                    Item::Decl("typedef void (*__dispatch_fn_t) (struct svc_req*, SVCXPRT*);"),
                ] },
            ], ""),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define	RPC_ANYSOCK	-1"#),
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-svc.h>"),
            Item::Blank,
            Item::Decl("extern struct pollfd *svc_pollfd;"),
            Item::Decl("extern int svc_max_pollfd;"),
            Item::Decl("extern fd_set svc_fdset;"),
            Item::Consts(&[
                ("svc_fds", V::Txt(r#"svc_fdset.fds_bits[0]"#)),
            ]),
            Item::Blank,
        ]},
    ],
};
