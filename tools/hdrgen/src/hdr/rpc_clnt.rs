use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/clnt.h",
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
        Item::Guard { name: "_RPC_CLNT_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<sys/types.h>"),
            Item::Include("<rpc/types.h>"),
            Item::Include("<rpc/clnt_stat.h>"),
            Item::Include("<rpc/auth.h>"),
            Item::Include("<sys/un.h>"),
            Item::Blank,
            Item::Block { head: "struct rpc_err ", body: &["", "  enum clnt_stat re_status;", "  union {", r#"    int RE_errno;"#, r#"    enum auth_stat RE_why;"#, "    struct {", r#"      u_long low;"#, r#"      u_long high;"#, "    } RE_vers;", r#"    struct {"#, "      long s1;", "      long s2;", r#"    } RE_lb;"#, "  } ru;", r#"#define	re_errno	ru.RE_errno"#, r#"#define	re_why		ru.RE_why"#, r#"#define	re_vers		ru.RE_vers"#, r#"#define	re_lb		ru.RE_lb"#, ""], tail: "" },
            Item::Blank,
            Item::Typedef("struct CLIENT", "CLIENT"),
            Item::Block { head: "struct CLIENT ", body: &["", r#"  AUTH	*cl_auth;"#, "  struct clnt_ops {", "    enum clnt_stat (*cl_call) (CLIENT *, u_long, xdrproc_t, caddr_t, xdrproc_t,", r#"			       caddr_t, struct timeval);"#, "    void (*cl_abort) (void);", "    void (*cl_geterr) (CLIENT *, struct rpc_err *);", "    bool_t (*cl_freeres) (CLIENT *, xdrproc_t, caddr_t);", "    void (*cl_destroy) (CLIENT *);", "    bool_t (*cl_control) (CLIENT *, int, char *);", "  } *cl_ops;", r#"  caddr_t cl_private;"#, ""], tail: "" },
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define	CLNT_CALL(rh, proc, xargs, argsp, xres, resp, secs)	\
	((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	clnt_call(rh, proc, xargs, argsp, xres, resp, secs)	\
	((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	CLNT_ABORT(rh)	((*(rh)->cl_ops->cl_abort)(rh))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	clnt_abort(rh)	((*(rh)->cl_ops->cl_abort)(rh))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	CLNT_GETERR(rh,errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	clnt_geterr(rh,errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	CLNT_FREERES(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	clnt_freeres(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))"#),
            Item::Blank,
            Item::Consts(&[
                ("CLSET_TIMEOUT", V::Sp("        1")),
                ("CLGET_TIMEOUT", V::Sp("        2")),
                ("CLGET_SERVER_ADDR", V::Sp("    3")),
                ("CLGET_FD", V::Sp("             6")),
                ("CLGET_SVC_ADDR", V::Sp("       7")),
                ("CLSET_FD_CLOSE", V::Sp("       8")),
                ("CLSET_FD_NCLOSE", V::Sp("      9")),
                ("CLGET_XID", V::Sp("            10")),
                ("CLSET_XID", V::Sp("            11")),
                ("CLGET_VERS", V::Sp("           12")),
                ("CLSET_VERS", V::Sp("           13")),
                ("CLGET_PROG", V::Sp("           14")),
                ("CLSET_PROG", V::Sp("           15")),
                ("CLSET_SVC_ADDR", V::Sp("       16")),
                ("CLSET_PUSH_TIMOD", V::Sp("     17")),
                ("CLSET_POP_TIMOD", V::Sp("      18")),
                ("CLSET_RETRY_TIMEOUT", V::Sp(r#"	4"#)),
                ("CLGET_RETRY_TIMEOUT", V::Sp(r#"	5"#)),
            ]),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define	CLNT_DESTROY(rh)	((*(rh)->cl_ops->cl_destroy)(rh))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	clnt_destroy(rh)	((*(rh)->cl_ops->cl_destroy)(rh))"#),
            Item::Blank,
            Item::Consts(&[
                ("RPCTEST_PROGRAM", V::Sp(r#"		((u_long)1)"#)),
                ("RPCTEST_VERSION", V::Sp(r#"		((u_long)1)"#)),
                ("RPCTEST_NULL_PROC", V::Sp(r#"	((u_long)2)"#)),
                ("RPCTEST_NULL_BATCH_PROC", V::Sp(r#"	((u_long)3)"#)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("NULLPROC", V::Txt("((u_long)0)")),
            ]),
            Item::Blank,
            Item::Block { head: "struct rpc_createerr ", body: &["", r#"	enum clnt_stat cf_stat;"#, r#"	struct rpc_err cf_error;"#, ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("UDPMSGSIZE", V::Sp(r#"	8800"#)),
                ("RPCSMALLMSGSIZE", V::Sp(r#"	400"#)),
            ]),
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-clnt.h>"),
            Item::Blank,
            Item::Decl("extern struct rpc_createerr rpc_createerr;"),
            Item::Blank,
        ]},
    ],
};
