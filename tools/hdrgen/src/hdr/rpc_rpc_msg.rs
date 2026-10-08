use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/rpc_msg.h",
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
        Item::Guard { name: "_RPC_MSG_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<rpc/xdr.h>"),
            Item::Include("<rpc/clnt.h>"),
            Item::Blank,
            Item::Consts(&[
                ("RPC_MSG_VERSION", V::Sp(r#"		((u_long) 2)"#)),
                ("RPC_SERVICE_PORT", V::Sp(r#"	((u_short) 2048)"#)),
            ]),
            Item::Blank,
            Item::Block { head: "enum msg_type ", body: &["", r#"	CALL=0,"#, r#"	REPLY=1"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum reply_stat ", body: &["", r#"	MSG_ACCEPTED=0,"#, r#"	MSG_DENIED=1"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum accept_stat ", body: &["", r#"	SUCCESS=0,"#, r#"	PROG_UNAVAIL=1,"#, r#"	PROG_MISMATCH=2,"#, r#"	PROC_UNAVAIL=3,"#, r#"	GARBAGE_ARGS=4,"#, r#"	SYSTEM_ERR=5"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "enum reject_stat ", body: &["", r#"	RPC_MISMATCH=0,"#, r#"	AUTH_ERROR=1"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct accepted_reply ", body: &["", r#"	struct opaque_auth	ar_verf;"#, r#"	enum accept_stat	ar_stat;"#, r#"	union {"#, r#"		struct {"#, r#"			u_long	low;"#, r#"			u_long	high;"#, r#"		} AR_versions;"#, r#"		struct {"#, r#"			caddr_t	where;"#, r#"			xdrproc_t proc;"#, r#"		} AR_results;"#, r#"	} ru;"#, r#"#define	ar_results	ru.AR_results"#, r#"#define	ar_vers		ru.AR_versions"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct rejected_reply ", body: &["", r#"	enum reject_stat rj_stat;"#, r#"	union {"#, r#"		struct {"#, r#"			u_long low;"#, r#"			u_long high;"#, r#"		} RJ_versions;"#, r#"		enum auth_stat RJ_why;"#, r#"	} ru;"#, r#"#define	rj_vers	ru.RJ_versions"#, r#"#define	rj_why	ru.RJ_why"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct reply_body ", body: &["", r#"	enum reply_stat rp_stat;"#, r#"	union {"#, r#"		struct accepted_reply RP_ar;"#, r#"		struct rejected_reply RP_dr;"#, r#"	} ru;"#, r#"#define	rp_acpt	ru.RP_ar"#, r#"#define	rp_rjct	ru.RP_dr"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct call_body ", body: &["", r#"	u_long cb_rpcvers;"#, r#"	u_long cb_prog;"#, r#"	u_long cb_vers;"#, r#"	u_long cb_proc;"#, r#"	struct opaque_auth cb_cred;"#, r#"	struct opaque_auth cb_verf;"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct rpc_msg ", body: &["", r#"	u_long			rm_xid;"#, r#"	enum msg_type		rm_direction;"#, r#"	union {"#, r#"		struct call_body RM_cmb;"#, r#"		struct reply_body RM_rmb;"#, r#"	} ru;"#, r#"#define	rm_call		ru.RM_cmb"#, r#"#define	rm_reply	ru.RM_rmb"#, ""], tail: "" },
            Item::Raw(Reason::GlibcMacro, r#"#define	acpted_rply	ru.RM_rmb.ru.RP_ar"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	rjcted_rply	ru.RM_rmb.ru.RP_dr"#),
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-msg.h>"),
            Item::Blank,
        ]},
    ],
};
