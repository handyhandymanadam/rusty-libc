use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/auth.h",
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
        Item::Guard { name: "_RPC_AUTH_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stdint.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<sys/socket.h>"),
            Item::Include("<rpc/xdr.h>"),
            Item::Blank,
            Item::Consts(&[
                ("MAX_AUTH_BYTES", V::Sp(r#"	400"#)),
                ("MAXNETNAMELEN", V::Sp(r#"	255"#)),
            ]),
            Item::Blank,
            Item::Block { head: "enum auth_stat ", body: &["", r#"	AUTH_OK=0,"#, r#"	AUTH_BADCRED=1,"#, r#"	AUTH_REJECTEDCRED=2,"#, r#"	AUTH_BADVERF=3,"#, r#"	AUTH_REJECTEDVERF=4,"#, r#"	AUTH_TOOWEAK=5,"#, r#"	AUTH_INVALIDRESP=6,"#, r#"	AUTH_FAILED=7"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "union des_block ", body: &["", r#"	struct {"#, r#"		uint32_t high;"#, r#"		uint32_t low;"#, r#"	} key;"#, r#"	char c[8];"#, ""], tail: "" },
            Item::Typedef("union des_block", "des_block"),
            Item::Blank,
            Item::Block { head: "struct opaque_auth ", body: &["", r#"	enum_t	oa_flavor;"#, r#"	caddr_t	oa_base;"#, r#"	u_int	oa_length;"#, ""], tail: "" },
            Item::Blank,
            Item::Typedef("struct AUTH", "AUTH"),
            Item::Block { head: "struct AUTH ", body: &["", "  struct opaque_auth ah_cred;", "  struct opaque_auth ah_verf;", "  union des_block ah_key;", "  struct auth_ops {", "    void (*ah_nextverf) (AUTH *);", "    int  (*ah_marshal) (AUTH *, XDR *);", "    int  (*ah_validate) (AUTH *, struct opaque_auth *);", "    int  (*ah_refresh) (AUTH *);", "    void (*ah_destroy) (AUTH *);", "  } *ah_ops;", "  caddr_t ah_private;", ""], tail: "" },
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define AUTH_NEXTVERF(auth)		((*((auth)->ah_ops->ah_nextverf))(auth))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define auth_nextverf(auth)		((*((auth)->ah_ops->ah_nextverf))(auth))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define AUTH_MARSHALL(auth, xdrs)	((*((auth)->ah_ops->ah_marshal))(auth, xdrs))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define auth_marshall(auth, xdrs)	((*((auth)->ah_ops->ah_marshal))(auth, xdrs))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define AUTH_VALIDATE(auth, verfp)	((*((auth)->ah_ops->ah_validate))((auth), verfp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define auth_validate(auth, verfp)	((*((auth)->ah_ops->ah_validate))((auth), verfp))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define AUTH_REFRESH(auth)		((*((auth)->ah_ops->ah_refresh))(auth))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define auth_refresh(auth)		((*((auth)->ah_ops->ah_refresh))(auth))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define AUTH_DESTROY(auth)		((*((auth)->ah_ops->ah_destroy))(auth))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define auth_destroy(auth)		((*((auth)->ah_ops->ah_destroy))(auth))"#),
            Item::Blank,
            Item::Decl("extern struct opaque_auth _null_auth;"),
            Item::Blank,
            Item::Consts(&[
                ("AUTH_NONE", V::Sp(r#"	0"#)),
            ]),
            Item::Raw(Reason::GlibcMacro, r#"#define	AUTH_NULL	0"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	AUTH_SYS	1"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	AUTH_UNIX	AUTH_SYS"#),
            Item::Raw(Reason::GlibcMacro, r#"#define	AUTH_SHORT	2"#),
            Item::Consts(&[
                ("AUTH_DES", V::Sp(r#"	3"#)),
                ("AUTH_DH", V::Sp(r#"		AUTH_DES"#)),
                ("AUTH_KERB", V::Sp("       4")),
            ]),
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-auth.h>"),
            Item::Blank,
        ]},
    ],
};
