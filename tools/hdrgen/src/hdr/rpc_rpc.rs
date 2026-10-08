use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/rpc.h",
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
        Item::Guard { name: "_RPC_RPC_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include(r#"<rpc/types.h>"#),
            Item::Include("<netinet/in.h>"),
            Item::Blank,
            Item::Include(r#"<rpc/xdr.h>"#),
            Item::Include(r#"<rpc/auth.h>"#),
            Item::Include(r#"<rpc/clnt.h>"#),
            Item::Include(r#"<rpc/rpc_msg.h>"#),
            Item::Include(r#"<rpc/auth_unix.h>"#),
            Item::Include(r#"<rpc/auth_des.h>"#),
            Item::Include(r#"<rpc/svc.h>"#),
            Item::Include(r#"<rpc/svc_auth.h>"#),
            Item::Blank,
            Item::Include("<rpc/netdb.h>"),
            Item::Blank,
            Item::Decl("extern fd_set *__rpc_thread_svc_fdset (void) __attribute__ ((__const__));"),
            Item::Consts(&[
                ("svc_fdset", V::Txt("(*__rpc_thread_svc_fdset ())")),
            ]),
            Item::Blank,
            Item::Decl(r#"extern struct rpc_createerr *__rpc_thread_createerr (void)
     __attribute__ ((__const__));"#),
            Item::Raw(Reason::GlibcMacro, "#define get_rpc_createerr() (*__rpc_thread_createerr ())"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifdef _RPC_MT_VARS", items: &[
                    Item::Consts(&[
                        ("rpc_createerr", V::Txt("(*__rpc_thread_createerr ())")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Decl(r#"extern struct pollfd **__rpc_thread_svc_pollfd (void)
     __attribute__ ((__const__));"#),
            Item::Consts(&[
                ("svc_pollfd", V::Txt("(*__rpc_thread_svc_pollfd ())")),
            ]),
            Item::Blank,
            Item::Decl("extern int *__rpc_thread_svc_max_pollfd (void) __attribute__ ((__const__));"),
            Item::Consts(&[
                ("svc_max_pollfd", V::Txt("(*__rpc_thread_svc_max_pollfd ())")),
            ]),
            Item::Blank,
        ]},
    ],
};
