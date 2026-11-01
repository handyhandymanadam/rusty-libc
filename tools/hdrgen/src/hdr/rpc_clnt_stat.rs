use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/clnt_stat.h",
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
        Item::Comment(r#"/* Structure layouts and constants follow Sun's RPC headers (as in glibc's sunrpc/rpc/);
   the function prototypes are generated from the Rust sources (bits/rlibc-rpc-*.h). */"#),
        Item::Guard { name: "_RPC_CLNT_STAT_H", value: "1", end: " /* rpc/clnt_stat.h */", items: &[
            Item::Blank,
            Item::Block { head: "enum clnt_stat ", body: &["", r#"	RPC_SUCCESS=0,			/* call succeeded */"#, r#"	RPC_CANTENCODEARGS=1,		/* can't encode arguments */"#, r#"	RPC_CANTDECODERES=2,		/* can't decode results */"#, r#"	RPC_CANTSEND=3,			/* failure in sending call */"#, r#"	RPC_CANTRECV=4,			/* failure in receiving result */"#, r#"	RPC_TIMEDOUT=5,			/* call timed out */"#, r#"	RPC_VERSMISMATCH=6,		/* rpc versions not compatible */"#, r#"	RPC_AUTHERROR=7,		/* authentication error */"#, r#"	RPC_PROGUNAVAIL=8,		/* program not available */"#, r#"	RPC_PROGVERSMISMATCH=9,		/* program version mismatched */"#, r#"	RPC_PROCUNAVAIL=10,		/* procedure unavailable */"#, r#"	RPC_CANTDECODEARGS=11,		/* decode arguments error */"#, r#"	RPC_SYSTEMERROR=12,		/* generic "other problem" */"#, r#"	RPC_NOBROADCAST = 21,		/* Broadcasting not supported */"#, r#"	RPC_UNKNOWNHOST=13,		/* unknown host name */"#, r#"	RPC_UNKNOWNPROTO=17,		/* unknown protocol */"#, r#"	RPC_UNKNOWNADDR = 19,		/* Remote address unknown */"#, r#"	RPC_RPCBFAILURE=14,		/* portmapper failed in its call */"#, "#define RPC_PMAPFAILURE RPC_RPCBFAILURE", r#"	RPC_PROGNOTREGISTERED=15,	/* remote program is not registered */"#, r#"	RPC_N2AXLATEFAILURE = 22,	/* Name to addr translation failed */"#, r#"	RPC_FAILED=16,"#, r#"	RPC_INTR=18,"#, r#"	RPC_TLIERROR=20,"#, r#"	RPC_UDERROR=23,"#, r#"	RPC_INPROGRESS = 24,"#, r#"	RPC_STALERACHANDLE = 25"#, ""], tail: "" },
            Item::Blank,
        ]},
    ],
};
