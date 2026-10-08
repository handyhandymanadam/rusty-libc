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
        Item::Guard { name: "_RPC_CLNT_STAT_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Block { head: "enum clnt_stat ", body: &["", r#"	RPC_SUCCESS=0,"#, r#"	RPC_CANTENCODEARGS=1,"#, r#"	RPC_CANTDECODERES=2,"#, r#"	RPC_CANTSEND=3,"#, r#"	RPC_CANTRECV=4,"#, r#"	RPC_TIMEDOUT=5,"#, r#"	RPC_VERSMISMATCH=6,"#, r#"	RPC_AUTHERROR=7,"#, r#"	RPC_PROGUNAVAIL=8,"#, r#"	RPC_PROGVERSMISMATCH=9,"#, r#"	RPC_PROCUNAVAIL=10,"#, r#"	RPC_CANTDECODEARGS=11,"#, r#"	RPC_SYSTEMERROR=12,"#, r#"	RPC_NOBROADCAST = 21,"#, r#"	RPC_UNKNOWNHOST=13,"#, r#"	RPC_UNKNOWNPROTO=17,"#, r#"	RPC_UNKNOWNADDR = 19,"#, r#"	RPC_RPCBFAILURE=14,"#, "#define RPC_PMAPFAILURE RPC_RPCBFAILURE", r#"	RPC_PROGNOTREGISTERED=15,"#, r#"	RPC_N2AXLATEFAILURE = 22,"#, r#"	RPC_FAILED=16,"#, r#"	RPC_INTR=18,"#, r#"	RPC_TLIERROR=20,"#, r#"	RPC_UDERROR=23,"#, r#"	RPC_INPROGRESS = 24,"#, r#"	RPC_STALERACHANDLE = 25"#, ""], tail: "" },
            Item::Blank,
        ]},
    ],
};
