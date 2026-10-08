use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/pmap_prot.h",
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
        Item::Guard { name: "_RPC_PMAP_PROT_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<rpc/xdr.h>"),
            Item::Blank,
            Item::Consts(&[
                ("PMAPPORT", V::Sp(r#"		((u_short)111)"#)),
                ("PMAPPROG", V::Sp(r#"		((u_long)100000)"#)),
                ("PMAPVERS", V::Sp(r#"		((u_long)2)"#)),
                ("PMAPVERS_PROTO", V::Sp(r#"		((u_long)2)"#)),
                ("PMAPVERS_ORIG", V::Sp(r#"		((u_long)1)"#)),
                ("PMAPPROC_NULL", V::Sp(r#"		((u_long)0)"#)),
                ("PMAPPROC_SET", V::Sp(r#"		((u_long)1)"#)),
                ("PMAPPROC_UNSET", V::Sp(r#"		((u_long)2)"#)),
                ("PMAPPROC_GETPORT", V::Sp(r#"	((u_long)3)"#)),
                ("PMAPPROC_DUMP", V::Sp(r#"		((u_long)4)"#)),
                ("PMAPPROC_CALLIT", V::Sp(r#"		((u_long)5)"#)),
            ]),
            Item::Blank,
            Item::Block { head: "struct pmap ", body: &["", r#"	long unsigned pm_prog;"#, r#"	long unsigned pm_vers;"#, r#"	long unsigned pm_prot;"#, r#"	long unsigned pm_port;"#, ""], tail: "" },
            Item::Blank,
            Item::Block { head: "struct pmaplist ", body: &["", r#"	struct pmap	pml_map;"#, r#"	struct pmaplist *pml_next;"#, ""], tail: "" },
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-pmap-prot.h>"),
            Item::Blank,
        ]},
    ],
};
