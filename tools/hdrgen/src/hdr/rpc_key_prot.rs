use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/key_prot.h",
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
        Item::Guard { name: "_KEY_PROT_H_RPCGEN", value: "", end: "", items: &[
            Item::Blank,
            Item::Include("<rpc/rpc.h>"),
            Item::Blank,
            Item::Consts(&[
                ("PROOT", V::Dec(3)),
                ("HEXMODULUS", V::Txt(r#""d4a0ba0250b6fd2ec626e7efd637df76c716e22d0944b88b""#)),
                ("HEXKEYBYTES", V::Dec(48)),
                ("KEYSIZE", V::Dec(192)),
                ("KEYBYTES", V::Dec(24)),
                ("KEYCHECKSUMSIZE", V::Dec(16)),
            ]),
            Item::Blank,
            Item::Block { head: "enum keystatus ", body: &["", r#"	KEY_SUCCESS = 0,"#, r#"	KEY_NOSECRET = 1,"#, r#"	KEY_UNKNOWN = 2,"#, r#"	KEY_SYSTEMERR = 3,"#, ""], tail: "" },
            Item::Typedef("enum keystatus", "keystatus"),
            Item::Blank,
            Item::Decl("typedef char keybuf[HEXKEYBYTES];"),
            Item::Blank,
            Item::Typedef("char *", "netnamestr"),
            Item::Blank,
            Item::Block { head: "struct cryptkeyarg ", body: &["", r#"	netnamestr remotename;"#, r#"	des_block deskey;"#, ""], tail: "" },
            Item::Typedef("struct cryptkeyarg", "cryptkeyarg"),
            Item::Blank,
            Item::Block { head: "struct cryptkeyarg2 ", body: &["", r#"	netnamestr remotename;"#, r#"	netobj remotekey;"#, r#"	des_block deskey;"#, ""], tail: "" },
            Item::Typedef("struct cryptkeyarg2", "cryptkeyarg2"),
            Item::Blank,
            Item::Block { head: "struct cryptkeyres ", body: &["", r#"	keystatus status;"#, r#"	union {"#, r#"		des_block deskey;"#, r#"	} cryptkeyres_u;"#, ""], tail: "" },
            Item::Typedef("struct cryptkeyres", "cryptkeyres"),
            Item::Blank,
            Item::Consts(&[
                ("MAXGIDS", V::Dec(16)),
            ]),
            Item::Blank,
            Item::Block { head: "struct unixcred ", body: &["", r#"	u_int uid;"#, r#"	u_int gid;"#, r#"	struct {"#, r#"		u_int gids_len;"#, r#"		u_int *gids_val;"#, r#"	} gids;"#, ""], tail: "" },
            Item::Typedef("struct unixcred", "unixcred"),
            Item::Blank,
            Item::Block { head: "struct getcredres ", body: &["", r#"	keystatus status;"#, r#"	union {"#, r#"		unixcred cred;"#, r#"	} getcredres_u;"#, ""], tail: "" },
            Item::Typedef("struct getcredres", "getcredres"),
            Item::Blank,
            Item::Block { head: "struct key_netstarg ", body: &["", r#"	keybuf st_priv_key;"#, r#"	keybuf st_pub_key;"#, r#"	netnamestr st_netname;"#, ""], tail: "" },
            Item::Typedef("struct key_netstarg", "key_netstarg"),
            Item::Blank,
            Item::Block { head: "struct key_netstres ", body: &["", r#"	keystatus status;"#, r#"	union {"#, r#"		key_netstarg knet;"#, r#"	} key_netstres_u;"#, ""], tail: "" },
            Item::Typedef("struct key_netstres", "key_netstres"),
            Item::Blank,
            Item::Consts(&[
                ("KEY_PROG", V::Txt("((u_long)100029)")),
                ("KEY_VERS", V::Txt("((u_long)1)")),
                ("KEY_SET", V::Txt("((u_long)1)")),
                ("KEY_ENCRYPT", V::Txt("((u_long)2)")),
                ("KEY_DECRYPT", V::Txt("((u_long)3)")),
                ("KEY_GEN", V::Txt("((u_long)4)")),
                ("KEY_GETCRED", V::Txt("((u_long)5)")),
                ("KEY_VERS2", V::Txt("((u_long)2)")),
                ("KEY_ENCRYPT_PK", V::Txt("((u_long)6)")),
                ("KEY_DECRYPT_PK", V::Txt("((u_long)7)")),
                ("KEY_NET_PUT", V::Txt("((u_long)8)")),
                ("KEY_NET_GET", V::Txt("((u_long)9)")),
                ("KEY_GET_CONV", V::Txt("((u_long)10)")),
            ]),
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-key-prot.h>"),
            Item::Blank,
        ]},
    ],
};
