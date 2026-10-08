use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/auth_des.h",
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
        Item::Guard { name: "_RPC_AUTH_DES_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<rpc/auth.h>"),
            Item::Blank,
            Item::Block { head: r#"enum authdes_namekind
  "#, body: &["", "    ADN_FULLNAME,", "    ADN_NICKNAME", "  "], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct authdes_fullname
  "#, body: &["", r#"    char *name;"#, r#"    des_block key;"#, r#"    uint32_t window;"#, "  "], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct authdes_cred
  "#, body: &["", "    enum authdes_namekind adc_namekind;", "    struct authdes_fullname adc_fullname;", "    uint32_t adc_nickname;", "  "], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct rpc_timeval
  "#, body: &["", "    uint32_t tv_sec;", "    uint32_t tv_usec;", "  "], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct authdes_verf
  "#, body: &["", "    union", "      {", r#"	struct rpc_timeval adv_ctime;"#, r#"	des_block adv_xtime;"#, "      }", "    adv_time_u;", "    uint32_t adv_int_u;", "  "], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("adv_timestamp", V::Sp("  adv_time_u.adv_ctime")),
                ("adv_xtimestamp", V::Txt("adv_time_u.adv_xtime")),
                ("adv_winverf", V::Sp("    adv_int_u")),
                ("adv_timeverf", V::Sp("   adv_time_u.adv_ctime")),
                ("adv_xtimeverf", V::Sp("  adv_time_u.adv_xtime")),
                ("adv_nickname", V::Sp("   adv_int_u")),
            ]),
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-auth-des.h>"),
            Item::Blank,
        ]},
    ],
};
