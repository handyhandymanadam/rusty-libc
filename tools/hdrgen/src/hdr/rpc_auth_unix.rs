use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/auth_unix.h",
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
        Item::Guard { name: "_RPC_AUTH_UNIX_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<sys/types.h>"),
            Item::Include("<rpc/types.h>"),
            Item::Include("<rpc/auth.h>"),
            Item::Include("<rpc/xdr.h>"),
            Item::Blank,
            Item::Consts(&[
                ("MAX_MACHINE_NAME", V::Dec(255)),
                ("NGRPS", V::Dec(16)),
            ]),
            Item::Blank,
            Item::Block { head: r#"struct authunix_parms
  "#, body: &["", "    u_long aup_time;", "    char *aup_machname;", "    uid_t aup_uid;", "    gid_t aup_gid;", "    u_int aup_len;", "    gid_t *aup_gids;", "  "], tail: "" },
            Item::Blank,
            Item::Block { head: r#"struct short_hand_verf
  "#, body: &["", "    struct opaque_auth new_cred;", "  "], tail: "" },
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-auth-unix.h>"),
            Item::Blank,
        ]},
    ],
};
