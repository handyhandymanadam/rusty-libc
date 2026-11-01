use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/des_crypt.h",
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
        Item::Guard { name: "__DES_CRYPT_H__", value: "1", end: " /* des_crypt.h */", items: &[
            Item::Blank,
            Item::Consts(&[
                ("DES_MAXDATA", V::Txt(r#"8192	/* max bytes encrypted in one call */"#)),
                ("DES_DIRMASK", V::Txt("(1 << 0)")),
                ("DES_ENCRYPT", V::Txt(r#"(0*DES_DIRMASK)	/* encrypt (from the standard) */"#)),
                ("DES_DECRYPT", V::Txt(r#"(1*DES_DIRMASK)	/* decrypt */"#)),
                ("DES_DEVMASK", V::Txt("(1 << 1)")),
            ]),
            Item::Raw(Reason::GlibcMacro, r#"#define	DES_HW (0*DES_DEVMASK)	/* invisible to software */"#),
            Item::Consts(&[
                ("DES_SW", V::Txt(r#"(1*DES_DEVMASK)	/* software */"#)),
            ]),
            Item::Blank,
            Item::Consts(&[
                ("DESERR_NONE", V::Txt(r#"0	/* succeeded */"#)),
                ("DESERR_NOHWDEVICE", V::Txt(r#"1	/* succeeded, but hw device not available */"#)),
                ("DESERR_HWERROR", V::Txt(r#"2	/* failed, hardware/driver error */"#)),
                ("DESERR_BADPARAM", V::Txt(r#"3	/* failed, bad parameter to call */"#)),
            ]),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, r#"#define DES_FAILED(err) \
	((err) > DESERR_NOHWDEVICE)"#),
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-des-crypt.h>"),
            Item::Blank,
        ]},
    ],
};
