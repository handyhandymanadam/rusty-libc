use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/types.h",
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
        Item::Guard { name: "_RPC_TYPES_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Typedef("int", "bool_t"),
            Item::Typedef("int", "enum_t"),
            Item::Typedef("unsigned long", "rpcprog_t"),
            Item::Typedef("unsigned long", "rpcvers_t"),
            Item::Typedef("unsigned long", "rpcproc_t"),
            Item::Typedef("unsigned long", "rpcprot_t"),
            Item::Typedef("unsigned long", "rpcport_t"),
            Item::Blank,
            Item::Consts(&[
                ("__dontcare__", V::Dec(-1)),
            ]),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef FALSE", items: &[
                    Item::Consts(&[
                        ("FALSE", V::Txt("(0)")),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifndef TRUE", items: &[
                    Item::Consts(&[
                        ("TRUE", V::Txt("(1)")),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifndef NULL", items: &[
                    Item::Consts(&[
                        ("NULL", V::Dec(0)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Include("<stdlib.h>"),
            Item::Raw(Reason::GlibcMacro, "#define mem_alloc(bsize) malloc(bsize)"),
            Item::Raw(Reason::GlibcMacro, "#define mem_free(ptr, bsize) free(ptr)"),
            Item::Blank,
            Item::Include("<sys/types.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef __u_char_defined", items: &[
                    Item::Typedef("unsigned char", "u_char"),
                    Item::Typedef("unsigned short int", "u_short"),
                    Item::Typedef("unsigned int", "u_int"),
                    Item::Typedef("unsigned long int", "u_long"),
                    Item::Typedef("long int", "quad_t"),
                    Item::Typedef("unsigned long int", "u_quad_t"),
                    Item::Consts(&[
                        ("__u_char_defined", V::Txt("")),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifndef __daddr_t_defined", items: &[
                    Item::Typedef("int", "daddr_t"),
                    Item::Consts(&[
                        ("__daddr_t_defined", V::Txt("")),
                    ]),
                ] },
            ], ""),
            Item::Blank,
            Item::Include("<sys/time.h>"),
            Item::Include("<netinet/in.h>"),
            Item::Blank,
            Item::Gate(&[
                Branch { head: "ifndef INADDR_LOOPBACK", items: &[
                    Item::ConstsFlat(&[
                        ("INADDR_LOOPBACK", V::Txt("(u_long)0x7F000001")),
                    ]),
                ] },
            ], ""),
            Item::Gate(&[
                Branch { head: "ifndef MAXHOSTNAMELEN", items: &[
                    Item::ConstsFlat(&[
                        ("MAXHOSTNAMELEN", V::Dec(64)),
                    ]),
                ] },
            ], ""),
            Item::Blank,
        ]},
    ],
};
