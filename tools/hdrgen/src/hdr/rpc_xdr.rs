use crate::model::*;

pub static HDR: Header = Header {
    path: "rpc/xdr.h",
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
        Item::Guard { name: "_RPC_XDR_H", value: "1", end: "", items: &[
            Item::Blank,
            Item::Include("<stdint.h>"),
            Item::Include("<sys/types.h>"),
            Item::Include("<rpc/types.h>"),
            Item::Include("<stdio.h>"),
            Item::Blank,
            Item::Block { head: "enum xdr_op ", body: &["", "  XDR_ENCODE = 0,", "  XDR_DECODE = 1,", "  XDR_FREE = 2", ""], tail: "" },
            Item::Blank,
            Item::Consts(&[
                ("BYTES_PER_XDR_UNIT", V::Txt("(4)")),
            ]),
            Item::Raw(Reason::GlibcMacro, "#define RNDUP(x)  (((x) + BYTES_PER_XDR_UNIT - 1) & ~(BYTES_PER_XDR_UNIT - 1))"),
            Item::Blank,
            Item::Typedef("struct XDR", "XDR"),
            Item::Block { head: r#"struct XDR
  "#, body: &["", r#"    enum xdr_op x_op;"#, "    struct xdr_ops", "      {", r#"	bool_t (*x_getlong) (XDR *__xdrs, long *__lp);"#, r#"	bool_t (*x_putlong) (XDR *__xdrs, const long *__lp);"#, r#"	bool_t (*x_getbytes) (XDR *__xdrs, caddr_t __addr, u_int __len);"#, r#"	bool_t (*x_putbytes) (XDR *__xdrs, const char *__addr, u_int __len);"#, r#"	u_int (*x_getpostn) (const XDR *__xdrs);"#, r#"	bool_t (*x_setpostn) (XDR *__xdrs, u_int __pos);"#, r#"	int32_t *(*x_inline) (XDR *__xdrs, u_int __len);"#, r#"	void (*x_destroy) (XDR *__xdrs);"#, r#"	bool_t (*x_getint32) (XDR *__xdrs, int32_t *__ip);"#, r#"	bool_t (*x_putint32) (XDR *__xdrs, const int32_t *__ip);"#, "      }", "     *x_ops;", r#"    caddr_t x_public;"#, r#"    caddr_t x_private;"#, r#"    caddr_t x_base;"#, r#"    u_int x_handy;"#, "  "], tail: "" },
            Item::Blank,
            Item::Decl("typedef bool_t (*xdrproc_t) (XDR *, void *,...);"),
            Item::Blank,
            Item::Decl("typedef int (*__xdr_io_fn_t) (char *, char *, int);"),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define XDR_GETINT32(xdrs, int32p) (*(xdrs)->x_ops->x_getint32)(xdrs, int32p)"),
            Item::Raw(Reason::GlibcMacro, "#define xdr_getint32(xdrs, int32p) (*(xdrs)->x_ops->x_getint32)(xdrs, int32p)"),
            Item::Raw(Reason::GlibcMacro, "#define XDR_PUTINT32(xdrs, int32p) (*(xdrs)->x_ops->x_putint32)(xdrs, int32p)"),
            Item::Raw(Reason::GlibcMacro, "#define xdr_putint32(xdrs, int32p) (*(xdrs)->x_ops->x_putint32)(xdrs, int32p)"),
            Item::Raw(Reason::GlibcMacro, "#define XDR_GETLONG(xdrs, longp) (*(xdrs)->x_ops->x_getlong)(xdrs, longp)"),
            Item::Raw(Reason::GlibcMacro, "#define xdr_getlong(xdrs, longp) (*(xdrs)->x_ops->x_getlong)(xdrs, longp)"),
            Item::Raw(Reason::GlibcMacro, "#define XDR_PUTLONG(xdrs, longp) (*(xdrs)->x_ops->x_putlong)(xdrs, longp)"),
            Item::Raw(Reason::GlibcMacro, "#define xdr_putlong(xdrs, longp) (*(xdrs)->x_ops->x_putlong)(xdrs, longp)"),
            Item::Raw(Reason::GlibcMacro, "#define XDR_GETBYTES(xdrs, addr, len) (*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)"),
            Item::Raw(Reason::GlibcMacro, "#define xdr_getbytes(xdrs, addr, len) (*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)"),
            Item::Raw(Reason::GlibcMacro, "#define XDR_PUTBYTES(xdrs, addr, len) (*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)"),
            Item::Raw(Reason::GlibcMacro, "#define xdr_putbytes(xdrs, addr, len) (*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)"),
            Item::Raw(Reason::GlibcMacro, "#define XDR_GETPOS(xdrs) (*(xdrs)->x_ops->x_getpostn)(xdrs)"),
            Item::Raw(Reason::GlibcMacro, "#define xdr_getpos(xdrs) (*(xdrs)->x_ops->x_getpostn)(xdrs)"),
            Item::Raw(Reason::GlibcMacro, "#define XDR_SETPOS(xdrs, pos) (*(xdrs)->x_ops->x_setpostn)(xdrs, pos)"),
            Item::Raw(Reason::GlibcMacro, "#define xdr_setpos(xdrs, pos) (*(xdrs)->x_ops->x_setpostn)(xdrs, pos)"),
            Item::Raw(Reason::GlibcMacro, "#define XDR_INLINE(xdrs, len) (*(xdrs)->x_ops->x_inline)(xdrs, len)"),
            Item::Raw(Reason::GlibcMacro, "#define xdr_inline(xdrs, len) (*(xdrs)->x_ops->x_inline)(xdrs, len)"),
            Item::Raw(Reason::GlibcMacro, r#"#define XDR_DESTROY(xdrs)					\
	do {							\
		if ((xdrs)->x_ops->x_destroy)			\
			(*(xdrs)->x_ops->x_destroy)(xdrs);	\
	} while (0)"#),
            Item::Raw(Reason::GlibcMacro, r#"#define xdr_destroy(xdrs)					\
	do {							\
		if ((xdrs)->x_ops->x_destroy)			\
			(*(xdrs)->x_ops->x_destroy)(xdrs);	\
	} while (0)"#),
            Item::Blank,
            Item::Consts(&[
                ("NULL_xdrproc_t", V::Txt("((xdrproc_t)0)")),
            ]),
            Item::Block { head: r#"struct xdr_discrim
"#, body: &["", "  int value;", "  xdrproc_t proc;", ""], tail: "" },
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define IXDR_GET_INT32(buf)           ((int32_t)ntohl((uint32_t)*(buf)++))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_PUT_INT32(buf, v)        (*(buf)++ = (int32_t)htonl((uint32_t)(v)))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_GET_U_INT32(buf)         ((uint32_t)IXDR_GET_INT32(buf))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_PUT_U_INT32(buf, v)      IXDR_PUT_INT32(buf, (int32_t)(v))"),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define IXDR_GET_LONG(buf) ((long)IXDR_GET_U_INT32(buf))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_PUT_LONG(buf, v) ((long)IXDR_PUT_INT32(buf, (long)(v)))"),
            Item::Raw(Reason::GlibcMacro, r#"#define IXDR_GET_U_LONG(buf)	      ((u_long)IXDR_GET_LONG(buf))"#),
            Item::Raw(Reason::GlibcMacro, r#"#define IXDR_PUT_U_LONG(buf, v)	      IXDR_PUT_LONG(buf, (long)(v))"#),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define IXDR_GET_BOOL(buf)            ((bool_t)IXDR_GET_LONG(buf))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_GET_ENUM(buf, t)         ((t)IXDR_GET_LONG(buf))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_GET_SHORT(buf)           ((short)IXDR_GET_LONG(buf))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_GET_U_SHORT(buf)         ((u_short)IXDR_GET_LONG(buf))"),
            Item::Blank,
            Item::Raw(Reason::GlibcMacro, "#define IXDR_PUT_BOOL(buf, v)         IXDR_PUT_LONG(buf, (long)(v))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_PUT_ENUM(buf, v)         IXDR_PUT_LONG(buf, (long)(v))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_PUT_SHORT(buf, v)        IXDR_PUT_LONG(buf, (long)(v))"),
            Item::Raw(Reason::GlibcMacro, "#define IXDR_PUT_U_SHORT(buf, v)      IXDR_PUT_LONG(buf, (long)(v))"),
            Item::Blank,
            Item::Consts(&[
                ("MAX_NETOBJ_SZ", V::Dec(1024)),
            ]),
            Item::Block { head: r#"struct netobj
"#, body: &["", "  u_int n_len;", "  char *n_bytes;", ""], tail: "" },
            Item::Typedef("struct netobj", "netobj"),
            Item::Blank,
            Item::Include("<bits/rlibc-rpc-xdr.h>"),
            Item::Blank,
        ]},
    ],
};
