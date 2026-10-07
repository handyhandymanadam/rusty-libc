/*
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
 */
#ifndef _RPC_XDR_H
#define _RPC_XDR_H 1

#include <stdint.h>
#include <sys/types.h>
#include <rpc/types.h>
#include <stdio.h>

enum xdr_op {
  XDR_ENCODE = 0,
  XDR_DECODE = 1,
  XDR_FREE = 2
};

#define BYTES_PER_XDR_UNIT (4)
#define RNDUP(x)  (((x) + BYTES_PER_XDR_UNIT - 1) & ~(BYTES_PER_XDR_UNIT - 1))

typedef struct XDR XDR;
struct XDR
  {
    enum xdr_op x_op;
    struct xdr_ops
      {
	bool_t (*x_getlong) (XDR *__xdrs, long *__lp);
	bool_t (*x_putlong) (XDR *__xdrs, const long *__lp);
	bool_t (*x_getbytes) (XDR *__xdrs, caddr_t __addr, u_int __len);
	bool_t (*x_putbytes) (XDR *__xdrs, const char *__addr, u_int __len);
	u_int (*x_getpostn) (const XDR *__xdrs);
	bool_t (*x_setpostn) (XDR *__xdrs, u_int __pos);
	int32_t *(*x_inline) (XDR *__xdrs, u_int __len);
	void (*x_destroy) (XDR *__xdrs);
	bool_t (*x_getint32) (XDR *__xdrs, int32_t *__ip);
	bool_t (*x_putint32) (XDR *__xdrs, const int32_t *__ip);
      }
     *x_ops;
    caddr_t x_public;
    caddr_t x_private;
    caddr_t x_base;
    u_int x_handy;
  };

typedef bool_t (*xdrproc_t) (XDR *, void *,...);

typedef int (*__xdr_io_fn_t) (char *, char *, int);

#define XDR_GETINT32(xdrs, int32p) (*(xdrs)->x_ops->x_getint32)(xdrs, int32p)
#define xdr_getint32(xdrs, int32p) (*(xdrs)->x_ops->x_getint32)(xdrs, int32p)
#define XDR_PUTINT32(xdrs, int32p) (*(xdrs)->x_ops->x_putint32)(xdrs, int32p)
#define xdr_putint32(xdrs, int32p) (*(xdrs)->x_ops->x_putint32)(xdrs, int32p)
#define XDR_GETLONG(xdrs, longp) (*(xdrs)->x_ops->x_getlong)(xdrs, longp)
#define xdr_getlong(xdrs, longp) (*(xdrs)->x_ops->x_getlong)(xdrs, longp)
#define XDR_PUTLONG(xdrs, longp) (*(xdrs)->x_ops->x_putlong)(xdrs, longp)
#define xdr_putlong(xdrs, longp) (*(xdrs)->x_ops->x_putlong)(xdrs, longp)
#define XDR_GETBYTES(xdrs, addr, len) (*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)
#define xdr_getbytes(xdrs, addr, len) (*(xdrs)->x_ops->x_getbytes)(xdrs, addr, len)
#define XDR_PUTBYTES(xdrs, addr, len) (*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)
#define xdr_putbytes(xdrs, addr, len) (*(xdrs)->x_ops->x_putbytes)(xdrs, addr, len)
#define XDR_GETPOS(xdrs) (*(xdrs)->x_ops->x_getpostn)(xdrs)
#define xdr_getpos(xdrs) (*(xdrs)->x_ops->x_getpostn)(xdrs)
#define XDR_SETPOS(xdrs, pos) (*(xdrs)->x_ops->x_setpostn)(xdrs, pos)
#define xdr_setpos(xdrs, pos) (*(xdrs)->x_ops->x_setpostn)(xdrs, pos)
#define XDR_INLINE(xdrs, len) (*(xdrs)->x_ops->x_inline)(xdrs, len)
#define xdr_inline(xdrs, len) (*(xdrs)->x_ops->x_inline)(xdrs, len)
#define XDR_DESTROY(xdrs)					\
	do {							\
		if ((xdrs)->x_ops->x_destroy)			\
			(*(xdrs)->x_ops->x_destroy)(xdrs);	\
	} while (0)
#define xdr_destroy(xdrs)					\
	do {							\
		if ((xdrs)->x_ops->x_destroy)			\
			(*(xdrs)->x_ops->x_destroy)(xdrs);	\
	} while (0)

#define NULL_xdrproc_t ((xdrproc_t)0)
struct xdr_discrim
{
  int value;
  xdrproc_t proc;
};

#define IXDR_GET_INT32(buf)           ((int32_t)ntohl((uint32_t)*(buf)++))
#define IXDR_PUT_INT32(buf, v)        (*(buf)++ = (int32_t)htonl((uint32_t)(v)))
#define IXDR_GET_U_INT32(buf)         ((uint32_t)IXDR_GET_INT32(buf))
#define IXDR_PUT_U_INT32(buf, v)      IXDR_PUT_INT32(buf, (int32_t)(v))

#define IXDR_GET_LONG(buf) ((long)IXDR_GET_U_INT32(buf))
#define IXDR_PUT_LONG(buf, v) ((long)IXDR_PUT_INT32(buf, (long)(v)))
#define IXDR_GET_U_LONG(buf)	      ((u_long)IXDR_GET_LONG(buf))
#define IXDR_PUT_U_LONG(buf, v)	      IXDR_PUT_LONG(buf, (long)(v))

#define IXDR_GET_BOOL(buf)            ((bool_t)IXDR_GET_LONG(buf))
#define IXDR_GET_ENUM(buf, t)         ((t)IXDR_GET_LONG(buf))
#define IXDR_GET_SHORT(buf)           ((short)IXDR_GET_LONG(buf))
#define IXDR_GET_U_SHORT(buf)         ((u_short)IXDR_GET_LONG(buf))

#define IXDR_PUT_BOOL(buf, v)         IXDR_PUT_LONG(buf, (long)(v))
#define IXDR_PUT_ENUM(buf, v)         IXDR_PUT_LONG(buf, (long)(v))
#define IXDR_PUT_SHORT(buf, v)        IXDR_PUT_LONG(buf, (long)(v))
#define IXDR_PUT_U_SHORT(buf, v)      IXDR_PUT_LONG(buf, (long)(v))

#define MAX_NETOBJ_SZ 1024
struct netobj
{
  u_int n_len;
  char *n_bytes;
};
typedef struct netobj netobj;

#include <bits/rlibc-rpc-xdr.h>

#endif
