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
#ifndef _RPC_CLNT_H
#define _RPC_CLNT_H 1

#include <sys/types.h>
#include <rpc/types.h>
#include <rpc/clnt_stat.h>
#include <rpc/auth.h>
#include <sys/un.h>

struct rpc_err {
  enum clnt_stat re_status;
  union {
    int RE_errno;
    enum auth_stat RE_why;
    struct {
      u_long low;
      u_long high;
    } RE_vers;
    struct {
      long s1;
      long s2;
    } RE_lb;
  } ru;
#define	re_errno	ru.RE_errno
#define	re_why		ru.RE_why
#define	re_vers		ru.RE_vers
#define	re_lb		ru.RE_lb
};

typedef struct CLIENT CLIENT;
struct CLIENT {
  AUTH	*cl_auth;
  struct clnt_ops {
    enum clnt_stat (*cl_call) (CLIENT *, u_long, xdrproc_t, caddr_t, xdrproc_t,
			       caddr_t, struct timeval);
    void (*cl_abort) (void);
    void (*cl_geterr) (CLIENT *, struct rpc_err *);
    bool_t (*cl_freeres) (CLIENT *, xdrproc_t, caddr_t);
    void (*cl_destroy) (CLIENT *);
    bool_t (*cl_control) (CLIENT *, int, char *);
  } *cl_ops;
  caddr_t cl_private;
};

#define	CLNT_CALL(rh, proc, xargs, argsp, xres, resp, secs)	\
	((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))
#define	clnt_call(rh, proc, xargs, argsp, xres, resp, secs)	\
	((*(rh)->cl_ops->cl_call)(rh, proc, xargs, argsp, xres, resp, secs))
#define	CLNT_ABORT(rh)	((*(rh)->cl_ops->cl_abort)(rh))
#define	clnt_abort(rh)	((*(rh)->cl_ops->cl_abort)(rh))
#define	CLNT_GETERR(rh,errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))
#define	clnt_geterr(rh,errp)	((*(rh)->cl_ops->cl_geterr)(rh, errp))
#define	CLNT_FREERES(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))
#define	clnt_freeres(rh,xres,resp) ((*(rh)->cl_ops->cl_freeres)(rh,xres,resp))
#define	CLNT_CONTROL(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))
#define	clnt_control(cl,rq,in) ((*(cl)->cl_ops->cl_control)(cl,rq,in))

#define CLSET_TIMEOUT        1
#define CLGET_TIMEOUT        2
#define CLGET_SERVER_ADDR    3
#define CLGET_FD             6
#define CLGET_SVC_ADDR       7
#define CLSET_FD_CLOSE       8
#define CLSET_FD_NCLOSE      9
#define CLGET_XID            10
#define CLSET_XID            11
#define CLGET_VERS           12
#define CLSET_VERS           13
#define CLGET_PROG           14
#define CLSET_PROG           15
#define CLSET_SVC_ADDR       16
#define CLSET_PUSH_TIMOD     17
#define CLSET_POP_TIMOD      18
#define CLSET_RETRY_TIMEOUT	4
#define CLGET_RETRY_TIMEOUT	5

#define	CLNT_DESTROY(rh)	((*(rh)->cl_ops->cl_destroy)(rh))
#define	clnt_destroy(rh)	((*(rh)->cl_ops->cl_destroy)(rh))

#define RPCTEST_PROGRAM		((u_long)1)
#define RPCTEST_VERSION		((u_long)1)
#define RPCTEST_NULL_PROC	((u_long)2)
#define RPCTEST_NULL_BATCH_PROC	((u_long)3)

#define NULLPROC ((u_long)0)

struct rpc_createerr {
	enum clnt_stat cf_stat;
	struct rpc_err cf_error;
};

#define UDPMSGSIZE	8800
#define RPCSMALLMSGSIZE	400

#include <bits/rlibc-rpc-clnt.h>

extern struct rpc_createerr rpc_createerr;

#endif
