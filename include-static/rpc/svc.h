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
#ifndef _RPC_SVC_H
#define _RPC_SVC_H 1

#include <sys/select.h>
#include <poll.h>
#include <rpc/rpc_msg.h>

enum xprt_stat {
	XPRT_DIED,
	XPRT_MOREREQS,
	XPRT_IDLE
};

typedef struct SVCXPRT SVCXPRT;
struct SVCXPRT {
  int xp_sock;
  u_short xp_port;
  const struct xp_ops {
    bool_t	(*xp_recv) (SVCXPRT *__xprt, struct rpc_msg *__msg);
    enum xprt_stat (*xp_stat) (SVCXPRT *__xprt);
    bool_t	(*xp_getargs) (SVCXPRT *__xprt, xdrproc_t __xdr_args,
			       caddr_t __args_ptr);
    bool_t	(*xp_reply) (SVCXPRT *__xprt, struct rpc_msg *__msg);
    bool_t	(*xp_freeargs) (SVCXPRT *__xprt, xdrproc_t __xdr_args,
				caddr_t __args_ptr);
    void	(*xp_destroy) (SVCXPRT *__xprt);
  } *xp_ops;
  int		xp_addrlen;
  struct sockaddr_in xp_raddr;
  struct opaque_auth xp_verf;
  caddr_t		xp_p1;
  caddr_t		xp_p2;
  char		xp_pad [256];
};

#define svc_getcaller(x) (&(x)->xp_raddr)

#define SVC_RECV(xprt, msg)	(*(xprt)->xp_ops->xp_recv)((xprt), (msg))
#define svc_recv(xprt, msg)	(*(xprt)->xp_ops->xp_recv)((xprt), (msg))
#define SVC_STAT(xprt)		(*(xprt)->xp_ops->xp_stat)(xprt)
#define svc_stat(xprt)		(*(xprt)->xp_ops->xp_stat)(xprt)
#define SVC_GETARGS(xprt, xargs, argsp)	(*(xprt)->xp_ops->xp_getargs)((xprt), (xargs), (argsp))
#define svc_getargs(xprt, xargs, argsp)	(*(xprt)->xp_ops->xp_getargs)((xprt), (xargs), (argsp))
#define SVC_REPLY(xprt, msg)	(*(xprt)->xp_ops->xp_reply) ((xprt), (msg))
#define svc_reply(xprt, msg)	(*(xprt)->xp_ops->xp_reply) ((xprt), (msg))
#define SVC_FREEARGS(xprt, xargs, argsp)	(*(xprt)->xp_ops->xp_freeargs)((xprt), (xargs), (argsp))
#define svc_freeargs(xprt, xargs, argsp)	(*(xprt)->xp_ops->xp_freeargs)((xprt), (xargs), (argsp))
#define SVC_DESTROY(xprt)	(*(xprt)->xp_ops->xp_destroy)(xprt)
#define svc_destroy(xprt)	(*(xprt)->xp_ops->xp_destroy)(xprt)

struct svc_req {
  rpcprog_t rq_prog;
  rpcvers_t rq_vers;
  rpcproc_t rq_proc;
  struct opaque_auth rq_cred;
  caddr_t rq_clntcred;
  SVCXPRT *rq_xprt;
};

#ifndef __DISPATCH_FN_T
#define __DISPATCH_FN_T
typedef void (*__dispatch_fn_t) (struct svc_req*, SVCXPRT*);
#endif

#define	RPC_ANYSOCK	-1

#include <bits/rlibc-rpc-svc.h>

extern struct pollfd *svc_pollfd;
extern int svc_max_pollfd;
extern fd_set svc_fdset;
#define svc_fds svc_fdset.fds_bits[0]

#endif
