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
#ifndef _RPC_AUTH_H
#define _RPC_AUTH_H 1

#include <stdint.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <rpc/xdr.h>

#define MAX_AUTH_BYTES	400
#define MAXNETNAMELEN	255

enum auth_stat {
	AUTH_OK=0,
	AUTH_BADCRED=1,
	AUTH_REJECTEDCRED=2,
	AUTH_BADVERF=3,
	AUTH_REJECTEDVERF=4,
	AUTH_TOOWEAK=5,
	AUTH_INVALIDRESP=6,
	AUTH_FAILED=7
};

union des_block {
	struct {
		uint32_t high;
		uint32_t low;
	} key;
	char c[8];
};
typedef union des_block des_block;

struct opaque_auth {
	enum_t	oa_flavor;
	caddr_t	oa_base;
	u_int	oa_length;
};

typedef struct AUTH AUTH;
struct AUTH {
  struct opaque_auth ah_cred;
  struct opaque_auth ah_verf;
  union des_block ah_key;
  struct auth_ops {
    void (*ah_nextverf) (AUTH *);
    int  (*ah_marshal) (AUTH *, XDR *);
    int  (*ah_validate) (AUTH *, struct opaque_auth *);
    int  (*ah_refresh) (AUTH *);
    void (*ah_destroy) (AUTH *);
  } *ah_ops;
  caddr_t ah_private;
};

#define AUTH_NEXTVERF(auth)		((*((auth)->ah_ops->ah_nextverf))(auth))
#define auth_nextverf(auth)		((*((auth)->ah_ops->ah_nextverf))(auth))
#define AUTH_MARSHALL(auth, xdrs)	((*((auth)->ah_ops->ah_marshal))(auth, xdrs))
#define auth_marshall(auth, xdrs)	((*((auth)->ah_ops->ah_marshal))(auth, xdrs))
#define AUTH_VALIDATE(auth, verfp)	((*((auth)->ah_ops->ah_validate))((auth), verfp))
#define auth_validate(auth, verfp)	((*((auth)->ah_ops->ah_validate))((auth), verfp))
#define AUTH_REFRESH(auth)		((*((auth)->ah_ops->ah_refresh))(auth))
#define auth_refresh(auth)		((*((auth)->ah_ops->ah_refresh))(auth))
#define AUTH_DESTROY(auth)		((*((auth)->ah_ops->ah_destroy))(auth))
#define auth_destroy(auth)		((*((auth)->ah_ops->ah_destroy))(auth))

extern struct opaque_auth _null_auth;

#define AUTH_NONE	0
#define	AUTH_NULL	0
#define	AUTH_SYS	1
#define	AUTH_UNIX	AUTH_SYS
#define	AUTH_SHORT	2
#define AUTH_DES	3
#define AUTH_DH		AUTH_DES
#define AUTH_KERB       4

#include <bits/rlibc-rpc-auth.h>

#endif
