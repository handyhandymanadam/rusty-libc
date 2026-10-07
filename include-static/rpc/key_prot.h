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
#ifndef _KEY_PROT_H_RPCGEN
#define _KEY_PROT_H_RPCGEN

#include <rpc/rpc.h>

#define PROOT 3
#define HEXMODULUS "d4a0ba0250b6fd2ec626e7efd637df76c716e22d0944b88b"
#define HEXKEYBYTES 48
#define KEYSIZE 192
#define KEYBYTES 24
#define KEYCHECKSUMSIZE 16

enum keystatus {
	KEY_SUCCESS = 0,
	KEY_NOSECRET = 1,
	KEY_UNKNOWN = 2,
	KEY_SYSTEMERR = 3,
};
typedef enum keystatus keystatus;

typedef char keybuf[HEXKEYBYTES];

typedef char *netnamestr;

struct cryptkeyarg {
	netnamestr remotename;
	des_block deskey;
};
typedef struct cryptkeyarg cryptkeyarg;

struct cryptkeyarg2 {
	netnamestr remotename;
	netobj remotekey;
	des_block deskey;
};
typedef struct cryptkeyarg2 cryptkeyarg2;

struct cryptkeyres {
	keystatus status;
	union {
		des_block deskey;
	} cryptkeyres_u;
};
typedef struct cryptkeyres cryptkeyres;

#define MAXGIDS 16

struct unixcred {
	u_int uid;
	u_int gid;
	struct {
		u_int gids_len;
		u_int *gids_val;
	} gids;
};
typedef struct unixcred unixcred;

struct getcredres {
	keystatus status;
	union {
		unixcred cred;
	} getcredres_u;
};
typedef struct getcredres getcredres;

struct key_netstarg {
	keybuf st_priv_key;
	keybuf st_pub_key;
	netnamestr st_netname;
};
typedef struct key_netstarg key_netstarg;

struct key_netstres {
	keystatus status;
	union {
		key_netstarg knet;
	} key_netstres_u;
};
typedef struct key_netstres key_netstres;

#define KEY_PROG ((u_long)100029)
#define KEY_VERS ((u_long)1)
#define KEY_SET ((u_long)1)
#define KEY_ENCRYPT ((u_long)2)
#define KEY_DECRYPT ((u_long)3)
#define KEY_GEN ((u_long)4)
#define KEY_GETCRED ((u_long)5)
#define KEY_VERS2 ((u_long)2)
#define KEY_ENCRYPT_PK ((u_long)6)
#define KEY_DECRYPT_PK ((u_long)7)
#define KEY_NET_PUT ((u_long)8)
#define KEY_NET_GET ((u_long)9)
#define KEY_GET_CONV ((u_long)10)

#include <bits/rlibc-rpc-key-prot.h>

#endif
