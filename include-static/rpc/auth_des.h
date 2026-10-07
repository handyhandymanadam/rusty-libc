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
#ifndef _RPC_AUTH_DES_H
#define _RPC_AUTH_DES_H 1

#include <rpc/auth.h>

enum authdes_namekind
  {
    ADN_FULLNAME,
    ADN_NICKNAME
  };

struct authdes_fullname
  {
    char *name;
    des_block key;
    uint32_t window;
  };

struct authdes_cred
  {
    enum authdes_namekind adc_namekind;
    struct authdes_fullname adc_fullname;
    uint32_t adc_nickname;
  };

struct rpc_timeval
  {
    uint32_t tv_sec;
    uint32_t tv_usec;
  };

struct authdes_verf
  {
    union
      {
	struct rpc_timeval adv_ctime;
	des_block adv_xtime;
      }
    adv_time_u;
    uint32_t adv_int_u;
  };

#define adv_timestamp  adv_time_u.adv_ctime
#define adv_xtimestamp adv_time_u.adv_xtime
#define adv_winverf    adv_int_u
#define adv_timeverf   adv_time_u.adv_ctime
#define adv_xtimeverf  adv_time_u.adv_xtime
#define adv_nickname   adv_int_u

#include <bits/rlibc-rpc-auth-des.h>

#endif
