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
#ifndef _RPC_CLNT_STAT_H
#define _RPC_CLNT_STAT_H 1

enum clnt_stat {
	RPC_SUCCESS=0,
	RPC_CANTENCODEARGS=1,
	RPC_CANTDECODERES=2,
	RPC_CANTSEND=3,
	RPC_CANTRECV=4,
	RPC_TIMEDOUT=5,
	RPC_VERSMISMATCH=6,
	RPC_AUTHERROR=7,
	RPC_PROGUNAVAIL=8,
	RPC_PROGVERSMISMATCH=9,
	RPC_PROCUNAVAIL=10,
	RPC_CANTDECODEARGS=11,
	RPC_SYSTEMERROR=12,
	RPC_NOBROADCAST = 21,
	RPC_UNKNOWNHOST=13,
	RPC_UNKNOWNPROTO=17,
	RPC_UNKNOWNADDR = 19,
	RPC_RPCBFAILURE=14,
#define RPC_PMAPFAILURE RPC_RPCBFAILURE
	RPC_PROGNOTREGISTERED=15,
	RPC_N2AXLATEFAILURE = 22,
	RPC_FAILED=16,
	RPC_INTR=18,
	RPC_TLIERROR=20,
	RPC_UDERROR=23,
	RPC_INPROGRESS = 24,
	RPC_STALERACHANDLE = 25
};

#endif
