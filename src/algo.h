/*
 * Sillybear - a SSH2 server
 * 
 * Copyright (c) 2002,2003 Matt Johnston
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE. */

#ifndef SILLYBEAR_ALGO_H_

#define SILLYBEAR_ALGO_H_

#include "includes.h"
#include "buffer.h"

#define SILLYBEAR_MODE_UNUSED 0
#define SILLYBEAR_MODE_CBC 1
#define SILLYBEAR_MODE_CTR 2

struct Algo_Type {

	const char *name; /* identifying name */
	char val; /* a value for this cipher, or -1 for invalid */
	const void *data; /* algorithm specific data */
	char usable; /* whether we can use this algorithm */
	const void *mode; /* the mode, currently only used for ciphers,
						 points to a 'struct sillybear_cipher_mode' */
};

typedef struct Algo_Type algo_type;

/* lists mapping ssh types of algorithms to internal values */
extern algo_type sshkex[];
extern algo_type sigalgs[];
extern algo_type sshciphers[];
extern algo_type sshhashes[];
extern algo_type ssh_compress[];
extern algo_type ssh_delaycompress[];
extern algo_type ssh_nocompress[];

extern const struct sillybear_cipher sillybear_nocipher;
extern const struct sillybear_cipher_mode sillybear_mode_none;
extern const struct sillybear_hash sillybear_nohash;

struct sillybear_cipher {
	const struct ltc_cipher_descriptor *cipherdesc;
	const unsigned long keysize;
	const unsigned char blocksize;
};

struct sillybear_cipher_mode {
	int (*start)(int cipher, const unsigned char *IV, 
			const unsigned char *key, 
			int keylen, int num_rounds, void *cipher_state);
	int (*encrypt)(const unsigned char *pt, unsigned char *ct, 
			unsigned long len, void *cipher_state);
	int (*decrypt)(const unsigned char *ct, unsigned char *pt, 
			unsigned long len, void *cipher_state);
	int (*aead_crypt)(unsigned int seq,
			const unsigned char *in, unsigned char *out,
			unsigned long len, unsigned long taglen,
			void *cipher_state, int direction);
	int (*aead_getlength)(unsigned int seq,
			const unsigned char *in, unsigned int *outlen,
			unsigned long len, void *cipher_state);
	const struct sillybear_hash *aead_mac;
};

struct sillybear_hash {
	const struct ltc_hash_descriptor *hash_desc;
	const unsigned long keysize;
	/* hashsize may be truncated from the size returned by hash_desc,
	   eg sha1-96 */
	const unsigned char hashsize;
};

enum sillybear_kex_mode {
#if SILLYBEAR_NORMAL_DH
	SILLYBEAR_KEX_NORMAL_DH,
#endif
#if SILLYBEAR_ECDH
	SILLYBEAR_KEX_ECDH,
#endif
#if SILLYBEAR_CURVE25519
	SILLYBEAR_KEX_CURVE25519,
#endif
#if SILLYBEAR_PQHYBRID
	SILLYBEAR_KEX_PQHYBRID,
#endif
};

struct sillybear_kex {
	enum sillybear_kex_mode mode;
	
	/* "normal" DH KEX */
	const unsigned char *dh_p_bytes;
	const int dh_p_len;

	/* kex specific, could be ecc_curve or pqhybrid_desc */
	const void* details;

	/* both */
	const struct ltc_hash_descriptor *hash_desc;
};

struct sillybear_kem_desc {
	unsigned int public_len;
	unsigned int secret_len;
	unsigned int ciphertext_len;
	unsigned int output_len;
	int (*kem_gen)(unsigned char *pk, unsigned char *sk);
	int (*kem_enc)(unsigned char *c, unsigned char *k, const unsigned char *pk);
	int (*kem_dec)(unsigned char *k, const unsigned char *c, const unsigned char *sk);
};

/* Includes all algorithms is useall is set */
void buf_put_algolist_all(buffer * buf, const algo_type localalgos[], int useall);
/* Includes "usable" algorithms */
void buf_put_algolist(buffer * buf, const algo_type localalgos[]);

#define KEXGUESS2_ALGO_NAME "kexguess2@matt.ucc.asn.au"

int buf_has_algo(buffer *buf, const char *algo);
algo_type * first_usable_algo(algo_type algos[]);
algo_type * buf_match_algo(buffer* buf, algo_type localalgos[],
		int kexguess2, int *goodguess);

#if SILLYBEAR_USER_ALGO_LIST
int check_user_algos(const char* user_algo_list, algo_type * algos, 
		const char *algo_desc);
char * algolist_string(const algo_type algos[]);
#endif

enum {
	SILLYBEAR_COMP_NONE,
	SILLYBEAR_COMP_ZLIB,
	SILLYBEAR_COMP_ZLIB_DELAY,
};

#endif /* SILLYBEAR_ALGO_H_ */
