#include "includes.h"
#include "dbutil.h"
#include "ssh.h"
#include "signkey_ossh.h"
#include "bignum.h"
#include "ecdsa.h"
#include "sk-ecdsa.h"
#include "sk-ed25519.h"
#include "rsa.h"
#include "dss.h"
#include "ed25519.h"

#if SILLYBEAR_RSA
/* OpenSSH raw private RSA format is
string       "ssh-rsa"
mpint        n
mpint        e
mpint        d
mpint        iqmp   (q^-1) mod p
mpint        p
mpint        q
*/

void buf_put_rsa_priv_ossh(buffer *buf, const sign_key *akey) {
	const sillybear_rsa_key *key = akey->rsakey;
	mp_int iqmp;

	sillybear_assert(key != NULL);
	if (!(key->p && key->q)) {
		sillybear_exit("Pre-0.33 Sillybear keys cannot be converted to OpenSSH keys.\n");
	}

	m_mp_init(&iqmp);
	/* iqmp = (q^-1) mod p */
	if (mp_invmod(key->q, key->p, &iqmp) != MP_OKAY) {
		sillybear_exit("Bignum error for iqmp\n");
	}
	buf_putstring(buf, SSH_SIGNKEY_RSA, SSH_SIGNKEY_RSA_LEN);
	buf_putmpint(buf, key->n);
	buf_putmpint(buf, key->e);
	buf_putmpint(buf, key->d);
	buf_putmpint(buf, &iqmp);
	buf_putmpint(buf, key->p);
	buf_putmpint(buf, key->q);
	mp_clear(&iqmp);
}

int buf_get_rsa_priv_ossh(buffer *buf, sign_key *akey) {
	int ret = SILLYBEAR_FAILURE;
	sillybear_rsa_key *key = NULL;
	mp_int iqmp;

	rsa_key_free(akey->rsakey);
	akey->rsakey = m_malloc(sizeof(*akey->rsakey));
	key = akey->rsakey;
	m_mp_alloc_init_multi(&key->e, &key->n, &key->d, &key->p, &key->q, NULL);

	buf_eatstring(buf);
	m_mp_init(&iqmp);
	if (buf_getmpint(buf, key->n) == SILLYBEAR_SUCCESS
		&& buf_getmpint(buf, key->e) == SILLYBEAR_SUCCESS
		&& buf_getmpint(buf, key->d) == SILLYBEAR_SUCCESS
		&& buf_getmpint(buf, &iqmp) == SILLYBEAR_SUCCESS
		&& buf_getmpint(buf, key->p) == SILLYBEAR_SUCCESS
		&& buf_getmpint(buf, key->q) == SILLYBEAR_SUCCESS) {
		ret = SILLYBEAR_SUCCESS;
	}
	mp_clear(&iqmp);
	return ret;
}

#endif /* SILLYBEAR_RSA */

#if SILLYBEAR_ED25519
/* OpenSSH raw private ed25519 format is
string       "ssh-ed25519"
uint32       32
byte[32]     pubkey
uint32       64
byte[32]     privkey
byte[32]     pubkey
*/

void buf_put_ed25519_priv_ossh(buffer *buf, const sign_key *akey) {
	const sillybear_ed25519_key *key = akey->ed25519key;
	sillybear_assert(key != NULL);
	buf_putstring(buf, SSH_SIGNKEY_ED25519, SSH_SIGNKEY_ED25519_LEN);
	buf_putint(buf, CURVE25519_LEN);
	buf_putbytes(buf, key->pub, CURVE25519_LEN);
	buf_putint(buf, CURVE25519_LEN*2);
	buf_putbytes(buf, key->priv, CURVE25519_LEN);
	buf_putbytes(buf, key->pub, CURVE25519_LEN);
}

int buf_get_ed25519_priv_ossh(buffer *buf, sign_key *akey) {
	sillybear_ed25519_key *key = NULL;
	uint32_t len;

	ed25519_key_free(akey->ed25519key);
	akey->ed25519key = m_malloc(sizeof(*akey->ed25519key));
	key = akey->ed25519key;

	/* Parse past the first string and pubkey */
	if (buf_get_ed25519_pub_key(buf, key, SILLYBEAR_SIGNKEY_ED25519)
			== SILLYBEAR_FAILURE) {
		sillybear_log(LOG_ERR, "Error parsing ed25519 key, pubkey");
		return SILLYBEAR_FAILURE;
	}
	len = buf_getint(buf);
	if (len != 2*CURVE25519_LEN) {
		sillybear_log(LOG_ERR, "Error parsing ed25519 key, bad length");
		return SILLYBEAR_FAILURE;
	}
	memcpy(key->priv, buf_getptr(buf, CURVE25519_LEN), CURVE25519_LEN);
	buf_incrpos(buf, CURVE25519_LEN);

	/* Sanity check */
	if (memcmp(buf_getptr(buf, CURVE25519_LEN), key->pub,
				CURVE25519_LEN) != 0) {
		sillybear_log(LOG_ERR, "Error parsing ed25519 key, mismatch pubkey");
		return SILLYBEAR_FAILURE;
	}
	return SILLYBEAR_SUCCESS;
}
#endif /* SILLYBEAR_ED255219 */

#if SILLYBEAR_ECDSA
/* OpenSSH raw private ecdsa format is the same as Sillybear's.
# First part is the same as the SSH wire pubkey format
string   "ecdsa-sha2-[identifier]"
string   [identifier]
string   Q
# With private part appended
mpint    d
*/

void buf_put_ecdsa_priv_ossh(buffer *buf, const sign_key *key) {
	ecc_key **eck = (ecc_key**)signkey_key_ptr((sign_key*)key, key->type);
	if (eck && *eck) {
		buf_put_ecdsa_priv_key(buf, *eck);
		return;
	}
	sillybear_exit("ecdsa key is not set");
}

int buf_get_ecdsa_priv_ossh(buffer *buf, sign_key *key) {
	ecc_key **eck = (ecc_key**)signkey_key_ptr(key, key->type);
	if (eck) {
		if (*eck) {
			ecc_free(*eck);
			m_free(*eck);
			*eck = NULL;
		}
		*eck = buf_get_ecdsa_priv_key(buf);
		if (*eck) {
			return SILLYBEAR_SUCCESS;
		}
	}
	return SILLYBEAR_FAILURE;
}
#endif /* SILLYBEAR_ECDSA */
