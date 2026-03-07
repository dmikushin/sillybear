#include "includes.h"
#include "dbutil.h"
#include "crypto_desc.h"
#include "ltc_prng.h"
#include "ecc.h"
#include "dbrandom.h"

#if SILLYBEAR_LTC_PRNG
	int sillybear_ltc_prng = -1;
#endif

/* Wrapper for libtommath */
static mp_err sillybear_rand_source(void* out, size_t size) {
	genrandom((unsigned char*)out, (unsigned int)size);
	return MP_OKAY;
}


/* Register the compiled in ciphers.
 * This should be run before using any of the ciphers/hashes */
void crypto_init() {

	const struct ltc_cipher_descriptor *regciphers[] = {
#if SILLYBEAR_AES
		&aes_desc,
#endif
#if SILLYBEAR_3DES
		&des3_desc,
#endif
		NULL
	};

	const struct ltc_hash_descriptor *reghashes[] = {
#if SILLYBEAR_SHA1_HMAC
		&sha1_desc,
#endif
#if SILLYBEAR_SHA256
		&sha256_desc,
#endif
#if SILLYBEAR_SHA384
		&sha384_desc,
#endif
#if SILLYBEAR_SHA512
		&sha512_desc,
#endif
		NULL
	};
	int i;

	for (i = 0; regciphers[i] != NULL; i++) {
		if (register_cipher(regciphers[i]) == -1) {
			sillybear_exit("Error registering crypto");
		}
	}

	for (i = 0; reghashes[i] != NULL; i++) {
		if (register_hash(reghashes[i]) == -1) {
			sillybear_exit("Error registering crypto");
		}
	}

#if SILLYBEAR_LTC_PRNG
	sillybear_ltc_prng = register_prng(&sillybear_prng_desc);
	if (sillybear_ltc_prng == -1) {
		sillybear_exit("Error registering crypto");
	}
#endif

	mp_rand_source(sillybear_rand_source);

#if SILLYBEAR_ECC
	ltc_mp = ltm_desc;
	sillybear_ecc_fill_dp();
#endif
}

