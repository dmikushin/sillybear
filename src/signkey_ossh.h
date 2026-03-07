#ifndef SILLYBEAR_SIGNKEY_OSSH_H_
#define SILLYBEAR_SIGNKEY_OSSH_H_

#include "signkey.h"

/* Helpers for OpenSSH format keys in sillybearconvert */

void buf_put_rsa_priv_ossh(buffer *buf, const sign_key *akey);
int buf_get_rsa_priv_ossh(buffer *buf, sign_key *akey);
void buf_put_ed25519_priv_ossh(buffer *buf, const sign_key *akey);
int buf_get_ed25519_priv_ossh(buffer *buf, sign_key *akey);
void buf_put_ecdsa_priv_ossh(buffer *buf, const sign_key *akey);
int buf_get_ecdsa_priv_ossh(buffer *buf, sign_key *akey);

#endif /* SILLYBEAR_SIGNKEY_OSSH_H_ */
