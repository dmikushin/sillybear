/* compile options depend on Sillybear options.h */
#include "options.h"

/* Sillybear config */

#define LTC_NOTHING

/* Use small code where possible */
#if SILLYBEAR_SMALL_CODE
#define LTC_SMALL_CODE
#endif

/* Fewer entries needed */
#define TAB_SIZE      5

#if SILLYBEAR_AES
#define LTC_RIJNDAEL
#endif

#if SILLYBEAR_3DES
#define LTC_DES
#endif

#if SILLYBEAR_ENABLE_CBC_MODE
#define LTC_CBC_MODE
#endif

#if SILLYBEAR_ENABLE_CTR_MODE
#define LTC_CTR_MODE
#endif

#if SILLYBEAR_ENABLE_GCM_MODE
#define LTC_GCM_MODE
#endif

#if SILLYBEAR_CHACHA20POLY1305
#define LTC_CHACHA
#define LTC_POLY1305
#endif

#if SILLYBEAR_SHA512
#define LTC_SHA512
#endif

#if SILLYBEAR_SHA384
#define LTC_SHA384
#endif

#if SILLYBEAR_SHA256
#define LTC_SHA256
#endif

#if SILLYBEAR_SHA1
#define LTC_SHA1
#endif

/* ECC */
#if SILLYBEAR_ECC
#define LTC_MECC
#define LTM_DESC

/* use Shamir's trick for point mul (speeds up signature verification) */
#define LTC_ECC_SHAMIR

#if SILLYBEAR_ECC_256
#define LTC_ECC256
#endif
#if SILLYBEAR_ECC_384
#define LTC_ECC384
#endif
#if SILLYBEAR_ECC_521
#define LTC_ECC521
#endif

#endif /* SILLYBEAR_ECC */

#define LTC_HMAC
#define LTC_HASH_HELPERS

#define LTC_NO_TEST

#define LTC_BASE64

/* end Sillybear config */
