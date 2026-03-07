/*******************************************************************
 * You shouldn't edit this file unless you know you need to.
 * This file is only included from options.h
 *******************************************************************/

#ifndef SILLYBEAR_VERSION
#define SILLYBEAR_VERSION "2025.89"
#endif

/* IDENT_VERSION_PART is the optional part after "SSH-2.0-sillybear". Refer to RFC4253 for requirements. */
#ifndef IDENT_VERSION_PART
#define IDENT_VERSION_PART "_" SILLYBEAR_VERSION
#endif
#define LOCAL_IDENT "SSH-2.0-sillybear" IDENT_VERSION_PART
#define PROGNAME "sillybear"

#ifndef SILLYBEAR_CLIENT
#define SILLYBEAR_CLIENT 0
#endif

#ifndef SILLYBEAR_SERVER
#define SILLYBEAR_SERVER 0
#endif

/* Spec recommends after one hour or 1 gigabyte of data. One hour
 * is a bit too verbose, so we try 8 hours */
#ifndef KEX_REKEY_TIMEOUT
#define KEX_REKEY_TIMEOUT (3600 * 8)
#endif
#ifndef KEX_REKEY_DATA
#define KEX_REKEY_DATA (1<<30) /* 2^30 == 1GB, this value must be < INT_MAX */
#endif
/* Close connections to clients which haven't authorised after AUTH_TIMEOUT */
#ifndef AUTH_TIMEOUT
#define AUTH_TIMEOUT 300 /* we choose 5 minutes */
#endif

#define SILLYBEAR_SVR_PUBKEY_OPTIONS_BUILT ((SILLYBEAR_SVR_PUBKEY_AUTH) && (SILLYBEAR_SVR_PUBKEY_OPTIONS))

#if !(NON_INETD_MODE || INETD_MODE)
	#error "NON_INETD_MODE or INETD_MODE (or both) must be enabled."
#endif

/* Would probably work on freebsd but hasn't been tested */
#if defined(HAVE_FEXECVE) && SILLYBEAR_REEXEC && defined(__linux__)
#define SILLYBEAR_DO_REEXEC 1
#else
#define SILLYBEAR_DO_REEXEC 0
#endif

/* A client should try and send an initial key exchange packet guessing
 * the algorithm that will match - saves a round trip connecting, has little
 * overhead if the guess was "wrong". */
#ifndef SILLYBEAR_KEX_FIRST_FOLLOWS
#define SILLYBEAR_KEX_FIRST_FOLLOWS 1
#endif
/* Use protocol extension to allow "first follows" to succeed more frequently.
 * This is currently Sillybear-specific but will gracefully fallback when connecting
 * to other implementations. */
#ifndef SILLYBEAR_KEXGUESS2
#define SILLYBEAR_KEXGUESS2 1
#endif

/* Minimum key sizes for DSS and RSA */
#ifndef MIN_DSS_KEYLEN
#define MIN_DSS_KEYLEN 1024
#endif
#ifndef MIN_RSA_KEYLEN
#define MIN_RSA_KEYLEN 1024
#endif

#define MAX_BANNER_SIZE 2050 /* this is 25*80 chars, any more is foolish */
#define MAX_BANNER_LINES 20 /* How many lines the client will display */

/* Define maxsize for motd information (80 x 25) */
#ifndef MOTD_MAXSIZE
#define MOTD_MAXSIZE 2000
#endif

/* the number of NAME=VALUE pairs to malloc for environ, if we don't have
 * the clearenv() function */
#define ENV_SIZE 100

#define MAX_CMD_LEN 9000 /* max length of a command */
#define MAX_TERM_LEN 200 /* max length of TERM name */

#define MAX_HOST_LEN 254 /* max hostname len for tcp fwding */

#define SILLYBEAR_MAX_PORTS 10 /* max number of ports which can be specified,
								 ipv4 and ipv6 don't count twice */

/* Each port might have at least a v4 and a v6 address */
#define MAX_LISTEN_ADDR (SILLYBEAR_MAX_PORTS*3)

#define _PATH_TTY "/dev/tty"

#define _PATH_CP "/bin/cp"

/* Default contents of /etc/shells if system getusershell() doesn't exist.
 * Paths taken from getusershell(3) manpage. These can be customised
 * on other platforms. One the commandline for CFLAGS it would look like eg
  -DCOMPAT_USER_SHELLS='"/bin/sh","/apps/bin/sh","/data/bin/zsh"'
 */
#ifndef COMPAT_USER_SHELLS
#define COMPAT_USER_SHELLS "/bin/sh","/bin/csh"
#endif

#define SILLYBEAR_ESCAPE_CHAR '~'

/* success/failure defines */
#define SILLYBEAR_SUCCESS 0
#define SILLYBEAR_FAILURE -1

#define SILLYBEAR_PASSWORD_ENV "SILLYBEAR_PASSWORD"

/* Default per client configuration file.
*/
#define SILLYBEAR_DEFAULT_SSH_CONFIG "~/.ssh/sillybear_config"

#define SILLYBEAR_NGROUP_MAX 1024

/* Required for pubkey auth */
#define SILLYBEAR_SIGNKEY_VERIFY ((SILLYBEAR_SVR_PUBKEY_AUTH) || (SILLYBEAR_CLIENT))

/* crypt(password) must take less time than the auth failure delay
   (250ms set in svr-auth.c). On Linux the delay depends on
   password length, 100 characters here was empirically derived.

   If a longer password is allowed Sillybear cannot compensate
   for the crypt time which will expose which usernames exist */
#define SILLYBEAR_MAX_PASSWORD_LEN 100

#define SHA1_HASH_SIZE 20
#define SHA256_HASH_SIZE 32
#define MAX_HASH_SIZE 64 /* sha512 */

#if SILLYBEAR_CHACHA20POLY1305
#define MAX_KEY_LEN 64 /* 2 x 256 bits for chacha20 */
#else
#define MAX_KEY_LEN 32 /* 256 bits for aes256 etc */
#endif
#define MAX_IV_LEN 20 /* must be same as max blocksize,  */

#if SILLYBEAR_SHA2_512_HMAC
#define MAX_MAC_LEN 64
#elif SILLYBEAR_SHA2_256_HMAC
#define MAX_MAC_LEN 32
#else
#define MAX_MAC_LEN 20
#endif

/* sha2-512 is not necessary unless unforseen problems arise with sha2-256 */
#ifndef SILLYBEAR_SHA2_512_HMAC
#define SILLYBEAR_SHA2_512_HMAC 0
#endif

#define SILLYBEAR_ECC ((SILLYBEAR_ECDH) || (SILLYBEAR_ECDSA))

/* Debian doesn't define this in system headers */
#if !defined(LTM_DESC) && (SILLYBEAR_ECC)
#define LTM_DESC
#endif

#define SILLYBEAR_ECC_256 (SILLYBEAR_ECC)
#define SILLYBEAR_ECC_384 (SILLYBEAR_ECC)
#define SILLYBEAR_ECC_521 (SILLYBEAR_ECC)

/* Only include necessary ECC curves building libtomcrypt */
#define LTC_NO_CURVES
#if SILLYBEAR_ECC_256
#define LTC_ECC256
#endif
#if SILLYBEAR_ECC_384
#define LTC_ECC384
#endif
#if SILLYBEAR_ECC_521
#define LTC_ECC521
#endif

#define SILLYBEAR_LTC_PRNG (SILLYBEAR_ECC)

/* RSA can be vulnerable to timing attacks which use the time required for
 * signing to guess the private key. Blinding avoids this attack, though makes
 * signing operations slightly slower. */
#define SILLYBEAR_RSA_BLINDING 1

#ifndef SILLYBEAR_RSA_SHA256
#define SILLYBEAR_RSA_SHA256 SILLYBEAR_RSA
#endif

/* Miller-Rabin primality testing is sufficient for RSA but not DSS.
 * It's a compile-time setting for libtommath, we can get a speedup
 * for key generation if DSS is disabled.
 * https://github.com/mkj/sillybear/issues/174#issuecomment-1267374858
 */
#if !SILLYBEAR_DSS
#define LTM_USE_ONLY_MR 1
#endif

/* hashes which will be linked and registered */
#define SILLYBEAR_SHA1 (SILLYBEAR_RSA_SHA1 || SILLYBEAR_DSS \
				|| SILLYBEAR_SHA1_HMAC || SILLYBEAR_SHA1_96_HMAC \
				|| SILLYBEAR_DH_GROUP1 || SILLYBEAR_DH_GROUP14_SHA1 )
/* sha256 is always used for fingerprints and dbrandom */
#define SILLYBEAR_SHA256 1
#define SILLYBEAR_SHA384 (SILLYBEAR_ECC_384)
/* LTC SHA384 depends on SHA512 */
#define SILLYBEAR_SHA512 ((SILLYBEAR_SHA2_512_HMAC) || (SILLYBEAR_ECC_521) \
			|| (SILLYBEAR_SHA384) || (SILLYBEAR_DH_GROUP16) \
			|| (SILLYBEAR_ED25519) || (SILLYBEAR_SNTRUP761))

#define SILLYBEAR_DH_GROUP14 ((SILLYBEAR_DH_GROUP14_SHA256) || (SILLYBEAR_DH_GROUP14_SHA1))

#define SILLYBEAR_NORMAL_DH ((SILLYBEAR_DH_GROUP1) || (SILLYBEAR_DH_GROUP14) || (SILLYBEAR_DH_GROUP16))

#ifndef SILLYBEAR_SK_ECDSA
#define SILLYBEAR_SK_ECDSA ((SILLYBEAR_SK_KEYS) && (SILLYBEAR_ECDSA))
#endif
#ifndef SILLYBEAR_SK_ED25519
#define SILLYBEAR_SK_ED25519 ((SILLYBEAR_SK_KEYS) && (SILLYBEAR_ED25519))
#endif

#define SILLYBEAR_PQHYBRID (SILLYBEAR_SNTRUP761 || SILLYBEAR_MLKEM768)
#define SILLYBEAR_CURVE25519_DEP (SILLYBEAR_CURVE25519 || SILLYBEAR_PQHYBRID)

/* Sillybear only uses server-sig-algs, only needed if we have rsa-sha256 pubkey auth */
#define SILLYBEAR_EXT_INFO ((SILLYBEAR_RSA_SHA256) \
		&& ((SILLYBEAR_CLI_PUBKEY_AUTH) || (SILLYBEAR_SVR_PUBKEY_AUTH)))

/* roughly 2x 521 bits */
#define MAX_ECC_SIZE 140

#define MAX_NAME_LEN 64 /* maximum length of a protocol name, isn't
						   explicitly specified for all protocols (just
						   for algos) but seems valid */

#define MAX_PROPOSED_ALGO 50

/* size/count limits */
/* From transport rfc */
#define MIN_PACKET_LEN 16

#define RECV_MAX_PACKET_LEN (MAX(35000, ((RECV_MAX_PAYLOAD_LEN)+100)))

/* for channel code */
#define RECV_WINDOWEXTEND (opts.recv_window / 3) /* We send a "window extend" every
								RECV_WINDOWEXTEND bytes */
#define MAX_RECV_WINDOW (10*1024*1024) /* 10 MB should be enough */

#define MAX_CHANNELS 1000 /* simple mem restriction, includes each tcp/x11
							connection, so can't be _too_ small */

#define MAX_STRING_LEN (MAX(MAX_CMD_LEN, 2400)) /* Sun SSH needs 2400 for algos,
                                                   MAX_CMD_LEN is usually longer */


/* Key type sizes are ordered large to small, all are
 determined empirically, and rounded up */
#if SILLYBEAR_RSA
/* 4096 bit RSA key */
#define MAX_PUBKEY_SIZE 600
#define MAX_PRIVKEY_SIZE 1700
#elif SILLYBEAR_DSS
#define MAX_PUBKEY_SIZE 500
#define MAX_PRIVKEY_SIZE 500
#else
/* 521 bit ecdsa key */
#define MAX_PUBKEY_SIZE 200
#define MAX_PRIVKEY_SIZE 250
#endif

/* For kex hash buffer, worst case size for Q_C || Q_S || K */
#if SILLYBEAR_MLKEM768
#define MAX_KEX_PARTS (2*4 + 1184 + 1088 + 32*2 + 68)
#elif SILLYBEAR_SNTRUP761
/* 2337 */
#define MAX_KEX_PARTS (2*4 + 1158 + 1039 + 32*2 + 68)
#elif SILLYBEAR_DH_GROUP16
/* 4096 bit group */
#define MAX_KEX_PARTS (3 * 520)
#else
/* Sufficent for 2048 bit group14, or ecdsa521 */
#define MAX_KEX_PARTS 1000
#endif

#define MAX_HOSTKEYS 4

/* The maximum size of the bignum portion of the kexhash buffer */
/* K_S + Q_C + Q_S + K */
#define KEXHASHBUF_MAX_INTS (MAX_PUBKEY_SIZE + MAX_KEX_PARTS)

#define SILLYBEAR_MAX_SOCKS 2 /* IPv4, IPv6 are all we'll get for now. Revisit
								in a few years time.... */

#define SILLYBEAR_MAX_CLI_PASS 1024

#define SILLYBEAR_MAX_CLI_INTERACT_PROMPTS 80 /* The number of prompts we'll 
												accept for keyb-interactive
												auth */


#define SILLYBEAR_AES ((SILLYBEAR_AES256) || (SILLYBEAR_AES128))

#define SILLYBEAR_AEAD_MODE ((SILLYBEAR_CHACHA20POLY1305) || (SILLYBEAR_ENABLE_GCM_MODE))

#define SILLYBEAR_CLI_ANYTCPFWD ((SILLYBEAR_CLI_REMOTETCPFWD) || (SILLYBEAR_CLI_LOCALTCPFWD))

#define SILLYBEAR_TCP_ACCEPT ((SILLYBEAR_CLI_LOCALTCPFWD) || (SILLYBEAR_SVR_REMOTETCPFWD))

/* TCP and stream local fwds share the same restrictions */
#define SILLYBEAR_SVR_LOCALANYFWD ((SILLYBEAR_SVR_LOCALTCPFWD) || (SILLYBEAR_SVR_LOCALSTREAMFWD))

#define SILLYBEAR_LISTENERS \
   ((SILLYBEAR_CLI_REMOTETCPFWD) || (SILLYBEAR_CLI_LOCALTCPFWD) || \
	(SILLYBEAR_SVR_REMOTETCPFWD) || (SILLYBEAR_SVR_LOCALANYFWD) || \
	(SILLYBEAR_SVR_AGENTFWD) || (SILLYBEAR_X11FWD))

#define SILLYBEAR_CLI_MULTIHOP ((SILLYBEAR_CLI_NETCAT) && (SILLYBEAR_CLI_PROXYCMD))

#define ENABLE_CONNECT_UNIX ((SILLYBEAR_CLI_AGENTFWD) || (SILLYBEAR_USE_PRNGD))

/* if we're using authorized_keys or known_hosts */ 
#define SILLYBEAR_KEY_LINES ((SILLYBEAR_CLIENT) || (SILLYBEAR_SVR_PUBKEY_AUTH))

/* Changing this is inadvisable, it appears to have problems
 * with flushing compressed data */
#define SILLYBEAR_ZLIB_MEM_LEVEL 8

#if (SILLYBEAR_SVR_PASSWORD_AUTH) && (SILLYBEAR_SVR_PAM_AUTH)
#error "You can't turn on PASSWORD and PAM auth both at once. Fix it in localoptions.h"
#endif

/* PAM requires ./configure --enable-pam */
#if !defined(HAVE_LIBPAM) && SILLYBEAR_SVR_PAM_AUTH
#error "SILLYBEAR_SVR_PAM_AUTH requires PAM headers. Perhaps ./configure --enable-pam ?"
#endif

#if SILLYBEAR_SVR_PASSWORD_AUTH && !HAVE_CRYPT
	#error "SILLYBEAR_SVR_PASSWORD_AUTH requires `crypt()'."
#endif

#if !(SILLYBEAR_SVR_PASSWORD_AUTH || SILLYBEAR_SVR_PAM_AUTH || SILLYBEAR_SVR_PUBKEY_AUTH)
	#error "At least one server authentication type must be enabled. SILLYBEAR_SVR_PUBKEY_AUTH and SILLYBEAR_SVR_PASSWORD_AUTH are recommended."
#endif

#if (SILLYBEAR_PLUGIN && !SILLYBEAR_SVR_PUBKEY_AUTH)
	#error "You must define SILLYBEAR_SVR_PUBKEY_AUTH in order to use plugins"
#endif

#if !(SILLYBEAR_AES128 || SILLYBEAR_3DES || SILLYBEAR_AES256 || SILLYBEAR_CHACHA20POLY1305)
	#error "At least one encryption algorithm must be enabled. AES128 is recommended."
#endif

#if !(SILLYBEAR_RSA || SILLYBEAR_DSS || SILLYBEAR_ECDSA || SILLYBEAR_ED25519)
	#error "At least one hostkey or public-key algorithm must be enabled; RSA is recommended."
#endif

#if SILLYBEAR_SVR_DROP_PRIVS && !defined(HAVE_SETRESGID)
	#error "SILLYBEAR_SVR_DROP_PRIVS requires setresgid()."
#endif

/* Source for randomness. This must be able to provide hundreds of bytes per SSH
 * connection without blocking. */
#ifndef SILLYBEAR_URANDOM_DEV
#define SILLYBEAR_URANDOM_DEV "/dev/urandom"
#endif

/* client keyboard interactive authentication is often used for password auth.
 rfc4256 */
#define SILLYBEAR_CLI_INTERACT_AUTH (SILLYBEAR_CLI_PASSWORD_AUTH)

/* We use sillybear_client and sillybear_server as shortcuts to avoid redundant
 * code, if we're just compiling as client or server */
#if (SILLYBEAR_SERVER) && (SILLYBEAR_CLIENT)

#define IS_SILLYBEAR_SERVER (ses.isserver == 1)
#define IS_SILLYBEAR_CLIENT (ses.isserver == 0)

#elif SILLYBEAR_SERVER

#define IS_SILLYBEAR_SERVER 1
#define IS_SILLYBEAR_CLIENT 0

#elif SILLYBEAR_CLIENT

#define IS_SILLYBEAR_SERVER 0
#define IS_SILLYBEAR_CLIENT 1

#else
/* Just building key utils? */
#define IS_SILLYBEAR_SERVER 0
#define IS_SILLYBEAR_CLIENT 0

#endif /* neither SILLYBEAR_SERVER nor SILLYBEAR_CLIENT */

#ifdef HAVE_FORK
#define SILLYBEAR_VFORK 0
#else
#define SILLYBEAR_VFORK 1
#endif

#ifndef SILLYBEAR_LISTEN_BACKLOG
#if MAX_UNAUTH_CLIENTS > MAX_CHANNELS
#define SILLYBEAR_LISTEN_BACKLOG MAX_UNAUTH_CLIENTS
#else
#define SILLYBEAR_LISTEN_BACKLOG MAX_CHANNELS
#endif
#endif

/* free memory before exiting */
#define SILLYBEAR_CLEANUP 1

/* Use this string since some implementations might special-case it */
#define SILLYBEAR_KEEPALIVE_STRING "keepalive@openssh.com"

/* Linux will attempt TCP fast open, falling back if not supported by the kernel.
 * Currently server is enabled but client is disabled by default until there
 * is further compatibility testing */
#ifdef __linux__
#define SILLYBEAR_SERVER_TCP_FAST_OPEN 1
#define SILLYBEAR_CLIENT_TCP_FAST_OPEN 0
#else
#define SILLYBEAR_SERVER_TCP_FAST_OPEN 0
#define SILLYBEAR_CLIENT_TCP_FAST_OPEN 0
#endif

#define SILLYBEAR_TRACKING_MALLOC (SILLYBEAR_FUZZ)

/* Used to work around Memory Sanitizer false positives */
#if defined(__has_feature)
#  if __has_feature(memory_sanitizer)
#    define SILLYBEAR_MSAN 1
#  endif
#endif
#ifndef SILLYBEAR_MSAN 
#define SILLYBEAR_MSAN 0
#endif

#ifndef DEBUG_DSS_VERIFY
#define DEBUG_DSS_VERIFY 0
#endif

#ifndef SILLYBEAR_MULTI
#define SILLYBEAR_MULTI 0
#endif

#if !SILLYBEAR_SVR_MULTIUSER && SILLYBEAR_SVR_DROP_PRIVS
#error SILLYBEAR_SVR_DROP_PRIVS needs SILLYBEAR_SVR_MULTIUSER
#endif

#if !(SILLYBEAR_SVR_DROP_PRIVS || !SILLYBEAR_SVR_MULTIUSER) && SILLYBEAR_SVR_LOCALSTREAMFWD 
#error SILLYBEAR_SVR_LOCALSTREAMFWD requires SILLYBEAR_SVR_DROP_PRIVS or !SILLYBEAR_SVR_MULTIUSER
#endif

/* Fuzzing expects all key types to be enabled */
#if SILLYBEAR_FUZZ
#if defined(SILLYBEAR_DSS)
#undef SILLYBEAR_DSS
#endif
#define SILLYBEAR_DSS 1

#if defined(SILLYBEAR_RSA_SHA1)
#undef SILLYBEAR_RSA_SHA1
#endif
#define SILLYBEAR_RSA_SHA1 1

#if defined(SILLYBEAR_USE_SSH_CONFIG)
#undef SILLYBEAR_USE_SSH_CONFIG
#endif
#define SILLYBEAR_USE_SSH_CONFIG 1

#endif /* SILLYBEAR_FUZZ */

/* no include guard for this file */
