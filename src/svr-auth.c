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

/* This file (auth.c) handles authentication requests, passing it to the
 * particular type (auth-passwd, auth-pubkey). */


#include "includes.h"
#include "dbutil.h"
#include "session.h"
#include "buffer.h"
#include "ssh.h"
#include "packet.h"
#include "auth.h"
#include "runopts.h"
#include "dbrandom.h"

static int checkusername(const char *username, unsigned int userlen);

/* initialise the first time for a session, resetting all parameters */
void svr_authinitialise() {
	memset(&ses.authstate, 0, sizeof(ses.authstate));
#if SILLYBEAR_SVR_PUBKEY_AUTH
	ses.authstate.authtypes |= AUTH_TYPE_PUBKEY;
#endif
#if SILLYBEAR_SVR_PASSWORD_AUTH || SILLYBEAR_SVR_PAM_AUTH
	if (!svr_opts.noauthpass) {
		ses.authstate.authtypes |= AUTH_TYPE_PASSWORD;
	}
#endif
}

/* Send a banner message if specified to the client. The client might
 * ignore this, but possibly serves as a legal "no trespassing" sign */
void send_msg_userauth_banner(const buffer *banner) {

	TRACE(("enter send_msg_userauth_banner"))

	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_BANNER);
	buf_putbufstring(ses.writepayload, banner);
	buf_putstring(ses.writepayload, "en", 2);

	encrypt_packet();

	TRACE(("leave send_msg_userauth_banner"))
}

/* handle a userauth request, check validity, pass to password or pubkey
 * checking, and handle success or failure */
void recv_msg_userauth_request() {

	char *username = NULL, *servicename = NULL, *methodname = NULL;
	unsigned int userlen, servicelen, methodlen;
	int valid_user = 0;

	TRACE(("enter recv_msg_userauth_request"))

	/* for compensating failure delay */
	gettime_wrapper(&ses.authstate.auth_starttime);

	/* ignore packets if auth is already done */
	if (ses.authstate.authdone == 1) {
		TRACE(("leave recv_msg_userauth_request: authdone already"))
		return;
	}

	/* send the banner if it exists, it will only exist once */
	if (svr_opts.banner) {
		send_msg_userauth_banner(svr_opts.banner);
		buf_free(svr_opts.banner);
		svr_opts.banner = NULL;
	}

	username = buf_getstring(ses.payload, &userlen);
	servicename = buf_getstring(ses.payload, &servicelen);
	methodname = buf_getstring(ses.payload, &methodlen);

	/* only handle 'ssh-connection' currently */
	if (servicelen != SSH_SERVICE_CONNECTION_LEN
			&& (strncmp(servicename, SSH_SERVICE_CONNECTION,
					SSH_SERVICE_CONNECTION_LEN) != 0)) {
		
		/* TODO - disconnect here */
		m_free(username);
		m_free(servicename);
		m_free(methodname);
		sillybear_exit("unknown service in auth");
	}

	/* check username is good before continuing. 
	 * the 'incrfail' varies depending on the auth method to
	 * avoid giving away which users exist on the system through
	 * the time delay. */
	if (checkusername(username, userlen) == SILLYBEAR_SUCCESS) {
		valid_user = 1;
	}

	/* user wants to know what methods are supported */
	if (methodlen == AUTH_METHOD_NONE_LEN &&
			strncmp(methodname, AUTH_METHOD_NONE,
				AUTH_METHOD_NONE_LEN) == 0) {
		TRACE(("recv_msg_userauth_request: 'none' request"))
		if (valid_user
				&& svr_opts.allowblankpass
				&& !svr_opts.noauthpass
				&& !(svr_opts.norootpass && ses.authstate.pw_uid == 0) 
				&& ses.authstate.pw_passwd[0] == '\0') 
		{
			sillybear_log(LOG_NOTICE, 
					"Auth succeeded with blank password for '%s' from %s",
					ses.authstate.pw_name,
					svr_ses.addrstring);
			send_msg_userauth_success();
			goto out;
		}
		else
		{
			/* 'none' has no failure delay */
			send_msg_userauth_failure(0, 0);
			goto out;
		}
	}
	
#if SILLYBEAR_SVR_PASSWORD_AUTH
	if (!svr_opts.noauthpass &&
			!(svr_opts.norootpass && ses.authstate.pw_uid == 0) ) {
		/* user wants to try password auth */
		if (methodlen == AUTH_METHOD_PASSWORD_LEN &&
				strncmp(methodname, AUTH_METHOD_PASSWORD,
					AUTH_METHOD_PASSWORD_LEN) == 0) {
			svr_auth_password(valid_user);
			goto out;
		}
	}
#endif

#if SILLYBEAR_SVR_PAM_AUTH
	if (!svr_opts.noauthpass &&
			!(svr_opts.norootpass && ses.authstate.pw_uid == 0) ) {
		/* user wants to try password auth */
		if (methodlen == AUTH_METHOD_PASSWORD_LEN &&
				strncmp(methodname, AUTH_METHOD_PASSWORD,
					AUTH_METHOD_PASSWORD_LEN) == 0) {
			svr_auth_pam(valid_user);
			goto out;
		}
	}
#endif

#if SILLYBEAR_SVR_PUBKEY_AUTH
	/* user wants to try pubkey auth */
	if (methodlen == AUTH_METHOD_PUBKEY_LEN &&
			strncmp(methodname, AUTH_METHOD_PUBKEY,
				AUTH_METHOD_PUBKEY_LEN) == 0) {
		svr_auth_pubkey(valid_user);
		goto out;
	}
#endif

	/* nothing matched, we just fail with a delay */
	send_msg_userauth_failure(0, 1);

out:

	m_free(username);
	m_free(servicename);
	m_free(methodname);
}

#ifdef HAVE_GETGROUPLIST
/* returns SILLYBEAR_SUCCESS or SILLYBEAR_FAILURE */
static int check_group_membership(gid_t check_gid, const char* username, gid_t user_gid) {
	int ngroups, i, ret;
	gid_t *grouplist = NULL;
	int match = SILLYBEAR_FAILURE;

	for (ngroups = 32; ngroups <= SILLYBEAR_NGROUP_MAX; ngroups *= 2) {
		grouplist = m_malloc(sizeof(gid_t) * ngroups);

		/* BSD returns ret==0 on success. Linux returns ret==ngroups on success */
		ret = getgrouplist(username, user_gid, grouplist, &ngroups);
		if (ret >= 0) {
			break;
		}
		m_free(grouplist);
		grouplist = NULL;
	}

	if (!grouplist) {
		sillybear_log(LOG_ERR, "Too many groups for user '%s'", username);
		return SILLYBEAR_FAILURE;
	}

	for (i = 0; i < ngroups; i++) {
		if (grouplist[i] == check_gid) {
			match = SILLYBEAR_SUCCESS;
			break;
		}
	}
	m_free(grouplist);

	return match;
}
#endif

/* Always use the running user's account for the session.
 * Any client username is accepted for the SSH protocol handshake,
 * but the session (shell, homedir, authorized_keys) always belongs
 * to the user that started the sillybear process.
 * returns SILLYBEAR_SUCCESS on valid username, SILLYBEAR_FAILURE on failure */
static int checkusername(const char *username, unsigned int userlen) {

	struct passwd *pw = NULL;

	TRACE(("enter checkusername"))
	if (userlen > MAX_USERNAME_LEN) {
		return SILLYBEAR_FAILURE;
	}

	if (strlen(username) != userlen) {
		sillybear_exit("Attempted username with a null byte");
	}

	if (ses.authstate.username == NULL) {
		/* Always fill passwd from the running user, not the connecting user */
		pw = getpwuid(getuid());
		if (!pw) {
			sillybear_exit("Failed to get running user info");
		}
		fill_passwd(pw->pw_name);
		ses.authstate.username = m_strdup(username);
	} else {
		/* check username hasn't changed */
		if (strcmp(username, ses.authstate.username) != 0) {
			sillybear_exit("Client trying multiple usernames");
		}
	}

	if (ses.authstate.checkusername_failed) {
		TRACE(("checkusername: returning cached failure"))
		return SILLYBEAR_FAILURE;
	}

	if (!ses.authstate.pw_name) {
		TRACE(("leave checkusername: running user lookup failed"))
		ses.authstate.checkusername_failed = 1;
		return SILLYBEAR_FAILURE;
	}

	TRACE(("uid = %d", ses.authstate.pw_uid))
	TRACE(("leave checkusername"))
	return SILLYBEAR_SUCCESS;
}

/* Send a failure message to the client, in responds to a userauth_request.
 * Partial indicates whether to set the "partial success" flag,
 * incrfail is whether to count this failure in the failure count (which
 * is limited. This function also handles disconnection after too many
 * failures */
void send_msg_userauth_failure(int partial, int incrfail) {

	buffer *typebuf = NULL;

	TRACE(("enter send_msg_userauth_failure"))

	CHECKCLEARTOWRITE();
	
	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_FAILURE);

	/* put a list of allowed types */
	typebuf = buf_new(30); /* long enough for PUBKEY and PASSWORD */

	if (ses.authstate.authtypes & AUTH_TYPE_PUBKEY) {
		buf_putbytes(typebuf, (const unsigned char *)AUTH_METHOD_PUBKEY, AUTH_METHOD_PUBKEY_LEN);
		if (ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
			buf_putbyte(typebuf, ',');
		}
	}
	
	if (ses.authstate.authtypes & AUTH_TYPE_PASSWORD) {
		buf_putbytes(typebuf, (const unsigned char *)AUTH_METHOD_PASSWORD, AUTH_METHOD_PASSWORD_LEN);
	}

	buf_putbufstring(ses.writepayload, typebuf);

	TRACE(("auth fail: methods %d, '%.*s'", ses.authstate.authtypes,
				typebuf->len, typebuf->data))

	buf_free(typebuf);

	buf_putbyte(ses.writepayload, partial ? 1 : 0);
	encrypt_packet();

	if (incrfail) {
		/* The SSH_MSG_AUTH_FAILURE response is delayed to attempt to
		avoid user enumeration and slow brute force attempts.
		The delay is adjusted by the time already spent in processing
		authentication (ses.authstate.auth_starttime timestamp). */

		/* Desired total delay 300ms +-50ms (in nanoseconds).
		Beware of integer overflow if increasing these values */
		const uint32_t mindelay = 250000000;
		const uint32_t vardelay = 100000000;
		uint32_t rand_delay;
		struct timespec delay;

		gettime_wrapper(&delay);
		delay.tv_sec -= ses.authstate.auth_starttime.tv_sec;
		delay.tv_nsec -= ses.authstate.auth_starttime.tv_nsec;

		/* carry */
		if (delay.tv_nsec < 0) {
			delay.tv_nsec += 1000000000;
			delay.tv_sec -= 1;
		}

		genrandom((unsigned char*)&rand_delay, sizeof(rand_delay));
		rand_delay = mindelay + (rand_delay % vardelay);

		if (delay.tv_sec == 0 && delay.tv_nsec <= rand_delay) {
			/* Compensate for elapsed time */
			delay.tv_nsec = rand_delay - delay.tv_nsec;
		} else {
			/* No time left or time went backwards, just delay anyway */
			delay.tv_sec = 0;
			delay.tv_nsec = rand_delay;
		}


#if SILLYBEAR_FUZZ
		if (!fuzz.fuzzing)
#endif
		{
			while (nanosleep(&delay, &delay) == -1 && errno == EINTR) { /* Go back to sleep */ }
		}

		ses.authstate.failcount++;
	}

	if (ses.authstate.failcount > svr_opts.maxauthtries) {
		char * userstr;
		/* XXX - send disconnect ? */
		TRACE(("Max auth tries reached, exiting"))

		if (ses.authstate.pw_name == NULL) {
			userstr = "is invalid";
		} else {
			userstr = ses.authstate.pw_name;
		}
		sillybear_exit("Max auth tries reached - user '%s'",
				userstr);
	}
	
	TRACE(("leave send_msg_userauth_failure"))
}

/* Send a success message to the user, and set the "authdone" flag */
void send_msg_userauth_success() {

	TRACE(("enter send_msg_userauth_success"))

	CHECKCLEARTOWRITE();

	buf_putbyte(ses.writepayload, SSH_MSG_USERAUTH_SUCCESS);
	encrypt_packet();

	/* authdone must be set after encrypt_packet() for 
	 * delayed-zlib mode */
	ses.authstate.authdone = 1;

#if SILLYBEAR_SVR_DROP_PRIVS
	/* Drop privileges as soon as authentication has happened. */
	svr_switch_user();
#endif
	ses.connect_time = 0;


#if SILLYBEAR_SVR_DROP_PRIVS
	/* If running as the user, we can rely on the OS
	 * to limit allowed ports */
	ses.allowprivport = 1;
#else
	if (ses.authstate.pw_uid == 0) {
		ses.allowprivport = 1;
	}
#endif

	/* Remove from the list of pre-auth sockets. Should be m_close(), since if
	 * we fail, we might end up leaking connection slots, and disallow new
	 * logins - a nasty situation. */							
	m_close(svr_ses.childpipe);

	TRACE(("leave send_msg_userauth_success"))

}

#if SILLYBEAR_SVR_DROP_PRIVS
/* Returns SILLYBEAR_SUCCESS or SILLYBEAR_FAILURE */
static int utmp_gid(gid_t *ret_gid) {
	struct group *utmp_gr = getgrnam("utmp");
	if (!utmp_gr) {
		TRACE(("No utmp group"));
		return SILLYBEAR_FAILURE;
	}

	*ret_gid = utmp_gr->gr_gid;
	return SILLYBEAR_SUCCESS;
}
#endif

/* Switch to the ses.authstate user.
 * Fails if not running as root and the user differs.
 *
 * This may be called either after authentication, or 
 * after shell/command fork if SILLYBEAR_SVR_DROP_PRIVS is unset.
 */
void svr_switch_user(void) {
	assert(ses.authstate.authdone);

	/* We can only change uid/gid as root ... */
	if (getuid() == 0) {

		if ((setgid(ses.authstate.pw_gid) < 0) ||
			(initgroups(ses.authstate.pw_name, 
						ses.authstate.pw_gid) < 0)) {
			sillybear_exit("Error changing user group");
		}

#if SILLYBEAR_SVR_DROP_PRIVS
		/* Retain utmp saved group so that wtmp/utmp can be written */
		int ret = utmp_gid(&svr_ses.utmp_gid);
		if (ret == SILLYBEAR_SUCCESS) {
			/* Set saved gid to utmp so that it can be
			 * restored for login_logout() etc. This saved
			 * group is cleared by the OS on execve() */
			int rc = setresgid(-1, -1, svr_ses.utmp_gid);
			if (rc == 0) {
				svr_ses.have_utmp_gid = 1;
			} else {
				/* Will not attempt to switch to utmp gid.
				 * login() etc may fail. */
				TRACE(("utmp setresgid failed"));
			}
		}
#endif

		if (setuid(ses.authstate.pw_uid) < 0) {
			sillybear_exit("Error changing user");
		}
	} else {
		/* ... but if the daemon is the same uid as the requested uid, we don't
		 * need to */

		/* XXX - there is a minor issue here, in that if there are multiple
		 * usernames with the same uid, but differing groups, then the
		 * differing groups won't be set (as with initgroups()). The solution
		 * is for the sysadmin not to give out the UID twice */
		if (getuid() != ses.authstate.pw_uid) {
			sillybear_exit("Couldn't	change user as non-root");
		}
	}
}

void svr_raise_gid_utmp(void) {
#if SILLYBEAR_SVR_DROP_PRIVS
	if (!svr_ses.have_utmp_gid) {
		return;
	}

	if (setegid(svr_ses.utmp_gid) != 0) {
		sillybear_log(LOG_WARNING, "failed setegid");
	}
#endif
}

void svr_restore_gid(void) {
#if SILLYBEAR_SVR_DROP_PRIVS
	if (!svr_ses.have_utmp_gid) {
		return;
	}

	if (setegid(getgid()) != 0) {
		sillybear_log(LOG_WARNING, "failed setegid");
	}
#endif
}
