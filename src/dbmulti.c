/*
 * Sillybear SSH
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

#include "includes.h"
#include "dbutil.h"

static int runprog(const char *multipath,
		const char *progname, int argc, char ** argv, int *match) {
	*match = SILLYBEAR_SUCCESS;

#ifdef DBMULTI_sillybear
		if (strcmp(progname, "sillybear") == 0) {
			return sillybear_main(argc, argv, multipath);
		}
#endif
#ifdef DBMULTI_dbclient
		if (strcmp(progname, "dbclient") == 0
				|| strcmp(progname, "ssh") == 0) {
			return cli_main(argc, argv);
		}
#endif
#ifdef DBMULTI_sillybearkey
		if (strcmp(progname, "sillybearkey") == 0
				|| strcmp(progname, "ssh-keygen") == 0) {
			return sillybearkey_main(argc, argv);
		}
#endif
#ifdef DBMULTI_sillybearconvert
		if (strcmp(progname, "sillybearconvert") == 0) {
			return sillybearconvert_main(argc, argv);
		}
#endif
#ifdef DBMULTI_scp
		if (strcmp(progname, "scp") == 0) {
			return scp_main(argc, argv);
		}
#endif
	*match = SILLYBEAR_FAILURE;
	return 1;
}

int main(int argc, char ** argv) {
	int i;
	for (i = 0; i < 2; i++) {
		const char* multipath = NULL;
		if (i == 1) {
			multipath = argv[0];
		}
		/* Try symlink first, then try as an argument eg "sillybearmulti dbclient host ..." */
		if (argc > i) {
			int match, res;
			/* figure which form we're being called as */
			const char* progname = basename(argv[i]);
			res = runprog(multipath, progname, argc-i, &argv[i], &match);
			if (match == SILLYBEAR_SUCCESS) {
				return res;
			}
		}
	}

	fprintf(stderr, "Sillybear SSH multi-purpose v%s\n"
			"Make a symlink pointing at this binary with one of the\n"
			"following names or run 'sillybearmulti <command>'.\n"
#ifdef DBMULTI_sillybear
			"'sillybear' - the Sillybear server\n"
#endif
#ifdef DBMULTI_dbclient
			"'dbclient' or 'ssh' - the Sillybear client\n"
#endif
#ifdef DBMULTI_sillybearkey
			"'sillybearkey' or 'ssh-keygen' - the key generator\n"
#endif
#ifdef DBMULTI_sillybearconvert
			"'sillybearconvert' - the key converter\n"
#endif
#ifdef DBMULTI_scp
			"'scp' - secure copy\n"
#endif
			,
			SILLYBEAR_VERSION);
	exit(1);

}
