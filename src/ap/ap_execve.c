/* ====================================================================
 * Copyright (c) 1995-1998 The Apache Group.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * 4. The names "Apache Server" and "Apache Group" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    apache@apache.org.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the Apache Group
 *    for use in the Apache HTTP server project (http://www.apache.org/)."
 *
 * THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Group and was originally based
 * on public domain software written at the National Center for
 * Supercomputing Applications, University of Illinois, Urbana-Champaign.
 * For more information on the Apache Group and the Apache HTTP server
 * project, please see <http://www.apache.org/>.
 *
 */

#include "httpd.h"
#include "http_log.h"

/*---------------------------------------------------------------*/

#ifdef NEED_HASHBANG_EMUL

#undef execle
#undef execve

static const char **hashbang(const char *filename, char **argv);


/* Historically, a list of arguments on the stack was often treated as
 * being equivalent to an array (since they already were "contiguous"
 * on the stack, and the arguments were pushed in the correct order).
 * On today's processors, this is not necessarily equivalent, because
 * often arguments are padded or passed partially in registers,
 * or the stack direction is backwards.
 * To be on the safe side, we copy the argument list to our own
 * local argv[] array. The va_arg logic makes sure we do the right thing.
 * XXX: malloc() is used because we expect to be overlaid soon.
 */
int ap_execle(const char *filename, const char *arg,...)
{
    va_list adummy;
    char **envp;
    char **argv;
    int argc, ret;

    /* First pass: Count arguments on stack */
    va_start(adummy, arg);
    for (argc = 0; va_arg(adummy, char *) != NULL; ++argc)
	continue;
    va_end(adummy);

    argv = (char **) malloc((argc + 2) * sizeof(*argv));

    /* Pass two --- copy the argument strings into the result space */
    va_start(adummy, arg);
    for (argc = 0; (argv[argc] = va_arg(adummy, char *)) != NULL; ++argc)
	continue;
    envp = va_arg(adummy, char **);
    va_end(adummy);

    ret = ap_execve(filename, argv, envp);
    free(argv);

    return ret;
}

int ap_execve(const char *filename, const char *argv[],
		    const char *envp[])
{
    const char *argv0 = argv[0];
    extern char **environ;

    if (envp == NULL)
	envp = (const char **) environ;

    /* Try to execute the file directly first: */
    execve(filename, argv, envp);

    /* Still with us? Then something went seriously wrong.
     * From the (linux) man page:
     * EACCES The file is not a regular file.
     * EACCES Execute permission is denied for the file.
     * EACCES Search  permission  is denied on a component of the path prefix.
     * EPERM  The file system is mounted noexec.
     * EPERM  The file system is mounted nosuid and the file  has an SUID or SGID bit set.
     * E2BIG  The argument list is too big.
     * ENOEXEC The magic number in the file is incorrect.
     * EFAULT filename  points  outside  your  accessible address space.
     * ENAMETOOLONG filename is too long.
     * ENOENT The file does not exist.
     * ENOMEM Insufficient kernel memory was available.
     * ENOTDIR A component of the path prefix is not a  directory.
     * ELOOP  filename contains a circular reference (i.e., via a symbolic link)
     */

    if (errno == ENOEXEC
    /* Probably a script.
     * Have a look; if there's a "#!" header then try to emulate
     * the feature found in all modern OS's:
     * Interpret the line following the #! as a command line
     * in shell style.
     */
	&& (argv = hashbang(filename, argv)) != NULL) {

        aplog_error(APLOG_MARK, APLOG_NOERRNO|APLOG_DEBUG, NULL,
                        "Script %s needs interpreter %s to exec", filename, argv[0]);

	/* new filename is the interpreter to call */
	filename = argv[0];

	/* Restore argv[0] as on entry */
	if (argv0 != NULL)
	    argv[0] = argv0;

	execve(filename, argv, envp);

	free(argv);
    }
    return -1;
}

/*---------------------------------------------------------------*/

/*
 * From: peter@zeus.dialix.oz.au (Peter Wemm)
 * (taken from tcsh)
 * If exec() fails look first for a #! [word] [word] ....
 * If it is, splice the header into the argument list and retry.
 * Return value: the original argv array (sans argv[0]), with the
 * script's argument list prepended.
 * XXX: malloc() is used so that everything can be free()ed after a failure.
 */
#define HACKBUFSZ 1024		/* Max chars in #! vector */
#define HACKVECSZ 128		/* Max words in #! vector */
static const char **hashbang(const char *filename, char **argv)
{
    char lbuf[HACKBUFSZ];
    char *sargv[HACKVECSZ];
    const char **newargv;
    char *p, *ws;
    int fd;
    int sargc = 0;
    int i, j;
#ifdef WIN32
    int fw = 0;			/* found at least one word */
    int first_word = 0;
#endif /* WIN32 */

    if ((fd = open(filename, O_RDONLY)) == -1)
	return NULL;

    if (read(fd, (char *) lbuf, 2) != 2
	|| lbuf[0] != '#' || lbuf[1] != '!'
	|| read(fd, (char *) lbuf, HACKBUFSZ) <= 0) {
	close(fd);
	return NULL;
    }

    close(fd);

    ws = NULL;			/* word started = 0 */

    for (p = lbuf; p < &lbuf[HACKBUFSZ];)
	switch (*p) {
	case ' ':
	case '\t':
#ifdef NEW_CRLF
	case '\r':
#endif /*NEW_CRLF */
	    if (ws) {		/* a blank after a word.. save it */
		*p = '\0';
#ifndef WIN32
		if (sargc < HACKVECSZ - 1)
		    sargv[sargc++] = ws;
		ws = NULL;
#else /* WIN32 */
		if (sargc < HACKVECSZ - 1) {
		    sargv[sargc] = first_word ? NULL : hb_subst(ws);
		    if (sargv[sargc] == NULL)
			sargv[sargc] = ws;
		    sargc++;
		}
		ws = NULL;
		fw = 1;
		first_word = 1;
#endif /* WIN32 */
	    }
	    p++;
	    continue;

	case '\0':		/* Whoa!! what the hell happened */
	    return NULL;

	case '\n':		/* The end of the line. */
	    if (
#ifdef WIN32
		   fw ||
#endif /* WIN32 */
		   ws) {	/* terminate the last word */
		*p = '\0';
#ifndef WIN32
		if (sargc < HACKVECSZ - 1)
		    sargv[sargc++] = ws;
#else /* WIN32 */
		if (sargc < HACKVECSZ - 1) {	/* deal with the 1-word case */
		    sargv[sargc] = first_word ? NULL : hb_subst(ws);
		    if (sargv[sargc] == NULL)
			sargv[sargc] = ws;
		    sargc++;
		}
#endif /* !WIN32 */
		sargv[sargc] = NULL;
	    }
	    /* Count number of entries in the old argv vector */
	    for (i = 0; argv[i] != NULL; ++i)
		continue;
	    ++i;

	    newargv = (char **) malloc((p - lbuf + 1) + (i + sargc + 1) * sizeof(*newargv));
	    ws = &((char *) newargv)[(i + sargc + 1) * sizeof(*newargv)];

	    /* Copy entries to allocated memory */
	    for (j = 0; j < sargc; ++j) {
		newargv[j] = strcpy(ws, sargv[j]);
		ws += strlen(ws) + 1;	/* skip trailing '\0' */
	    }
	    newargv[sargc] = filename;

	    /* Append the old array. The old argv[0] is skipped. */
	    if (i > 1)
		memcpy(&newargv[sargc + 1], &argv[1], (i - 1) * sizeof(*newargv));
	    newargv[sargc + i] = NULL;

	    ws = NULL;

	    return newargv;

	default:
	    if (!ws)		/* Start a new word? */
		ws = p;
	    p++;
	    break;
	}
    return NULL;
}
#else
void ap_execve_is_not_here(void) {}
#endif /* NEED_HASHBANG_EMUL */
