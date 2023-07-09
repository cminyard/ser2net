/*
 *  ser2net - A program for allowing telnet connection to serial ports
 *  Copyright (C) 2023  Corey Minyard <minyard@acm.org>
 *
 *  SPDX-License-Identifier: GPL-2.0-only
 *
 *  In addition, as a special exception, the copyright holders of
 *  ser2net give you permission to combine ser2net with free software
 *  programs or libraries that are released under the GNU LGPL and
 *  with code included in the standard release of OpenSSL under the
 *  OpenSSL license (or modified versions of such code, with unchanged
 *  license). You may copy and distribute such a system following the
 *  terms of the GNU GPL for ser2net and the licenses of the other code
 *  concerned, provided that you include the source code of that
 *  other code when and as the GNU GPL requires distribution of source
 *  code.
 *
 *  Note that people who make modified versions of ser2net are not
 *  obligated to grant this special exception for their modified
 *  versions; it is their choice whether to do so. The GNU General
 *  Public License gives permission to release a modified version
 *  without this exception; this exception also makes it possible to
 *  release a modified version which carries forward this exception.
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <errno.h>
#include <string.h>

#include <gensio/gensio.h>

#include "ser2net.h"
#include "fileio.h"

#define READBUF_SIZE 1024

struct ftypes {
    FILE *f;
    char *rbuf;
    unsigned int rpos;
    unsigned int rlen;
};

int
f_open(const char *filename, int iop, int mode, ftype **rf)
{
    ftype *f;
    char *op;
    int oop = 0, rv = 0, fd;

    if (iop & DO_READ && iop & DO_WRITE) {
	oop = O_RDWR;
	op = "r+";
    } else if (iop & DO_READ) {
	oop = O_RDONLY;
	op = "r";
    } else if (iop & DO_WRITE) {
	oop = O_WRONLY;
	op = "w";
    } else {
	/* Must set read or write. */
	return GE_INVAL;
    }
    if (iop & DO_CREATE)
	oop |= O_CREAT;

    f = malloc(sizeof(*f));
    if (!f)
	return GE_NOMEM;
    f->f = NULL;
    f->rbuf = NULL;

    if (iop & DO_READ) {
	f->rbuf = malloc(READBUF_SIZE);
	if (!f->rbuf) {
	    rv = GE_NOMEM;
	    goto out_err;
	}
	f->rpos = 0;
	f->rlen = 0;
    }

    fd = open(filename, oop, mode);
    if (fd == -1) {
	rv = gensio_os_err_to_err(so, errno);
	goto out_err;
    }

    f->f = fdopen(fd, op);
    if (!f->f) {
	close(fd);
	rv = gensio_os_err_to_err(so, errno);
	goto out_err;
    }

    if (iop & DO_APPEND) {
	rv = fseek(f->f, 0, SEEK_END);
	if (rv == -1) {
	    rv = gensio_os_err_to_err(so, errno);
	    goto out_err;
	} else {
	    rv = 0;
	}
    }

 out_err:
    if (rv) {
	if (f->rbuf)
	    free(f->rbuf);
	free(f);
    } else {
	*rf = f;
    }
	
    return rv;
}

int
f_stdio_open(FILE *stdf, int op, int mode, ftype **rf)
{
    ftype *f = malloc(sizeof(*f));

    if (!f)
	return GE_NOMEM;
    if (op & DO_READ) {
	f->rbuf = malloc(READBUF_SIZE);
	if (!f->rbuf) {
	    free(f);
	    return GE_NOMEM;
	}
	f->rpos = 0;
	f->rlen = 0;
    }

    f->f = stdf;
    *rf = f;
    return 0;
}

int
f_close(ftype *f)
{
    fclose(f->f);
    if (f->rbuf)
	free(f->rbuf);
    free(f);
    return 0;
}

int
f_write(ftype *f, const void *buf, unsigned int len, unsigned int *outlen)
{
    int rv = 0;

    if (len > 0) {
	rv = fwrite(buf, 1, len, f->f);
	if (rv == 0)
	    return gensio_os_err_to_err(so, errno);
	/*
	 * This is primarily used for tracing, so flush on every write.
	 */
	fflush(f->f);
    }
    if (outlen)
	*outlen = rv;
    return 0;
}

int
f_read(ftype *f, void *ibuf, unsigned int len, unsigned int *routlen)
{
    char *buf = ibuf;
    unsigned int clen;
    unsigned int outlen = 0;
    int rv = 0, rc;

    if (!f->rbuf)
	return GE_NOTSUP;

    while (len > 0) {
	if (f->rlen > 0) {
	    clen = len;
	    if (len > f->rlen)
		clen = f->rlen;
	    memcpy(buf, f->rbuf + f->rpos, clen);
	    f->rlen -= clen;
	    f->rpos += clen;
	    len -= clen;
	    buf += clen;
	    outlen += clen;
	    continue;
	}

	rc = fread(f->rbuf, 1, READBUF_SIZE, f->f);
	if (rc == 0) {
	    if (feof(f->f)) {
		if (outlen == 0)
		    rv = GE_REMCLOSE;
	    } else {
		rv = gensio_os_err_to_err(so, errno);
	    }
	    break;
	}
	f->rlen = rc;
	f->rpos = 0;
    }

    if (!rv && routlen)
	*routlen = outlen;

    return rv;
}

int
f_gets(ftype *f, char **ibuf, unsigned int *ilen, unsigned int *ibuflen)
{
    int rv = 0, rc;
    unsigned int len = *ilen, buflen = *ibuflen;
    char *buf = *ibuf, *newbuf = NULL;

    if (!f->rbuf)
	return GE_NOTSUP;

    if (len > buflen)
	return GE_INVAL;

    do {
	while (f->rlen > 0) {
	    /* Do this first so we have room for a '\0'. */
	    if (len == buflen) {
		newbuf = realloc(buf, buflen + 256);
		if (!newbuf) {
		    rv = GE_NOMEM;
		    goto out_err;
		}
		buf = newbuf;
		*ibuf = newbuf;
		buflen += 256;
		*ibuflen = buflen;
	    }
	    if (f->rbuf[f->rpos] == '\n') {
		f->rpos++;
		f->rlen--;
		goto found;
	    }
	    buf[len++] = f->rbuf[f->rpos++];
	    f->rlen--;
	}

	rc = fread(f->rbuf, 1, READBUF_SIZE, f->f);
	if (rc == 0) {
	    if (feof(f->f)) {
		if (len == *ilen)
		    rv = GE_REMCLOSE;
	    } else {
		rv = gensio_os_err_to_err(so, errno);
		goto out_err;
	    }
	    break;
	}
	f->rlen = rc;
	f->rpos = 0;
    } while(1);

 found:
    /*
     * This is safe without a check, we checked for room before
     * looking for the '\n'.
     */
    buf[len] = '\0';
    *ilen = len;

 out_err:
    return rv;
}

int
f_seek(ftype *f, unsigned int pos, int op)
{
    int rv;

    if (op != SEEK_ABSOLUTE)
	return GE_INVAL;

    rv = fseek(f->f, pos, SEEK_SET);
    if (rv == -1) {
	rv = gensio_os_err_to_err(so, errno);
    } else {
	f->rlen = 0;
	rv = 0;
    }
    return rv;
}
