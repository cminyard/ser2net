/*
 *  gensio - A library for abstracting stream I/O
 *  Copyright (C) 2018  Corey Minyard <minyard@acm.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <errno.h>
#include <string.h>

#include <utils/telnet.h>
#include <utils/utils.h>

#include <gensio/gensio_class.h>
#include <gensio/gensio_filter_telnet.h>

enum telnet_write_state {
    TELNET_NOT_WRITING,
    TELNET_IN_TN_WRITE,
    TELNET_IN_USER_WRITE
};

struct telnet_filter {
    struct gensio_filter filter;

    struct gensio_os_funcs *o;
    bool is_client;

    struct gensio_lock *lock;

    bool setup_done;
    int in_urgent;

    const struct telnet_cmd *telnet_cmds;
    const unsigned char *telnet_init_seq;
    unsigned int telnet_init_seq_len;

    bool allow_2217;
    bool rfc2217_set;
    struct timeval rfc2217_end_wait;

    const struct gensio_telnet_filter_callbacks *telnet_cbs;
    void *handler_data;

    gensio_filter_cb filter_cb;
    void *filter_cb_data;

    /*
     * To avoid problems with splitting TN_IACs, we do not split up
     * telnet chunks or user chunks.  We use this to mark what we
     * are doing.
     */
    enum telnet_write_state write_state;

    struct telnet_data_s tn_data;

    /* Data waiting to be delivered to the user. */
    unsigned char *read_data;
    unsigned int max_read_size;
    unsigned int read_data_pos;
    unsigned int read_data_len;

    /* Data waiting to be written. */
    unsigned char *write_data;
    unsigned int max_write_size;
    unsigned int write_data_pos;
    unsigned int write_data_len;
};

#define filter_to_telnet(v) container_of(v, struct telnet_filter, filter)

static void
telnet_lock(struct telnet_filter *tfilter)
{
    tfilter->o->lock(tfilter->lock);
}

static void
telnet_unlock(struct telnet_filter *tfilter)
{
    tfilter->o->unlock(tfilter->lock);
}

static void
telnet_set_callbacks(struct gensio_filter *filter,
		     gensio_filter_cb cb, void *cb_data)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    tfilter->filter_cb = cb;
    tfilter->filter_cb_data = cb_data;
}

static bool
telnet_ul_read_pending(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    bool rv;

    telnet_lock(tfilter);
    rv = tfilter->read_data_len;
    telnet_unlock(tfilter);
    return rv;
}

static bool
telnet_ll_write_pending(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    bool rv;

    telnet_lock(tfilter);
    rv = tfilter->write_data_len ||
	buffer_cursize(&tfilter->tn_data.out_telnet_cmd);
    telnet_unlock(tfilter);
    return rv;
}

static bool
telnet_ll_read_needed(struct gensio_filter *filter)
{
    return false;
}

static int
telnet_check_open_done(struct gensio_filter *filter)
{
    return 0;
}

static int
telnet_try_connect(struct gensio_filter *filter, struct timeval *timeout)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    struct timeval now;

    if (tfilter->rfc2217_set)
	return 0;

    tfilter->o->get_monotonic_time(tfilter->o, &now);
    if (cmp_timeval(&now, &tfilter->rfc2217_end_wait) > 0) {
	tfilter->rfc2217_set = true;
	return 0;
    }

    timeout->tv_sec = 0;
    timeout->tv_usec = 500000;
    return EAGAIN;
}

static int
telnet_try_disconnect(struct gensio_filter *filter, struct timeval *timeout)
{
    return 0;
}

struct telnet_buffer_data {
    gensio_ul_filter_data_handler handler;
    void *cb_data;
};

static int
telnet_buffer_do_write(void *cb_data, void *buf, size_t buflen,
		       size_t *written)
{
    struct telnet_buffer_data *data = cb_data;
    unsigned int count;
    int err;

    err = data->handler(data->cb_data, &count, buf, buflen);
    if (!err)
	*written = count;
    return err;
}

static int
telnet_ul_write(struct gensio_filter *filter,
		gensio_ul_filter_data_handler handler, void *cb_data,
		unsigned int *rcount,
		const unsigned char *buf, unsigned int buflen)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    int err = 0;

    telnet_lock(tfilter);
    if (tfilter->write_data_len || buflen == 0) {
	if (rcount)
	    *rcount = 0;
    } else {
	unsigned int inlen = buflen;

	tfilter->write_data_len =
	    process_telnet_xmit(tfilter->write_data, tfilter->max_write_size,
				&buf, &inlen);
	*rcount = buflen - inlen;
    }

    if (tfilter->write_state != TELNET_IN_USER_WRITE &&
		buffer_cursize(&tfilter->tn_data.out_telnet_cmd)) {
	struct telnet_buffer_data data = { handler, cb_data };
	int buferr;

	if (buffer_write(telnet_buffer_do_write, &data,
			 &tfilter->tn_data.out_telnet_cmd, &buferr))
	    err = buferr;
	else if (buffer_cursize(&tfilter->tn_data.out_telnet_cmd))
	    tfilter->write_state = TELNET_IN_TN_WRITE;
	else
	    tfilter->write_state = TELNET_NOT_WRITING;
    }

    if (tfilter->write_state != TELNET_IN_TN_WRITE &&
		tfilter->write_data_len) {
	unsigned int count = 0;

	err = handler(cb_data, &count,
		      tfilter->write_data + tfilter->write_data_pos,
		      tfilter->write_data_len);
	if (!err) {
	    if (count >= tfilter->write_data_len) {
		tfilter->write_state = TELNET_NOT_WRITING;
		tfilter->write_data_len = 0;
		tfilter->write_data_pos = 0;
	    } else {
		tfilter->write_state = TELNET_IN_USER_WRITE;
		tfilter->write_data_len -= count;
		tfilter->write_data_pos += count;
	    }
	}
    }
    telnet_unlock(tfilter);

    return err;
}

static int
telnet_ll_write(struct gensio_filter *filter,
		gensio_ll_filter_data_handler handler, void *cb_data,
		unsigned int *rcount,
		unsigned char *buf, unsigned int buflen)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    int err = 0;

    telnet_lock(tfilter);
    if (tfilter->read_data_pos || buflen == 0) {
	if (rcount)
	    *rcount = 0;
    } else {
	unsigned int inlen = buflen;

	if (tfilter->in_urgent) {
	    /* We are in urgent data, just read until we get a mark. */
	    for (; inlen > 0; inlen--, buf++) {
		if (tfilter->in_urgent == 2) {
		    if (*buf == TN_DATA_MARK) {
			/* Found it. */
			tfilter->in_urgent = 0;
			if (tfilter->telnet_cbs &&
				    tfilter->telnet_cbs->got_sync) {
			    telnet_unlock(tfilter);
			    tfilter->telnet_cbs->got_sync
				(tfilter->handler_data);
			    telnet_lock(tfilter);
			}
			break;
		    }
		    tfilter->in_urgent = 1;
		} else if (*buf == TN_IAC) {
		    tfilter->in_urgent = 2;
		}
	    }
	}

	/*
	 * Process the telnet receive data unlocked.  It can do callbacks to
	 * the users, and we are guaranteed to be single-threaded in the
	 * data handling here.
	 */
	telnet_unlock(tfilter);
	tfilter->read_data_len +=
	    process_telnet_data(tfilter->read_data + tfilter->read_data_len,
				tfilter->max_read_size - tfilter->read_data_len,
				&buf, &inlen, &tfilter->tn_data);
	telnet_lock(tfilter);
	*rcount = buflen - inlen;
    }

    if (tfilter->read_data_len) {
	unsigned int count = 0;

	telnet_unlock(tfilter);
	err = handler(cb_data, &count,
		      tfilter->read_data + tfilter->read_data_pos,
		      tfilter->read_data_len);
	telnet_lock(tfilter);
	if (!err) {
	    if (count >= tfilter->read_data_len) {
		tfilter->read_data_len = 0;
		tfilter->read_data_pos = 0;
	    } else {
		tfilter->read_data_len -= count;
		tfilter->read_data_pos += count;
	    }
	}
    }
    telnet_unlock(tfilter);

    return err;
}

static void
telnet_ll_urgent(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    tfilter->in_urgent = 1;
}

static int
com_port_will_do(void *cb_data, unsigned char cmd)
{
    struct telnet_filter *tfilter = cb_data;
    int err = 0;

    if (tfilter->telnet_cbs)
	err = tfilter->telnet_cbs->com_port_will_do(tfilter->handler_data, cmd);
    tfilter->rfc2217_set = true;
    return err;
}

static void
com_port_handler(void *cb_data, unsigned char *option, int len)
{
    struct telnet_filter *tfilter = cb_data;

    if (tfilter->telnet_cbs)
	return tfilter->telnet_cbs->com_port_cmd(tfilter->handler_data,
						 option, len);
}

static void
telnet_output_ready(void *cb_data)
{
    struct telnet_filter *tfilter = cb_data;

    if (tfilter->setup_done && tfilter->filter_cb)
	tfilter->filter_cb(tfilter->filter_cb_data,
			   GENSIO_FILTER_CB_OUTPUT_READY, NULL);
}

static void
telnet_cmd_handler(void *cb_data, unsigned char cmd)
{
    struct telnet_filter *tfilter = cb_data;

    if (tfilter->telnet_cbs && tfilter->telnet_cbs->got_cmd)
	tfilter->telnet_cbs->got_cmd(tfilter->handler_data, cmd);
}

static int
telnet_setup(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    int err;

    err = telnet_init(&tfilter->tn_data, tfilter, telnet_output_ready,
		      telnet_cmd_handler, tfilter->telnet_cmds,
		      tfilter->telnet_init_seq, tfilter->telnet_init_seq_len);
    if (tfilter->is_client)
	tfilter->rfc2217_set = !tfilter->allow_2217;
    else
	tfilter->rfc2217_set = true; /* Don't wait for this on the server. */
    if (!err && !tfilter->rfc2217_set) {
	tfilter->o->get_monotonic_time(tfilter->o,
				       &tfilter->rfc2217_end_wait);
	tfilter->rfc2217_end_wait.tv_sec += 4; /* FIXME - magic number */
	tfilter->setup_done = true;
	if (buffer_cursize(&tfilter->tn_data.out_telnet_cmd))
	    tfilter->write_state = TELNET_IN_TN_WRITE;
	else
	    tfilter->write_state = TELNET_NOT_WRITING;
    }
    return err;
}

static void
telnet_filter_cleanup(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    tfilter->setup_done = false;
    tfilter->in_urgent = 0;
    tfilter->read_data_len = 0;
    tfilter->read_data_pos = 0;
    tfilter->write_data_len = 0;
    tfilter->write_data_pos = 0;
    telnet_cleanup(&tfilter->tn_data);
}

static void
telnet_filter_timeout(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    if (tfilter->telnet_cbs && tfilter->telnet_cbs->timeout)
	tfilter->telnet_cbs->timeout(tfilter->handler_data);
}

static void
telnet_free(struct gensio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    if (tfilter->lock)
	tfilter->o->free_lock(tfilter->lock);
    if (tfilter->read_data)
	tfilter->o->free(tfilter->o, tfilter->read_data);
    if (tfilter->write_data)
	tfilter->o->free(tfilter->o, tfilter->write_data);
    if (tfilter->telnet_cbs)
	tfilter->telnet_cbs->free(tfilter->handler_data);
    telnet_cleanup(&tfilter->tn_data);
    tfilter->o->free(tfilter->o, tfilter);
}

static int gensio_telnet_filter_func(struct gensio_filter *filter, int op,
				  const void *func, void *data,
				  unsigned int *count,
				  void *buf, const void *cbuf,
				  unsigned int buflen)
{
    switch (op) {
    case GENSIO_FILTER_FUNC_SET_CALLBACK:
	telnet_set_callbacks(filter, func, data);
	return 0;

    case GENSIO_FILTER_FUNC_UL_READ_PENDING:
	return telnet_ul_read_pending(filter);

    case GENSIO_FILTER_FUNC_UL_WRITE_PENDING:
	return telnet_ll_write_pending(filter);

    case GENSIO_FILTER_FUNC_LL_READ_NEEDED:
	return telnet_ll_read_needed(filter);

    case GENSIO_FILTER_FUNC_CHECK_OPEN_DONE:
	return telnet_check_open_done(filter);

    case GENSIO_FILTER_FUNC_TRY_CONNECT:
	return telnet_try_connect(filter, data);

    case GENSIO_FILTER_FUNC_TRY_DISCONNECT:
	return telnet_try_disconnect(filter, data);

    case GENSIO_FILTER_FUNC_UL_WRITE:
	return telnet_ul_write(filter, func, data, count, cbuf, buflen);

    case GENSIO_FILTER_FUNC_LL_WRITE:
	return telnet_ll_write(filter, func, data, count, buf, buflen);

    case GENSIO_FILTER_FUNC_LL_URGENT:
	telnet_ll_urgent(filter);
	return 0;

    case GENSIO_FILTER_FUNC_SETUP:
	return telnet_setup(filter);

    case GENSIO_FILTER_FUNC_CLEANUP:
	telnet_filter_cleanup(filter);
	return 0;

    case GENSIO_FILTER_FUNC_FREE:
	telnet_free(filter);
	return 0;

    case GENSIO_FILTER_FUNC_TIMEOUT:
	telnet_filter_timeout(filter);
	return 0;

    default:
	return ENOTSUP;
    }
}

static void telnet_filter_send_option(struct gensio_filter *filter,
				      const unsigned char *buf,
				      unsigned int len)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    telnet_lock(tfilter);
    telnet_send_option(&tfilter->tn_data, buf, len);
    telnet_unlock(tfilter);
}

static void telnet_filter_start_timer(struct gensio_filter *filter,
				      struct timeval *timeout)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    tfilter->filter_cb(tfilter->filter_cb_data,
		       GENSIO_FILTER_CB_START_TIMER, timeout);
}

const struct gensio_telnet_filter_rops telnet_filter_rops = {
    .send_option = telnet_filter_send_option,
    .start_timer = telnet_filter_start_timer
};

static struct gensio_filter *
gensio_telnet_filter_raw_alloc(struct gensio_os_funcs *o,
			       bool is_client,
			       bool allow_2217,
			       unsigned int max_read_size,
			       unsigned int max_write_size,
			       const struct gensio_telnet_filter_callbacks *cbs,
			       void *handler_data,
			       const struct telnet_cmd *telnet_cmds,
			       const unsigned char *telnet_init_seq,
			       unsigned int telnet_init_seq_len,
			       const struct gensio_telnet_filter_rops **rops)
{
    struct telnet_filter *tfilter;

    tfilter = o->zalloc(o, sizeof(*tfilter));
    if (!tfilter)
	return NULL;

    tfilter->o = o;
    tfilter->is_client = is_client;
    tfilter->allow_2217 = allow_2217;
    tfilter->max_write_size = max_write_size;
    tfilter->max_read_size = max_read_size;
    tfilter->telnet_cmds = telnet_cmds;
    tfilter->telnet_init_seq = telnet_init_seq;
    tfilter->telnet_init_seq_len = telnet_init_seq_len;

    tfilter->lock = o->alloc_lock(o);
    if (!tfilter->lock)
	goto out_nomem;

    tfilter->read_data = o->zalloc(o, max_read_size);
    if (!tfilter->read_data)
	goto out_nomem;

    tfilter->write_data = o->zalloc(o, max_write_size);
    if (!tfilter->read_data)
	goto out_nomem;

    *rops = &telnet_filter_rops;
    tfilter->filter.func = gensio_telnet_filter_func;
    tfilter->telnet_cbs = cbs;
    tfilter->handler_data = handler_data;

    return &tfilter->filter;

 out_nomem:
    telnet_free(&tfilter->filter);
    return NULL;
}

static struct telnet_cmd telnet_server_cmds_2217[] =
{
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   0,     1,          1,       0, },
    { TN_OPT_ECHO,		   0,     1,          1,       1, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          1,       1, },
    { TN_OPT_COM_PORT,		   1,     0,          0,       1,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};

static struct telnet_cmd telnet_server_cmds[] =
{
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   0,     1,          1,       0, },
    { TN_OPT_ECHO,		   0,     1,          1,       1, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          1,       1, },
    { TN_OPT_COM_PORT,		   0,     0,          0,       0,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};

static unsigned char telnet_server_init_seq_2217[] = {
    TN_IAC, TN_WILL, TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_WILL, TN_OPT_ECHO,
    TN_IAC, TN_DONT, TN_OPT_ECHO,
    TN_IAC, TN_DO,   TN_OPT_BINARY_TRANSMISSION,
    TN_IAC, TN_WILL, TN_OPT_BINARY_TRANSMISSION,
    TN_IAC, TN_DO,   TN_OPT_COM_PORT,
};

static unsigned char telnet_server_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_SUPPRESS_GO_AHEAD,
    TN_IAC, TN_WILL, TN_OPT_ECHO,
    TN_IAC, TN_DONT, TN_OPT_ECHO,
    TN_IAC, TN_DO,   TN_OPT_BINARY_TRANSMISSION,
    TN_IAC, TN_WILL, TN_OPT_BINARY_TRANSMISSION,
};

int
gensio_telnet_server_filter_alloc(struct gensio_os_funcs *o,
		 bool allow_rfc2217,
		 unsigned int max_read_size,
		 unsigned int max_write_size,
		 const struct gensio_telnet_filter_callbacks *cbs,
		 void *handler_data,
		 const struct gensio_telnet_filter_rops **rops,
		 struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    const struct telnet_cmd *telnet_cmds;
    unsigned char *init_seq;
    unsigned int init_seq_len;

    if (allow_rfc2217) {
	telnet_cmds = telnet_server_cmds_2217;
	init_seq_len = sizeof(telnet_server_init_seq_2217);
	init_seq = telnet_server_init_seq_2217;
    } else {
	telnet_cmds = telnet_server_cmds;
	init_seq_len = sizeof(telnet_server_init_seq);
	init_seq = telnet_server_init_seq;
    }

    filter = gensio_telnet_filter_raw_alloc(o, false, allow_rfc2217,
					    max_read_size, max_write_size,
					    cbs, handler_data,
					    telnet_cmds,
					    init_seq, init_seq_len, rops);

    if (!filter)
	return ENOMEM;

    *rfilter = filter;
    return 0;
}

static const struct telnet_cmd telnet_client_cmds[] = {
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   1,     0,          0,       0, },
    { TN_OPT_ECHO,		   1,     0,          0,       0, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       0, },
    { TN_OPT_COM_PORT,		   1,     0,          1,       0,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};

static const unsigned char telnet_client_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_COM_PORT,
};

int
gensio_telnet_filter_alloc(struct gensio_os_funcs *o, char *args[],
			   const struct gensio_telnet_filter_callbacks *cbs,
			   void *handler_data,
			   const struct gensio_telnet_filter_rops **rops,
			   struct gensio_filter **rfilter)
{
    struct gensio_filter *filter;
    unsigned int i;
    unsigned int max_read_size = 4096; /* FIXME - magic number. */
    unsigned int max_write_size = 4096; /* FIXME - magic number. */
    bool allow_2217 = true;
    unsigned int init_seq_len;

    for (i = 0; args[i]; i++) {
	const char *val;

	if (cmpstrval(args[i], "rfc2217=", &val)) {
	    if ((strcmp(val, "true") == 0) || (strcmp(val, "1") == 0))
		allow_2217 = true;
	    else if ((strcmp(val, "false") == 0) || (strcmp(val, "0") == 0))
		allow_2217 = false;
	    else
		return EINVAL;
	    continue;
	}
	if (gensio_check_keyuint(args[i], "writebuf", &max_write_size) > 0)
	    continue;
	if (gensio_check_keyuint(args[i], "readbuf", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    init_seq_len = (allow_2217 ? sizeof(telnet_client_init_seq) : 0);

    filter = gensio_telnet_filter_raw_alloc(o, true, allow_2217,
					    max_read_size, max_write_size,
					    cbs, handler_data,
					    telnet_client_cmds,
					    telnet_client_init_seq,
					    init_seq_len,
					    rops);

    if (!filter)
	return ENOMEM;

    *rfilter = filter;
    return 0;
}
