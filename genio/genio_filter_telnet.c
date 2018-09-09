/*
 *  genio - A library for abstracting stream I/O
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
#include <genio/genio_internal.h>
#include <genio/genio_base.h>
#include <utils/telnet.h>
#include <utils/utils.h>

enum telnet_write_state {
    TELNET_NOT_WRITING,
    TELNET_IN_TN_WRITE,
    TELNET_IN_USER_WRITE
};

struct telnet_filter {
    struct genio_filter filter;

    struct genio_os_funcs *o;
    bool is_client;

    struct genio_lock *lock;

    bool setup_done;
    int in_urgent;

    bool allow_2217;
    bool rfc2217_set;
    struct timeval rfc2217_end_wait;

    const struct genio_telnet_filter_callbacks *telnet_cbs;
    void *handler_data;

    const struct genio_filter_callbacks *filter_cbs;
    void *cb_data;

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
telnet_set_callbacks(struct genio_filter *filter,
		     const struct genio_filter_callbacks *cbs,
		     void *cb_data)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    tfilter->filter_cbs = cbs;
    tfilter->cb_data = cb_data;
}

static bool
telnet_ul_read_pending(struct genio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    bool rv;

    telnet_lock(tfilter);
    rv = tfilter->read_data_len;
    telnet_unlock(tfilter);
    return rv;
}

static bool
telnet_ll_write_pending(struct genio_filter *filter)
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
telnet_ll_read_needed(struct genio_filter *filter)
{
    return false;
}

static int
telnet_check_open_done(struct genio_filter *filter)
{
    return 0;
}

static int
telnet_try_connect(struct genio_filter *filter, struct timeval *timeout)
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
telnet_try_disconnect(struct genio_filter *filter, struct timeval *timeout)
{
    return 0;
}

struct telnet_buffer_data {
    genio_ul_filter_data_handler handler;
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
telnet_ul_write(struct genio_filter *filter,
	     genio_ul_filter_data_handler handler, void *cb_data,
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
telnet_ll_write(struct genio_filter *filter,
	     genio_ll_filter_data_handler handler, void *cb_data,
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
			if (tfilter->telnet_cbs) {
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
	tfilter->read_data_len =
	    process_telnet_data(tfilter->read_data, tfilter->max_read_size,
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
telnet_ll_urgent(struct genio_filter *filter)
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

    if (tfilter->setup_done && tfilter->filter_cbs)
	tfilter->filter_cbs->output_ready(tfilter->cb_data);
}

static void
telnet_cmd_handler(void *cb_data, unsigned char cmd)
{
}

static const struct telnet_cmd telnet_cmds[] = {
    /*                        I will,  I do,  sent will, sent do */
    { TN_OPT_SUPPRESS_GO_AHEAD,	   1,     0,          0,       0, },
    { TN_OPT_ECHO,		   1,     0,          0,       0, },
    { TN_OPT_BINARY_TRANSMISSION,  1,     1,          0,       0, },
    { TN_OPT_COM_PORT,		   1,     0,          1,       0,
      .option_handler = com_port_handler, .will_do_handler = com_port_will_do },
    { TELNET_CMD_END_OPTION }
};

static const unsigned char telnet_init_seq[] = {
    TN_IAC, TN_WILL, TN_OPT_COM_PORT,
};

static int
telnet_setup(struct genio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);
    int err;

    err = telnet_init(&tfilter->tn_data, tfilter, telnet_output_ready,
		      telnet_cmd_handler, telnet_cmds,
		      telnet_init_seq,
		      tfilter->allow_2217 ? sizeof(telnet_init_seq) : 0);
    if (!err) {
	tfilter->rfc2217_set = !tfilter->allow_2217;
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
telnet_filter_cleanup(struct genio_filter *filter)
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
telnet_filter_timeout(struct genio_filter *filter)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    if (tfilter->telnet_cbs && tfilter->telnet_cbs->timeout)
	tfilter->telnet_cbs->timeout(tfilter->handler_data);
}

static void
telnet_free(struct genio_filter *filter)
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

const static struct genio_filter_ops telnet_filter_ops = {
    .set_callbacks = telnet_set_callbacks,
    .ul_read_pending = telnet_ul_read_pending,
    .ll_write_pending = telnet_ll_write_pending,
    .ll_read_needed = telnet_ll_read_needed,
    .check_open_done = telnet_check_open_done,
    .try_connect = telnet_try_connect,
    .try_disconnect = telnet_try_disconnect,
    .ul_write = telnet_ul_write,
    .ll_write = telnet_ll_write,
    .ll_urgent = telnet_ll_urgent,
    .timeout = telnet_filter_timeout,
    .setup = telnet_setup,
    .cleanup = telnet_filter_cleanup,
    .free = telnet_free
};

static void telnet_filter_send_option(struct genio_filter *filter,
				      const unsigned char *buf,
				      unsigned int len)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    telnet_lock(tfilter);
    telnet_send_option(&tfilter->tn_data, buf, len);
    telnet_unlock(tfilter);
}

static void telnet_filter_start_timer(struct genio_filter *filter,
				      struct timeval *timeout)
{
    struct telnet_filter *tfilter = filter_to_telnet(filter);

    tfilter->filter_cbs->start_timer(tfilter->cb_data, timeout);
}

const struct genio_telnet_filter_rops telnet_filter_rops = {
    .send_option = telnet_filter_send_option,
    .start_timer = telnet_filter_start_timer
};

static struct genio_filter *
genio_telnet_filter_raw_alloc(struct genio_os_funcs *o,
			      bool is_client,
			      bool allow_2217,
			      unsigned int max_read_size,
			      unsigned int max_write_size,
			      const struct genio_telnet_filter_callbacks *cbs,
			      void *handler_data,
			      const struct genio_telnet_filter_rops **rops)
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
    tfilter->filter.ops = &telnet_filter_ops;
    tfilter->telnet_cbs = cbs;
    tfilter->handler_data = handler_data;

    return &tfilter->filter;

 out_nomem:
    telnet_free(&tfilter->filter);
    return NULL;
}

int
genio_telnet_server_filter_alloc(struct genio_os_funcs *o,
		 bool allow_rfc2217,
		 unsigned int max_read_size,
		 unsigned int max_write_size,
		 const struct genio_telnet_filter_callbacks *cbs,
		 void *handler_data,
		 const struct genio_telnet_filter_rops **rops,
		 struct genio_filter **rfilter)
{
    struct genio_filter *filter;

    filter = genio_telnet_filter_raw_alloc(o, false, allow_rfc2217,
					   max_read_size, max_write_size,
					   cbs, handler_data, rops);

    if (!filter)
	return ENOMEM;

    *rfilter = filter;
    return 0;
}

int
genio_telnet_filter_alloc(struct genio_os_funcs *o, char *args[],
			  const struct genio_telnet_filter_callbacks *cbs,
			  void *handler_data,
			  const struct genio_telnet_filter_rops **rops,
			  struct genio_filter **rfilter)
{
    struct genio_filter *filter;
    unsigned int i;
    unsigned int max_read_size = 4096; /* FIXME - magic number. */
    unsigned int max_write_size = 4096; /* FIXME - magic number. */
    bool allow_2217;

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
	if (genio_check_keyuint(args[i], "maxwrite", &max_write_size) > 0)
	    continue;
	if (genio_check_keyuint(args[i], "maxread", &max_read_size) > 0)
	    continue;
	return EINVAL;
    }

    filter = genio_telnet_filter_raw_alloc(o, true, allow_2217,
					   max_read_size, max_write_size,
					   cbs, handler_data, rops);

    if (!filter)
	return ENOMEM;

    *rfilter = filter;
    return 0;
}
