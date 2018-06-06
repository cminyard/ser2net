
#include <errno.h>

#include <stdlib.h>
#include "netio.h"
#include "netio_internal.h"
#include "utils.h"

void
netio_set_callbacks(struct netio *net,
		    const struct netio_callbacks *cbs, void *user_data)
{
    net->cbs = cbs;
    net->user_data = user_data;
}

void *
netio_get_user_data(struct netio *net)
{
    return net->user_data;
}

void
netio_set_user_data(struct netio *net, void *user_data)
{
    net->user_data = user_data;
}

int netio_write(struct netio *net, int *count,
		const void *buf, unsigned int buflen)
{
    return net->funcs->write(net, count, buf, buflen);
}

int netio_raddr_to_str(struct netio *net, int *pos,
		       char *buf, unsigned int buflen)
{
    return net->funcs->raddr_to_str(net, pos, buf, buflen);
}

void netio_close(struct netio *net)
{
    net->funcs->close(net);
}

void netio_set_read_callback_enable(struct netio *net, bool enabled)
{
    net->funcs->set_read_callback_enable(net, enabled);
}

void netio_set_write_callback_enable(struct netio *net, bool enabled)
{
    net->funcs->set_write_callback_enable(net, enabled);
}

void *
netio_acceptor_get_user_data(struct netio_acceptor *acceptor)
{
    return acceptor->user_data;
}

void
netio_acceptor_set_user_data(struct netio_acceptor *acceptor,
			     void *user_data)
{
    acceptor->user_data = user_data;
}

int netio_acc_add_remaddr(struct netio_acceptor *acceptor, const char *str)
{
    return acceptor->funcs->add_remaddr(acceptor, str);
}

int
netio_acc_startup(struct netio_acceptor *acceptor)
{
    return acceptor->funcs->startup(acceptor);
}

int
netio_acc_shutdown(struct netio_acceptor *acceptor)
{
    return acceptor->funcs->shutdown(acceptor);
}

void
netio_acc_set_accept_callback_enable(struct netio_acceptor *acceptor,
				     bool enabled)
{
    acceptor->funcs->set_accept_callback_enable(acceptor, enabled);
}

void
netio_acc_free(struct netio_acceptor *acceptor)
{
    acceptor->funcs->free(acceptor);
}

bool
netio_acc_exit_on_close(struct netio_acceptor *acceptor)
{
    return acceptor->exit_on_close;
}

int str_to_netio_acceptor(const char *str,
			  unsigned int max_read_size,
			  const struct netio_acceptor_callbacks *cbs,
			  void *user_data,
			  struct netio_acceptor **acceptor)
{
    int err;
    struct addrinfo *ai = NULL;
    bool is_dgram, is_port_set;

    if (strisallzero(str)) {
	err = stdio_netio_acceptor_alloc(max_read_size, cbs, user_data,
					 acceptor);
    } else {
	err = scan_network_port(str, &ai, &is_dgram, &is_port_set);
	if (!err) {
	    if (!is_port_set) {
		err = EINVAL;
	    } else if (is_dgram) {
		err = udp_netio_acceptor_alloc(str, ai, max_read_size, cbs,
					       user_data, acceptor);
	    } else {
		err = tcp_netio_acceptor_alloc(str, ai, max_read_size, cbs,
					       user_data, acceptor);
	    }

	    if (err) {
		freeaddrinfo(ai);
	    }
	}
    }

    return err;
}
