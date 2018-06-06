
#include <errno.h>

#include <stdlib.h>
#include "netio.h"
#include "utils.h"

int netio_write(struct netio *net, int *count,
		const void *buf, unsigned int buflen)
{
    return net->write(net, count, buf, buflen);
}

int netio_raddr_to_str(struct netio *net, int *pos,
		       char *buf, unsigned int buflen)
{
    return net->raddr_to_str(net, pos, buf, buflen);
}

void netio_close(struct netio *net)
{
    net->close(net);
}

void netio_set_read_callback_enable(struct netio *net, bool enabled)
{
    net->set_read_callback_enable(net, enabled);
}

void netio_set_write_callback_enable(struct netio *net, bool enabled)
{
    net->set_write_callback_enable(net, enabled);
}

int netio_acc_add_remaddr(struct netio_acceptor *acceptor, const char *str)
{
    return acceptor->add_remaddr(acceptor, str);
}

int
netio_acc_startup(struct netio_acceptor *acceptor)
{
    return acceptor->startup(acceptor);
}

int
netio_acc_shutdown(struct netio_acceptor *acceptor)
{
    return acceptor->shutdown(acceptor);
}

void
netio_acc_set_accept_callback_enable(struct netio_acceptor *acceptor,
				     bool enabled)
{
    acceptor->set_accept_callback_enable(acceptor, enabled);
}

void
netio_acc_free(struct netio_acceptor *acceptor)
{
    acceptor->free(acceptor);
}


int str_to_netio_acceptor(const char *str,
			  unsigned int max_read_size,
			  struct netio_acceptor **acceptor)
{
    int err;
    struct addrinfo *ai = NULL;
    bool is_dgram, is_port_set;

    if (strisallzero(str)) {
	err = stdio_netio_acceptor_alloc(max_read_size, acceptor);
    } else {
	err = scan_network_port(str, &ai, &is_dgram, &is_port_set);
	if (!err) {
	    if (!is_port_set) {
		err = EINVAL;
	    } else if (is_dgram) {
		err = udp_netio_acceptor_alloc(str, ai, max_read_size,
					       acceptor);
	    } else {
		err = tcp_netio_acceptor_alloc(str, ai, max_read_size,
					       acceptor);
	    }

	    if (err) {
		freeaddrinfo(ai);
	    }
	}
    }

    return err;
}
