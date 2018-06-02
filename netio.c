
#include <errno.h>

#include <stdlib.h>
#include "netio.h"
#include "utils.h"

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
