
#include <string.h>
#include "port.h"

struct gensio_lock *ports_lock;
port_info_t *ports = NULL; /* Linked list of ports. */
port_info_t *new_ports = NULL; /* New ports during config/reconfig. */
port_info_t *new_ports_end = NULL;

net_info_t *
first_live_net_con(port_info_t *port)
{
    net_info_t *netcon;

    for_each_connection(port, netcon) {
	if (netcon->net)
	    return netcon;
    }

    return NULL;
}

bool
port_in_use(port_info_t *port)
{
    return (port->net_to_dev_state != PORT_UNCONNECTED &&
	    port->net_to_dev_state != PORT_CLOSED);
}

/* Checks to see if some other port has the same device in use.  Must
   be called with ports_lock held. */
int
is_device_already_inuse(port_info_t *check_port)
{
    port_info_t *port = ports;

    while (port != NULL) {
	if (port != check_port) {
	    if ((strcmp(port->devname, check_port->devname) == 0)
				&& port_in_use(port)) {
		return 1;
	    }
	}
	port = port->next;
    }

    return 0;
}

gensiods
net_raddr(struct gensio *io, struct sockaddr_storage *addr, gensiods *socklen)
{
    *socklen = sizeof(*addr);
#if (defined(gensio_version_major) && (gensio_version_major > 2 || \
	       (gensio_version_major == 2 && gensio_version_minor > 0)))
    return gensio_control(io, GENSIO_CONTROL_DEPTH_FIRST, true,
			  GENSIO_CONTROL_RADDR_BIN,
			  (char *) addr, socklen);
#else
    return gensio_get_raddr(io, (char *) addr, socklen);
#endif
}

void
reset_timer(net_info_t *netcon)
{
    netcon->timeout_left = netcon->port->timeout;
}
