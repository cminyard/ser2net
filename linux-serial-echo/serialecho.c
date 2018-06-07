// SPDX-License-Identifier: GPL-2.0+

/*
 * serialecho - Emulate a serial device in loopback
 *
 * This attempts to emulate a basic serial device.  It uses the baud
 * rate and sends the bytes through the loopback as approximately the
 * speed it would on a normal serial device.
 *
 * The device will appear as /dev/ttyEcho<n>.
 *
 * You may create an arbitrary number of devices by setting the nr_ports
 * module parameter.  The default is one.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/device.h>
#include <linux/serial_core.h>
#include <linux/kthread.h>
#include <linux/hrtimer.h>
#include <linux/slab.h>

#define PORT_SERIALECHO 72549

#ifdef CONFIG_HIGH_RES_TIMERS
#define SERIALECHO_WAKES_PER_SEC	1000
#else
#define SERIALECHO_WAKES_PER_SEC	HZ
#endif

#define SERIALECHO_XBUFSIZE	32
struct serialecho_port {
	struct uart_port port;
	bool registered;
	bool rx_enabled;
	bool tx_enabled;
	unsigned char xmitbuf[SERIALECHO_XBUFSIZE];
	struct circ_buf buf;

	unsigned int div;
	unsigned int bytes_per_interval;
	unsigned int per_interval_residual;

	struct task_struct *thread;
};

#define circ_sbuf_space(buf) CIRC_SPACE((buf)->head, (buf)->tail, \
					SERIALECHO_XBUFSIZE)
#define circ_sbuf_empty(buf) ((buf)->head == (buf)->tail)

static unsigned int serialecho_tx_empty(struct uart_port *port)
{
	struct serialecho_port *sport =
		container_of(port, struct serialecho_port, port);

	if (circ_sbuf_empty(&sport->buf))
		return TIOCSER_TEMT;
	return 0;
} 

static void serialecho_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
}

static unsigned int serialecho_get_mctrl(struct uart_port *port)
{ 
	return TIOCM_CAR | TIOCM_DSR | TIOCM_CTS;
}

static void serialecho_stop_tx(struct uart_port *port)
{
	struct serialecho_port *sport =
		container_of(port, struct serialecho_port, port);

	sport->tx_enabled = false;
}

static void serialecho_set_baud_rate(struct serialecho_port *sport,
				     unsigned int baud, unsigned int cflag)
{
	unsigned int bits_per_char;

	switch (cflag & CSIZE) {
	case CS5: bits_per_char = 7; break;
	case CS6: bits_per_char = 8; break;
	case CS7: bits_per_char = 9; break;
	default:  bits_per_char = 10; break; /* CS8 and others. */
	}
	if (cflag & CSTOPB)
		bits_per_char++;

	sport->div = SERIALECHO_WAKES_PER_SEC * bits_per_char;
	sport->bytes_per_interval = baud / sport->div;
	sport->per_interval_residual = baud % sport->div;
}

static void serialecho_transfer_data(struct serialecho_port *sport)
{
	struct uart_port *port = &sport->port;
	struct circ_buf *tbuf = &port->state->xmit;
	struct circ_buf *rbuf = &sport->buf;

	while (!uart_circ_empty(tbuf) && circ_sbuf_space(rbuf)) {
		unsigned char c = tbuf->buf[tbuf->tail];

		tbuf->tail = (tbuf->tail + 1) % UART_XMIT_SIZE;
		rbuf->buf[rbuf->head] = c;
		rbuf->head = (rbuf->head + 1) % SERIALECHO_XBUFSIZE;
	}
	if (uart_circ_chars_pending(tbuf) < WAKEUP_CHARS)
		uart_write_wakeup(port);
}

static void serialecho_xmit_one(struct serialecho_port *sport)
{
	struct uart_port *port = &sport->port;
	struct circ_buf *rbuf = &sport->buf;
	unsigned char c = rbuf->buf[rbuf->tail];

	rbuf->tail = (rbuf->tail + 1) % SERIALECHO_XBUFSIZE;
	uart_insert_char(port, 0, 0, c, 0);
}

static void serialecho_thread_delay(void)
{
#ifdef CONFIG_HIGH_RES_TIMERS
	ktime_t timeout;

	timeout = ns_to_ktime(1000000000 / SERIALECHO_WAKES_PER_SEC);
	set_current_state(TASK_INTERRUPTIBLE);
	schedule_hrtimeout(&timeout, HRTIMER_MODE_REL);
#else
	schedule_timeout_interruptible(1);
#endif
}

static int serialecho_thread(void *data)
{
	struct serialecho_port *sport = data;
	struct uart_port *port = &sport->port;
	struct circ_buf *rbuf = &sport->buf;
	unsigned int residual = 0;

	while (!kthread_should_stop()) {
		unsigned int sent = 0;
		unsigned int to_send;

		spin_lock_irq(&port->lock);

		serialecho_transfer_data(sport);

		to_send = sport->bytes_per_interval;
		while (!circ_sbuf_empty(rbuf) && to_send) {
			serialecho_xmit_one(sport);
			sent++;
			to_send--;
		}

		residual += sport->per_interval_residual;
		if (residual >= sport->div) {
			residual -= sport->div;
			if (!circ_sbuf_empty(rbuf)) {
				serialecho_xmit_one(sport);
				sent++;
			}
		}
		spin_unlock_irq(&port->lock);

		if (sent)
			tty_flip_buffer_push(&port->state->port);

		serialecho_thread_delay();
	}

	return 0;
}

static void serialecho_start_tx(struct uart_port *port)
{
	struct serialecho_port *sport =
		container_of(port, struct serialecho_port, port);

	sport->tx_enabled = true;
}

static void serialecho_stop_rx(struct uart_port *port)
{
	struct serialecho_port *sport =
		container_of(port, struct serialecho_port, port);

	sport->rx_enabled = false;
}

static void serialecho_break_ctl(struct uart_port *port, int break_state)
{
}

static int serialecho_startup(struct uart_port *port)
{
	struct serialecho_port *sport =
		container_of(port, struct serialecho_port, port);
	int rv = 0;

	sport->tx_enabled = false;
	sport->rx_enabled = true;

	serialecho_set_baud_rate(sport, 9600, CS8);

	sport->thread = kthread_run(serialecho_thread, sport,
				    "serialecho%d", port->line);
	if (IS_ERR(sport->thread)) {
		rv = PTR_ERR(sport->thread);
		sport->thread = NULL;
		pr_err("serialecho: Could not start thread: %d", rv);
	}

	return 0;
}

static void serialecho_shutdown(struct uart_port *port)
{
	struct serialecho_port *sport =
		container_of(port, struct serialecho_port, port);

	kthread_stop(sport->thread);
	sport->tx_enabled = false;
	sport->rx_enabled = false;
}

static void serialecho_release_port(struct uart_port *port)
{
}

static void
serialecho_set_termios(struct uart_port *port, struct ktermios *termios,
	        struct ktermios *old)
{
	struct serialecho_port *sport =
		container_of(port, struct serialecho_port, port);
	unsigned int baud = uart_get_baud_rate(port, termios, old,
					       10, 100000000);

	spin_lock_irq(&port->lock);
	serialecho_set_baud_rate(sport, baud, termios->c_cflag);
	spin_unlock_irq(&port->lock);
}

/**
 * serialecho_type - Describe the port.
 * @port: Ptr to the uart_port.
 *
 * Return a pointer to a string constant describing the
 * specified port.
 */
static const char *serialecho_type(struct uart_port *port)
{
	return "SerialEcho";
}

static void serialecho_config_port(struct uart_port *port, int type)
{
	port->type = PORT_SERIALECHO;
}

static const struct uart_ops serialecho_ops = {
	.tx_empty =		serialecho_tx_empty,
	.set_mctrl =		serialecho_set_mctrl,
	.get_mctrl =		serialecho_get_mctrl,
	.stop_tx =		serialecho_stop_tx,
	.start_tx =		serialecho_start_tx,
	.stop_rx =		serialecho_stop_rx,
	.break_ctl =		serialecho_break_ctl,
	.startup =		serialecho_startup,
	.shutdown =		serialecho_shutdown,
	.release_port =		serialecho_release_port,
	.set_termios =		serialecho_set_termios,
	.type =			serialecho_type,
	.config_port =		serialecho_config_port
};

static struct uart_driver serialecho_driver = {
	.owner = THIS_MODULE,
	.driver_name = "ttyEcho",
	.dev_name = "ttyEcho"
};


static unsigned int nr_ports = 1;
module_param(nr_ports, uint, 0444);
MODULE_PARM_DESC(nr_ports, "The number of ports to create.  Defaults to 1");

static struct serialecho_port *serialecho_ports;

static int __init serialecho_init(void)
{
	unsigned int i;
	int rv;

	serialecho_ports = kcalloc(nr_ports,
				   sizeof(struct uart_port),
				   GFP_KERNEL);
	if (!serialecho_ports) {
		pr_err("serialecho: Unable to allocate ports.\n");
		rv = ENOMEM;
		goto out;
	}

	serialecho_driver.nr = nr_ports;
	rv = uart_register_driver(&serialecho_driver);
	if (rv) {
		kfree(serialecho_ports);
		pr_err("serialecho: Unable to register driver.\n");
		goto out;
	}

	for (i = 0; i < nr_ports; i++) {
		struct serialecho_port *sport = &serialecho_ports[i];
		struct uart_port *port = &sport->port;

		sport->buf.buf = sport->xmitbuf;
		/* Won't configure without some I/O or mem address set. */
		port->iobase = 1;
		port->line = i;
		port->flags = UPF_BOOT_AUTOCONF;
		port->ops = &serialecho_ops;
		spin_lock_init(&port->lock);
		rv = uart_add_one_port(&serialecho_driver, port);
		if (rv)
			pr_err("serialecho: Unable to add uart port %d: %d\n",
			       i, rv);
		else
			sport->registered = true;
	}
	rv = 0;

	pr_info("serialecho ready\n");
out:
	return rv;
}

static void __exit serialecho_exit(void)
{
	unsigned int i;

	for (i = 0; i < nr_ports; i++) {
		struct serialecho_port *sport = &serialecho_ports[i];
		struct uart_port *port = &sport->port;

		if (sport->registered)
			uart_remove_one_port(&serialecho_driver, port);
	}
	uart_unregister_driver(&serialecho_driver);
	pr_info("serialecho unloaded\n");
}

module_init(serialecho_init);
module_exit(serialecho_exit);

MODULE_AUTHOR("Corey Minyard");
MODULE_DESCRIPTION("Serial echo device");
MODULE_LICENSE("GPL");
