// SPDX-License-Identifier: GPL-2.0+

/*
 * serialecho - Emulate a serial device in loopback or pipe
 *
 * This attempts to emulate a basic serial device.  It uses the baud
 * rate and sends the bytes through the loopback as approximately the
 * speed it would on a normal serial device.
 *
 * It creates two types of devices.  Echo devices simply echo back the
 * data to the same device.  These devices will appear as /dev/ttyEcho<n>.
 *
 * Pipe devices will transfer the data between two devices.  The
 * devices will appear as /dev/ttyPipeA<n> and /dev/ttyPipeB<n>.  And
 * data written to PipeA reads from PipeB, and vice-versa.
 *
 * You may create an arbitrary number of devices by setting the
 * nr_echo ports and nr_pipe_ports module parameters.  The default is
 * four for both.
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
#include <linux/spinlock.h>

#define PORT_SERIALECHO 72549
#define PORT_SERIALPIPEA 72550
#define PORT_SERIALPIPEB 72551

#ifdef CONFIG_HIGH_RES_TIMERS
#define SERIALECHO_WAKES_PER_SEC	1000
#else
#define SERIALECHO_WAKES_PER_SEC	HZ
#endif

#define SERIALECHO_XBUFSIZE	32

struct serialecho_intf {
	struct uart_port port;

	/*
	 * This is my transmit buffer, my thread picks this up and
	 * injects them into the other port's uart.
	 */
	unsigned char xmitbuf[SERIALECHO_XBUFSIZE];
	struct circ_buf buf;

	/* My transmitter is enabled. */
	bool tx_enabled;

	/* I can receive characters. */
	bool rx_enabled;

	/* Is the port registered with the uart driver? */
	bool registered;

	/*
	 * The serial echo port on the other side of this pipe (or points
	 * to myself in loopback mode.
	 */
	struct serialecho_intf *ointf;

	unsigned int div;
	unsigned int bytes_per_interval;
	unsigned int per_interval_residual;

	const char *threadname;
	struct task_struct *thread;
};

#define circ_sbuf_space(buf) CIRC_SPACE((buf)->head, (buf)->tail, \
					SERIALECHO_XBUFSIZE)
#define circ_sbuf_empty(buf) ((buf)->head == (buf)->tail)

static struct serialecho_intf *serialecho_port_to_intf(struct uart_port *port)
{
	return container_of(port, struct serialecho_intf, port);
}

static unsigned int serialecho_tx_empty(struct uart_port *port)
{
	struct serialecho_intf *intf = serialecho_port_to_intf(port);

	if (circ_sbuf_empty(&intf->buf))
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
	struct serialecho_intf *intf = serialecho_port_to_intf(port);

	intf->tx_enabled = true;
}

static void serialecho_set_baud_rate(struct serialecho_intf *intf,
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

	intf->div = SERIALECHO_WAKES_PER_SEC * bits_per_char;
	intf->bytes_per_interval = baud / intf->div;
	intf->per_interval_residual = baud % intf->div;
}

static void serialecho_transfer_data(struct serialecho_intf *intf)
{
	struct uart_port *port = &intf->port;
	struct circ_buf *cbuf = &port->state->xmit;
	struct circ_buf *tbuf = &intf->buf;

	while (!uart_circ_empty(cbuf) && circ_sbuf_space(tbuf)) {
		unsigned char c = cbuf->buf[cbuf->tail];

		cbuf->tail = (cbuf->tail + 1) % UART_XMIT_SIZE;
		tbuf->buf[tbuf->head] = c;
		tbuf->head = (tbuf->head + 1) % SERIALECHO_XBUFSIZE;
	}
	if (uart_circ_chars_pending(cbuf) < WAKEUP_CHARS)
		uart_write_wakeup(port);
}

static unsigned int serialecho_xmit_one(struct serialecho_intf *intf)
{
	struct uart_port *oport = &intf->ointf->port;
	struct circ_buf *tbuf = &intf->buf;
	unsigned char c = tbuf->buf[tbuf->tail];

	tbuf->tail = (tbuf->tail + 1) % SERIALECHO_XBUFSIZE;
	if (intf->ointf->rx_enabled) {
		uart_insert_char(oport, 0, 0, c, 0);
		return 1;
	}
	return 0;
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
	struct serialecho_intf *intf = data;
	struct uart_port *port = &intf->port;
	struct uart_port *oport = &intf->ointf->port;
	struct circ_buf *tbuf = &intf->buf;
	unsigned int residual = 0;

	while (!kthread_should_stop()) {
		unsigned int sent = 0;
		unsigned int to_send;
		unsigned int div;

		spin_lock_irq(&port->lock);
		if (!intf->tx_enabled) {
			spin_unlock_irq(&port->lock);
			goto do_delay;
		}
		serialecho_transfer_data(intf);
		to_send = intf->bytes_per_interval;
		residual += intf->per_interval_residual;
		div = intf->div;
		spin_unlock_irq(&port->lock);

		spin_lock_irq(&oport->lock);
		while (!circ_sbuf_empty(tbuf) && to_send) {
			sent += serialecho_xmit_one(intf);
			to_send--;
		}

		if (residual >= div) {
			residual -= div;
			if (!circ_sbuf_empty(tbuf))
				sent += serialecho_xmit_one(intf);
		}

		if (sent)
			tty_flip_buffer_push(&oport->state->port);
		spin_unlock_irq(&oport->lock);
	do_delay:
		serialecho_thread_delay();
	}

	return 0;
}

static void serialecho_start_tx(struct uart_port *port)
{
	struct serialecho_intf *intf = serialecho_port_to_intf(port);

	intf->tx_enabled = true;
}

static void serialecho_stop_rx(struct uart_port *port)
{
	struct serialecho_intf *intf = serialecho_port_to_intf(port);

	intf->rx_enabled = false;
}

static void serialecho_break_ctl(struct uart_port *port, int break_state)
{
}

static int serialecho_startup(struct uart_port *port)
{
	struct serialecho_intf *intf = serialecho_port_to_intf(port);
	int rv = 0;

	intf->thread = kthread_run(serialecho_thread, intf,
				   "%s%d", intf->threadname, port->line);
	if (IS_ERR(intf->thread)) {
		rv = PTR_ERR(intf->thread);
		intf->thread = NULL;
		pr_err("serialecho: Could not start thread: %d", rv);
	} else {
		unsigned long flags;

		spin_lock_irqsave(&port->lock, flags);
		intf->tx_enabled = false;
		intf->rx_enabled = true;

		serialecho_set_baud_rate(intf, 9600, CS8);
		spin_unlock_irqrestore(&port->lock, flags);
	}

	return rv;
}

static void serialecho_shutdown(struct uart_port *port)
{
	struct serialecho_intf *intf = serialecho_port_to_intf(port);
	unsigned long flags;

	spin_lock_irqsave(&port->lock, flags);
	intf->tx_enabled = false;
	spin_unlock_irqrestore(&port->lock, flags);
	kthread_stop(intf->thread);
}

static void serialecho_release_port(struct uart_port *port)
{
}

static void
serialecho_set_termios(struct uart_port *port, struct ktermios *termios,
	        struct ktermios *old)
{
	struct serialecho_intf *intf = serialecho_port_to_intf(port);
	unsigned int baud = uart_get_baud_rate(port, termios, old,
					       10, 100000000);
	unsigned long flags;

	spin_lock_irqsave(&port->lock, flags);
	serialecho_set_baud_rate(intf, baud, termios->c_cflag);
	spin_unlock_irqrestore(&port->lock, flags);
}

static const char *serialecho_type(struct uart_port *port)
{
	return "SerialEcho";
}

static const char *serialpipea_type(struct uart_port *port)
{
	return "SerialPipeA";
}

static const char *serialpipeb_type(struct uart_port *port)
{
	return "SerialPipeB";
}

static void serialecho_config_port(struct uart_port *port, int type)
{
	port->type = PORT_SERIALECHO;
}

static void serialpipea_config_port(struct uart_port *port, int type)
{
	port->type = PORT_SERIALPIPEA;
}

static void serialpipeb_config_port(struct uart_port *port, int type)
{
	port->type = PORT_SERIALPIPEB;
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

static const struct uart_ops serialpipea_ops = {
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
	.type =			serialpipea_type,
	.config_port =		serialpipea_config_port
};

static const struct uart_ops serialpipeb_ops = {
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
	.type =			serialpipeb_type,
	.config_port =		serialpipeb_config_port
};

static struct uart_driver serialecho_driver = {
	.owner = THIS_MODULE,
	.driver_name = "ttyEcho",
	.dev_name = "ttyEcho"
};

static struct uart_driver serialpipea_driver = {
	.owner = THIS_MODULE,
	.driver_name = "ttyPipeA",
	.dev_name = "ttyPipeA"
};

static struct uart_driver serialpipeb_driver = {
	.owner = THIS_MODULE,
	.driver_name = "ttyPipeB",
	.dev_name = "ttyPipeB"
};


static unsigned int nr_echo_ports = 4;
module_param(nr_echo_ports, uint, 0444);
MODULE_PARM_DESC(nr_echo_ports,
		 "The number of echo ports to create.  Defaults to 4");

static struct serialecho_intf *serialecho_ports;

static unsigned int nr_pipe_ports = 4;
module_param(nr_pipe_ports, uint, 0444);
MODULE_PARM_DESC(nr_pipe_ports,
		 "The number of pipe ports to create.  Defaults to 4");

static struct serialecho_intf *serialecho_ports;
static struct serialecho_intf *serialpipe_ports;

static int __init serialecho_init(void)
{
	unsigned int i;
	int rv;

	serialecho_ports = kcalloc(nr_echo_ports,
				   sizeof(*serialecho_ports),
				   GFP_KERNEL);
	if (!serialecho_ports) {
		pr_err("serialecho: Unable to allocate echo ports.\n");
		rv = ENOMEM;
		goto out;
	}

	serialpipe_ports = kcalloc(nr_pipe_ports * 2,
				   sizeof(*serialpipe_ports),
				   GFP_KERNEL);
	if (!serialpipe_ports) {
		kfree(serialecho_ports);
		pr_err("serialecho: Unable to allocate pipe ports.\n");
		rv = ENOMEM;
		goto out;
	}

	serialecho_driver.nr = nr_echo_ports;
	rv = uart_register_driver(&serialecho_driver);
	if (rv) {
		kfree(serialecho_ports);
		kfree(serialpipe_ports);
		pr_err("serialecho: Unable to register driver.\n");
		goto out;
	}

	serialpipea_driver.nr = nr_pipe_ports;
	rv = uart_register_driver(&serialpipea_driver);
	if (rv) {
		uart_unregister_driver(&serialecho_driver);
		kfree(serialecho_ports);
		kfree(serialpipe_ports);
		pr_err("serialecho: Unable to register driver.\n");
		goto out;
	}

	serialpipeb_driver.nr = nr_pipe_ports;
	rv = uart_register_driver(&serialpipeb_driver);
	if (rv) {
		uart_unregister_driver(&serialpipea_driver);
		uart_unregister_driver(&serialecho_driver);
		kfree(serialecho_ports);
		kfree(serialpipe_ports);
		pr_err("serialecho: Unable to register driver.\n");
		goto out;
	}

	for (i = 0; i < nr_echo_ports; i++) {
		struct serialecho_intf *intf = &serialecho_ports[i];
		struct uart_port *port = &intf->port;

		intf->buf.buf = intf->xmitbuf;
		intf->ointf = intf;
		intf->threadname = "serialecho";
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
			intf->registered = true;
	}

	for (i = 0; i < nr_pipe_ports * 2; i += 2) {
		struct serialecho_intf *intfa = &serialpipe_ports[i];
		struct serialecho_intf *intfb = &serialpipe_ports[i + 1];
		struct uart_port *porta = &intfa->port;
		struct uart_port *portb = &intfb->port;

		intfa->buf.buf = intfa->xmitbuf;
		intfb->buf.buf = intfb->xmitbuf;
		intfa->ointf = intfb;
		intfb->ointf = intfa;
		intfa->threadname = "serialpipea";
		intfb->threadname = "serialpipeb";

		/* Won't configure without some I/O or mem address set. */
		porta->iobase = 1;
		porta->line = i / 2;
		porta->flags = UPF_BOOT_AUTOCONF;
		porta->ops = &serialpipea_ops;
		spin_lock_init(&porta->lock);
		rv = uart_add_one_port(&serialpipea_driver, porta);
		if (rv) {
			pr_err("serialecho: Unable to add uart pipe aport %d: %d\n",
			       i, rv);
			continue;
		} else {
			intfa->registered = true;
		}

		portb->iobase = 1;
		portb->line = i / 2;
		portb->flags = UPF_BOOT_AUTOCONF;
		portb->ops = &serialpipeb_ops;
		spin_lock_init(&portb->lock);
		rv = uart_add_one_port(&serialpipeb_driver, portb);
		if (rv) {
			pr_err("serialecho: Unable to add uart pipe b port %d: %d\n",
			       i, rv);
			intfa->registered = false;
			uart_remove_one_port(&serialpipea_driver, porta);
		} else {
			intfb->registered = true;
		}
	}
	rv = 0;

	pr_info("serialecho ready\n");
out:
	return rv;
}

static void __exit serialecho_exit(void)
{
	unsigned int i;

	for (i = 0; i < nr_echo_ports; i++) {
		struct serialecho_intf *intf = &serialecho_ports[i];
		struct uart_port *port = &intf->port;

		if (intf->registered)
			uart_remove_one_port(&serialecho_driver, port);
	}

	for (i = 0; i < nr_pipe_ports * 2; i += 2) {
		struct serialecho_intf *intfa = &serialpipe_ports[i];
		struct serialecho_intf *intfb = &serialpipe_ports[i + 1];
		struct uart_port *porta = &intfa->port;
		struct uart_port *portb = &intfb->port;

		if (intfa->registered)
			uart_remove_one_port(&serialpipea_driver, porta);
		if (intfb->registered)
			uart_remove_one_port(&serialpipeb_driver, portb);
	}
	uart_unregister_driver(&serialecho_driver);
	uart_unregister_driver(&serialpipea_driver);
	uart_unregister_driver(&serialpipeb_driver);

	kfree(serialecho_ports);
	kfree(serialpipe_ports);

	pr_info("serialecho unloaded\n");
}

module_init(serialecho_init);
module_exit(serialecho_exit);

MODULE_AUTHOR("Corey Minyard");
MODULE_DESCRIPTION("Serial echo device");
MODULE_LICENSE("GPL");
