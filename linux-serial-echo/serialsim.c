// SPDX-License-Identifier: GPL-2.0+

/*
 * serialsim - Emulate a serial device in a loopback and/or pipe
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
 *
 * This driver supports modifying the modem control lines and
 * injecting various serial errors.  It also supports a simulated null
 * modem between the two pipes, or in a loopback on the echo device.
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
#include <linux/ctype.h>
#include <linux/string.h>

#define PORT_SERIALECHO 72549
#define PORT_SERIALPIPEA 72550
#define PORT_SERIALPIPEB 72551

#ifdef CONFIG_HIGH_RES_TIMERS
#define SERIALECHO_WAKES_PER_SEC	1000
#else
#define SERIALECHO_WAKES_PER_SEC	HZ
#endif

#define SERIALECHO_XBUFSIZE	32

/* For things to send on the line, in flags field. */
#define DO_FRAME_ERR		0x01
#define DO_PARITY_ERR		0x02
#define DO_OVERRUN_ERR		0x04
#define DO_BREAK		0x08

struct serialecho_intf {
	struct uart_port port;

	/*
	 * This is my transmit buffer, my thread picks this up and
	 * injects them into the other port's uart.
	 */
	unsigned char xmitbuf[SERIALECHO_XBUFSIZE];
	struct circ_buf buf;

	/* Error flags to send. */
	bool break_reported;
	unsigned int flags;

	/* Modem state. */
	unsigned int mctrl;
	bool do_null_modem;
	spinlock_t mctrl_lock;
	struct tasklet_struct mctrl_tasklet;

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
#define circ_sbuf_next(idx) (((idx) + 1) % SERIALECHO_XBUFSIZE)

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

/*
 * We have to lock multiple locks, make sure to do it in the same order all
 * the time.
 */
static void serialecho_null_modem_lock_irq(struct serialecho_intf *intf) {
	spin_lock_irq(&intf->port.lock);
	if (intf == intf->ointf) {
		spin_lock(&intf->mctrl_lock);
	} else if (intf < intf->ointf) {
		spin_lock(&intf->mctrl_lock);
		spin_lock(&intf->ointf->mctrl_lock);
	} else {
		spin_lock(&intf->ointf->mctrl_lock);
		spin_lock(&intf->mctrl_lock);
	}
}

static void serialecho_null_modem_unlock_irq(struct serialecho_intf *intf)
{
	if (intf == intf->ointf) {
		spin_unlock(&intf->mctrl_lock);
	} else {
		/* Order doesn't matter here. */
		spin_unlock(&intf->mctrl_lock);
		spin_unlock(&intf->ointf->mctrl_lock);
	}
	spin_unlock_irq(&intf->port.lock);
}

/*
 * This must be called holdnig intf->port.lock and intf->mctrl_lock.
 */
static void _serialecho_set_modem_lines(struct serialecho_intf *intf,
					unsigned int mask,
					unsigned int new_mctrl)
{
	unsigned int changes;
	unsigned int mctrl = (intf->mctrl & ~mask) | (new_mctrl & mask);

	if (mctrl == intf->mctrl)
		return;

	if (!intf->rx_enabled) {
		intf->mctrl = mctrl;
		return;
	}

	changes = mctrl ^ intf->mctrl;
	intf->mctrl = mctrl;
	if (changes & TIOCM_CAR)
		uart_handle_dcd_change(&intf->port, mctrl & TIOCM_CAR);
	if (changes & TIOCM_CTS)
		uart_handle_cts_change(&intf->port, mctrl & TIOCM_CTS);
	if (changes & TIOCM_RNG)
		intf->port.icount.rng++;
	if (changes & TIOCM_DSR)
		intf->port.icount.dsr++;
}

#define NULL_MODEM_MCTRL (TIOCM_CAR | TIOCM_CTS | TIOCM_DSR)
#define LOCAL_MCTRL (NULL_MODEM_MCTRL | TIOCM_RNG)

/*
 * Must be called holding intf->port.lock, intf->mctrl_lock, and
 * intf->ointf.mctrl_lock.
 */
static void serialecho_handle_null_modem_update(struct serialecho_intf *intf)
{
	unsigned int mctrl = 0;

	/* Pull the values from the remote side for myself. */
	if (intf->ointf->mctrl & TIOCM_DTR)
		mctrl |= TIOCM_CAR | TIOCM_DSR;
	if (intf->ointf->mctrl & TIOCM_RTS)
		mctrl |= TIOCM_CTS;

	_serialecho_set_modem_lines(intf, NULL_MODEM_MCTRL, mctrl);
}

static void serialecho_set_null_modem(struct serialecho_intf *intf, bool val)
{
	serialecho_null_modem_lock_irq(intf);

	if (!!val == !!intf->do_null_modem)
		goto out_unlock;

	if (!val) {
		intf->do_null_modem = false;
		goto out_unlock;
	}

	/* Enabling NULL modem. */
	intf->do_null_modem = true;

	serialecho_handle_null_modem_update(intf);

out_unlock:
	serialecho_null_modem_unlock_irq(intf);
}

static void serialecho_set_modem_lines(struct serialecho_intf *intf,
				       unsigned int mask,
				       unsigned int new_mctrl)
{
	mask &= LOCAL_MCTRL;

	spin_lock_irq(&intf->port.lock);
	spin_lock(&intf->mctrl_lock);

	if (intf->do_null_modem)
		mask &= ~NULL_MODEM_MCTRL;

	_serialecho_set_modem_lines(intf, mask, new_mctrl);

	spin_unlock(&intf->mctrl_lock);
	spin_unlock_irq(&intf->port.lock);
}

static void mctrl_tasklet(unsigned long data)
{
	struct serialecho_intf *intf = (void *) data;

	serialecho_null_modem_lock_irq(intf);
	serialecho_handle_null_modem_update(intf);
	serialecho_null_modem_unlock_irq(intf);
}

static void serialecho_set_mctrl(struct uart_port *port, unsigned int mctrl)
{
	struct serialecho_intf *intf = serialecho_port_to_intf(port);

	spin_lock(&intf->mctrl_lock);
	intf->mctrl &= ~(TIOCM_RTS | TIOCM_DTR);
	intf->mctrl |= mctrl & (TIOCM_RTS | TIOCM_DTR);
	spin_unlock(&intf->mctrl_lock);

	/*
	 * We are called holding port->lock, but we must be able to claim
	 * intf->ointf->port.lock, and that can result in deadlock.  So
	 * we have to run this elsewhere.  Note that we run the other
	 * end's tasklet.
	 */
	tasklet_schedule(&intf->ointf->mctrl_tasklet);
}

static unsigned int serialecho_get_mctrl(struct uart_port *port)
{ 
	struct serialecho_intf *intf = serialecho_port_to_intf(port);
	unsigned int rv;

	spin_lock(&intf->mctrl_lock);
	rv = intf->mctrl;
	spin_unlock(&intf->mctrl_lock);

	return rv;
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
		tbuf->head = circ_sbuf_next(tbuf->head);
		port->icount.tx++;
	}
	if (uart_circ_chars_pending(cbuf) < WAKEUP_CHARS)
		uart_write_wakeup(port);
}

static unsigned int serialecho_get_flag(struct serialecho_intf *intf,
					unsigned int *status)
{
	unsigned int flags = intf->flags;

	*status = flags;

	/* Overrun is always reported through a different way. */
	if (flags & DO_OVERRUN_ERR) {
		intf->port.icount.overrun++;
		intf->flags &= ~DO_OVERRUN_ERR;
	}

	if (flags & DO_BREAK && !intf->break_reported) {
		intf->port.icount.brk++;
		intf->break_reported = true;
		return TTY_BREAK;
	}
	if (flags & DO_FRAME_ERR) {
		intf->port.icount.frame++;
		intf->flags &= ~DO_FRAME_ERR;
		return TTY_FRAME;
	}
	if (flags & DO_PARITY_ERR) {
		intf->port.icount.parity++;
		intf->flags &= ~DO_PARITY_ERR;
		return TTY_PARITY;
	}

	return TTY_NORMAL;
}

static void serialecho_set_flags(struct serialecho_intf *intf,
				 unsigned int status)
{
	spin_lock_irq(&intf->port.lock);
	intf->flags |= status;
	spin_unlock_irq(&intf->port.lock);
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
		unsigned int to_send;
		unsigned int div;
		unsigned char buf[SERIALECHO_XBUFSIZE];
		unsigned int pos = 0;
		unsigned int flag;
		unsigned int status = 0;

		spin_lock_irq(&port->lock);
		if (!intf->tx_enabled) {
			spin_unlock_irq(&port->lock);
			goto do_delay;
		}

		/* Move the data into the transmit buffer. */
		serialecho_transfer_data(intf);

		/* Send the data to the other side. */
		to_send = intf->bytes_per_interval;
		residual += intf->per_interval_residual;
		div = intf->div;
		while (!circ_sbuf_empty(tbuf) && to_send) {
			buf[pos++] = tbuf->buf[tbuf->tail];
			tbuf->tail = circ_sbuf_next(tbuf->tail);
			to_send--;
		}
		if (residual >= div) {
			residual -= div;
			if (!circ_sbuf_empty(tbuf)) {
				buf[pos++] = tbuf->buf[tbuf->tail];
				tbuf->tail = circ_sbuf_next(tbuf->tail);
			}
		}
		spin_unlock_irq(&port->lock);

		spin_lock_irq(&oport->lock);
		flag = serialecho_get_flag(intf->ointf, &status);
		if (intf->ointf->rx_enabled) {
			for (to_send = 0; to_send < pos; to_send++) {
				oport->icount.rx++;
				uart_insert_char(oport, status,
						 DO_OVERRUN_ERR,
						 buf[to_send], flag);
				flag = 0;
				status = 0;
			}
		}
		spin_unlock_irq(&oport->lock);

		if (pos)
			tty_flip_buffer_push(&oport->state->port);
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
	struct serialecho_intf *intf = serialecho_port_to_intf(port);
	struct serialecho_intf *ointf = intf->ointf;

	spin_lock_irq(&ointf->port.lock);
	if (!break_state && ointf->flags & DO_BREAK) {
		/* Turning break off. */
		ointf->break_reported = false;
		ointf->flags &= ~DO_BREAK;
	} else if (break_state) {
		ointf->flags |= DO_BREAK;
	}
	spin_unlock_irq(&ointf->port.lock);
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

static struct serialecho_intf *serialecho_ports;
static struct serialecho_intf *serialpipe_ports;

static unsigned int nr_echo_ports = 4;
module_param(nr_echo_ports, uint, 0444);
MODULE_PARM_DESC(nr_echo_ports,
		 "The number of echo ports to create.  Defaults to 4");

static struct serialecho_intf *serialecho_ports;

static unsigned int nr_pipe_ports = 4;
module_param(nr_pipe_ports, uint, 0444);
MODULE_PARM_DESC(nr_pipe_ports,
		 "The number of pipe ports to create.  Defaults to 4");

static char *gettok(char **s)
{
	char *t = skip_spaces(*s);
	char *p = t;

	while (*p && !isspace(*p))
		p++;
	if (*p)
		*p++ = '\0';
	*s = p;

	return t;
}

static bool tokeq(const char *t, const char *m)
{
	return strcmp(t, m) == 0;
}

static unsigned int parse_modem_line(char op, unsigned int flag,
				     unsigned int *mctrl)
{
	if (op == '+')
		*mctrl |= flag;
	else
		*mctrl &= ~flag;
	return flag;
}

static ssize_t serialecho_ctrl_op(struct device *dev,
				  struct device_attribute *attr,
				  const char *val, size_t count)
{
	struct tty_port *tport = dev_get_drvdata(dev);
	struct uart_state *state = container_of(tport, struct uart_state, port);
	struct uart_port *port = state->uart_port;
	struct serialecho_intf *intf = serialecho_port_to_intf(port);
	char *str = kstrndup(val, count, GFP_KERNEL);
	char *p, *s = str;
	int rv = count;
	unsigned int flags = 0;
	unsigned int nullmodem = 0;
	unsigned int mctrl_mask = 0, mctrl = 0;

	if (!str)
		return -ENOMEM;

	p = gettok(&s);
	while (*p) {
		char op = '\0';
		int err = 0;

		switch (*p) {
		case '+':
		case '-':
			op = *p++;
			break;
		default:
			break;
		}

		if (tokeq(p, "frame"))
			flags |= DO_FRAME_ERR;
		else if (tokeq(p, "parity"))
			flags |= DO_PARITY_ERR;
		else if (tokeq(p, "overrun"))
			flags |= DO_OVERRUN_ERR;
		else if (tokeq(p, "nullmodem"))
			nullmodem = op;
		else if (tokeq(p, "dsr"))
			mctrl_mask |= parse_modem_line(op, TIOCM_DSR, &mctrl);
		else if (tokeq(p, "cts"))
			mctrl_mask |= parse_modem_line(op, TIOCM_CTS, &mctrl);
		else if (tokeq(p, "cd"))
			mctrl_mask |= parse_modem_line(op, TIOCM_CAR, &mctrl);
		else if (tokeq(p, "ring"))
			mctrl_mask |= parse_modem_line(op, TIOCM_RNG, &mctrl);
		else
			err = -EINVAL;

		if (err) {
			rv = err;
			goto out;
		}
		p = gettok(&s);
	}

	if (flags)
		serialecho_set_flags(intf, flags);
	if (nullmodem)
		serialecho_set_null_modem(intf, nullmodem == '+');
	if (mctrl_mask)
		serialecho_set_modem_lines(intf, mctrl_mask, mctrl);

out:
	kfree(str);

	return rv;
}

static DEVICE_ATTR(ctrl, S_IWUSR | S_IWGRP,
		   NULL, serialecho_ctrl_op);

static struct attribute *serialecho_dev_attrs[] = {
	&dev_attr_ctrl.attr,
	NULL,
};

static struct attribute_group serialecho_dev_attr_group = {
	.attrs = serialecho_dev_attrs,
};

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
		intf->do_null_modem = true;
		spin_lock_init(&intf->mctrl_lock);
		tasklet_init(&intf->mctrl_tasklet, mctrl_tasklet, (long) intf);
		/* Won't configure without some I/O or mem address set. */
		port->iobase = 1;
		port->line = i;
		port->flags = UPF_BOOT_AUTOCONF;
		port->ops = &serialecho_ops;
		spin_lock_init(&port->lock);
		port->attr_group = &serialecho_dev_attr_group;
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
		intfa->do_null_modem = true;
		intfb->do_null_modem = true;
		spin_lock_init(&intfa->mctrl_lock);
		spin_lock_init(&intfb->mctrl_lock);
		tasklet_init(&intfa->mctrl_tasklet, mctrl_tasklet,
			     (long) intfa);
		tasklet_init(&intfb->mctrl_tasklet, mctrl_tasklet,
			     (long) intfb);

		/* Won't configure without some I/O or mem address set. */
		porta->iobase = 1;
		porta->line = i / 2;
		porta->flags = UPF_BOOT_AUTOCONF;
		porta->ops = &serialpipea_ops;
		spin_lock_init(&porta->lock);
		porta->attr_group = &serialecho_dev_attr_group;
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
		portb->attr_group = &serialecho_dev_attr_group;
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
		tasklet_kill(&intf->mctrl_tasklet);
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
		tasklet_kill(&intfa->mctrl_tasklet);
		tasklet_kill(&intfb->mctrl_tasklet);
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
