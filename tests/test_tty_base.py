#!/usr/bin/python3
import termioschk
import termios
import utils

class basehandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios()

termioschk.test_ser2net_termios("base termios settings", basehandler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class cs5handler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CS5,
                                           cflags_mask=termios.CSIZE)

termioschk.test_ser2net_termios("cs5 termios settings", cs5handler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n51",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class cs6handler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CS6,
                                           cflags_mask=termios.CSIZE)

termioschk.test_ser2net_termios("cs6 termios settings", cs6handler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n61",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class cs7handler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CS7,
                                           cflags_mask=termios.CSIZE)

termioschk.test_ser2net_termios("cs7 termios settings", cs7handler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n71",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class cs8handler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CS8,
                                           cflags_mask=termios.CSIZE)

termioschk.test_ser2net_termios("cs8 termios settings", cs8handler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class parevenhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.PARENB,
                                           cflags_mask=termios.PARODD)

termioschk.test_ser2net_termios("even parity termios settings",
                                parevenhandler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600E81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class paroddhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=(termios.PARENB
                                                   | termios.PARODD))

termioschk.test_ser2net_termios("odd parity termios settings",
                                paroddhandler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600o81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class twostophandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CSTOPB)

termioschk.test_ser2net_termios("2 stop bit termios settings",
                                twostophandler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n82",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class xonhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(iflags=(termios.IXON |
                                                   termios.IXOFF))

termioschk.test_ser2net_termios("xon/xoff termios settings",
                                xonhandler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81,xonxoff",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class rtshandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CRTSCTS)

termioschk.test_ser2net_termios("rts/cts termios settings",
                                rtshandler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81,rtscts",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class clocalhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CLOCAL)

termioschk.test_ser2net_termios("clocal termios settings",
                                clocalhandler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81,local",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class hupclhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.HUPCL)

termioschk.test_ser2net_termios("hupcl termios settings",
                                hupclhandler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81,hangup-when-done",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class baudhandler:
    def __init__(self, speed):
        self.baud = speed;
        return

    def op(self, io1, io2):
        t = termioschk.dup_base_termios(cflags=self.baud,
                                        cflags_mask = termios.CBAUD)
        t[4] = self.baud
        t[5] = self.baud
        return t

termioschk.test_ser2net_termios("300 baud serialdev settings",
                                baudhandler(termios.B300),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,300n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("600 baud serialdev settings",
                                baudhandler(termios.B600),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,600n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("1200 baud serialdev settings",
                                baudhandler(termios.B1200),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,1200n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("2400 baud serialdev settings",
                                baudhandler(termios.B2400),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,2400n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("4800 baud serialdev settings",
                                baudhandler(termios.B4800),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,4800n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("9600 baud serialdev settings",
                                baudhandler(termios.B9600),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("19200 baud serialdev settings",
                                baudhandler(termios.B19200),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,19200n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("38400 baud serialdev settings",
                                baudhandler(termios.B38400),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,38400n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("57600 baud serialdev settings",
                                baudhandler(termios.B57600),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,57600n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("115200 baud serialdev settings",
                                baudhandler(termios.B115200),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,115200n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("230400 baud serialdev settings",
                                baudhandler(termios.B230400),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,230400n81",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

# The Python termios module doesn't support above 230400, so we can't
# test it easily here.
