#!/usr/bin/python
import termioschk
import termios

class basehandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios()

termioschk.test_ser2net_termios("base termios settings", basehandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class cs5handler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CS5,
                                           cflags_mask=termios.CSIZE)

termioschk.test_ser2net_termios("cs5 termios settings", cs5handler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N51\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class cs6handler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CS6,
                                           cflags_mask=termios.CSIZE)

termioschk.test_ser2net_termios("cs6 termios settings", cs6handler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N61\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class cs7handler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CS7,
                                           cflags_mask=termios.CSIZE)

termioschk.test_ser2net_termios("cs7 termios settings", cs7handler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N71\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class cs8handler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CS8,
                                           cflags_mask=termios.CSIZE)

termioschk.test_ser2net_termios("cs8 termios settings", cs8handler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class parevenhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.PARENB,
                                           cflags_mask=termios.PARODD)

termioschk.test_ser2net_termios("even parity termios settings",
                                parevenhandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600E81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class paroddhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=(termios.PARENB
                                                   | termios.PARODD))

termioschk.test_ser2net_termios("odd parity termios settings",
                                paroddhandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600O81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class twostophandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CSTOPB)

termioschk.test_ser2net_termios("2 stop bit termios settings",
                                twostophandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N82\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class xonhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(iflags=(termios.IXON |
                                                   termios.IXOFF))

termioschk.test_ser2net_termios("xon/xoff termios settings",
                                xonhandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N81 XONXOFF\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class rtshandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CRTSCTS)

termioschk.test_ser2net_termios("rts/cts termios settings",
                                rtshandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N81 RTSCTS\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class clocalhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.CLOCAL)

termioschk.test_ser2net_termios("clocal termios settings",
                                clocalhandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N81 LOCAL\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class hupclhandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios(cflags=termios.HUPCL)

termioschk.test_ser2net_termios("hupcl termios settings",
                                hupclhandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N81 " +
                                "HANGUP_WHEN_DONE\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

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

termioschk.test_ser2net_termios("300 baud termios settings",
                                baudhandler(termios.B300),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 300N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("600 baud termios settings",
                                baudhandler(termios.B600),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 600N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("1200 baud termios settings",
                                baudhandler(termios.B1200),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 1200N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("2400 baud termios settings",
                                baudhandler(termios.B2400),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 2400N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("4800 baud termios settings",
                                baudhandler(termios.B4800),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 4800N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("9600 baud termios settings",
                                baudhandler(termios.B9600),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 9600N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("19200 baud termios settings",
                                baudhandler(termios.B19200),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 19200N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("38400 baud termios settings",
                                baudhandler(termios.B38400),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 38400N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("57600 baud termios settings",
                                baudhandler(termios.B57600),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 57600N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("115200 baud termios settings",
                                baudhandler(termios.B115200),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 115200N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("230400 baud termios settings",
                                baudhandler(termios.B230400),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b 230400N81\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

# The Python termios module doesn't support above 230400, so we can't
# test it easily here.
