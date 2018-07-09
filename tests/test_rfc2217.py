#!/usr/bin/python
import termioschk
import termios
import time
import genio

class basehandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios()

termioschk.test_ser2net_termios("base rfc2217", basehandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

class cshandler:
    def __init__(self, cs, bits):
        self.cs = cs
        self.bits = bits
        return

    def op(self, io1, io2):
        sio1 = io1.cast_to_sergenio()
        bits = sio1.sg_datasize_s(self.bits)
        if (bits != self.bits):
            raise Exception("Bit value was not set, set to %d, got %d" %
                            (self.bits, bits))
        return termioschk.dup_base_termios(cflags=self.cs,
                                           cflags_mask=termios.CSIZE)

termioschk.test_ser2net_termios("cs5 rfc2217 settings",
                                cshandler(termios.CS5, 5),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("cs6 rfc2217 settings",
                                cshandler(termios.CS6, 6),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("cs7 rfc2217 settings",
                                cshandler(termios.CS7, 7),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("cs8 rfc2217 settings",
                                cshandler(termios.CS8, 8),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

class parhandler:
    def __init__(self, tval, val):
        self.tval = tval
        self.val = val
        return

    def op(self, io1, io2):
        sio1 = io1.cast_to_sergenio()
        sio1.sg_parity_s(self.val)
        return termioschk.dup_base_termios(cflags=self.tval,
                                           cflags_mask=(termios.PARODD |
                                                        termios.PARENB))

termioschk.test_ser2net_termios("even parity rfc2217 settings",
                                parhandler(termios.PARENB,
                                           genio.SERGENIO_PARITY_EVEN),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("odd parity rfc2217 settings",
                                parhandler(termios.PARENB | termios.PARODD,
                                           genio.SERGENIO_PARITY_ODD),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

class twostophandler:
    def op(self, io1, io2):
        sio1 = io1.cast_to_sergenio()
        sio1.sg_stopbits_s(2)
        return termioschk.dup_base_termios(cflags=termios.CSTOPB)

termioschk.test_ser2net_termios("2 stop bit termios settings",
                                twostophandler(),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

class baudhandler:
    def __init__(self, tval, val):
        self.tval = tval
        self.val = val
        return

    def op(self, io1, io2):
        sio1 = io1.cast_to_sergenio()
        sio1.sg_baud_s(self.val)
        t = termioschk.dup_base_termios(cflags=self.tval,
                                        cflags_mask=termios.CBAUD)
        t[4] = self.tval
        t[5] = self.tval
        return t

termioschk.test_ser2net_termios("300 baud termios settings",
                                baudhandler(termios.B300, 300),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("600 baud termios settings",
                                baudhandler(termios.B600, 600),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("1200 baud termios settings",
                                baudhandler(termios.B1200, 1200),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("2400 baud termios settings",
                                baudhandler(termios.B2400, 2400),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("4800 baud termios settings",
                                baudhandler(termios.B4800, 4800),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("9600 baud termios settings",
                                baudhandler(termios.B9600, 9600),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("19200 baud termios settings",
                                baudhandler(termios.B19200, 19200),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("38400 baud termios settings",
                                baudhandler(termios.B38400, 38400),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("57600 baud termios settings",
                                baudhandler(termios.B57600, 57600),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("115200 baud termios settings",
                                baudhandler(termios.B115200, 115200),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("230400 baud termios settings",
                                baudhandler(termios.B230400, 230400),
        "BANNER:b:12345\n    3023:telnet:100:/dev/ttyPipeA0:b remctl\n",
        "ser,telnet,tcp,localhost,3023",
        "ser,termios,/dev/ttyPipeB0,9600N81")
