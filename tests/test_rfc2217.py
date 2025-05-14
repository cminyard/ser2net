#!/usr/bin/python3
import termioschk
import termios
import time
import gensio
import utils
from serialsim import *

class basehandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios()

termioschk.test_ser2net_termios("base rfc2217", basehandler(),
        ("connection: &con",
         "  accepter: telnet,tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0",
         "  options:",
         "    banner: 12345"),
        "telnet,tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class cshandler:
    def __init__(self, cs, bits):
        self.cs = cs
        self.bits = str(bits)
        return

    def op(self, io1, io2):
        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_DATASIZE,
                       self.bits, -1)
        bits = io1.acontrol_s(0, gensio.GENSIO_CONTROL_GET,
                              gensio.GENSIO_ACONTROL_SER_DATASIZE,
                              "", -1)
        if (bits != self.bits):
            raise Exception("Bit value was not set, set to %s, got %s" %
                            (self.bits, str(bits)))
        return termioschk.dup_base_termios(cflags=self.cs,
                                           cflags_mask=termios.CSIZE)

# Check that setting termios fails if rfc2217 isn't set.
goterr = False
try:
    termioschk.test_ser2net_termios("rfc2217 setting fail on rfc2217 not set",
                                    cshandler(termios.CS5, 5),
        ("connection: &con",
         "  accepter: telnet(rfc2217=false),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
          "telnet(rfc2217),tcp,localhost,3023",
          "serialdev,/dev/ttyPipeB0,9600N81")
except Exception as E:
    if str(E) != "gensio:acontrol_s: Operation not supported":
        raise
    print("  Success")
    goterr = True
if not goterr:
    raise Exception("Did not get error setting telnet rfc2217 when disabled.")

termioschk.test_ser2net_termios("cs5 rfc2217 settings",
                                cshandler(termios.CS5, 5),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("cs6 rfc2217 settings",
                                cshandler(termios.CS6, 6),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("cs7 rfc2217 settings",
                                cshandler(termios.CS7, 7),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("cs8 rfc2217 settings",
                                cshandler(termios.CS8, 8),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class parhandler:
    def __init__(self, tval, val):
        self.tval = tval
        self.val = val
        return

    def op(self, io1, io2):
        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_PARITY,
                       self.val, -1)
        return termioschk.dup_base_termios(cflags=self.tval,
                                           cflags_mask=(termios.PARODD |
                                                        termios.PARENB))

termioschk.test_ser2net_termios("even parity rfc2217 settings",
                                parhandler(termios.PARENB, "even"),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("odd parity rfc2217 settings",
                                parhandler(termios.PARENB | termios.PARODD,
                                           "odd"),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class twostophandler:
    def op(self, io1, io2):
        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_STOPBITS,
                       "2", -1)
        return termioschk.dup_base_termios(cflags=termios.CSTOPB)

termioschk.test_ser2net_termios("2 stop bit rfx2217 settings",
                                twostophandler(),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class xonhandler:
    def op(self, io1, io2):
        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_FLOWCONTROL,
                       "xonxoff", -1)
        return termioschk.dup_base_termios(iflags=termios.IXON | termios.IXOFF)

termioschk.test_ser2net_termios("xon/xoff rfc2217 settings",
                                xonhandler(),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class rtshandler:
    def op(self, io1, io2):
        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_FLOWCONTROL,
                       "rtscts", -1)
        return termioschk.dup_base_termios(cflags=termios.CRTSCTS)

termioschk.test_ser2net_termios("xon/xoff rfc2217 settings",
                                xonhandler(),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

class baudhandler:
    def __init__(self, tval, val):
        self.tval = tval
        self.val = str(val)
        return

    def op(self, io1, io2):
        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_BAUD,
                       self.val, -1)
        t = termioschk.dup_base_termios(cflags=self.tval,
                                        cflags_mask=termios.CBAUD)
        t[4] = self.tval
        t[5] = self.tval
        return t

termioschk.test_ser2net_termios("300 baud rfc2217 settings",
                                baudhandler(termios.B300, 300),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("600 baud rfc2217 settings",
                                baudhandler(termios.B600, 600),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("1200 baud rfc2217 settings",
                                baudhandler(termios.B1200, 1200),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("2400 baud rfc2217 settings",
                                baudhandler(termios.B2400, 2400),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("4800 baud rfc2217 settings",
                                baudhandler(termios.B4800, 4800),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("9600 baud rfc2217 settings",
                                baudhandler(termios.B9600, 9600),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("19200 baud rfc2217 settings",
                                baudhandler(termios.B19200, 19200),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("38400 baud rfc2217 settings",
                                baudhandler(termios.B38400, 38400),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("57600 baud rfc2217 settings",
                                baudhandler(termios.B57600, 57600),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("115200 baud rfc2217 settings",
                                baudhandler(termios.B115200, 115200),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("230400 baud rfc2217 settings",
                                baudhandler(termios.B230400, 230400),
        ("connection: &con",
         "  accepter: telnet(rfc2217),tcp,3023",
         "  connector: serialdev,/dev/ttyPipeA0,9600n81",
         "  options:",
         "    banner: 12345"),
        "telnet(rfc2217),tcp,localhost,3023",
        "serialdev,/dev/ttyPipeB0,9600N81")

def test_dtr():
    config = ("connection: &con",
              "  accepter: telnet(rfc2217),tcp,3023",
              "  connector: serialdev,/dev/ttyPipeA0,9600n81",
              "  options:",
              "    banner: 12345")
    io1str = "telnet(rfc2217),tcp,localhost,3023"
    io2str = "serialdev,/dev/ttyPipeB0,9600N81"

    print("serialdev dtr rfc2217:\n  config=%s  io1=%s\n  io2=%s" %
          (config, io1str, io2str))

    o = utils.o
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
    try:
        io1.handler.set_compare("12345")
        if (io1.handler.wait_timeout(1000) == 0):
            raise Exception("%s: %s: Timed out waiting for banner" %
                            ("test dtr", io1.handler.name))

        io1.read_cb_enable(True);
        io2.read_cb_enable(True);

        set_remote_null_modem(utils.remote_id_int(io2), False);

        val = io1.acontrol_s(0, gensio.GENSIO_CONTROL_GET,
                             gensio.GENSIO_ACONTROL_SER_DTR,
                             "", -1)
        if (val != "on"):
            raise Exception("Expected DTR on at start, got %d" % val);
        val = get_remote_modem_ctl(utils.remote_id_int(io2))
        if (not (val & SERIALSIM_TIOCM_DTR)):
            raise Exception("Expected remote DTR on at start");

        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_DTR,
                       "off", -1)
        val = io1.acontrol_s(0, gensio.GENSIO_CONTROL_GET,
                             gensio.GENSIO_ACONTROL_SER_DTR,
                             "", -1)
        if (val != "off"):
            raise Exception("Expected DTR off");
        val = get_remote_modem_ctl(utils.remote_id_int(io2))
        if (val & SERIALSIM_TIOCM_DTR):
            raise Exception("Expected remote DTR off");

        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_DTR,
                       "on", -1)
        val = io1.acontrol_s(0, gensio.GENSIO_CONTROL_GET,
                             gensio.GENSIO_ACONTROL_SER_DTR,
                             "", -1)
        if (val != "on"):
            raise Exception("Expected DTR on");
        val = get_remote_modem_ctl(utils.remote_id_int(io2))
        if (not (val & SERIALSIM_TIOCM_DTR)):
            raise Exception("Expected remote DTR on");

        set_remote_null_modem(utils.remote_id_int(io2), True);
    except:
        utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
        raise
    utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
    print("  Success!")
    return

test_dtr()

def test_rts():
    config = ("connection: &con",
              "  accepter: telnet(rfc2217),tcp,3023",
              "  connector: serialdev,/dev/ttyPipeA0,9600n81",
              "  options:",
              "    banner: 12345")
    io1str = "telnet(rfc2217),tcp,localhost,3023"
    io2str = "serialdev,/dev/ttyPipeB0,9600N81"

    print("serialdev rts rfc2217:\n  config=%s  io1=%s\n  io2=%s" %
          (config, io1str, io2str))

    o = utils.o
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)

    try:
        io1.handler.set_compare("12345")
        if (io1.handler.wait_timeout(1000) == 0):
            raise Exception("%s: %s: Timed out waiting for banner" %
                            (io1.handler.name))

        io1.read_cb_enable(True);
        io2.read_cb_enable(True);

        set_remote_null_modem(utils.remote_id_int(io2), False);

        val = io1.acontrol_s(0, gensio.GENSIO_CONTROL_GET,
                             gensio.GENSIO_ACONTROL_SER_RTS,
                             "", -1)
        if (val != "on"):
            raise Exception("Expected RTS on at start, got %d" % val);
        val = get_remote_modem_ctl(utils.remote_id_int(io2))
        if (not (val & SERIALSIM_TIOCM_RTS)):
            raise Exception("Expected remote RTS on at start");

        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_RTS,
                       "off", -1)
        val = io1.acontrol_s(0, gensio.GENSIO_CONTROL_GET,
                             gensio.GENSIO_ACONTROL_SER_RTS,
                             "", -1)
        if (val != "off"):
            raise Exception("Expected RTS off");
        val = get_remote_modem_ctl(utils.remote_id_int(io2))
        if (val & SERIALSIM_TIOCM_RTS):
            raise Exception("Expected remote RTS off");

        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_RTS,
                       "on", -1)
        val = io1.acontrol_s(0, gensio.GENSIO_CONTROL_GET,
                             gensio.GENSIO_ACONTROL_SER_RTS,
                             "", -1)
        if (val != "on"):
            raise Exception("Expected RTS on");
        val = get_remote_modem_ctl(utils.remote_id_int(io2))
        if (not (val & SERIALSIM_TIOCM_RTS)):
            raise Exception("Expected remote RTS on");

        set_remote_null_modem(utils.remote_id_int(io2), True);
    except:
        utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
        raise
    utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
    print("  Success!")
    return

test_rts()

class CtrlRspHandler:
    def __init__(self, o, val):
        self.val = val
        self.waiter = gensio.waiter(o)
        return

    def control_done(self, io, err, value):
        if (err):
            raise Exception("Error getting signature: %s" % err)
        value = value.decode(encoding='utf-8')
        if (value != str(self.val)):
            raise Exception("Value was '%s', expected '%s'" %
                            (value, self.val))
        self.waiter.wake();
        return

    def wait_timeout(self, timeout):
        return self.waiter.wait_timeout(1, timeout)

def test_flush():
    config = ("connection: &con",
              "  accepter: telnet(rfc2217),tcp,3023",
              "  connector: serialdev,/dev/ttyPipeA0,9600n81,local")
    io1str = "telnet(rfc2217),tcp,localhost,3023"
    io2str = "serialdev,/dev/ttyPipeB0,9600N81,local"

    print("serialdev flush rfc2217:\n  config=%s  io1=%s\n  io2=%s" %
          (config, io1str, io2str))

    o = utils.o
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)

    try:
        gensio.GENSIO_ACONTROL_SER_FLUSH
    except:
        print("  Unsupported!")
        return

    try:
        io1.read_cb_enable(True);
        io1.handler.set_expected_flush(1)
        h = CtrlRspHandler(o, "recv")
        io1.acontrol(0, gensio.GENSIO_CONTROL_SET,
                     gensio.GENSIO_ACONTROL_SER_FLUSH,
                     "recv", h, -1)
        if h.wait_timeout(1000) == 0:
            raise Exception("Timeout waiting for client flush response")
    except:
        utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
        raise
    utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
    print("  Success!")
    return

test_flush()

def test_modemstate():
    config = ("connection: &con",
              "  accepter: telnet(rfc2217),tcp,3023",
              "  connector: serialdev,/dev/ttyPipeA0,9600n81,local")
    io1str = "telnet(rfc2217),tcp,localhost,3023"
    io2str = "serialdev,/dev/ttyPipeB0,9600N81"

    print("serialdev modemstate rfc2217:\n  config=%s  io1=%s\n  io2=%s" %
          (config, io1str, io2str))

    o = utils.o
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str,
                                              do_io1_open = False)
    try:
        io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_DTR,
                       "off", -1);
        io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_RTS,
                       "off", -1);
        set_remote_null_modem(utils.remote_id_int(io2), False);
        set_remote_modem_ctl(utils.remote_id_int(io2),
                             (SERIALSIM_TIOCM_CAR |
                              SERIALSIM_TIOCM_CTS |
                              SERIALSIM_TIOCM_DSR |
                              SERIALSIM_TIOCM_RNG) << 16)

        io1.handler.set_expected_modemstate(0)
        io1.open_s()
        io1.read_cb_enable(True);
        if (io1.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for modemstate 1" %
                            ("test modemstate", io1.handler.name))

        io2.read_cb_enable(True);

        io1.handler.set_expected_modemstate(
            gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_CD)
        set_remote_modem_ctl(utils.remote_id_int(io2),
                             ((SERIALSIM_TIOCM_CAR << 16) |
                              SERIALSIM_TIOCM_CAR))
        if (io1.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for modemstate 2" %
                            ("test modemstate", io1.handler.name))

        io1.handler.set_expected_modemstate(
            gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_CD |
            gensio.GENSIO_SER_MODEMSTATE_DSR)
        set_remote_modem_ctl(utils.remote_id_int(io2),
                             ((SERIALSIM_TIOCM_DSR << 16) |
                              SERIALSIM_TIOCM_DSR))
        if (io1.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for modemstate 3" %
                            ("test modemstate", io1.handler.name))

        io1.handler.set_expected_modemstate(
            gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_CD |
            gensio.GENSIO_SER_MODEMSTATE_DSR |
            gensio.GENSIO_SER_MODEMSTATE_CTS)
        set_remote_modem_ctl(utils.remote_id_int(io2),
                             ((SERIALSIM_TIOCM_CTS << 16) |
                              SERIALSIM_TIOCM_CTS))
        if (io1.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for modemstate 4" %
                            ("test modemstate", io1.handler.name))

        io1.handler.set_expected_modemstate(
            gensio.GENSIO_SER_MODEMSTATE_RI_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_CD |
            gensio.GENSIO_SER_MODEMSTATE_DSR |
            gensio.GENSIO_SER_MODEMSTATE_CTS |
            gensio.GENSIO_SER_MODEMSTATE_RI)
        set_remote_modem_ctl(utils.remote_id_int(io2),
                             ((SERIALSIM_TIOCM_RNG << 16) |
                              SERIALSIM_TIOCM_RNG))
        if (io1.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for modemstate 5" %
                            ("test modemstate", io1.handler.name))

        io1.handler.set_expected_modemstate(
            gensio.GENSIO_SER_MODEMSTATE_RI_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED)
        set_remote_modem_ctl(utils.remote_id_int(io2),
                             (SERIALSIM_TIOCM_CAR |
                              SERIALSIM_TIOCM_CTS |
                              SERIALSIM_TIOCM_DSR |
                              SERIALSIM_TIOCM_RNG) << 16)
        if (io1.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for modemstate 6" %
                            ("test modemstate", io1.handler.name))

        io1.handler.set_expected_modemstate(
            gensio.GENSIO_SER_MODEMSTATE_CD_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_DSR_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_CTS_CHANGED |
            gensio.GENSIO_SER_MODEMSTATE_CD |
            gensio.GENSIO_SER_MODEMSTATE_DSR |
            gensio.GENSIO_SER_MODEMSTATE_CTS)
        io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_DTR,
                       "on", -1);
        io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_RTS,
                       "on", -1);
        set_remote_null_modem(utils.remote_id_int(io2), True);
        if (io1.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for modemstate 7" %
                            ("test modemstate", io1.handler.name))
    except:
        utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
        raise
    utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
    print("  Success!")
    return

test_modemstate()

def test_linestate():
    config = ("connection: &con",
              "  accepter: telnet(rfc2217),tcp,3023",
              "  connector: serialdev,/dev/ttyPipeA0,9600n81,local")
    io1str = "telnet(rfc2217),tcp,localhost,3023"
    io2str = "serialdev,/dev/ttyPipeB0,9600N81,local"

    print("serialdev linestate rfc2217:\n  config=%s  io1=%s\n  io2=%s" %
          (config, io1str, io2str))

    o = utils.o
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
    try:
        utils.test_dataxfer(io1, io2, "a\xffx\xff\xffy")

        io2.read_cb_enable(True);
        io2.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_SET_LINESTATE_MASK,
                       str(gensio.GENSIO_SER_LINESTATE_BREAK |
                           gensio.GENSIO_SER_LINESTATE_PARITY_ERR), -1)

        io2.handler.set_expected_linestate(gensio.GENSIO_SER_LINESTATE_BREAK)
        io2.read_cb_enable(True);
        io1.control(0, gensio.GENSIO_CONTROL_SET,
                    gensio.GENSIO_CONTROL_SER_SEND_BREAK, "")

        if (io2.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for linestate 1" %
                            ("test linestate", io1.handler.name))

        io1.read_cb_enable(True);
        io1.acontrol_s(0, gensio.GENSIO_CONTROL_SET,
                       gensio.GENSIO_ACONTROL_SER_SET_LINESTATE_MASK,
                       str(gensio.GENSIO_SER_LINESTATE_BREAK |
                           gensio.GENSIO_SER_LINESTATE_PARITY_ERR), -1)
        # If youdon't do a synchronous call above, the sent break below
        # may happen before the linestate mask is set.

        io1.handler.set_expected_linestate(gensio.GENSIO_SER_LINESTATE_BREAK)
        io1.read_cb_enable(True);
        io2.control(0, gensio.GENSIO_CONTROL_SET,
                    gensio.GENSIO_CONTROL_SER_SEND_BREAK, "")
        if (io1.handler.wait_timeout(2000) == 0):
            raise Exception("%s: %s: Timed out waiting for linestate 2" %
                            ("test linestate", io1.handler.name))
    except:
        utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
        raise
    utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
    print("  Success!")
    return

test_linestate()
