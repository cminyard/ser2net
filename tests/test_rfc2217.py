#!/usr/bin/python
import termioschk
import termios
import time
import gensio
import utils

class basehandler:
    def op(self, io1, io2):
        return termioschk.dup_base_termios()

termioschk.test_ser2net_termios("base rfc2217", basehandler(),
        "BANNER:b:12345\ntelnet,3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class cshandler:
    def __init__(self, cs, bits):
        self.cs = cs
        self.bits = bits
        return

    def op(self, io1, io2):
        sio1 = io1.cast_to_sergensio()
        bits = sio1.sg_datasize_s(self.bits)
        if (bits != self.bits):
            raise Exception("Bit value was not set, set to %d, got %d" %
                            (self.bits, bits))
        return termioschk.dup_base_termios(cflags=self.cs,
                                           cflags_mask=termios.CSIZE)

# Check that setting termios fails if rfc2217 isn't set.
goterr = False
try:
    termioschk.test_ser2net_termios("rfc2217 setting fail on rfc2217 not set",
                                    cshandler(termios.CS5, 5),
          "BANNER:b:12345\ntelnet(rfc2217=false),3023:raw:100:/dev/ttyPipeA0:b\n",
          "telnet,tcp,localhost,3023",
          "termios,/dev/ttyPipeB0,9600N81")
except Exception as E:
    if str(E) != "sergensio:sg_datasize_s: Operation not supported":
        raise
    print "  Success"
    goterr = True
if not goterr:
    raise Exception("Did not get error setting telnet rfc2217 when disabled.")

# Check that setting termios fails if local rfc2217 isn't set.
goterr = False
try:
    termioschk.test_ser2net_termios("rfc2217 settings fail on no local rfc2217",
                                    cshandler(termios.CS5, 5),
            "BANNER:b:12345\ntelnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
            "telnet(rfc2217=0),tcp,localhost,3023",
            "termios,/dev/ttyPipeB0,9600N81")
except RuntimeError as E:
    if str(E) != "Error casting from gensio to sergensio":
        raise
    print "  Success"
    goterr = True
if not goterr:
    raise Exception("Did not get error setting telnet rfc2217 when disabled.")

termioschk.test_ser2net_termios("cs5 rfc2217 settings",
                                cshandler(termios.CS5, 5),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("cs6 rfc2217 settings",
                                cshandler(termios.CS6, 6),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("cs7 rfc2217 settings",
                                cshandler(termios.CS7, 7),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("cs8 rfc2217 settings",
                                cshandler(termios.CS8, 8),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class parhandler:
    def __init__(self, tval, val):
        self.tval = tval
        self.val = val
        return

    def op(self, io1, io2):
        sio1 = io1.cast_to_sergensio()
        sio1.sg_parity_s(self.val)
        return termioschk.dup_base_termios(cflags=self.tval,
                                           cflags_mask=(termios.PARODD |
                                                        termios.PARENB))

termioschk.test_ser2net_termios("even parity rfc2217 settings",
                                parhandler(termios.PARENB,
                                           gensio.SERGENSIO_PARITY_EVEN),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("odd parity rfc2217 settings",
                                parhandler(termios.PARENB | termios.PARODD,
                                           gensio.SERGENSIO_PARITY_ODD),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class twostophandler:
    def op(self, io1, io2):
        sio1 = io1.cast_to_sergensio()
        sio1.sg_stopbits_s(2)
        return termioschk.dup_base_termios(cflags=termios.CSTOPB)

termioschk.test_ser2net_termios("2 stop bit rfx2217 settings",
                                twostophandler(),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class xonhandler:
    def op(self, io1, io2):
        sio1 = io1.cast_to_sergensio()
        sio1.sg_flowcontrol_s(gensio.SERGENSIO_FLOWCONTROL_XON_XOFF)
        return termioschk.dup_base_termios(iflags=termios.IXON | termios.IXOFF)

termioschk.test_ser2net_termios("xon/xoff rfc2217 settings",
                                xonhandler(),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class rtshandler:
    def op(self, io1, io2):
        sio1 = io1.cast_to_sergensio()
        sio1.sg_flowcontrol_s(gensio.SERGENSIO_FLOWCONTROL_RTS_CTS)
        return termioschk.dup_base_termios(cflags=termios.CRTSCTS)

termioschk.test_ser2net_termios("xon/xoff rfc2217 settings",
                                xonhandler(),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

class baudhandler:
    def __init__(self, tval, val):
        self.tval = tval
        self.val = val
        return

    def op(self, io1, io2):
        sio1 = io1.cast_to_sergensio()
        sio1.sg_baud_s(self.val)
        t = termioschk.dup_base_termios(cflags=self.tval,
                                        cflags_mask=termios.CBAUD)
        t[4] = self.tval
        t[5] = self.tval
        return t

termioschk.test_ser2net_termios("300 baud rfc2217 settings",
                                baudhandler(termios.B300, 300),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("600 baud rfc2217 settings",
                                baudhandler(termios.B600, 600),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("1200 baud rfc2217 settings",
                                baudhandler(termios.B1200, 1200),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("2400 baud rfc2217 settings",
                                baudhandler(termios.B2400, 2400),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("4800 baud rfc2217 settings",
                                baudhandler(termios.B4800, 4800),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("9600 baud rfc2217 settings",
                                baudhandler(termios.B9600, 9600),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("19200 baud rfc2217 settings",
                                baudhandler(termios.B19200, 19200),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("38400 baud rfc2217 settings",
                                baudhandler(termios.B38400, 38400),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("57600 baud rfc2217 settings",
                                baudhandler(termios.B57600, 57600),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("115200 baud rfc2217 settings",
                                baudhandler(termios.B115200, 115200),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

termioschk.test_ser2net_termios("230400 baud rfc2217 settings",
                                baudhandler(termios.B230400, 230400),
        "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n",
        "telnet,tcp,localhost,3023",
        "termios,/dev/ttyPipeB0,9600N81")

def test_dtr():
    config = "BANNER:b:12345\n    telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n"
    io1str = "telnet,tcp,localhost,3023"
    io2str = "termios,/dev/ttyPipeB0,9600N81"

    print("termios dtr rfc2217:\n  config=%s  io1=%s\n  io2=%s" %
          (config, io1str, io2str))

    o = gensio.alloc_gensio_selector()
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
    sio1 = io1.cast_to_sergensio()
    sio2 = io2.cast_to_sergensio()
    io1.handler.set_compare("12345")
    if (io1.handler.wait_timeout(1000)):
        raise Exception("%s: %s: Timed out waiting for banner" %
                        ("test dtr", io1.handler.name))

    io1.read_cb_enable(True);
    io2.read_cb_enable(True);

    sio2.set_remote_null_modem(False);

    val = sio1.sg_dtr_s(0)
    if (val != gensio.SERGENSIO_DTR_ON):
        raise Exception("Expected DTR on at start, got %d" % val);
    val = sio2.get_remote_modem_ctl()
    if (not (val & gensio.SERGENSIO_TIOCM_DTR)):
        raise Exception("Expected remote DTR on at start");

    val = sio1.sg_dtr_s(gensio.SERGENSIO_DTR_OFF)
    if (val != gensio.SERGENSIO_DTR_OFF):
        raise Exception("Expected DTR off");
    val = sio2.get_remote_modem_ctl()
    if (val & gensio.SERGENSIO_TIOCM_DTR):
        raise Exception("Expected remote DTR off");

    val = sio1.sg_dtr_s(gensio.SERGENSIO_DTR_ON)
    if (val != gensio.SERGENSIO_DTR_ON):
        raise Exception("Expected DTR on");
    val = sio2.get_remote_modem_ctl()
    if (not (val & gensio.SERGENSIO_TIOCM_DTR)):
        raise Exception("Expected remote DTR on");

    sio2.set_remote_null_modem(True);
    utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
    print("  Success!")
    return

test_dtr()

def test_rts():
    config = "BANNER:b:12345\ntelnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:b\n"
    io1str = "telnet,tcp,localhost,3023"
    io2str = "termios,/dev/ttyPipeB0,9600N81"

    print("termios rts rfc2217:\n  config=%s  io1=%s\n  io2=%s" %
          (config, io1str, io2str))

    o = gensio.alloc_gensio_selector()
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
    sio1 = io1.cast_to_sergensio()
    sio2 = io2.cast_to_sergensio()
    io1.handler.set_compare("12345")
    if (io1.handler.wait_timeout(1000)):
        raise Exception("%s: %s: Timed out waiting for banner" %
                        (name, io1.handler.name))

    io1.read_cb_enable(True);
    io2.read_cb_enable(True);

    sio2.set_remote_null_modem(False);

    val = sio1.sg_rts_s(0)
    if (val != gensio.SERGENSIO_RTS_ON):
        raise Exception("Expected RTS on at start, got %d" % val);
    val = sio2.get_remote_modem_ctl()
    if (not (val & gensio.SERGENSIO_TIOCM_RTS)):
        raise Exception("Expected remote RTS on at start");

    val = sio1.sg_rts_s(gensio.SERGENSIO_RTS_OFF)
    if (val != gensio.SERGENSIO_RTS_OFF):
        raise Exception("Expected RTS off");
    val = sio2.get_remote_modem_ctl()
    if (val & gensio.SERGENSIO_TIOCM_RTS):
        raise Exception("Expected remote RTS off");

    val = sio1.sg_rts_s(gensio.SERGENSIO_RTS_ON)
    if (val != gensio.SERGENSIO_RTS_ON):
        raise Exception("Expected RTS on");
    val = sio2.get_remote_modem_ctl()
    if (not (val & gensio.SERGENSIO_TIOCM_RTS)):
        raise Exception("Expected remote RTS on");

    sio2.set_remote_null_modem(True);
    utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
    print("  Success!")
    return

test_rts()

def test_modemstate():
    config = "telnet(rfc2217),3023:raw:100:/dev/ttyPipeA0:remctl LOCAL\n"
    io1str = "telnet,tcp,localhost,3023"
    io2str = "termios,/dev/ttyPipeB0,9600N81"

    print("termios modemstate rfc2217:\n  config=%s  io1=%s\n  io2=%s" %
          (config, io1str, io2str))

    o = gensio.alloc_gensio_selector()
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str,
                                              do_io1_open = False)
    sio1 = io1.cast_to_sergensio()
    sio2 = io2.cast_to_sergensio()

    sio2.set_remote_null_modem(False);
    sio2.set_remote_modem_ctl((gensio.SERGENSIO_TIOCM_CAR |
                               gensio.SERGENSIO_TIOCM_CTS |
                               gensio.SERGENSIO_TIOCM_DSR |
                               gensio.SERGENSIO_TIOCM_RNG) << 16)

    io1.handler.set_expected_modemstate(0)
    io1.open_s()
    io1.read_cb_enable(True);
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 1" %
                        ("test dtr", io1.handler.name))

    io2.read_cb_enable(True);

    io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_CD)
    sio2.set_remote_modem_ctl((gensio.SERGENSIO_TIOCM_CAR << 16) |
                              gensio.SERGENSIO_TIOCM_CAR)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 2" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_CD |
                                        gensio.SERGENSIO_MODEMSTATE_DSR)
    sio2.set_remote_modem_ctl((gensio.SERGENSIO_TIOCM_DSR << 16) |
                              gensio.SERGENSIO_TIOCM_DSR)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 3" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_CD |
                                        gensio.SERGENSIO_MODEMSTATE_DSR |
                                        gensio.SERGENSIO_MODEMSTATE_CTS)
    sio2.set_remote_modem_ctl((gensio.SERGENSIO_TIOCM_CTS << 16) |
                              gensio.SERGENSIO_TIOCM_CTS)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 4" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_RI_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_CD |
                                        gensio.SERGENSIO_MODEMSTATE_DSR |
                                        gensio.SERGENSIO_MODEMSTATE_CTS |
                                        gensio.SERGENSIO_MODEMSTATE_RI)
    sio2.set_remote_modem_ctl((gensio.SERGENSIO_TIOCM_RNG << 16) |
                              gensio.SERGENSIO_TIOCM_RNG)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 5" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_RI_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED)
    sio2.set_remote_modem_ctl((gensio.SERGENSIO_TIOCM_CAR |
                               gensio.SERGENSIO_TIOCM_CTS |
                               gensio.SERGENSIO_TIOCM_DSR |
                               gensio.SERGENSIO_TIOCM_RNG) << 16)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 6" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(gensio.SERGENSIO_MODEMSTATE_CD_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_DSR_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_CTS_CHANGED |
                                        gensio.SERGENSIO_MODEMSTATE_CD |
                                        gensio.SERGENSIO_MODEMSTATE_DSR |
                                        gensio.SERGENSIO_MODEMSTATE_CTS)
    sio2.set_remote_null_modem(True);
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 7" %
                        ("test dtr", io1.handler.name))

    utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
    print("  Success!")
    return

test_modemstate()
