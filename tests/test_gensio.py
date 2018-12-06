#!/usr/bin/python
import utils
import gensio

o = gensio.alloc_gensio_selector();

def test_echo_device():
    print("Test echo device")
    io = utils.alloc_io(o, "termios,/dev/ttyEcho0,38400")
    utils.test_dataxfer(io, io, "This is a test string!")
    utils.io_close(io)
    print("  Success!")

def test_serial_pipe_device():
    print("Test serial pipe device")
    io1 = utils.alloc_io(o, "termios,/dev/ttyPipeA0,9600")
    io2 = utils.alloc_io(o, "termios,/dev/ttyPipeB0,9600")
    utils.test_dataxfer(io1, io2, "This is a test string!")
    utils.io_close(io1)
    utils.io_close(io2)
    print("  Success!")

class TestAccept:
    def __init__(self, o, io1, iostr, tester, name = None,
                 io1_dummy_write = None):
        self.o = o
        if (name):
            self.name = name
        else:
            self.name = iostr
        self.io1 = io1
        self.waiter = gensio.waiter(o)
        self.acc = gensio.gensio_accepter(o, iostr, self);
        self.acc.startup()
        io1.open_s()
        if (io1_dummy_write):
            # For UDP, kick start things.
            io1.write(io1_dummy_write)
        self.wait()
        if (io1_dummy_write):
            self.io2.handler.set_compare(io1_dummy_write)
            if (self.io2.handler.wait_timeout(1000)):
                raise Exception(("%s: %s: " % ("test_accept",
                                               self.io2.handler.name)) +
                        ("Timed out waiting for dummy read at byte %d" %
                         self.io2.handler.compared))
        tester(self.io1, self.io2)

    def new_connection(self, acc, io):
        utils.HandleData(self.o, None, io = io, name = self.name)
        self.io2 = io
        self.waiter.wake()

    def accepter_log(self, acc, level, logstr):
        print("***%s LOG: %s: %s" % (level, self.name, logstr))

    def wait(self):
        self.waiter.wait(1)

def do_test(io1, io2):
    utils.test_dataxfer(io1, io2, "This is a test string!")
    print("  Success!")

def ta_tcp():
    print("Test accept tcp")
    io1 = utils.alloc_io(o, "tcp,localhost,3023", do_open = False)
    TestAccept(o, io1, "tcp,3023", do_test)

def ta_udp():
    print("Test accept udp")
    io1 = utils.alloc_io(o, "udp,localhost,3023", do_open = False)
    TestAccept(o, io1, "udp,3023", do_test, io1_dummy_write = "A")

def ta_ssl_tcp():
    print("Test accept ssl-tcp")
    io1 = utils.alloc_io(o, "ssl(CA=%s/CA.pem),tcp,localhost,3024" % utils.srcdir, do_open = False)
    ta = TestAccept(o, io1, "ssl(key=%s/key.pem,cert=%s/cert.pem,CA=%s/CA.pem),3024" % (utils.srcdir, utils.srcdir, utils.srcdir), do_test)

def do_telnet_test(io1, io2):
    do_test(io1, io2)
    sio1 = io1.cast_to_sergensio()
    sio2 = io1.cast_to_sergensio()
    io1.read_cb_enable(True);
    io2.read_cb_enable(True);

    io2.handler.set_expected_server_cb("baud", 1000, 2000)
    io1.handler.set_expected_client_cb("baud", 2000)
    sio1.sg_baud(1000, io1.handler)
    if io2.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for server baud set")
    if io1.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for client baud response")

    io2.handler.set_expected_server_cb("datasize", 5, 6)
    io1.handler.set_expected_client_cb("datasize", 6)
    sio1.sg_datasize(5, io1.handler)
    if io2.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for server datasize set")
    if io1.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for client datasize response")

    io2.handler.set_expected_server_cb("parity", 1, 5)
    io1.handler.set_expected_client_cb("parity", 5)
    sio1.sg_parity(1, io1.handler)
    if io2.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for server parity set")
    if io1.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for client parity response")

    io2.handler.set_expected_server_cb("stopbits", 2, 1)
    io1.handler.set_expected_client_cb("stopbits", 1)
    sio1.sg_stopbits(2, io1.handler)
    if io2.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for server stopbits set")
    if io1.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for client stopbits response")

    io2.handler.set_expected_server_cb("flowcontrol", 1, 2)
    io1.handler.set_expected_client_cb("flowcontrol", 2)
    sio1.sg_flowcontrol(1, io1.handler)
    if io2.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for server flowcontrol set")
    if io1.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for client flowcontrol response")

    io2.handler.set_expected_server_cb("iflowcontrol", 3, 4)
    io1.handler.set_expected_client_cb("iflowcontrol", 4)
    sio1.sg_iflowcontrol(3, io1.handler)
    if io2.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for server flowcontrol set")
    if io1.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for client flowcontrol response")

    io2.handler.set_expected_server_cb("sbreak", 2, 1)
    io1.handler.set_expected_client_cb("sbreak", 1)
    sio1.sg_sbreak(2, io1.handler)
    if io2.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for server sbreak set")
    if io1.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for client sbreak response")

    io2.handler.set_expected_server_cb("dtr", 1, 2)
    io1.handler.set_expected_client_cb("dtr", 2)
    sio1.sg_dtr(1, io1.handler)
    if io2.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for server dtr set")
    if io1.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for client dtr response")

    io2.handler.set_expected_server_cb("rts", 2, 1)
    io1.handler.set_expected_client_cb("rts", 1)
    sio1.sg_rts(2, io1.handler)
    if io2.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for server rts set")
    if io1.handler.wait_timeout(1000):
        raise Exception("Timeout waiting for client rts response")
    return

def ta_ssl_telnet():
    print("Test accept ssl telnet")
    io1 = utils.alloc_io(o, "telnet,tcp,localhost,3027", do_open = False)
    ta = TestAccept(o, io1, "telnet(rfc2217=true),3027", do_telnet_test)

def test_modemstate():
    io1str = "termios,/dev/ttyPipeA0,9600N81,LOCAL"
    io2str = "termios,/dev/ttyPipeB0,9600N81"

    print("termios modemstate:\n  io1=%s\n  io2=%s" % (io1str, io2str))

    o = gensio.alloc_gensio_selector()
    io1 = utils.alloc_io(o, io1str, do_open = False)
    io2 = utils.alloc_io(o, io2str)
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

    utils.io_close(io1)
    utils.io_close(io2)
    print("  Success!")
    return

def test_stdio_basic():
    print("Test stdio basic echo")
    io = utils.alloc_io(o, "stdio,cat", chunksize = 64)
    utils.test_dataxfer(io, io, "This is a test string!")
    utils.io_close(io)
    print("  Success!")

def test_stdio_basic_stderr():
    print("Test stdio basic stderr echo")
    io = utils.alloc_io(o, "stdio,sh -c 'cat 1>&2'", chunksize = 64)
    io.handler.ignore_input = True
    io.read_cb_enable(True)
    err = io.open_channel_s("", None)
    utils.HandleData(o, "stderr", chunksize = 64, io = err)
    utils.test_dataxfer(io, err, "This is a test string!")
    utils.io_close(io)
    utils.io_close(err)
    print("  Success!")

def test_stdio_small():
    print("Test stdio small echo")
    rb = gensio.get_random_bytes(512)
    io = utils.alloc_io(o, "stdio,cat", chunksize = 64)
    utils.test_dataxfer(io, io, rb)
    utils.io_close(io)
    print("  Success!")

def do_small_test(io1, io2):
    rb = gensio.get_random_bytes(512)
    print("  testing io1 to io2")
    utils.test_dataxfer(io1, io2, rb)
    print("  testing io2 to io1")
    utils.test_dataxfer(io2, io1, rb)
    print("  Success!")

def test_tcp_small():
    print("Test tcp small")
    io1 = utils.alloc_io(o, "tcp,localhost,3025", do_open = False,
                         chunksize = 64)
    ta = TestAccept(o, io1, "tcp,3025", do_small_test)

def test_telnet_small():
    print("Test telnet small")
    io1 = utils.alloc_io(o, "telnet,tcp,localhost,3026", do_open = False,
                         chunksize = 64)
    ta = TestAccept(o, io1, "telnet(rfc2217=true),3026", do_small_test)

import ipmisimdaemon
def test_ipmisol_small():
    print("Test ipmisol small")
    isim = ipmisimdaemon.IPMISimDaemon(o)
    io1 = utils.alloc_io(o, "termios,/dev/ttyPipeA0,9600")
    io2 = utils.alloc_io(o, "ipmisol,lan -U ipmiusr -P test -p 9001 localhost,9600")
    utils.test_dataxfer(io1, io2, "This is a test string!")
    utils.io_close(io1)
    utils.io_close(io2)
    print("  Success!")

test_ipmisol_small()

def test_ipmisol_large():
    print("Test ipmisol large")
    isim = ipmisimdaemon.IPMISimDaemon(o)
    io1 = utils.alloc_io(o, "termios,/dev/ttyPipeA0,115200")
    io2 = utils.alloc_io(o, "ipmisol,lan -U ipmiusr -P test -p 9001 localhost,115200")
    rb = gensio.get_random_bytes(104857)
    utils.test_dataxfer(io1, io2, rb, timeout=10000)
    utils.io_close(io1)
    utils.io_close(io2)
    print("  Success!")

def test_rs485():
    io1str = "termios,/dev/ttyPipeA0,9600N81,LOCAL,rs485=103:495"
    io2str = "termios,/dev/ttyPipeB0,9600N81"

    print("termios rs485:\n  io1=%s\n  io2=%s" % (io1str, io2str))

    o = gensio.alloc_gensio_selector()
    io1 = utils.alloc_io(o, io1str)
    io2 = utils.alloc_io(o, io2str)

    sio2 = io2.cast_to_sergensio()
    rs485 = sio2.get_remote_rs485()
    check_rs485 = "103 495 enabled"
    if rs485 != check_rs485:
        raise Exception("%s: %s: Modemstate was not '%s', it was '%s'" %
                        ("test rs485", io1.handler.name, check_rs485, rs485))

    utils.io_close(io1)
    utils.io_close(io2)
    print("  Success!")

test_echo_device()
test_serial_pipe_device()
test_stdio_basic()
test_stdio_basic_stderr()
test_stdio_small()
ta_tcp()
ta_udp()
ta_ssl_tcp()
test_modemstate()
test_tcp_small()
test_telnet_small()
ta_ssl_telnet()
test_ipmisol_large()
test_rs485()
