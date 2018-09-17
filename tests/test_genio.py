#!/usr/bin/python
import utils
import genio

o = genio.alloc_genio_selector();

def t1():
    print("Test echo device")
    io = utils.alloc_io(o, "termios,/dev/ttyEcho0,38400")
    utils.test_dataxfer(io, io, "This is a test string!")
    utils.io_close(io)

def t2():
    print("Test serial pipe device")
    io1 = utils.alloc_io(o, "termios,/dev/ttyPipeA0,9600")
    io2 = utils.alloc_io(o, "termios,/dev/ttyPipeB0,9600")
    utils.test_dataxfer(io1, io2, "This is a test string!")
    utils.io_close(io1)
    utils.io_close(io2)

class TestAccept:
    def __init__(self, o, io1, iostr, bufsize, tester, name = None,
                 io1_dummy_write = None):
        self.o = o
        if (name):
            self.name = name
        else:
            self.name = iostr
        self.io1 = io1
        self.waiter = genio.waiter(o)
        self.bufsize = bufsize
        self.acc = genio.genio_acceptor(o, iostr, bufsize, self);
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
        utils.HandleData(self.o, None, self.bufsize, io = io, name = self.name)
        self.io2 = io
        self.waiter.wake()

    def wait(self):
        self.waiter.wait()

def do_test(io1, io2):
    utils.test_dataxfer(io1, io2, "This is a test string!")

def ta_tcp():
    print("Test accept tcp")
    io1 = utils.alloc_io(o, "tcp,localhost,3023", do_open = False)
    ta = TestAccept(o, io1, "tcp,3023", 1024, do_test)

def ta_udp():
    print("Test accept udp")
    io1 = utils.alloc_io(o, "udp,localhost,3023", do_open = False)
    ta = TestAccept(o, io1, "udp,3023", 1024, do_test, io1_dummy_write = "A")

def ta_ssl_tcp():
    print("Test accept ssl-tcp")
    io1 = utils.alloc_io(o, "ssl(CA=%s/CA.pem),tcp,localhost,3024" % utils.srcdir, do_open = False)
    ta = TestAccept(o, io1, "ssl(key=%s/key.pem,cert=%s/cert.pem,CA=%s/CA.pem),3024" % (utils.srcdir, utils.srcdir, utils.srcdir), 1024, do_test)

def do_telnet_test(io1, io2):
    do_test(io1, io2)
    sio1 = io1.cast_to_sergenio()
    sio2 = io1.cast_to_sergenio()
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
    print("Test accept telnet")
    io1 = utils.alloc_io(o, "telnet,tcp,localhost,3025", do_open = False)
    ta = TestAccept(o, io1, "telnet(rfc2217=true),3025", 1024, do_telnet_test)

def test_modemstate():
    io1str = "termios,/dev/ttyPipeA0,9600N81,LOCAL"
    io2str = "termios,/dev/ttyPipeB0,9600N81"

    print("termios modemstate:\n  io1=%s\n  io2=%s" % (io1str, io2str))

    o = genio.alloc_genio_selector()
    io1 = utils.alloc_io(o, io1str, do_open = False)
    io2 = utils.alloc_io(o, io2str)
    sio1 = io1.cast_to_sergenio()
    sio2 = io2.cast_to_sergenio()

    sio2.set_remote_null_modem(False);
    sio2.set_remote_modem_ctl((genio.SERGENIO_TIOCM_CAR |
                               genio.SERGENIO_TIOCM_CTS |
                               genio.SERGENIO_TIOCM_DSR |
                               genio.SERGENIO_TIOCM_RNG) << 16)

    io1.handler.set_expected_modemstate(0)
    io1.open_s()
    io1.read_cb_enable(True);
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 1" %
                        ("test dtr", io1.handler.name))

    io2.read_cb_enable(True);

    io1.handler.set_expected_modemstate(genio.SERGENIO_MODEMSTATE_CD_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_CD)
    sio2.set_remote_modem_ctl((genio.SERGENIO_TIOCM_CAR << 16) |
                              genio.SERGENIO_TIOCM_CAR)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 2" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(genio.SERGENIO_MODEMSTATE_DSR_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_CD |
                                        genio.SERGENIO_MODEMSTATE_DSR)
    sio2.set_remote_modem_ctl((genio.SERGENIO_TIOCM_DSR << 16) |
                              genio.SERGENIO_TIOCM_DSR)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 3" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(genio.SERGENIO_MODEMSTATE_CTS_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_CD |
                                        genio.SERGENIO_MODEMSTATE_DSR |
                                        genio.SERGENIO_MODEMSTATE_CTS)
    sio2.set_remote_modem_ctl((genio.SERGENIO_TIOCM_CTS << 16) |
                              genio.SERGENIO_TIOCM_CTS)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 4" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(genio.SERGENIO_MODEMSTATE_RI_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_CD |
                                        genio.SERGENIO_MODEMSTATE_DSR |
                                        genio.SERGENIO_MODEMSTATE_CTS |
                                        genio.SERGENIO_MODEMSTATE_RI)
    sio2.set_remote_modem_ctl((genio.SERGENIO_TIOCM_RNG << 16) |
                              genio.SERGENIO_TIOCM_RNG)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 5" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(genio.SERGENIO_MODEMSTATE_RI_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_CD_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_DSR_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_CTS_CHANGED)
    sio2.set_remote_modem_ctl((genio.SERGENIO_TIOCM_CAR |
                               genio.SERGENIO_TIOCM_CTS |
                               genio.SERGENIO_TIOCM_DSR |
                               genio.SERGENIO_TIOCM_RNG) << 16)
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 6" %
                        ("test dtr", io1.handler.name))

    io1.handler.set_expected_modemstate(genio.SERGENIO_MODEMSTATE_CD_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_DSR_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_CTS_CHANGED |
                                        genio.SERGENIO_MODEMSTATE_CD |
                                        genio.SERGENIO_MODEMSTATE_DSR |
                                        genio.SERGENIO_MODEMSTATE_CTS)
    sio2.set_remote_null_modem(True);
    if (io1.handler.wait_timeout(2000)):
        raise Exception("%s: %s: Timed out waiting for modemstate 7" %
                        ("test dtr", io1.handler.name))

    utils.io_close(io1)
    utils.io_close(io2)
    print("  Success!")
    return

ta_ssl_telnet()
t1()
t2()
ta_tcp()
ta_udp()
ta_ssl_tcp()
test_modemstate()
