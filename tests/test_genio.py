#!/usr/bin/python
import utils
import genio

o = genio.alloc_genio_selector();

def t1():
    print("Test1")
    io = utils.alloc_io(o, "termios,/dev/ttyEcho0,38400")
    utils.test_dataxfer(io, io, "This is a test string!")

def t2():
    print("Test2")
    io1 = utils.alloc_io(o, "termios,/dev/ttyPipeA0,9600")
    io2 = utils.alloc_io(o, "termios,/dev/ttyPipeB0,9600")
    utils.test_dataxfer(io1, io2, "This is a test string!")

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

t1()
t2()
ta_tcp()
ta_udp()
ta_ssl_tcp()
