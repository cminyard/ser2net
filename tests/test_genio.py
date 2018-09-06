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
    def __init__(self, o, io1, iostr, bufsize, tester, name = None):
        self.o = o
        if (name):
            self.name = name
        else:
            self.name = iostr
        self.io1 = io1
        self.waiter = genio.waiter(o)
        self.tester = tester
        self.bufsize = bufsize
        self.acc = genio.genio_acceptor(o, iostr, bufsize, self);
        self.acc.startup()
        io1.open_s()
        self.wait()

    def new_connection(self, acc, io):
        utils.HandleData(self.o, None, self.bufsize, io = io)
        self.tester(self.io1, io)
        self.waiter.wake()

    def wait(self):
        self.waiter.wait()

def do_test(io1, io2):
    utils.test_dataxfer(io1, io2, "This is a test string!")

def ta1():
    print("Test accept tcp")
    io1 = utils.alloc_io(o, "tcp,localhost,3023", do_open = False)
    ta = TestAccept(o, io1, "tcp,3023", 1024, do_test)

t1()
t2()
ta1()
