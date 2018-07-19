#!/usr/bin/python
import utils
import genio

o = genio.alloc_genio_selector();

def t1():
    print("Test1")
    io = utils.alloc_io(o, "ser,termios,/dev/ttyEcho0,38400")
    utils.test_dataxfer(io, io, "This is a test string!")

def t2():
    print("Test2")
    io1 = utils.alloc_io(o, "ser,termios,/dev/ttyPipeA0,9600")
    io2 = utils.alloc_io(o, "ser,termios,/dev/ttyPipeB0,9600")
    utils.test_dataxfer(io1, io2, "This is a test string!")

t1()
t2()
