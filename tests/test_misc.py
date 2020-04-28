#!/usr/bin/python3
import gensio
import utils
from serialsim import *
import tempfile
import os

print("Testing miscellaneous features")

print("  kickolduser")
ser2net, io1, io2 = utils.setup_2_ser2net(utils.o,
              ("connection: &con",
               "  accepter: tcp,3023",
               "  connector: serialdev,/dev/ttyPipeA0,9600N81",
               "  options:",
               "    kickolduser: true"),
              "tcp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81")
io3 = None
try:
    io1.handler.set_expected_err("Remote end closed connection")
    io1.read_cb_enable(True)
    io3 = utils.alloc_io(utils.o, "tcp,localhost,3023")
    if io1.handler.wait_timeout(1000) == 0:
        raise Exception("kickolduser: remote end didn't close")
finally:
    if io3 is not None:
        utils.io_close(io3)
    utils.finish_2_ser2net(ser2net, io1, io2)

print("  multiple connections")
ser2net, io1, io2 = utils.setup_2_ser2net(utils.o,
              ("connection: &con",
               "  accepter: tcp,3023",
               "  connector: serialdev,/dev/ttyPipeA0,9600N81",
               "  options:",
               "    max-connections: 2"),
              "tcp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81")
io3 = None
io4 = None
try:
    utils.test_dataxfer(io2, io1, "Test string")
    io3 = utils.alloc_io(utils.o, "tcp,localhost,3023")
    io3.handler.set_compare("Test 2 string")
    utils.test_dataxfer(io2, io1, "Test 2 string")
    if io3.handler.wait_timeout(1000) == 0:
        raise Exception("max-connections: Didn't receive data")

    io4 = utils.alloc_io(utils.o, "tcp,localhost,3023", do_open = False)
    io4.handler.set_compare("Port already in use\r\n")
    io4.handler.set_expected_err("Remote end closed connection")
    io4.open_s()
    io4.read_cb_enable(True)
    if io4.handler.wait_timeout(1000) == 0:
        raise Exception("max-connections: Overconnect didn't receive errstring")
    io4.read_cb_enable(True)
    if io4.handler.wait_timeout(1000) == 0:
        raise Exception("max-connections: Overconnect didn't remclose")

finally:
    if io3 is not None:
        utils.io_close(io3)
    if io4 is not None:
        utils.io_close(io4)
    utils.finish_2_ser2net(ser2net, io1, io2)

print("  Success!")
