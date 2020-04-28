#!/usr/bin/python3
import gensio
import utils
from serialsim import *
import tempfile
import os

print("Testing kick old user")

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
    if io1.handler.wait_timeout(10000) == 0:
        raise Exception("kickolduser: remote end didn't close")
finally:
    if io3 is not None:
        utils.io_close(io3)
    utils.finish_2_ser2net(ser2net, io1, io2)

print("  Success!")
