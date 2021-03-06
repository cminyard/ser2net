#!/usr/bin/python3
import gensio
import utils
from serialsim import *
import tempfile
import os

from dataxfer import test_one_xfer

def gettempfile():
    fo = tempfile.mkstemp()
    os.close(fo[0])
    return fo[1]

def validate_file_contents(test, fn, contents):
    f = open(fn)
    a = f.read()
    f.close()
    if a != contents:
        raise Exception("%s: expected contents '%s', got '%s'" %
                        (test, contents, a))

temp1 = gettempfile()
try:
    temp2 = gettempfile()
except:
    os.unlink(temp1)
    raise
try:
    temp3 = gettempfile()
except:
    os.unlink(temp1)
    os.unlink(temp2)
    raise

try:
    print("Testing file tracing")

    test_one_xfer("trace read", None, "Testing Trace Read!",
                  ("connection: &con",
                   "  accepter: tcp,3023",
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    trace-read: %s" % temp1),
                   "tcp,localhost,3023",
                   "serialdev,/dev/ttyPipeB0,9600N81")

    validate_file_contents("trace_read", temp1, "Testing Trace Read!")

    test_one_xfer("trace write", "Testing Trace Write!", None, 
                  ("connection: &con",
                   "  accepter: tcp,3023",
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    trace-write: %s" % temp1),
                   "tcp,localhost,3023",
                   "serialdev,/dev/ttyPipeB0,9600N81")

    # Notice that in appends by default.
    validate_file_contents("trace_write", temp1,
                           "Testing Trace Read!Testing Trace Write!")
    os.truncate(temp1, 0)
    os.truncate(temp2, 0)

    test_one_xfer("trace read2", None, "Testing Trace Read2!",
                  ("connection: &con",
                   "  accepter: tcp,3023",
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    trace-read: %s" % temp1,
                   "    trace-write: %s" % temp2),
                   "tcp,localhost,3023",
                   "serialdev,/dev/ttyPipeB0,9600N81")

    validate_file_contents("trace_read2", temp1, "Testing Trace Read2!")
    validate_file_contents("trace_read2/w", temp2, "")
    os.truncate(temp1, 0)

    test_one_xfer("trace write2", "Testing Trace Write2!", None,
                  ("connection: &con",
                   "  accepter: tcp,3023",
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    trace-read: %s" % temp1,
                   "    trace-write: %s" % temp2),
                   "tcp,localhost,3023",
                   "serialdev,/dev/ttyPipeB0,9600N81")

    validate_file_contents("trace_write2", temp2, "Testing Trace Write2!")
    validate_file_contents("trace_write2/r", temp1, "")
    os.truncate(temp2, 0)

    test_one_xfer("trace read/write", "Testing 2nd Trace Write!",
                  "Testing 2nd Trace Read!",
                  ("connection: &con",
                   "  accepter: tcp,3023",
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    trace-read: %s" % temp1,
                   "    trace-write: %s" % temp2),
                   "tcp,localhost,3023",
                   "serialdev,/dev/ttyPipeB0,9600N81")
    validate_file_contents("trace read/write1", temp1,
                           "Testing 2nd Trace Read!")
    validate_file_contents("trace read/write2", temp2,
                           "Testing 2nd Trace Write!")
    os.truncate(temp1, 0)
    os.truncate(temp2, 0)

    test_one_xfer("trace both", None, "Testing Trace Both!",
                  ("connection: &con",
                   "  accepter: tcp,3023",
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    trace-both: %s" % temp1),
                   "tcp,localhost,3023",
                   "serialdev,/dev/ttyPipeB0,9600N81")

    validate_file_contents("trace_both", temp1, "Testing Trace Both!")
    os.truncate(temp1, 0)

    test_one_xfer("trace both2", "Testing Trace Both2!", None,
                  ("connection: &con",
                   "  accepter: tcp,3023",
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    trace-both: %s" % temp1),
                   "tcp,localhost,3023",
                   "serialdev,/dev/ttyPipeB0,9600N81")

    validate_file_contents("trace_both", temp1, "Testing Trace Both2!")
    os.truncate(temp1, 0)

    test_one_xfer("trace all", None, "Testing Trace All!",
                  ("connection: &con",
                   "  accepter: tcp,3023",
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    trace-read: %s" % temp1,
                   "    trace-write: %s" % temp2,
                   "    trace-both: %s" % temp3),
                   "tcp,localhost,3023",
                   "serialdev,/dev/ttyPipeB0,9600N81")

    validate_file_contents("trace_both", temp1, "Testing Trace All!")
    validate_file_contents("trace_both", temp2, "")
    validate_file_contents("trace_both", temp3, "Testing Trace All!")
    os.truncate(temp1, 0)
    os.truncate(temp3, 0)

    test_one_xfer("trace all2", "Testing Trace All!", None,
                  ("connection: &con",
                   "  accepter: tcp,3023",
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    trace-read: %s" % temp1,
                   "    trace-write: %s" % temp2,
                   "    trace-both: %s" % temp3),
                   "tcp,localhost,3023",
                   "serialdev,/dev/ttyPipeB0,9600N81")

    validate_file_contents("trace_both2", temp1, "")
    validate_file_contents("trace_both2", temp2, "Testing Trace All!")
    validate_file_contents("trace_both2", temp3, "Testing Trace All!")
    os.truncate(temp1, 0)
    os.truncate(temp3, 0)

    print("  Success!")

finally:
    os.unlink(temp1)
    os.unlink(temp2)
    os.unlink(temp3)
