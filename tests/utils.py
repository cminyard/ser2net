#
# genio test utilities
#
# This file contains some classes and functions useful for testing
# genio handling
#

import os
import genio
import tempfile
import signal
import time

debug = 0

class HandlerException(Exception):
    """Exception for HandleData errors"""

    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return repr(self.value)
    def __str__(self):
        return str(self.value)

class HandleData:
    """Data handler for testing genio.

    This is designed to handle input and output from genio.  To write
    data, call set_write_data() to set some data and write it.  To wait
    for data to be read, call set_compare() to wait for the given data
    to be read.

    This just starts things up and runs asynchronously.  You can wait
    for a completion with wait() or wait_timeout().

    The io handler is in the io attribute of the object.  The handler
    object of that io will be this object.
    """

    def __init__(self, iostr, bufsize, name = None):
        """Start a genio object with this handler"""
        if (name):
            self.name = name
        else:
            self.name = iostr
        self.waiter = genio.waiter_s()
        self.to_write = None
        self.to_compare = None
        self.ignore_input = False
        self.io = genio.genio(iostr, bufsize, self)
        self.io.handler = self;
        return

    def set_compare(self, to_compare, start_reader = True):
        """Set some data to compare

        If start_reader is true (default), it enable the read callback.
        If the data does not compare, an exception is raised.
        """
        self.compared = 0
        self.to_compare = to_compare
        if (start_reader):
            self.io.read_cb_enable(True)
        return

    def set_write_data(self, to_write, start_writer = True):
        self.to_write = to_write
        if (start_writer):
            self.io.write_cb_enable(True)
        return

    def close(self):
        self.io.close(self)
        return

    def wait(self):
        self.waiter.wait()

    def wait_timeout(self, timeout):
        return self.waiter.wait_timeout(timeout)


    # Everything below here is internal handling functions.

    def read_callback(self, io, err, buf, flags):
        if (debug >= 2):
            print self.name + ": Got data(%d): %s" % (self.compared,  str(buf))
        if (self.ignore_input):
            return len(buf)
        if (not self.to_compare):
            if (debug):
                print self.name + ": Got data, but nothing to compare"
            io.read_cb_enable(False)
            return
        if (err):
            raise HandlerException(self.name + ": read: " + err)

        if (len(buf) > len(self.to_compare)):
            count = len(self.to_compare)
        else:
            count = len(buf)

        for i in range(0, count):
            if (buf[i] != self.to_compare[self.compared]):
                raise HandlerException("%s: compare falure on byte %d, "
                                       "expected %x, got %x" %
                                       (self.name, self.compared,
                                        ord(self.to_compare[self.compared]),
                                        ord(buf[i])))
            self.compared += 1

        if (self.compared >= len(self.to_compare)):
            self.to_compare = None
            io.write_cb_enable(False)
            self.waiter.wake()

        return count

    def write_callback(self, io):
        if (not self.to_write):
            if (debug):
                print self.name + ": Got write, but no data"
            io.write_cb_enable(False)
            return

        count = io.write(self.to_write)
        if (debug):
            print self.name + ": wrote %d bytes" % count
        if (count >= len(self.to_write)):
            io.write_cb_enable(False)
            self.to_write = None
            self.waiter.wake()
        else:
            self.to_write = self.to_write[count:]
        return

    def urgent_callback(self, io):
        print self.name + ": Urgent data"
        return

    def close_done(self, io):
        if (debug):
            print self.name + ": Closed"
        self.waiter.wake()
        return

class Ser2netDaemon:
    """Create a ser2net daemon instance and start it up

    ser2net is started with the given config data as a config file
    The SER2NET_EXEC environment variable can be set to tell ser2net
    to run ser2net with a specific path.

    For testing stdio handling for ser2net, you may use the io
    attribute for it but you must set it's handler's ignore_input
    attribute to False or you won't get any data, and you must
    set it back to True when done.
    """

    def __init__(self, configdata, extra_args = ""):
        """Create a running ser2net program

        The given config data is written to a file and used as the config file.
        It is started with the -r and -d options set, you can supply extra
        options if you like as a string.
        """
        
        prog = os.getenv("SER2NET_EXEC")
        if (not prog):
            prog = "ser2net"
        self.cfile = tempfile.NamedTemporaryFile()
        self.cfile.write(configdata)
        self.cfile.flush()

        args = "stdio," + prog + " -r -d -c " + self.cfile.name + " " + extra_args
        if (debug):
            print "Running: " + args
        self.handler = HandleData(args, 1024, name="ser2net daemon")

        self.io = self.handler.io
        self.io.open()

        self.pid = self.io.remote_id()
        self.handler.set_compare("Ready\n")
        if (self.handler.wait_timeout(2000)):
            raise Exception("Timeout waiting for ser2net to start")

        self.handler.ignore_input = True
        return

    def __del__(self):
        self.terminate()
        return

    def signal(self, sig):
        """"Send a signal to ser2net"""
        os.kill(self.pid, sig)
        return

    def terminate(self):
        """Terminate the running ser2net

        This closes the io and sends a SIGTERM to ser2net and waits
        a bit for it to terminate.  If it does not terminate, send
        SIGTERM a few more times.  If it still refuses to close, send
        a SIGKILL.  If all that fails, raise an exception.
        """
        self.handler.close()
        count = 10
        while (count > 0):
            if (count < 6):
                self.signal(signal.SIGTERM)
            else:
                self.signal(signal.SIGKILL)
            # It would be really nice if waitpid had a timeout options,
            # in absense of that simulate it, sort of.
            subcount = 500
            while (subcount > 0):
                time.sleep(.01)
                pid, rv = os.waitpid(self.pid, os.WNOHANG)
                if (pid > 0):
                    return
                subcount -= 1
            count -= 1
        raise Exception("ser2net did not terminate");

def alloc_io(iostr, do_open = True, bufsize = 1024):
    """Allocate an io instance with a HandlerData handler

    If do_open is True (default), open it, too.
    """
    h = HandleData(iostr, bufsize)
    if (do_open):
        h.io.open()
    return h.io

def test_dataxfer(io1, io2, data, timeout = 1000):
    """Test a transfer of data from io1 to io2

    If the transfer does not complete by "timeout" milliseconds, raise
    an exception.
    """
    io1.handler.set_write_data(data)
    io2.handler.set_compare(data)
    if (io1.handler.wait_timeout(timeout)):
        raise Exception("%s: %s: Timed out waiting for write completion" %
                        ("test_dataxfer", io1.handler.name))
    if (io2.handler.wait_timeout(timeout)):
        raise Exception("%s: %s: Timed out waiting for read completion" %
                        ("test_dataxfer", io2.handler.name))
    return

def test_dataxfer_simul(io1, io2, data, timeout = 10000):
    """Test a simultaneous bidirectional transfer of data between io1 to io2

    If the transfer does not complete by "timeout" milliseconds, raise
    an exception.
    """
    io1.handler.set_write_data(data)
    io1.handler.set_compare(data)
    io2.handler.set_write_data(data)
    io2.handler.set_compare(data)
    if (io1.handler.wait_timeout(timeout)):
        raise Exception("%s: %s: Timed out waiting for write completion" %
                        ("test_dataxfer", io1.handler.name))
    if (io2.handler.wait_timeout(timeout)):
        raise Exception("%s: %s: Timed out waiting for write completion" %
                        ("test_dataxfer", io2.handler.name))
    if (io1.handler.wait_timeout(timeout)):
        raise Exception("%s: %s: Timed out waiting for read completion" %
                        ("test_dataxfer", io1.handler.name))
    if (io2.handler.wait_timeout(timeout)):
        raise Exception("%s: %s: Timed out waiting for read completion" %
                        ("test_dataxfer", io2.handler.name))
    return

def io_close(io, timeout = 1000):
    """close the given genio

    If it does not succeed in timeout milliseconds, raise and exception.
    """
    io.handler.close()
    if (io.handler.wait_timeout(timeout)):
        raise Exception("%s: %s: Timed out waiting for close" %
                        ("io_close", io.handler.name))
