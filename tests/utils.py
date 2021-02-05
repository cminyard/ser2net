#
# gensio test utilities
#
# This file contains some classes and functions useful for testing
# gensio handling
#

import os
import gensio
import signal
import time
import curses.ascii
import sys

debug = 0

def split_version(v):
    vs = v.split(".")
    vs2 = vs[2].split("-")
    if len(vs2) > 1:
        vs = (int(vs[0]), int(vs[1]), int(vs2[0]), vs2[1])
    else:
        vs = (int(vs[0]), int(vs[1]), int(vs[2]), "")
    return vs

def gensio_version_ge(v):
    """Return True if the version v is >= the gensio version, false if not"""
    try:
        gv = gensio.version
    except Exception as E:
        return True # Versions with a version macro are older than we care about

    gvs = split_version(gv)
    vs = split_version(v)
    if int(vs[0]) < int(gvs[0]):
        return True
    if int(vs[0]) > int(gvs[0]):
        return False
    if int(vs[1]) < int(gvs[1]):
        return True
    if int(vs[1]) > int(gvs[1]):
        return False
    if int(vs[2]) < int(gvs[2]):
        return True
    if int(vs[2]) > int(gvs[2]):
        return False
    return vs[3] <= gvs[3]

class Logger:
    def gensio_log(self, level, log):
        print("***%s log: %s" % (level, log))

o = gensio.alloc_gensio_selector(Logger());

class HandlerException(Exception):
    """Exception for HandleData errors"""

    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return repr(self.value)
    def __str__(self):
        return str(self.value)

def buf_to_prstr(buf):
    if buf is None:
        return (0, "")
    s = ""
    for i in buf:
        if curses.ascii.isprint(i):
            s = s + chr(i)
        else:
            s = s + "\\x%2.2x" % i
    return (len(buf), s)

class HandleData:
    """Data handler for testing gensio.

    This is designed to handle input and output from gensio.  To write
    data, call set_write_data() to set some data and write it.  To wait
    for data to be read, call set_compare() to wait for the given data
    to be read.

    This just starts things up and runs asynchronously.  You can wait
    for a completion with wait() or wait_timeout().

    The io handler is in the io attribute of the object.  The handler
    object of that io will be this object.
    """

    def __init__(self, o, iostr, name = None, chunksize=10240,
                 io = None, io_is_accepter = False):
        """Start a gensio object with this handler"""
        if (name):
            self.name = name
        else:
            self.name = iostr
        self.waiter = gensio.waiter(o)
        self.to_write = None
        self.to_compare = None
        self.to_waitfor = None
        self.expecting_modemstate = False
        self.expecting_linestate = False
        self.expected_server_cb = None
        self.expected_server_value = 0
        self.expected_server_return = 0
        self.ignore_input = False
        self.expected_err = None
        self.io = None
        self.acc = None
        if io:
            if io_is_accepter:
                self.acc = io
            else:
                self.io = io
            io.set_cbs(self)
        else:
            if io_is_accepter:
                self.acc = gensio.gensio_accepter(o, iostr, self)
            else:
                self.io = gensio.gensio(o, iostr, self)

        if io_is_accepter:
            self.acc.handler = self
        else:
            self.io.handler = self
        self.chunksize = chunksize
        self.debug = 0
        return

    def set_compare(self, to_compare, start_reader = True):
        """Set some data to compare

        If start_reader is true (default), it enable the read callback.
        If the data does not compare, an exception is raised.
        """
        self.compared = 0
        if to_compare.__class__ == str:
            to_compare = bytes(to_compare, 'utf8')
        self.to_compare = to_compare
        if (start_reader):
            self.io.read_cb_enable(True)
        return

    def set_waitfor(self, waitfor, start_reader = True):
        """Wait for the given string to come in

        If start_reader is true (default), it enable the read callback.
        If the data does not compare, an exception is raised.
        """
        self.compared = 0
        self.to_waitfor = bytes(waitfor, encoding="utf8")
        if (start_reader):
            self.io.read_cb_enable(True)
        return

    def set_write_data(self, to_write, start_writer = True,
                       close_on_done = False):
        self.close_on_done = close_on_done
        self.wrpos = 0
        if to_write.__class__ == str:
            to_write = bytes(to_write, 'utf8')
        self.wrlen = len(to_write)
        self.to_write = to_write
        if (start_writer):
            self.io.write_cb_enable(True)
        return

    def set_expected_err(self, err):
        self.expected_err = err;
        return;

    def close(self):
        self.ignore_input = True
        self.io.close(self)
        return

    def shutdown(self):
        self.acc.shutdown(self)
        return

    def wait(self):
        self.waiter.wait(1)

    def wait_timeout(self, timeout):
        return self.waiter.wait_timeout(1, timeout)


    # Everything below here is internal handling functions.

    def read_callback(self, io, err, buf, auxdata):
        if self.to_compare:
            iolen = len(self.to_compare)
        elif self.to_waitfor:
            iolen = len(self.to_waitfor)
        else:
            iolen = None

        if (debug or self.debug) and iolen != None:
            print("%s: Got %d bytes at pos %d of %d" % (self.name, len(buf),
                                                        self.compared, iolen))
        if (debug >= 2 or self.debug >= 2):
            buflen = 0
            s = ""
            (buflen, s) = buf_to_prstr(buf)
            print("%s: Got data: (err %s %d bytes) %s" % (self.name, str(err),
                                                          buflen, s))
            if self.to_compare is not None:
                (buflen, s) = buf_to_prstr(self.to_compare[self.compared:])
                print("%s: Waiting: (%d bytes) %s" % (self.name, buflen, s))

        if err is not None and self.expected_err is not None:
            if self.expected_err != err:
                raise HandlerException(self.name + ": err: " + err)
            self.waiter.wake()
            return 0

        if (err):
            raise HandlerException(self.name + ": read: " + err)
        if (self.ignore_input):
            return len(buf)
        if (self.to_waitfor):
            for i in range(0, len(buf)):
                if buf[i] == self.to_waitfor[self.compared]:
                    self.compared += 1
                    if (len(self.to_waitfor) == self.compared):
                        self.to_waitfor = None
                        io.read_cb_enable(False)
                        self.waiter.wake()
                else:
                    self.compared = 0
            return len(buf)

        if (not self.to_compare):
            if (debug):
                print(self.name + ": Got data, but nothing to compare")
            io.read_cb_enable(False)
            return len(buf)

        if (len(buf) > len(self.to_compare)):
            count = len(self.to_compare)
        else:
            count = len(buf)

        if count > self.chunksize:
            count = self.chunksize

        for i in range(0, count):
            if (buf[i] != self.to_compare[self.compared]):
                raise HandlerException("%s: compare failure on byte %d, "
                                       "expected %x, got %x" %
                                       (self.name, self.compared,
                                        self.to_compare[self.compared],
                                        buf[i]))
            self.compared += 1

        if (self.compared >= len(self.to_compare)):
            self.to_compare = None
            io.read_cb_enable(False)
            self.waiter.wake()

        return count

    def write_callback(self, io):
        if (not self.to_write):
            if (debug or self.debug):
                print(self.name + ": Got write, but no data")
            io.write_cb_enable(False)
            return

        if (self.wrpos + self.chunksize > self.wrlen):
            wrdata = self.to_write[self.wrpos:]
        else:
            wrdata = self.to_write[self.wrpos:self.wrpos + self.chunksize]
        count = io.write(wrdata, None)
        if (debug or self.debug):
            print(self.name + ": wrote %d bytes" % count)

        if (count + self.wrpos >= self.wrlen):
            io.write_cb_enable(False)
            if (self.close_on_done):
                self.io.closeme = False
                self.close()
            self.to_write = None
            self.waiter.wake()
        else:
            self.wrpos += count
        return

    def urgent_callback(self, io):
        print(self.name + ": Urgent data")
        return

    def modemstate(self, io, modemstate):
        if (not self.expecting_modemstate):
            if (debug or self.debug):
                print("Got unexpected modemstate for %s: %x" %
                      (self.name, modemstate))
            return
        if (modemstate != self.expected_modemstate):
            raise HandlerException("%s: Expecting modemstate 0x%x, got 0x%x" %
                                   (self.name, self.expected_modemstate,
                                    modemstate))
        self.expecting_modemstate = False
        self.waiter.wake()
        return

    def set_expected_modemstate(self, modemstate):
        self.expecting_modemstate = True
        self.expected_modemstate = modemstate
        return

    def linestate(self, io, linestate):
        if (not self.expecting_linestate):
            if (debug or self.debug):
                print("Got unexpected linestate %x" % linestate)
            return
        if (linestate != self.expected_linestate):
            raise HandlerException("%s: Expecting linestate 0x%x, got 0x%x" %
                                   (self.name, self.expected_linestate,
                                    linestate))
        self.expecting_linestate = False
        self.waiter.wake()
        return

    def set_expected_linestate(self, linestate):
        self.expecting_linestate = True
        self.expected_linestate = linestate
        return

    def set_expected_server_cb(self, name, value, retval):
        self.expected_server_cb = name
        self.expected_server_value = value
        self.expected_server_return = retval
        return

    def set_expected_client_cb(self, name, value):
        self.expected_server_cb = name
        self.expected_server_value = value
        return

    def check_set_expected_telnet_cb(self, name, value):
        if not self.expected_server_cb:
            if (debug or self.debug):
                print("Got unexpected server cb: %s %d" % (name, value))
            return False
        if self.expected_server_cb != name:
            raise HandlerException(
                "Got wrong server cb, expected %s, got %s (%d)" %
                (self.expected_server_cb, name, value))
        if self.expected_server_value != value:
            raise HandlerException(
                "Got wrong server cb value for %s, expected %d, got %d" %
                (name, self.expected_server_value, value))
        self.waiter.wake()
        return True

    def baud(self, sio, err, baud):
        if not self.check_set_expected_telnet_cb("baud", baud):
            return
        return

    def datasize(self, sio, err, datasize):
        if not self.check_set_expected_telnet_cb("datasize", datasize):
            return
        return

    def parity(self, sio, err, parity):
        if not self.check_set_expected_telnet_cb("parity", parity):
            return
        return

    def stopbits(self, sio, err, stopbits):
        if not self.check_set_expected_telnet_cb("stopbits", stopbits):
            return
        return

    def flowcontrol(self, sio, err, flowcontrol):
        if not self.check_set_expected_telnet_cb("flowcontrol", flowcontrol):
            return
        return

    def iflowcontrol(self, sio, err, iflowcontrol):
        if not self.check_set_expected_telnet_cb("iflowcontrol", iflowcontrol):
            return
        return

    def sbreak(self, sio, err, sbreak):
        if not self.check_set_expected_telnet_cb("sbreak", sbreak):
            return
        return

    def dtr(self, sio, err, dtr):
        if not self.check_set_expected_telnet_cb("dtr", dtr):
            return
        return

    def rts(self, sio, err, rts):
        if not self.check_set_expected_telnet_cb("rts", rts):
            return
        return

    def sbaud(self, sio, baud):
        if not self.check_set_expected_telnet_cb("baud", baud):
            return
        sio.sg_baud(self.expected_server_return, None)
        return

    def sdatasize(self, sio, datasize):
        if not self.check_set_expected_telnet_cb("datasize", datasize):
            return
        sio.sg_datasize(self.expected_server_return, None)
        return

    def sparity(self, sio, parity):
        if not self.check_set_expected_telnet_cb("parity", parity):
            return
        sio.sg_parity(self.expected_server_return, None)
        return

    def sstopbits(self, sio, stopbits):
        if not self.check_set_expected_telnet_cb("stopbits", stopbits):
            return
        sio.sg_stopbits(self.expected_server_return, None)
        return

    def sflowcontrol(self, sio, flowcontrol):
        if not self.check_set_expected_telnet_cb("flowcontrol", flowcontrol):
            return
        sio.sg_flowcontrol(self.expected_server_return, None)
        return

    def siflowcontrol(self, sio, iflowcontrol):
        if not self.check_set_expected_telnet_cb("iflowcontrol", iflowcontrol):
            return
        sio.sg_iflowcontrol(self.expected_server_return, None)
        return

    def ssbreak(self, sio, sbreak):
        if not self.check_set_expected_telnet_cb("sbreak", sbreak):
            return
        sio.sg_sbreak(self.expected_server_return, None)
        return

    def sdtr(self, sio, dtr):
        if not self.check_set_expected_telnet_cb("dtr", dtr):
            return
        sio.sg_dtr(self.expected_server_return, None)
        return

    def srts(self, sio, rts):
        if not self.check_set_expected_telnet_cb("rts", rts):
            return
        sio.sg_rts(self.expected_server_return, None)
        return

    def close_done(self, io):
        if (debug or self.debug):
            print(self.name + ": Closed")
        self.waiter.wake()
        return

    # Accepter things below

    def log(self, acc, level, logval):
        raise HandlerException(
            "%s: Got accepter log: %s:%s:%s" % (name, acc, level, logval))
        return

    def new_connection(self, acc, io):
        if self.io is not None:
            raise HandlerException("%s: Got connection while connected" % name)
        io.handler = self
        io.is_accepter = False
        self.io = io
        io.set_cbs(self)
        if (debug or self.debug):
            print(self.name + ": New connection")
        self.waiter.wake()
        return

    def shutdown_done(self, acc):
        if (debug or self.debug):
            print(self.name + ": Shutdown")
        self.waiter.wake()
        return

import collections

PY3 = sys.version_info[0] == 3

if PY3:
    string_types = str
else:
    string_types = basestring

def is_nonstr_sequence(obj):
    if isinstance(obj, string_types):
        return False
    return isinstance(obj, collections.Sequence)

class Ser2netDaemon:
    """Create a ser2net daemon instance and start it up

    ser2net is started with the given config data as a config file
    The SER2NET_EXEC environment variable can be set to tell ser2net
    to run ser2net with a specific path.

    For testing stdio handling for ser2net, you may use the io
    attribute for it but you must set its handler's ignore_input
    attribute to False or you won't get any data, and you must
    set it back to True when done.
    """

    def __init__(self, o, configdata, extra_args = ""):
        """Create a running ser2net program

        The given config data is written to a file and used as the config file.
        It is started with the -r and -d options set, you can supply extra
        options if you like as a string.
        """
        
        prog = os.getenv("SER2NET_EXEC")
        if (not prog):
            prog = "ser2net"
        configstr = ""
        if is_nonstr_sequence(configdata):
            # yaml config information
            for i in configdata:
                configstr += " -Y '" + i + "'"
        else:
            raise Exception("config data must be a sequence of strings")
        self.o = o

        args = "stdio," + prog + " -t 4 -r -d" + configstr + " " + extra_args
        if (debug):
            print("Running: " + args)
        self.handler = HandleData(o, args, name="ser2net daemon")

        self.io = self.handler.io
        self.io.closeme = True
        self.io.open_s()

        # Open stderr output
        self.err = self.io.alloc_channel(None, self)
        self.err.open_s()
        self.err.closeme = True

        self.pid = remote_id_int(self.io)
        self.handler.set_waitfor("Ready\n")
        if (self.handler.wait_timeout(2000) == 0):
            raise Exception("Timeout waiting for ser2net to start")

        self.handler.ignore_input = True

        # Uncomment the following or set it yourself to get output from
        # the ser2net daemon printed.
        #self.handler.debug = 2

        # Leave read on so if we enable debug we can see output from the
        # daemon.
        self.io.read_cb_enable(True)
        self.err.read_cb_enable(True)
        return

    def __del__(self):
        if (self.handler):
            self.terminate()
        return

    def signal(self, sig):
        """"Send a signal to ser2net"""
        os.kill(self.pid, sig)
        return

    def read_callback(self, io, err, buf, auxdata):
        if err:
            print("Error from ser2net: " + err);
            return 0

        print("Error output from ser2net: " + str(buf, 'utf8'));
        return len(buf)

    def terminate(self):
        """Terminate the running ser2net

        This closes the io and sends a SIGTERM to ser2net and waits
        a bit for it to terminate.  If it does not terminate, send
        SIGTERM a few more times.  If it still refuses to close, send
        a SIGKILL.  If all that fails, raise an exception.
        """
        if (debug):
            print("Terminating")

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
                    if self.io.closeme:
                        self.handler.close()
                    if self.err.closeme:
                        self.err.close_s()
                    self.handler = None
                    return
                subcount -= 1
            count -= 1
        raise Exception("ser2net did not terminate");

def alloc_io(o, iostr, do_open = True, chunksize = 10240,
             io_is_accepter = False):
    """Allocate an io instance with a HandlerData handler

    If do_open is True (default), open it, too.
    """
    h = HandleData(o, iostr, chunksize = chunksize,
                   io_is_accepter = io_is_accepter)
    if (do_open):
        if io_is_accepter:
            h.acc.startup()
        else:
            h.io.open_s()
    if io_is_accepter:
        h.acc.is_accepter = True
        return h.acc
    else:
        h.io.is_accepter = False
        return h.io

def test_dataxfer(io1, io2, data, timeout = 1000, compare = None):
    """Test a transfer of data from io1 to io2

    If the transfer does not complete by "timeout" milliseconds, raise
    an exception.
    """
    if compare is None:
        compare = data
    io1.handler.set_write_data(data)
    io2.handler.set_compare(compare)
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io1.handler.name)) +

                        ("Timed out waiting for write completion at byte %d" %
                         io1.handler.wrpos))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io2.handler.name)) +

                        ("Timed out waiting for read completion at byte %d" %
                         io2.handler.compared))
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
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception("%s: %s: Timed out waiting for write completion" %
                        ("test_dataxfer", io1.handler.name))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception("%s: %s: Timed out waiting for write completion" %
                        ("test_dataxfer", io2.handler.name))
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception("%s: %s: Timed out waiting for read completion" %
                        ("test_dataxfer", io1.handler.name))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception("%s: %s: Timed out waiting for read completion" %
                        ("test_dataxfer", io2.handler.name))
    return

def test_write_drain(io1, io2, data, timeout = 1000):
    """Test that a close does not loose data.

    If the transfer does not complete by "timeout" milliseconds, raise
    an exception.
    """
    io1.handler.set_write_data(data, close_on_done = True)
    io2.handler.set_compare(data)
    if (io1.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io1.handler.name)) +
                        ("Timed out waiting for write completion at byte %d" %
                         io1.handler.wrpos))
    if (io2.handler.wait_timeout(timeout) == 0):
        raise Exception(("%s: %s: " % ("test_dataxfer", io2.handler.name)) +
                        ("Timed out waiting for read completion at byte %d" %
                         io2.handler.compared))
    return

def io_close(io, timeout = 1000):
    """close the given gensio

    If it does not succeed in timeout milliseconds, raise and exception.
    """
    io.closeme = False
    if io.is_accepter:
        io.handler.shutdown()
    else:
        io.handler.close()
    if (io.handler.wait_timeout(timeout) == 0):
        raise Exception("%s: %s: Timed out waiting for close" %
                        ("io_close", io.handler.name))
    return

def setup_2_ser2net(o, config, io1str, io2str, do_io1_open = True,
                    extra_args = "", io1_is_accepter = False):
    """Setup a ser2net daemon and two gensio connections

    Create a ser2net daemon instance with the given config and two
    gensio connections with the given strings.

    If io1str is None, use the stdio of the ser2net connection as
    io1 (generally for testing stdio to ser2net).

    A "closeme" boolean attribute is added to io1 telling if They
    should be closed upon completion of the test, this is set to false
    for ser2net stdio.
    """
    io1 = None
    io2 = None
    ser2net = Ser2netDaemon(o, config, extra_args = extra_args)
    try:
        if io1str:
            io1 = alloc_io(o, io1str, do_io1_open,
                           io_is_accepter = io1_is_accepter)
            io1.closeme = do_io1_open
        else:
            io1 = ser2net.io
            io1.handler.ignore_input = False
            io1.closeme = False
        io2 = alloc_io(o, io2str)
        io2.closeme = True
    except:
        if io1:
            if io1.closeme:
                io_close(io1)
        if io2:
            io_close(io2)
        ser2net.terminate()
        raise
    return (ser2net, io1, io2)

def finish_2_ser2net(ser2net, io1, io2, handle_except = True):
    if io1.closeme:
        if io1.is_accepter and io1.handler.io is not None:
            try:
                io_close(io1.handler.io)
            except Exception as E:
                pass
        try:
            io_close(io1)
        except:
            pass
    else:
        io1.handler.ignore_input = True
    if io2.closeme:
        try:
            io_close(io2)
        except:
            pass
    else:
        io2.handler.ignore_input = True
    if handle_except and sys.exc_info()[0]:
        g = gensio.waiter(ser2net.o)
        print("Exception occurred, waiting a bit for things to clear.")
        g.wait_timeout(1, 2000)
    ser2net.terminate()
    return


keydir = os.getenv("keydir")
if not keydir:
    if (not keydir):
        keydir = "ca"

srcdir = os.getenv("srcdir")
if not srcdir:
    srcdir = os.path.dirname(sys.argv[0])
    if (not srcdir):
        srcdir = "."

def remote_id_int(io):
    return int(io.control(0, True, gensio.GENSIO_CONTROL_REMOTE_ID, None))
