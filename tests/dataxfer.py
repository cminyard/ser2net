
import gensio
import utils
import time

o = utils.o

def test_transfer(name, data, config, io1str, io2str, timeout=1000,
                  extra_args=""):
    """Test a transfer between two gensio objects

    This function takes a name (for reporting), some data to transfer,
    a config file for ser2net, and transfers the data one direction,
    then the other, then both ways at the same time.
    """
    print("Transfer %s:\n  config=%s  io1=%s\n  io2=%s" %
          (name, config, io1str, io2str))

    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str,
                                              extra_args = extra_args)
    try:
        print("  io1 to io2")
        utils.test_dataxfer(io1, io2, data, timeout=timeout)
        print("  io2 to io1")
        utils.test_dataxfer(io2, io1, data, timeout=timeout)
        print("  bidirectional")
        utils.test_dataxfer_simul(io1, io2, data, timeout=timeout)
    finally:
        utils.finish_2_ser2net(ser2net, io1, io2)
    print("  Success!")
    return

def test_write_drain(name, data, config, io1str, io2str, timeout=3000,
                     initial_write_io1 = None, switch_delay = 0.0):
    """Test that close does not lose data

    This function takes a name (for reporting), some data to transfer,
    a config file for ser2net, and writes the data and immediately
    closes the connection after the write succeeds and makes sure all
    the written data gets there.

    If initial_write_io1 is not None, the string is written to io1 when
    transferring from io2 to io1.  This is a hack for UDP, ser2net will
    not be connected to the udp port until it receives some data from
    it.
    """
    print("Write drain %s:\n  config=%s  io1=%s\n  io2=%s" %
          (name, config, io1str, io2str))

    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
    try:
        print("  io1 to io2")
        utils.test_write_drain(io1, io2, data, timeout=timeout)
    finally:
        utils.finish_2_ser2net(ser2net, io1, io2)

    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
    try:
        print("  io2 to io1")
        end = time.time() + switch_delay
        while (time.time() < end):
            gensio.waiter(o).wait_timeout(1, int(switch_delay / 5))
        if initial_write_io1:
            io1.handler.set_write_data(initial_write_io1)
            io2.handler.set_compare(initial_write_io1)
            if io1.handler.wait_timeout(1000) == 0:
                raise Exception(
                  "%s: Timed out on dummy write completion" % io1.handler.name)
            if io2.handler.wait_timeout(1000) == 0:
                raise Exception(
                  "%s: Timed out on dummy read completion" % io1.handler.name)
        utils.test_write_drain(io2, io1, data, timeout=timeout)
    finally:
        utils.finish_2_ser2net(ser2net, io1, io2)

    print("  Success!")
    return

def test_one_xfer(name, data1, data2, config, io1str, io2str, timeout=1000,
                  extra_args="", compare1 = None, compare2 = None):

    print("  " + name)
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str,
                                              extra_args = extra_args)
    try:
        if data1:
            utils.test_dataxfer(io1, io2, data1, timeout=timeout,
                                compare = compare1)
        if data2:
            utils.test_dataxfer(io2, io1, data2, timeout=timeout,
                                compare = compare2)
    finally:
        utils.finish_2_ser2net(ser2net, io1, io2)
    return

def test_connect_back(name, data, config, io1str, io2str, timeout=3000,
                      extra_args = ""):
    print("Connect back %s:\n  config=%s  io1=%s\n  io2=%s" %
          (name, config, io1str, io2str))
    ser2net, acc1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str,
                                               extra_args = extra_args,
                                               io1_is_accepter = True)
    try:
        # Send some data to start the connection.
        io2.handler.set_write_data(data)

        # Now wait for the connect back.
        if (acc1.handler.wait_timeout(timeout) == 0):
            raise Exception(
                "%s: Timed out on connect back" % acc1.handler.name)

        acc1.handler.set_compare(data)
        if (acc1.handler.wait_timeout(timeout) == 0):
            raise Exception(
                "%s: Timed out on connect back data" % acc1.handler.name)

    finally:
        utils.finish_2_ser2net(ser2net, acc1, io2)
    print("  Success!")
    return
