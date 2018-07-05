
import utils

def test_transfer(name, data, config, io1str, io2str, timeout=1000):
    """Test a transfer between two genio objects

    This function takes a name (for reporting), some data to transfer,
    a config file for ser2net, and 
    """
    print "Transfer %s:\n  config=%s  io1=%s\n  io2=%s" % (
        name, config, io1str, io2str)

    ser2net = utils.Ser2netDaemon(config)

    close_io1 = True
    if (io1str):
        io1 = utils.alloc_io(io1str)
    else:
        io1 = ser2net.io
        io1.handler.ignore_input = False
        close_io1 = False
    io2 = utils.alloc_io(io2str)

    print "  io1 to io2"
    utils.test_dataxfer(io1, io2, data, timeout=timeout)
    print "  io2 to io1"
    utils.test_dataxfer(io2, io1, data, timeout=timeout)
    print "  bidirectional"
    utils.test_dataxfer_simul(io1, io2, data, timeout=timeout)

    if (close_io1):
        utils.io_close(io1)
    else:
        io1.handler.ignore_input = True
    utils.io_close(io2)
    print "  Success!"
