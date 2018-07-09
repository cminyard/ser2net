
import utils

def test_transfer(name, data, config, io1str, io2str, timeout=1000):
    """Test a transfer between two genio objects

    This function takes a name (for reporting), some data to transfer,
    a config file for ser2net, and 
    """
    print "Transfer %s:\n  config=%s  io1=%s\n  io2=%s" % (
        name, config, io1str, io2str)

    ser2net, io1, io2 = utils.setup_2_ser2net(config, io1str, io2str)

    print "  io1 to io2"
    utils.test_dataxfer(io1, io2, data, timeout=timeout)
    print "  io2 to io1"
    utils.test_dataxfer(io2, io1, data, timeout=timeout)
    print "  bidirectional"
    utils.test_dataxfer_simul(io1, io2, data, timeout=timeout)

    utils.finish_2_ser2net(ser2net, io1, io2)
    print "  Success!"
