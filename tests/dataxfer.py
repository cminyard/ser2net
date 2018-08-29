
import genio
import utils

def test_transfer(name, data, config, io1str, io2str, timeout=1000):
    """Test a transfer between two genio objects

    This function takes a name (for reporting), some data to transfer,
    a config file for ser2net, and transfers the data one direction,
    then the other, then both ways at the same time.
    """
    print("Transfer %s:\n  config=%s  io1=%s\n  io2=%s" %
          (name, config, io1str, io2str))

    o = genio.alloc_genio_selector()
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
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

def test_write_drain(name, data, config, io1str, io2str, timeout=1000):
    """Test that close does not loose data

    This function takes a name (for reporting), some data to transfer,
    a config file for ser2net, and writes the data and immediately
    closes the connection after the write succeeds and makes sure all
    the written data gets there.
    """
    print("Write drain %s:\n  config=%s  io1=%s\n  io2=%s" %
          (name, config, io1str, io2str))

    o = genio.alloc_genio_selector()
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
    try:
        print("  io1 to io2")
        utils.test_write_drain(io1, io2, data, timeout=timeout)
    finally:
        utils.finish_2_ser2net(ser2net, io1, io2)

    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
    try:
        print("  io2 to io1")
        utils.test_write_drain(io2, io1, data, timeout=timeout)
    finally:
        utils.finish_2_ser2net(ser2net, io1, io2)

    print("  Success!")
    return
