
import termios
import copy

import gensio
import utils

# This is the termios ser2net sets up when it opens a serial port.
# Same for sergensio_termios gensio.
base_termios = [ 0, 0, 0, 0, 0, 0,
                 [ '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
                   '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
                   '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0',
                   '\0', '\0', '\0', '\0', '\0', '\0', '\0', '\0' ]]

def setup_base_termios():
    base_termios[0] = termios.IGNBRK
    base_termios[2] = (termios.B9600 | termios.CREAD | termios.CS8)
    base_termios[4] = termios.B9600
    base_termios[5] = termios.B9600
    base_termios[6][termios.VTIME] = 0
    base_termios[6][termios.VMIN] = 1
    base_termios[6][termios.VSTART] = chr(17)
    base_termios[6][termios.VSTOP] = chr(19)
    return

setup_base_termios()

def dup_termios(t, iflags=0, iflags_mask=0,
                oflags=0, oflags_mask=0,
                cflags=0, cflags_mask=0,
                lflags=0, lflags_mask=0):
    """Duplicate the given termios, then apply the masks and or the values
    given."""
    n = copy.deepcopy(t)
    n[0] = (n[0] & ~iflags_mask) | iflags
    n[1] = (n[1] & ~oflags_mask) | oflags
    n[2] = (n[2] & ~cflags_mask) | cflags
    n[3] = (n[3] & ~lflags_mask) | lflags
    return n

def dup_base_termios(iflags=0, iflags_mask=0,
                     oflags=0, oflags_mask=0,
                     cflags=0, cflags_mask=0,
                     lflags=0, lflags_mask=0):
    return dup_termios(base_termios, iflags, iflags_mask, oflags, oflags_mask,
                       cflags, cflags_mask, lflags, lflags_mask)

def compare_termios(tio1, tio2):
    for i in range(0, 6):
        if tio1[i] != tio2[i]:
            return i;
    for i in range(0, len(tio2[6])):
        if tio1[6][i] != tio2[6][i]:
            return i + 6;
    return 0

def test_ser2net_termios(name, handler, config, io1str, io2str):
    """Test the settings of ser2net termios

    Set up a ser2net daemon and two connections, call the given handler
    which will return a termios set.  Then fetch the termios from io2
    and make sure they match.
    """
    print("termios %s:\n  config=%s  io1=%s\n  io2=%s" %
          (name, config, io1str, io2str))

    o = gensio.alloc_gensio_selector();
    ser2net, io1, io2 = utils.setup_2_ser2net(o, config, io1str, io2str)
    try:
        io1.handler.set_compare("12345")
        if (io1.handler.wait_timeout(1000)):
            raise Exception("%s: %s: Timed out waiting for banner" %
                            (name, io1.handler.name))
        sio2 = io2.cast_to_sergensio()
        io1.read_cb_enable(True)
        io2.read_cb_enable(True)

        expected_termios = handler.op(io1, io2)

        io2_rem_termios = sio2.get_remote_termios()

        c = compare_termios(expected_termios, io2_rem_termios)
        if (c != 0):
            raise Exception("Termios mismatch at %d\nExpected: %s\nBut got  %s" %
                            (c, str(expected_termios), str(io2_rem_termios)))

    finally:
        utils.finish_2_ser2net(ser2net, io1, io2, handle_except = False)
    print("  Success!")
