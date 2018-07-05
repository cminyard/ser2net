
import genio
import utils

def test_transfer(name, data, config, io1str, io2str, timeout=1000):
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

#utils.debug = 2

test_transfer("basic stdio", "This is a test!",
              "0:raw:100:/dev/ttyPipeA0:9600N81\n",
              None,
              "ser,termios,/dev/ttyPipeB0,9600N81")

test_transfer("basic tcp", "This is a test!",
              "3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "tcp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,9600N81")

test_transfer("basic udp", "This is a test!",
              "udp,3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "udp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,9600N81")

rb = genio.get_random_bytes(512)

test_transfer("tcp small random", rb,
              "3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "tcp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,9600N81",
              timeout=5000)

test_transfer("stdio small random", rb,
              "0:raw:100:/dev/ttyPipeA0:9600N81\n",
              None,
              "ser,termios,/dev/ttyPipeB0,9600N81",
              timeout=5000)

test_transfer("udp small random", rb,
              "udp,3023:raw:100:/dev/ttyPipeA0:9600N81 net-to-dev-bufsize=1024\n",
              "udp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,9600N81",
              timeout=5000)

rb = genio.get_random_bytes(1048576)

test_transfer("tcp large random", rb,
              "3023:raw:100:/dev/ttyPipeA0:115200N81\n",
              "tcp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,115200N81",
              timeout=100000)

test_transfer("stdio large random", rb,
              "0:raw:100:/dev/ttyPipeA0:115200N81\n",
              None,
              "ser,termios,/dev/ttyPipeB0,115200N81",
              timeout=100000)

test_transfer("udp large random", rb,
              "udp,3023:raw:100:/dev/ttyPipeA0:115200N81 net-to-dev-bufsize=1024\n",
              "udp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,115200N81",
              timeout=100000)

test_transfer("telnet large random", rb,
              "3023:telnet:100:/dev/ttyPipeA0:115200N81\n",
              "ser,telnet,tcp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,115200N81",
              timeout=100000)

