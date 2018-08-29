#!/usr/bin/python

from dataxfer import test_transfer, test_write_drain

test_transfer("basic udp", "This is a test!",
              "udp,3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "udp,localhost,3023",
              "termios,/dev/ttyPipeB0,9600N81")

# The initial_write_io1 thing is required because we must write some
# data out our UDP port to ser2net so ser2net "connects" to our UDP
# port.
test_write_drain("basic udp", "This is a write drain test!",
                 "udp,3023:raw:100:/dev/ttyPipeA0:9600N81\n",
                 "udp,localhost,3023",
                 "termios,/dev/ttyPipeB0,9600N81",
                 initial_write_io1 = "A")
