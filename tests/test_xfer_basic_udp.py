#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain, test_connect_back

test_transfer("basic udp", "This is a test!",
              ("connection: &con",
               "  accepter: udp,3023",
               "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
              "udp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81")

# The initial_write_io1 thing is required because we must write some
# data out our UDP port to ser2net so ser2net "connects" to our UDP
# port.
test_write_drain("basic udp", "This is a write drain test!",
                 ("connection: &con",
                  "  accepter: udp,3023",
                  "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
                 "udp,localhost,3023",
                 "serialdev,/dev/ttyPipeB0,9600N81",
                 initial_write_io1 = "A")

test_connect_back("basic udp", "UDP Connect back test!",
                 ("connection: &con",
                  "  accepter: udp,3023",
                  "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                  "  options:",
                  "    connback: udp,localhost,3024"),
                 "udp,localhost,3024",
                 "serialdev,/dev/ttyPipeB0,9600N81")
