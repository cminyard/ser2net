#!/usr/bin/python

import genio
from dataxfer import test_transfer

rb = genio.get_random_bytes(1048576)

test_transfer("telnet large random", rb,
              "3023:telnet:100:/dev/ttyPipeA0:115200N81\n",
              "telnet,tcp,localhost,3023",
              "termios,/dev/ttyPipeB0,115200N81",
              timeout=100000)

