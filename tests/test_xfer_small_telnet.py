#!/usr/bin/python

import genio
from dataxfer import test_transfer

rb = genio.get_random_bytes(512)

test_transfer("telnet small random", rb,
              "3023:telnet:100:/dev/ttyPipeA0:9600N81\n",
              "telnet,tcp,localhost,3023",
              "termios,/dev/ttyPipeB0,9600N81",
              timeout=5000)
