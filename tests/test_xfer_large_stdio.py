#!/usr/bin/python

import genio
from dataxfer import test_transfer

rb = genio.get_random_bytes(1048576)

test_transfer("stdio large random", rb,
              "0:raw:100:/dev/ttyPipeA0:115200N81\n",
              None,
              "termios,/dev/ttyPipeB0,115200N81",
              timeout=100000)
