#!/usr/bin/python

import gensio
from dataxfer import test_transfer

rb = gensio.get_random_bytes(512)

test_transfer("stdio small random", rb,
              "0:raw:100:/dev/ttyPipeA0:9600N81\n",
              None,
              "termios,/dev/ttyPipeB0,9600N81",
              timeout=5000)
