#!/usr/bin/python

import genio
from dataxfer import test_transfer

rb = genio.get_random_bytes(512)

test_transfer("stdio small random", rb,
              "0:raw:100:/dev/ttyPipeA0:9600N81\n",
              None,
              "ser,termios,/dev/ttyPipeB0,9600N81",
              timeout=5000)
