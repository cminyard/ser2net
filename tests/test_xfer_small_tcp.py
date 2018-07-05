#!/usr/bin/python

import genio
from dataxfer import test_transfer

rb = genio.get_random_bytes(512)

test_transfer("tcp small random", rb,
              "3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "tcp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,9600N81",
              timeout=5000)
