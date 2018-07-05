#!/usr/bin/python

import genio
from dataxfer import test_transfer

rb = genio.get_random_bytes(512)

test_transfer("udp small random", rb,
              "udp,3023:raw:100:/dev/ttyPipeA0:9600N81 net-to-dev-bufsize=1024\n",
              "udp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,9600N81",
              timeout=5000)
