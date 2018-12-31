#!/usr/bin/python

import gensio
from dataxfer import test_transfer

rb = gensio.get_random_bytes(512)

test_transfer("udp small random", rb,
              "udp,3023:raw:100:/dev/ttyPipeA0:9600N81 net-to-dev-bufsize=1024\n",
              "udp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81",
              timeout=5000)
