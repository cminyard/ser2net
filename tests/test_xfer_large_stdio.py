#!/usr/bin/python

import gensio
from dataxfer import test_transfer

rb = gensio.get_random_bytes(1048576)

test_transfer("stdio large random", rb,
              "0:raw:100:/dev/ttyPipeA0:115200N81\n",
              None,
              "serialdev,/dev/ttyPipeB0,115200N81",
              timeout=100000)
