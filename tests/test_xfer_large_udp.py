#!/usr/bin/python3

import os
import gensio
from dataxfer import test_transfer

rb = os.urandom(1048576)

test_transfer("udp large random", rb,
              ("connection: &con",
               "  accepter: relpkt,udp,3023",
               "  connector: serialdev,/dev/ttyPipeA1,115200n81"),
              "relpkt,udp,localhost,3023",
              "serialdev,/dev/ttyPipeB1,115200N81",
              timeout=150000)
