#!/usr/bin/python3

import os
import gensio
from dataxfer import test_transfer

rb = os.urandom(1048576)

test_transfer("telnet large random", rb,
              ("connection: &con",
               "  accepter: telnet,tcp,3023",
               "  connector: serialdev,/dev/ttyPipeA0,115200n81"),
              "telnet,tcp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,115200N81",
              timeout=150000)
