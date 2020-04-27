#!/usr/bin/python3

import os
import gensio
from dataxfer import test_transfer

rb = os.urandom(1048576)

test_transfer("stdio large random", rb,
              ("connection: &con",
               "  accepter: stdio",
               "  connector: serialdev,/dev/ttyPipeA0,115200n81"),
              None,
              "serialdev,/dev/ttyPipeB0,115200N81",
              timeout=150000)
