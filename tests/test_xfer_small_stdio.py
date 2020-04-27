#!/usr/bin/python3

import os
import gensio
from dataxfer import test_transfer

rb = os.urandom(512)

test_transfer("stdio small random", rb,
              ("connection: &con",
               "  accepter: stdio",
               "  connector: serialdev,/dev/ttyPipeA0,9600n81"),
              None,
              "serialdev,/dev/ttyPipeB0,9600N81",
              timeout=5000)
