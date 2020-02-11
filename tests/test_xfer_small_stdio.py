#!/usr/bin/python3

import os
import gensio
from dataxfer import test_transfer

rb = os.urandom(512)

test_transfer("stdio small random", rb,
              "0:raw:100:/dev/ttyPipeA0:9600N81\n",
              None,
              "serialdev,/dev/ttyPipeB0,9600N81",
              timeout=5000)
