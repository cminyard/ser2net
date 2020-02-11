#!/usr/bin/python3

import os
import gensio
from dataxfer import test_transfer

rb = os.urandom(1048576)

test_transfer("tcp large random", rb,
              "3023:raw:100:/dev/ttyPipeA0:115200N81\n",
              "tcp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,115200N81",
              timeout=150000)
