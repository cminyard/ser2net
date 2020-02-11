#!/usr/bin/python3

import os
import gensio
from dataxfer import test_transfer

rb = os.urandom(1048576)

test_transfer("telnet large random", rb,
              "3023:telnet:100:/dev/ttyPipeA0:115200N81\n",
              "telnet,tcp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,115200N81",
              timeout=150000)
