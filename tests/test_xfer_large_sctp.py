#!/usr/bin/python3

import os
import gensio
from dataxfer import test_transfer

rb = os.urandom(1048576)

test_transfer("sctp large random", rb,
              "sctp,3023:raw:100:/dev/ttyPipeA0:115200N81\n",
              "sctp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,115200N81",
              timeout=150000)
