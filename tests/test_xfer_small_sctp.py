#!/usr/bin/python

import os
import gensio
from dataxfer import test_transfer

rb = os.urandom(512)

test_transfer("sctp small random", rb,
              "sctp,3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "sctp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81",
              timeout=5000)
