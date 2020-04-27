#!/usr/bin/python3

import os
from dataxfer import test_transfer, test_write_drain
import ipmisimdaemon
import gensio
import utils

o = utils.o
isim = ipmisimdaemon.IPMISimDaemon(o)

rb = os.urandom(512)

test_transfer("basic ipmisol", rb,
              ("connection: &con",
               "  accepter: tcp,3023",
               "  connector: ipmisol,lan -U ipmiusr -P test -p 9001 localhost,9600"),
              "tcp,localhost,3023",
              "serialdev,/dev/ttyPipeA0,9600N81", timeout=5000)
