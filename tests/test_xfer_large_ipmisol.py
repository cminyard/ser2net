#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain
import ipmisimdaemon
import gensio
import utils
import os

o = utils.o
isim = ipmisimdaemon.IPMISimDaemon(o)

rb = os.urandom(1048576)

test_transfer("basic ipmisol", rb,
              ("connection: &con",
               "  accepter: tcp,3023",
               "  connector: ipmisol,lan -U ipmiusr -P test -p 9001 localhost,115200"),
              "tcp,localhost,3023",
              "serialdev,/dev/ttyPipeA0,115200N81", timeout=150000)
