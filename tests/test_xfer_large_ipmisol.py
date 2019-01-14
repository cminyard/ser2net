#!/usr/bin/python

from dataxfer import test_transfer, test_write_drain
import ipmisimdaemon
import gensio
import utils

o = utils.o
isim = ipmisimdaemon.IPMISimDaemon(o)

rb = gensio.get_random_bytes(1048576)

test_transfer("basic ipmisol", rb,
              "3023:raw:100:ipmisol,lan -U ipmiusr -P test -p 9001 localhost,115200\n",
              "tcp,localhost,3023",
              "serialdev,/dev/ttyPipeA0,115200N81", timeout=100000)
