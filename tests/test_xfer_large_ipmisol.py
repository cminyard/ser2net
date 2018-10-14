#!/usr/bin/python

from dataxfer import test_transfer, test_write_drain
import ipmisimdaemon
import gensio

o = gensio.alloc_gensio_selector()
isim = ipmisimdaemon.IPMISimDaemon(o)

rb = gensio.get_random_bytes(1048576)

test_transfer("basic ipmisol", rb,
              "3023:raw:100:ipmisol,lan -U ipmiusr -P test -p 9001 localhost,115200\n",
              "tcp,localhost,3023",
              "termios,/dev/ttyPipeA0,115200N81", o=o, timeout=100000)
