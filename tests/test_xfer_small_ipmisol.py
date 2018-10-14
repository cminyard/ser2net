#!/usr/bin/python

from dataxfer import test_transfer, test_write_drain
import ipmisimdaemon
import gensio

o = gensio.alloc_gensio_selector()
isim = ipmisimdaemon.IPMISimDaemon(o)

rb = gensio.get_random_bytes(512)

test_transfer("basic ipmisol", rb,
              "3023:raw:100:ipmisol,lan -U ipmiusr -P test -p 9001 localhost,9600\n",
              "tcp,localhost,3023",
              "termios,/dev/ttyPipeA0,9600N81", o=o, timeout=5000)
