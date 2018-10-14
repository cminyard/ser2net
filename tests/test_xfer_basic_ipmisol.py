#!/usr/bin/python

from dataxfer import test_transfer, test_write_drain
import ipmisimdaemon
import gensio
import utils

utils.debug=0

o = gensio.alloc_gensio_selector()
isim = ipmisimdaemon.IPMISimDaemon(o)

test_transfer("basic ipmisol", "This is a test!",
              "3023:raw:100:ipmisol,lan -U ipmiusr -P test -p 9001 localhost,9600\n",
              "tcp,localhost,3023",
              "termios,/dev/ttyPipeA0,9600N81", o=o)

test_write_drain("basic tcp", "This is a write drain test!",
                 "3023:raw:100:ipmisol,lan -U ipmiusr -P test -p 9001 localhost,9600\n",
                 "tcp,localhost,3023",
                 "termios,/dev/ttyPipeA0,9600N81", o=o)
