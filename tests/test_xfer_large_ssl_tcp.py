#!/usr/bin/python

import gensio
from dataxfer import test_transfer
import utils

rb = gensio.get_random_bytes(1048576)

test_transfer("ssl tcp large random", rb,
              "ssl(key=%s/key.pem,cert=%s/cert.pem,CA=%s/CA.pem),3023:raw:100:/dev/ttyPipeA0:115200N81\n" % (utils.srcdir, utils.srcdir, utils.srcdir),
              "ssl(CA=%s/CA.pem),tcp,localhost,3023" % utils.srcdir,
              "serialdev,/dev/ttyPipeB0,115200N81",
              timeout=100000)
