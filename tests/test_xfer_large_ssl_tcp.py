#!/usr/bin/python3

import os
import gensio
from dataxfer import test_transfer
import utils

rb = os.urandom(1048576)

test_transfer("ssl tcp large random", rb,
              ("connection: &con",
               "  accepter: ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,3023" %
                     (utils.keydir, utils.keydir),
               "  connector: serialdev,/dev/ttyPipeA0,115200n81"),
              "ssl(CA=%s/CA.pem),tcp,localhost,3023" % utils.keydir,
              "serialdev,/dev/ttyPipeB0,115200N81",
              timeout=150000)
