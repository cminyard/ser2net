#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain
import utils

test_transfer("basic ssl tcp", "This is a test!",
              "ssl(key=%s/key.pem,cert=%s/cert.pem),3023:raw:100:/dev/ttyPipeA0:9600N81\n" % (utils.keydir, utils.keydir),
              "ssl(CA=%s/CA.pem),tcp,localhost,3023" % utils.keydir,
              "serialdev,/dev/ttyPipeB0,9600N81")

test_write_drain("basic ssl tcp", "This is a write drain test!",
                 "ssl(key=%s/key.pem,cert=%s/cert.pem),3023:raw:100:/dev/ttyPipeA0:9600N81\n" % (utils.keydir, utils.keydir),
                 "ssl(CA=%s/CA.pem),tcp,localhost,3023" % utils.keydir,
                 "serialdev,/dev/ttyPipeB0,9600N81")
