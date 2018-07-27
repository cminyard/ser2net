#!/usr/bin/python

from dataxfer import test_transfer

test_transfer("basic tcp", "This is a test!",
              "3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "tcp,localhost,3023",
              "termios,/dev/ttyPipeB0,9600N81")
