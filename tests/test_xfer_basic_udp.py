#!/usr/bin/python

from dataxfer import test_transfer

test_transfer("basic udp", "This is a test!",
              "udp,3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "udp,localhost,3023",
              "ser,termios,/dev/ttyPipeB0,9600N81")
