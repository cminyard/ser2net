#!/usr/bin/python

from dataxfer import test_transfer

test_transfer("basic stdio", "This is a test!",
              "0:raw:100:/dev/ttyPipeA0:9600N81\n",
              None,
              "ser,termios,/dev/ttyPipeB0,9600N81")

