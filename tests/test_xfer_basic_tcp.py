#!/usr/bin/python

from dataxfer import test_transfer, test_write_drain

test_transfer("basic tcp", "This is a test!",
              "3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "tcp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81")

test_write_drain("basic tcp", "This is a write drain test!",
                 "3023:raw:100:/dev/ttyPipeA0:9600N81\n",
                 "tcp,localhost,3023",
                 "serialdev,/dev/ttyPipeB0,9600N81")
