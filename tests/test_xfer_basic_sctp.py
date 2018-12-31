#!/usr/bin/python

from dataxfer import test_transfer, test_write_drain

test_transfer("basic sctp", "This is a test!",
              "sctp,3023:raw:100:/dev/ttyPipeA0:9600N81\n",
              "sctp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81")

test_write_drain("basic sctp", "This is a write drain test!",
                 "sctp,3023:raw:100:/dev/ttyPipeA0:9600N81\n",
                 "sctp,localhost,3023",
                 "serialdev,/dev/ttyPipeB0,9600N81")
