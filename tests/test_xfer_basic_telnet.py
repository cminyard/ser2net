#!/usr/bin/python

from dataxfer import test_transfer, test_write_drain

test_transfer("basic telnet", "This is a test!",
              "3023:telnet:100:/dev/ttyPipeA0:9600N81\n",
              "telnet,tcp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81")

test_write_drain("basic telnet", "This is a write drain test!",
                 "3023:telnet:100:/dev/ttyPipeA0:9600N81\n",
                 "telnet,tcp,localhost,3023",
                 "serialdev,/dev/ttyPipeB0,9600N81")
