#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain

test_transfer("basic tcp", "This is a test!",
              ("connection: &con",
               "  accepter: tcp,3023",
               "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
              "tcp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81")

test_write_drain("basic tcp", "This is a write drain test!",
                 ("connection: &con",
                  "  accepter: tcp,3023",
                  "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
                 "tcp,localhost,3023",
                 "serialdev,/dev/ttyPipeB0,9600N81")
