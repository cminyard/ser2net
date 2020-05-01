#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain, test_connect_back

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

test_connect_back("basic tcp", "TCP Connect back test!",
                 ("connection: &con",
                  "  accepter: tcp,3023",
                  "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                  "  options:",
                  "    connback: tcp,localhost,3024"),
                 "tcp,localhost,3024",
                 "serialdev,/dev/ttyPipeB0,9600N81")
