#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain, test_connect_back

test_transfer("basic sctp", "This is a test!",
              ("connection: &con",
               "  accepter: sctp,3023",
               "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
              "sctp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81")

test_write_drain("basic sctp", "This is a write drain test!",
                 ("connection: &con",
                  "  accepter: sctp,3023",
                  "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
                 "sctp,localhost,3023",
                 "serialdev,/dev/ttyPipeB0,9600N81")

test_connect_back("basic sctp", "SCTP Connect back test!",
                 ("connection: &con",
                  "  accepter: sctp,3023",
                  "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                  "  options:",
                  "    connback: sctp,localhost,3024"),
                 "sctp,localhost,3024",
                 "serialdev,/dev/ttyPipeB0,9600N81")
