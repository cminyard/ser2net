#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain

test_transfer("basic stdio", "This is a test!",
              ("connection: &con",
               "  accepter: stdio",
               "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
              None,
              "serialdev,/dev/ttyPipeB0,9600N81")

test_write_drain("basic stdio", "This is a write drain test!",
                 ("connection: &con",
                  "  accepter: stdio",
                  "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
                 None,
                 "serialdev,/dev/ttyPipeB0,9600N81")
