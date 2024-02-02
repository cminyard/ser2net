#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain, test_connect_back

test_transfer("basic telnet", "This is a test!",
              ("connection: &con",
               "  accepter: telnet,tcp,3023",
               "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
              "telnet,tcp,localhost,3023",
              "serialdev,/dev/ttyPipeB0,9600N81")

test_write_drain("basic telnet", "This is a write drain test!",
                 ("connection: &con",
                  "  accepter: telnet,tcp,3023",
                  "  connector: serialdev,/dev/ttyPipeA0,300N81,local"),
                 "telnet,tcp,localhost,3023",
                 "serialdev,/dev/ttyPipeB0,300N81,local")

test_connect_back("basic telnet", "Telnet Connect back test!",
                 ("connection: &con",
                  "  accepter: telnet,tcp,3023",
                  "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                  "  options:",
                  "    connback: telnet,tcp,localhost,3024"),
                 "telnet,tcp,localhost,3024",
                 "serialdev,/dev/ttyPipeB0,9600N81")
