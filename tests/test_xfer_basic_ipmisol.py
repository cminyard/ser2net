#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain
import ipmisimdaemon
import gensio
import utils

o = utils.o
isim = ipmisimdaemon.IPMISimDaemon(o)

test_transfer("basic ipmisol", "This is a test!",
              ("connection: &con",
               "  accepter: tcp,3023",
               "  connector: ipmisol,lan -U ipmiusr -P test -p %d localhost,9600" % ipmisimdaemon.ipmisol_port),
              "tcp,localhost,3023",
              "serialdev,/dev/ttyPipeA0,9600N81")

# Give the old ipmi_sim a little time to shut down.
gensio.waiter(o).wait_timeout(1, 1000)

# Note that ipmi_sim messes with the modem state lines, so adding
# LOCAL is required on termios.  Also, we had to add a small delay
# after the opens are complete to give time for ser2net to connect to
# ipmi_sim and set things up.  Otherwise it would often lose the first
# couple of characters going from io2 to io1.
test_write_drain("basic tcp", "This is a write drain test!",
              ("connection: &con",
               "  accepter: tcp,3023",
               "  connector: ipmisol,lan -U ipmiusr -P test -p %d localhost,9600" % ipmisimdaemon.ipmisol_port),
                 "tcp,localhost,3023",
                 "serialdev,/dev/ttyPipeA0,9600N81,local",
                 switch_delay = 0.25)
