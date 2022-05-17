#!/usr/bin/python3

from dataxfer import test_transfer, test_write_drain, test_connect_back
import utils

test_transfer("basic ssl tcp", "This is a test!",
              ("connection: &con",
               "  accepter: ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,3023"
                 % (utils.keydir, utils.keydir),
               "  connector: serialdev,/dev/ttyPipeA0,9600N81"),
              "ssl(CA=%s/CA.pem),tcp,localhost,3023" % utils.keydir,
              "serialdev,/dev/ttyPipeB0,9600N81")

test_write_drain("basic ssl tcp", "This is a write drain test!",
                 ("connection: &con",
                  "  accepter: ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,3023"
                  % (utils.keydir, utils.keydir),
                  "  connector: serialdev,/dev/ttyPipeA0,9600N81,local"),
                 "ssl(CA=%s/CA.pem),tcp,localhost,3023" % utils.keydir,
                 "serialdev,/dev/ttyPipeB0,9600N81")

# Note that in the connect back we set cert=.  By default the
# certificate and private key are set by defaults in ser2net; if they
# cannot load then they will fail.  This avoids runtime failures if
# the default certificate is not present.
test_connect_back("basic ssl tcp", "SSL Connect back test!",
                  ("connection: &con",
                   "  accepter: ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,3023"
                       % (utils.keydir, utils.keydir),
                   "  connector: serialdev,/dev/ttyPipeA0,9600N81",
                   "  options:",
                   "    connback: ssl(CA=%s/CA.pem,cert=),tcp,localhost,3024"
                       % (utils.keydir)),
                 "ssl(key=%s/key.pem,cert=%s/cert.pem),tcp,localhost,3024"
                     % (utils.keydir, utils.keydir),
                 "serialdev,/dev/ttyPipeB0,9600N81")
