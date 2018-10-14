#
# gensio test utilities
#
# This file contains some classes and functions useful for testing
# gensio handling
#

import os
import tempfile
import utils
import signal
import time

default_ipmisim_emu = """
mc_setbmc 0x20\n
\n
mc_add 0x20 0 no-device-sdrs 0x23 9 8 0x9f 0x1291 0xf02 persist_sdr\n
sel_enable 0x20 1000 0x0a\n
\n
mc_enable 0x20\n
"""

default_ipmisim_config = """
name "ser2net_sim"\n
\n
set_working_mc 0x20\n
\n
  startlan 1\n
    addr localhost 9001\n
\n
    # Maximum privilege limit on the channel.\n
    priv_limit admin\n
\n
    # Allowed IPMI 1.5 authorization types\n
    allowed_auths_callback none md2 md5 straight\n
    allowed_auths_user none md2 md5 straight\n
    allowed_auths_operator none md2 md5 straight\n
    allowed_auths_admin none md2 md5 straight\n
\n
    # guid for IPMI 2.0 authorization  You can also use a string\n
    guid a123456789abcdefa123456789abcdef\n
\n
  endlan\n
\n
  sol "/dev/ttyPipeB0" 115200\n
\n
  # Start startcmd at startup?  Default is false.\n
  startnow false\n
\n
  # Now add some users.  User 0 is invalid, user 1 is the special "anonymous"\n
  # user and cannot take a username.  Note that the users here are only\n
  # used if the persistent user config doesn't exist.\n
  #    # valid name      passw  priv-lim max-sess allowed-auths (ignored)\n
  user 1 true  ""        "test" user     10       none md2 md5 straight\n
  user 2 true  "ipmiusr" "test" admin    10       none md2 md5 straight\n
"""

class IPMISimDaemon:
    """Create an IPMI Sim daemon instance and start it up

    ipmi_sim is started with the given config data as a config file
    The IPMISIM_EXEC environment variable can be set to tell this code
    to run ipmi_sim with a specific path.
    """

    def __init__(self, o, configdata = None, emudata = None, extra_args = ""):
        """Create a running ipmisim program

        The given config data is written to a file and used as the config file.
        It is started with the -r and -d options set, you can supply extra
        options if you like as a string.
        """
        
        prog = os.getenv("IPMISIM_EXEC")
        if (not prog):
            prog = "ipmi_sim"

        if not configdata:
            configdata = default_ipmisim_config
        if not emudata:
            emudata = default_ipmisim_emu

        self.cfile = tempfile.NamedTemporaryFile(mode="w+")
        self.cfile.write(configdata)
        self.cfile.flush()
        self.efile = tempfile.NamedTemporaryFile(mode="w+")
        self.efile.write(emudata)
        self.efile.flush()
        self.o = o

        args = "stdio," + prog + " -p -c " + self.cfile.name + " -f " + self.efile.name + " " + extra_args
        if (utils.debug):
            print("Running: " + args)
        self.handler = utils.HandleData(o, args, name="ipmisim daemon")

        self.io = self.handler.io
        self.io.closeme = True
        self.io.open_s()

        # Uncomment the following or set it yourself to get output from
        # the ipmisim daemon printed.
        #self.handler.debug = 2

        self.pid = self.io.remote_id()
        self.handler.set_waitfor("> ")
        if (self.handler.wait_timeout(2000)):
            raise Exception("Timeout waiting for ipmi_sim to start")

        self.handler.ignore_input = True

        # Leave read on so if we enable debug we can see output from the
        # daemon.
        self.io.read_cb_enable(True)
        return

    def __del__(self):
        if (self.handler):
            self.terminate()
        return

    def signal(self, sig):
        """"Send a signal to ipmi_sim"""
        os.kill(self.pid, sig)
        return

    def terminate(self):
        """Terminate the running ipmi_sim

        This closes the io and sends a SIGTERM to ipmi_sim and waits
        a bit for it to terminate.  If it does not terminate, send
        SIGTERM a few more times.  If it still refuses to close, send
        a SIGKILL.  If all that fails, raise an exception.
        """
        if (self.handler.debug or utils.debug):
            print("Terminating")
        if self.io.closeme:
            self.handler.close()
        count = 10
        while (count > 0):
            if (count < 6):
                self.signal(signal.SIGTERM)
            else:
                self.signal(signal.SIGKILL)
            # It would be really nice if waitpid had a timeout options,
            # in absense of that simulate it, sort of.
            subcount = 500
            while (subcount > 0):
                time.sleep(.01)
                pid, rv = os.waitpid(self.pid, os.WNOHANG)
                if (pid > 0):
                    self.handler = None
                    return
                subcount -= 1
            count -= 1
        raise Exception("ipmisim did not terminate");
