=======
ser2net
=======

This is ser2net, a program for allowing connections between gensio
accepters and gensio connectors.  Generally, this would be a network
connections to serial ports or IPMI Serial Over Lan (SOL) connections,
but there are lots of gensios and lots of options.  See gensio(5) for
information on gensios.

Note that the gensio library is required for ser2net.  It is available
as a tarball in the ser2net sourceforge files, or you can get it from
github at https://github.com/cminyard/gensio

See the man page ser2net(8) for information about using the program.
Also see ser2net.yaml(5) for information on the configuration file.
An example configuration file is provided in ser2net.yaml.

Since gensios support encryption and authentication, these are also
available to ser2net.  The gensiot and gtlssh programs that are part
of gensio can do this encryption.  The telnet-ssl program can also be
used for this.  This is documented in ser2net.yaml(5).

Note that ser2net supports RFC 2217 (remote control of serial port
parameters) via the telnet gensio, but you must have a compliant
client.  The gensiot client can do this, as well as gtlssh.  The
gensio library provides programmatic access for C and Python.  Beyond
that, the only one I know of is kermit
(http://www.columbia.edu/kermit).

ser2net supports making connections to IPMI SOL (serial over LAN)
capable systems.  This way, if you have a system with SOL, you can use
it with programs that speak sockets and avoid having to run a serial
cable to the system.  It uses OpenIPMI for this, so you have to know
how to make an OpenIPMI connection to the remote system.  That can be
rather complicated, but for a simple example, add a connection like::

  connection: &ipmicon1
    accepter: telnet,tcp,3022
    connector: ipmisol,lan -U <userid> -P <password> <ipmi BMC IP>,115200

Obviously, use the IPMI BMC userid and password here.  Depending on
your system there are a lot of other options, and configuration of
IPMI on the remote system is not for the faint of heart.  And also, if
you put passwords in the ser2net.conf file, it becomes a security
issue and you should make it readable only by the user that runs
ser2net.  There are ways to insert data from files, too, so the
password doesn't have to be in the clear in the main configuration
file, see the ser2net.yaml(5) manpage for details.

ser2net also supports threading.  By default it runs with a single
thread but you can add '-t <num threads>' and it will spawn the given
number of threads.  On modern Linux systems it uses epoll to avoid
the "thundering herd" issue, so it should be quite scalable.  Also,
it runs reconfigurations in a separate thread to avoid a reconfig
blocking things up.

If you don't want to compile with threads, you can add
"--with-pthreads=no" to the configure line.

This is a normal autoconf system, nothing special.  Note that if you
get this directly from git, you won't have the build infrastructure
included.  There is a script named "reconf" in the main directory
that will create it for you.

If you don't know about autoconf, the INSTALL file has some info,
or google it.

If you want the opposite of ser2net (you want to connect to a "local"
serial port device that is really remote) then Cyclades has provided
a tool for this at https://sourceforge.net/projects/cyclades-serial/.
It is capable of connecting to ser2net using RFC2217.

If you check this out from git, you won't have all the configure
programs and files, because those are generated.  Do::

   autoreconf -i

to generate everything first.  Then you can run configure.

=============
Running Tests
=============

There are a number of tests for ser2net.  They currently only run on
Linux and require some external tools.

They require the serialsim kernel module and python interface.  These
are at https://github.com/cminyard/serialsim and allow the tests to
use a simulated serial port to read modem control line, inject errors,
etc.

They require the gensio python module.

They also require the ipmi_sim program from the OpenIPMI library at
https://github.com/cminyard/openipmi to run the ipmisol tests.
