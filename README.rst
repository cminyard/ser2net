=======
ser2net
=======

This is ser2net, a program for allowing connections between gensio
accepters and gensio connectors.  Generally, this would be a network
connections to serial ports or IPMI Serial Over Lan (SOL) connections,
but there are lots of gensios and lots of options.  See gensio(5) for
information on gensios.

========
Building
========

You need two libraries to build ser2net: libyaml and gensio.  On
Ubuntu you can install libyaml with:

  apt install libyaml-dev

The gensio library may be available on your distro, or it may not, or
it may be old and missing things you need.  It is available as a
tarball in the ser2net sourceforge files, or you can get it from
github at https://github.com/cminyard/gensio.  A lot of the
capabilities of ser2net (crypto, mdns, IPMI) come from gensio, so it
must be compiled correctly for those.

This is a normal autoconf system, nothing special.  Note that if you
get this directly from git, you won't have the build infrastructure
included.  There is a script named "reconf" in the main directory
that will create it for you.

If you don't know about autoconf, the INSTALL file has some info,
or google it.

=================
Docker Containers
=================

Docker container support is available at:
   https://github.com/jippi/docker-ser2net

=====
Using
=====

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

If you want the opposite of ser2net (you want to connect to a "local"
serial port device that is really remote) then Cyclades has provided
a tool for this at https://sourceforge.net/projects/cyclades-serial/.
It is capable of connecting to ser2net using RFC2217.

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

==================================
A Complete Encrypted Example Setup
==================================

Lets suppose you have a server with serial port /dev/ttyUSB0 that you
want to make available on the network, and you want the connection
encrypted.  Here an example, after installing gensio and ser2net.

Edit the ser2net configuration file::

  sudo mkdir /etc/ser2net
  sudo vi /etc/ser2net/ser2net.yaml

The contents of ser2net.yaml should be::

  %YAML 1.1
  ---

  define: &banner Connected to port \N(\d)\r\n

  default:
        name: local
        value: true
        class: serialdev

  default:
        name: mdns
        value: true

  default:
        name: mdns-sysattrs
        value: true

  connection: &my-console
        accepter: telnet(rfc2217),mux,certauth(),ssl,tcp,3001
        connector: serialdev,/dev/ttyUSB0,115200N81
        options:
                banner: *banner

Create a user for ser2net to run as::

  sudo useradd -r -M -d /usr/share/ser2net -G dialout ser2net
  sudo mkdir /usr/share/ser2net
  sudo chown ser2net.ser2net /usr/share/ser2net

You don't want to run ser2net as root, that's a bad security
practice.  Now generate the server keys::

  sudo gtlssh-keygen --keydir /etc/ser2net serverkey ser2net
  sudo chown ser2net.ser2net /etc/ser2net/*

ser2net's authentication directory is in /usr/share/ser2net/auth::

  sudo -u ser2net mkdir /usr/share/ser2net/auth

Now we must create the keys for logging in to the server.  You do this
on your host system with gtlssh-keygen, assuming you haven't already
done so.  Assume your userid is myuser, and you are logged in on the
host system (not the server).  Generate the key::

  gtlssh-keygen keygen

And copy $HOME/.gtlssh/default.crt to the server.  You will put it in
/usr/share/ser2net/auth/myuser/allowed_certs, and you want to give it
a meaningful name.  General best practice is to have a separate key
for every client system and put each key onto the target, so using the
client name is good practice.

Note: Do not copy the .key file anywhere else.  That is the file you
need to keep secret.  Just copy the .crt file.

So here we go (after the default.crt file is copied to the server)::

  sudo -u ser2net mkdir -p /usr/share/ser2net/auth/myuser/allowed_certs
  sudo -u ser2net cp default.crt \
        /usr/share/ser2net/auth/myuser/allowed_certs/client.crt
  sudo -u ser2net gtlssh-keygen rehash \
        /usr/share/ser2net/auth/myuser/allowed_certs

Don't forget the rehash step.  If you add or remove a key from
allowed_certs, you have to rehash.

Then start (or restart) ser2net and you should be set.  Make sure it
runs as the user ser2net, like::

  sudo -u ser2net ser2net

From myuser on client, you can connect to the port::

  gtlssh --telnet -p 3001 server

If you have avahi enabled (it's usually on by default on modern
systems) you can use mdns.  You may notice that mdns is configured in
the ser2net configuration, so the name of the connection (my-console
in this case) is available via mdns.  So you can just do::

  gtlssh -m my-console

and gtlssh will look up the mdns name, the port, if telnet is enabled,
etc. and make the connection.  This only works on a local network,
though, if you are bridged it won't work.
