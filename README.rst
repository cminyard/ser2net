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
it may be old and missing things you need.  To use the one from your
distro on Ubuntu, you can probably do:

  apt install libgensio-dev

Otherwise, the gensio library is available as a tarball in the ser2net
sourceforge files, or you can get it from github at
https://github.com/cminyard/gensio.  A lot of the capabilities of
ser2net (crypto, mdns, IPMI) come from gensio, so it must be compiled
correctly for those.

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

===========================================
Connecting to ser2net from the command line
===========================================

This is a very broad subject and depends on the exact configuration,
but to aid in ser2net's usage, a few basic examples are available.

If you have a basic ser2net configuration like::

  connection: &my-port
        accepter: tcp,3001
        connector: serialdev,/dev/ttyUSB0,115200N81

then ser2net just opens a TCP port for you to connect to.  You should
*not* use the "telnet" command to connect to this.  ser2net will not
do the telnet protocol in this case, and it may confuse the telnet
command.

Instead, you can use the gensiot tool from the gensio library (that
ser2net is based upon) to connect.  In the above case, you can do::

  gensiot tcp,host,3001

and it will connect to the port and you can type and such.  You may
notice some consistency in the naming, ser2net is just a veneer over
gensio (with a bunch of added features) and the accepter and connector
lines are directly the strings that the gensio library uses for
accepting and making connections.  You can use gensiot as a pipe and
it will attempt to "do the right thing" based on how it's started.

If you want telnet, you must add telnet to the accepter::

  connection: &my-port
        accepter: telnet,tcp,3001
        connector: serialdev,/dev/ttyUSB0,115200N81

but that really doesn't add any value, except that you can use the
telnet command to connect.  The big value you get with telnet is that
you can enabled rfc2217, as::

  connection: &my-port
        accepter: telnet(rfc2217),tcp,3001
        connector: serialdev,/dev/ttyUSB0,115200N81

Then you can use gensiot:

  gensiot telnet(rfc2217),tcp,host,3001

and with that, you can actually control the serial port parameters,
like baud, stop bits, etc.  See the gensio man page for details.
Unfortunately, the standard telnet command won't do rfc2217.

If you want encryption, see "A Complete Encrypted Example Setup"
below.  You can use the gtlssh command from the gensio library to make
encrypted connections.  You can also use gensiot to make a secure
connection, but you must hand-specify the entire protocol stack and
all the keys and certificates.

====================================
Connecting to ser2net with a program
====================================

You can, of course, connect to ser2net with a program.  If you just
set up tcp, then you can make a normal TCP connection and it will just
work.

If you have telnet specified, then your program must handle the telnet
protocol on top of TCP.

You can also make authenticated and encrypted connections from a
program, but things get more complicated.  You can use the ssl gensio
layer and do mutual authentication with the clientauth option for the
ssl gensio in ser2net.  Then normal SSL will do two-way authentication.

If you want fancier authentication, like password based, then you
would need to use the certauth gensio.  You will need to use the
gensio library, as it's probably the only implementation of certauth
around.  You could write your own, but I wouldn't recommend it.  I'm
not sure I would do it myself if I had to do it again.

Really, if you do anything more than raw TCP, and even if you just do
TCP, I'd strongly suggest using the gensio library.  It make a lot of
things easy, and once you have something that uses it, adding new
features from the library is *very* easy.  It has C, C++, Rust, Go,
and Python bindings.

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
authenticated and encrypted.  Here is an example, after installing
gensio and ser2net.

Note that this is for use with gensio's gtlssh, *not* with normal ssh.
Normal ssh does not currently work with ser2net.  I looked at doing
ssh, and it turned out to be hard to do, as ssh isn't a neatly layered
protocol with easily separable authentication, and the current ssh
libraries available are not suitable at all for gensio.

Anyway, to do this, edit the ser2net configuration file::

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

===============
Windows Support
===============

You can build ser2net for windows.  You need a gensio built for
Windows, of course, and that's supported.  It should just build under
UCRT64 and/or MINGW64.  Beyond gensio, you will also need
mingw-w64-x86_64-libyaml installed.

The sysconfdir and datarootdir do not work on Windows, instead it uses
a file relative to the executable's dectory, ../etc/ser2net and
../share/ser2net. Other than that, everything pretty much works the same.

For installation, use the following configuration::

  ../configure --sbindir=/Ser2Net/bin --libexecdir=/Ser2Net/bin --mandir=/Ser2Net/man \
      --includedir=/Ser2Net/include --prefix=/Ser2Net \
      CPPFLAGS=-I$HOME/install/Gensio/include LDFLAGS=-L$HOME/install/Gensio/lib

Where gensio is already installed there, and then do::

  make install DESTDIR=$HOME/install

You can then use the Inno Setup Compiler to compile ser2net into an
executable installer using the ser2net.iss file.
