
AM_CFLAGS = -I$(top_srcdir)

utst_builddir = $(shell readlink -f $(top_builddir))
utst_srcdir = $(shell readlink -f $(top_srcdir))

AM_TESTS_ENVIRONMENT = \
    LD_LIBRARY_PATH=$(prefix)/lib; export LD_LIBRARY_PATH; \
    TESTPATH=$(utst_srcdir)/tests; export TESTPATH; \
    SER2NET_EXEC=$(utst_builddir)/ser2net; export SER2NET_EXEC; \
    if [ ! -e ca ]; then \
	$(utst_srcdir)/tests/make_keys; \
    fi;

test_setup:
	echo "$(AM_TESTS_ENVIRONMENT) python3 $(utst_srcdir)/tests/"

TESTS = test_xfer_basic_tcp.py test_xfer_basic_udp.py test_xfer_basic_stdio.py \
	test_xfer_basic_ssl_tcp.py test_xfer_basic_telnet.py \
	test_xfer_basic_ipmisol.py test_xfer_basic_sctp.py \
	test_tty_base.py test_rfc2217.py \
	test_tracing.py test_opstrings.py test_misc.py \
	test_xfer_small_tcp.py test_xfer_small_udp.py test_xfer_small_stdio.py \
	test_xfer_small_ssl_tcp.py test_xfer_small_telnet.py \
	test_xfer_small_ipmisol.py test_xfer_small_sctp.py \
	test_xfer_large_stdio.py test_xfer_large_tcp.py \
	test_xfer_large_telnet.py test_xfer_large_ssl_tcp.py \
	test_xfer_large_ipmisol.py test_xfer_large_sctp.py

EXTRA_DIST = $(TESTS) utils.py dataxfer.py ipmisimdaemon.py termioschk.py

clean-local:
	rm -rf ca
