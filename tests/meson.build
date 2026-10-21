python_tests = [
    'test_xfer_basic_tcp.py', 'test_xfer_basic_udp.py',
    'test_xfer_basic_stdio.py', 'test_xfer_basic_ssl_tcp.py',
    'test_xfer_basic_telnet.py', 'test_xfer_basic_ipmisol.py',
    'test_xfer_basic_sctp.py', 'test_tty_base.py', 'test_rfc2217.py',
    'test_tracing.py', 'test_opstrings.py', 'test_misc.py',
    'test_xfer_small_tcp.py', 'test_xfer_small_udp.py',
    'test_xfer_small_stdio.py', 'test_xfer_small_ssl_tcp.py',
    'test_xfer_small_telnet.py', 'test_xfer_small_ipmisol.py',
    'test_xfer_small_sctp.py', 'test_xfer_large_stdio.py',
    'test_xfer_large_tcp.py', 'test_xfer_large_telnet.py',
    'test_xfer_large_ssl_tcp.py', 'test_xfer_large_ipmisol.py',
    'test_xfer_large_sctp.py', 'test_xfer_large_udp.py',
]

sh = find_program('sh')
python3 = find_program('python3')
testpath = meson.current_source_dir()

test_env = environment()
test_env.set('TESTPATH', testpath)
test_env.set('SER2NET_EXEC', ser2net.full_path())

# Like AM_TESTS_ENVIRONMENT in Makefile.am, create the keys for the SSL
# tests on the first run.
runtest = 'if [ ! -e ca ]; then "$0"/make_keys; fi; exec "$1" "$0"/"$2"'

foreach t : python_tests
    test(
        t,
        sh,
        args: ['-c', runtest, testpath, python3.full_path(), t],
        env: test_env,
        workdir: meson.current_build_dir(),
        depends: ser2net,
        is_parallel: false,
        timeout: 600,
    )
endforeach
