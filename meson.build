project(
    'ser2net', 'c',
    # Keep in sync with AC_INIT in configure.ac
    version: '4.6.8',
    meson_version: '>= 0.61.0',
    default_options: [
      'warning_level=1' # value "1" will add "-Wall" to the compiler flags
    ],
)
cc = meson.get_compiler('c')

prefix = get_option('prefix')
sysconfdir = prefix / get_option('sysconfdir')
datadir = prefix / get_option('datadir')
sbindir = prefix / get_option('sbindir')

# The sources don't include a config.h, configure.ac passes everything
# on the command line, so do the same here.
c_args = [
    '-DVERSION="@0@"'.format(meson.project_version()),
    '-DSYSCONFDIR="@0@"'.format(sysconfdir),
    '-DDATAROOT="@0@"'.format(datadir),
]

deps = []

pam_dep = cc.find_library('pam', required: get_option('pam'))
if pam_dep.found() and cc.has_header('security/pam_appl.h',
                                     required: get_option('pam'))
    deps += pam_dep
    c_args += '-DUSE_PAM'
endif

crypt_dep = dependency('libxcrypt', required: false)
if not crypt_dep.found()
    crypt_dep = cc.find_library('crypt')
endif
deps += crypt_dep
if cc.has_function('crypt_r', dependencies: crypt_dep)
    c_args += '-DHAVE_CRYPT_R=1'
elif not cc.has_function('crypt', dependencies: crypt_dep)
    error('No libcrypt with crypt_r() or crypt()')
endif

if get_option('sysfs-led-support').disable_auto_if(
        host_machine.system() != 'linux').allowed()
    c_args += '-DUSE_SYSFS_LED_FEATURE=1'
endif

if cc.has_header('wordexp.h')
    c_args += '-DHAVE_WORDEXP_H=1'
endif
if cc.has_function('wordexp')
    c_args += '-DHAVE_WORDEXP=1'
endif

gensio_dep = dependency('libgensio')
deps += gensio_dep
# Newer gensio versions split the OS handler and mdns code into separate
# libraries.
if not cc.has_function('gensio_list_add_tail', dependencies: gensio_dep)
    deps += dependency('libgensioosh')
endif
if not cc.has_function('gensio_alloc_mdns', dependencies: gensio_dep)
    deps += dependency('libgensiomdns')
endif

deps += dependency('yaml-0.1')

add_project_arguments(c_args, language: 'c')

ser2net_sources = files(
    'controller.c', 'dataxfer.c', 'readconfig.c', 'port.c',
    'ser2net.c', 'led.c', 'led_sysfs.c', 'yamlconf.c', 'auth.c', 'gbuf.c',
    'trace.c', 'portconfig.c', 'ser2net_str.c', 'portinfo.c', 'rotator.c',
    'defaults.c', 'addsysattrs.c', 'mdns.c', 'timeproc.c', 'fileio.c',
)

ser2net = executable(
    'ser2net',
    ser2net_sources,
    dependencies: deps,
    install: true,
    install_dir: get_option('sbindir'),
)

install_man('ser2net.8', 'ser2net.yaml.5')

# Like noinst_DATA in Makefile.am, generated but not installed.
service_conf = configuration_data()
service_conf.set('ser2netbindir', sbindir)
configure_file(
    input: 'ser2net.service.in',
    output: 'ser2net.service',
    configuration: service_conf,
)

subdir('tests')
