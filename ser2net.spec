Name: ser2net
Version: 1.3
Release: 1
License: GPL
Summary: Serial to network proxy
Group: System Environment/Daemons
Packager: Ivan F. Martinez <ivanfm@ecodigit.com.br>
Source: http://prdownloads.sourceforge.net/ser2net/ser2net-%{version}.tar.gz
URL: http://sourceforge.net/projects/ser2net/
BuildRoot: /var/tmp/%{name}-%{version}-root
AutoReqProv: no
%description
Make serial ports available to network via TCP/IP
connection

%prep

%setup

%build
./configure --prefix="/usr" 
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/etc
cp ser2net.conf $RPM_BUILD_ROOT/etc
make DESTDIR=$RPM_BUILD_ROOT install

%files
%defattr(-,root,root)                                                                                         
%config(noreplace) /etc/ser2net.conf
%doc README NEWS ChangeLog COPYING INSTALL AUTHORS
/bin/*
/man/*


%changelog
* Fri Jun 29 2001 Corey Minyard <minyard@acm.org>
- Updated to 1.3
- Set the prefix to "/" to install at root.
* Tue Jun 19 2001 Ivan F. Martinez <ivanfm@ecodigit.com.br>
- package created
