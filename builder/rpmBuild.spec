Name:       rtcagent
Version:
Release:
Summary:    capture SIP traffic include TLS without certificate
License:    AGPL-3.0
URL:        https://www.qxip.net
Source0:    %{name}-%{version}.tar.gz

%global _missing_build_ids_terminate_build 0
%define debug_package %{nil}

BuildRequires: make
BuildRequires: clang

%description
SIP/TLS plaintext capture,

supports kamailio, freeswitch, opensips

%prep
%setup -c

%build
make

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/local/bin/
install -m 755 bin/rtcagent %{buildroot}/usr/local/bin/rtcagent

%files
/usr/local/bin/rtcagent

%changelog
