Summary: Tool to collect debug information
Name: scylla-doctor
Release: 1%{?dist}
License: AGPL-3.0-only
BuildArch: noarch
Requires: (scylla-enterprise-python3 or scylla-python3 or python3)

%description
Collects debug information required for troubleshooting
issues with a Scylla database.

%prep

%build

%install
mkdir -p %{buildroot}/opt/scylladb/bin/
install -m 755 %{_topdir}/../../scylla_doctor.pyz %{buildroot}/opt/scylladb/bin/scylla_doctor.pyz

%post
ln -s -f /opt/scylladb/bin/scylla_doctor.pyz /usr/bin/scylla-doctor

%preun
rm -f /usr/bin/scylla-doctor

%files
/opt/scylladb/bin/scylla_doctor.pyz

%doc AUTHORS README.md CHANGELOG LICENSE

%changelog
* Tue May 28 2024 Vladislav Zolotarov <vladz@scylladb.com>
- Initial version of the package
