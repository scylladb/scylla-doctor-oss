SHELL=/bin/bash

# Determine whether to use podman or docker
CONTAINER_ENGINE := $(shell if command -v podman &> /dev/null; then echo podman; else echo docker; fi)

.PHONY: container-build
container-build: version
	$(CONTAINER_ENGINE) build -t scylla-doctor-test -f Dockerfile.test .
	$(CONTAINER_ENGINE) rm -f scylla-doctor-test || true
	$(CONTAINER_ENGINE) run --privileged -d --name scylla-doctor-test --cap-add=NET_ADMIN scylla-doctor-test --listen-address 127.0.0.1

.PHONY: container-enter
container-enter: container-build
	@bash -c '\
	set -e; \
	trap "$(CONTAINER_ENGINE) stop scylla-doctor-test || true" EXIT; \
	$(CONTAINER_ENGINE) exec -ti -w /doctor scylla-doctor-test bash \
'

.PHONY: container-lint
container-lint: container-build
	@bash -c '\
	set -e; \
	trap "$(CONTAINER_ENGINE) stop scylla-doctor-test || true" EXIT; \
	$(CONTAINER_ENGINE) exec -ti -w /doctor scylla-doctor-test python3 -m flake8; \
	$(CONTAINER_ENGINE) exec -ti -w /doctor scylla-doctor-test python3 -m mypy . --show-error-codes \
'

.PHONY: container-test
container-test: container-build
	@bash -c '\
	set -e; \
	trap "$(CONTAINER_ENGINE) stop scylla-doctor-test || true" EXIT; \
	$(CONTAINER_ENGINE) exec -ti -w /doctor scylla-doctor-test python3 -m flake8; \
	$(CONTAINER_ENGINE) exec -ti -w /doctor scylla-doctor-test python3 -m mypy . --show-error-codes; \
	$(CONTAINER_ENGINE) exec -ti -w /doctor scylla-doctor-test python3 -m pytest -vv --runxfail --cov-report html --cov-report term --cov=. --durations 10; \
	rm -rf ./tmp; \
	$(CONTAINER_ENGINE) cp scylla-doctor-test:/doctor/htmlcov ./tmp \
'

.PHONY: container-single-test
container-single-test: container-build
	@bash -c '\
	set -e; \
	trap "$(CONTAINER_ENGINE) stop scylla-doctor-test || true" EXIT; \
	$(CONTAINER_ENGINE) exec -ti -w /doctor scylla-doctor-test python3 -m pytest -vv $(TEST) \
'

.PHONY: version
version:
	$(shell echo `cat dist/common/major`.`cat dist/common/minor` > ./version)

DEST_DIR ?= ./tmp

.PHONY: portable
portable:
	rm -rf ./tmp && mkdir ./tmp
	$(MAKE) copy_stripped
	python3 -m zipapp -p "/opt/scylladb/python3/bin/python3" ./tmp -m "scylla_doctor:main" -o scylla_doctor.pyz
	rm -rf ./tmp

.PHONY: full
full:
	rm -rf ./tmp && mkdir ./tmp
	$(MAKE) copy_all
	python3 -m zipapp -p "/usr/bin/env python3" ./tmp -m "scylla_doctor:main" -o scylla_doctor.pyz
	rm -rf ./tmp


.PHONY: copy_stripped
copy_stripped: version
	cp scylla_doctor.py common.py collectors.py utils.py collectors_base.py analyzers_base.py version $(DEST_DIR)
	cp -r models $(DEST_DIR)

.PHONY: copy_all
copy_all:
	$(MAKE) copy_stripped
	cp analyzers.py $(DEST_DIR)

.PHONY: clean
clean:
	rm -rf $(DEST_DIR) scylla_doctor.pyz version

.PHONY: clean_tgz
clean_tgz:
	rm -f scylla-doctor-*.tar.gz changelog

.PHONY: clean_deb
clean_deb:
	find dist/debian/* -maxdepth 0 -type d | xargs rm -rf
	rm -f dist/debian/*.deb

.PHONY: clean_rpm
clean_rpm:
	rm -rf dist/rpmbuild

.PHONY: gen_next_stripped_deb
gen_next_stripped_deb:
	FULL_VERSION=$(shell echo `cat dist/common/major`.`cat dist/common/minor`) $(MAKE) -C dist/debian -f $(PWD)/Makefile make_stripped_deb_with_version

.PHONY: gen_next_stripped_rpm
gen_next_stripped_rpm:
	FULL_VERSION=$(shell echo `cat dist/common/major`.`cat dist/common/minor`) $(MAKE) make_stripped_rpm_with_version

.PHONY: gen_tgz
gen_tgz:
	FULL_VERSION=$(shell echo `cat dist/common/major`.`cat dist/common/minor`) $(MAKE) make_tgz_with_version

.PHONY: make_stripped_deb_with_version
make_stripped_deb_with_version:
	mkdir -p scylla-doctor-$(FULL_VERSION)/DEBIAN
	mkdir -p scylla-doctor-$(FULL_VERSION)/opt/scylladb/bin
	mkdir -p scylla-doctor-$(FULL_VERSION)/etc/scylla
	mkdir -p scylla-doctor-$(FULL_VERSION)/usr/share/doc/scylla-doctor/
	cp postinst prerm scylla-doctor-$(FULL_VERSION)/DEBIAN/
	cp changelog scylla-doctor-$(FULL_VERSION)/usr/share/doc/scylla-doctor/changelog.Debian
	cp ../../AUTHORS ../../README.md copyright ../../CHANGELOG ../../../LICENSE scylla-doctor-$(FULL_VERSION)/usr/share/doc/scylla-doctor/
	gzip scylla-doctor-$(FULL_VERSION)/usr/share/doc/scylla-doctor/changelog.Debian
	echo "Version: "$(FULL_VERSION) > scylla-doctor-$(FULL_VERSION)/DEBIAN/control.tmp
	cat scylla-doctor-$(FULL_VERSION)/DEBIAN/control.tmp control > scylla-doctor-$(FULL_VERSION)/DEBIAN/control
	rm -f scylla-doctor-$(FULL_VERSION)/DEBIAN/control.tmp
	cp ../../scylla_doctor.pyz scylla-doctor-$(FULL_VERSION)/opt/scylladb/bin/
	chmod a+x scylla-doctor-$(FULL_VERSION)/opt/scylladb/bin/scylla_doctor.pyz
	cp ../../scylla_doctor.conf scylla-doctor-$(FULL_VERSION)/etc/scylla/
	dpkg-deb --build --root-owner-group -Zxz scylla-doctor-$(FULL_VERSION)
	rm -rf scylla-doctor-$(FULL_VERSION)

.PHONY: make_stripped_rpm_with_version
make_stripped_rpm_with_version:
	mkdir -p dist/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
	echo "Version: "$(FULL_VERSION) > dist/rpmbuild/SPECS/scylla-doctor.spec.tmp
	cat dist/rpmbuild/SPECS/scylla-doctor.spec.tmp dist/redhat/scylla-doctor.spec > dist/rpmbuild/SPECS/scylla-doctor.spec
	rm -f dist/rpmbuild/SPECS/scylla-doctor.spec.tmp
	cp AUTHORS README.md CHANGELOG ../LICENSE dist/rpmbuild/BUILD/
	rpmbuild -bb --define "_topdir `pwd`/dist/rpmbuild" dist/rpmbuild/SPECS/scylla-doctor.spec

.PHONY: make_tgz_with_version
make_tgz_with_version:
	tar czvf scylla-doctor-$(FULL_VERSION).tar.gz scylla_doctor.pyz scylla_doctor.conf AUTHORS README.md CHANGELOG ../LICENSE

# Create a DEB artifact for a stripped Scylla Doctor version
.PHONY: stripped_deb
stripped_deb:
	$(MAKE) clean
	$(MAKE) clean_deb
	$(MAKE) portable
	$(MAKE) gen_next_stripped_deb

# Create an RPM artifact for a stripped Scylla Doctor version
.PHONY: stripped_rpm
stripped_rpm:
	$(MAKE) clean
	$(MAKE) clean_rpm
	$(MAKE) portable
	$(MAKE) gen_next_stripped_rpm

.PHONY: stripped_tgz
stripped_tgz:
	$(MAKE) clean
	$(MAKE) clean_tgz
	$(MAKE) portable
	$(MAKE) gen_tgz

.PHONY: full_tgz
full_tgz:
	$(MAKE) clean
	$(MAKE) clean_tgz
	$(MAKE) full
	$(MAKE) gen_tgz