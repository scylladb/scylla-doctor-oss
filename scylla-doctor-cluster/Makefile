MY_DIRECTORY = $(shell pwd)
SCYLLA_DOCTOR_DIR = $(MY_DIRECTORY)/../scylla-doctor

.PHONY: portable
portable:
	rm -rf ./tmp
	mkdir tmp
	$(MAKE) copy_all -C $(SCYLLA_DOCTOR_DIR) DEST_DIR=$(MY_DIRECTORY)/tmp
	cp scylla_doctor_cluster.py ./tmp/
	python3 -m zipapp -p "/usr/bin/env python3" ./tmp -m "scylla_doctor_cluster:main" -o scylla_doctor_cluster.pyz
	rm -rf ./tmp

.PHONY: make_tgz_with_version
make_tgz_with_version:
	cp ../scylla-doctor/CHANGELOG CHANGELOG.scylla-doctor
	tar czvf scylla-doctor-cluster-$(FULL_VERSION).tar.gz scylla_doctor_cluster.pyz requirements.txt scylla_doctor_cluster.ini README.md CHANGELOG CHANGELOG.scylla-doctor ../LICENSE
	rm CHANGELOG.scylla-doctor

.PHONY: tgz
tgz:
	$(MAKE) clean
	$(MAKE) clean_tgz
	$(MAKE) portable
	FULL_VERSION=$(shell echo `cat $(SCYLLA_DOCTOR_DIR)/dist/common/major`.`cat $(SCYLLA_DOCTOR_DIR)/dist/common/minor`) $(MAKE) make_tgz_with_version

.PHONY: clean
clean:
	rm -rf ./tmp *.pyz

.PHONY: clean_tgz
clean_tgz:
	rm -rf *.tar.gz
