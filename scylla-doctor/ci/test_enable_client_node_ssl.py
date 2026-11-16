# Copyright (C) 2021-present ScyllaDB
#
# This file is part of Scylla Doctor.
#
# Scylla Doctor is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Scylla Doctor is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Scylla Doctor.  If not, see <http://www.gnu.org/licenses/>.

import shutil
import threading
from pathlib import Path

import pytest
import yaml

from ci.enable_client_node_ssl import (
    configure_cqlshrc,
    generate_self_signed_certs,
    patch_scylla_yaml,
)


def test_patch_scylla_yaml_appends_when_missing(tmp_path: Path) -> None:
    yaml_file = tmp_path / "scylla.yaml"
    yaml_file.write_text("cluster_name: Test\n")
    certificate = tmp_path / "db.crt"
    keyfile = tmp_path / "db.key"
    patch_scylla_yaml(yaml_file, certificate, keyfile)

    parsed = yaml.safe_load(yaml_file.read_text())
    assert parsed["cluster_name"] == "Test"
    assert parsed["client_encryption_options"]["enabled"] is True
    assert parsed["client_encryption_options"]["certificate"] == str(certificate)
    assert parsed["client_encryption_options"]["keyfile"] == str(keyfile)


def test_patch_scylla_yaml_replaces_existing_section(tmp_path: Path) -> None:
    yaml_file = tmp_path / "scylla.yaml"
    yaml_file.write_text(
        "client_encryption_options:\n"
        "  enabled: false\n"
        "  certificate: /old.crt\n"
        "  keyfile: /old.key\n"
    )
    certificate = tmp_path / "db.crt"
    keyfile = tmp_path / "db.key"
    patch_scylla_yaml(yaml_file, certificate, keyfile)

    parsed = yaml.safe_load(yaml_file.read_text())
    assert parsed["client_encryption_options"]["enabled"] is True
    assert parsed["client_encryption_options"]["certificate"] == str(certificate)


def test_patch_scylla_yaml_is_idempotent(tmp_path: Path) -> None:
    yaml_file = tmp_path / "scylla.yaml"
    yaml_file.write_text("cluster_name: Test\n")
    certificate = tmp_path / "db.crt"
    keyfile = tmp_path / "db.key"
    patch_scylla_yaml(yaml_file, certificate, keyfile)
    first = yaml_file.read_text()
    patch_scylla_yaml(yaml_file, certificate, keyfile)
    assert yaml_file.read_text() == first


def test_configure_cqlshrc_appends_ssl_section(tmp_path: Path) -> None:
    cqlshrc = tmp_path / ".cassandra" / "cqlshrc"
    cqlshrc.parent.mkdir()
    cqlshrc.write_text("[connection]\nhostname = 127.0.0.1\n")
    certificate = tmp_path / "db.crt"
    configure_cqlshrc(cqlshrc, certificate, timeout_seconds=0)

    text = cqlshrc.read_text()
    assert "[connection]" in text
    assert "[ssl]" in text
    assert f"certfile = {certificate}" in text
    assert "validate = false" in text


def test_configure_cqlshrc_waits_for_entrypoint_to_replace_stale_ssl_section(tmp_path: Path) -> None:
    """
    On a container restart the previous run's cqlshrc (with [ssl]) still exists when configure-cqlsh
    starts; it must wait for docker-entrypoint.py to rewrite the file before appending again.
    """
    cqlshrc = tmp_path / "cqlshrc"
    certificate = tmp_path / "db.crt"
    cqlshrc.write_text(f"[connection]\nhostname = stale\n[ssl]\ncertfile = {certificate}\nvalidate = false\n")
    rewrite = threading.Timer(0.5, cqlshrc.write_text, args=("[connection]\nhostname = 127.0.0.1\n",))
    rewrite.start()
    configure_cqlshrc(cqlshrc, certificate, timeout_seconds=5)
    rewrite.join()

    text = cqlshrc.read_text()
    assert "hostname = 127.0.0.1" in text
    assert "stale" not in text
    assert text.count("[ssl]") == 1


def test_configure_cqlshrc_times_out_without_entrypoint(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        configure_cqlshrc(tmp_path / "cqlshrc", tmp_path / "db.crt", timeout_seconds=0)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl is required to generate test certificates")
def test_generate_self_signed_certs(tmp_path: Path) -> None:
    paths = generate_self_signed_certs(tmp_path / "ssl")
    assert paths["certificate"].is_file()
    assert paths["keyfile"].is_file()
