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

"""Prepare client-to-node SSL for Scylla Doctor CI / docker tests.

Must run ``prepare`` *before* Scylla starts so ``scylla.yaml`` is the source of the
enabled encryption options (not command-line overrides). ``configure-cqlsh`` must
run *after* ``/docker-entrypoint.py`` because that entrypoint rewrites ``cqlshrc``.
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional

import yaml

DEFAULT_CERT_DIR = "/etc/scylla/ssl"
DEFAULT_SCYLLA_YAML = "/etc/scylla/scylla.yaml"


def generate_self_signed_certs(directory: Path) -> Dict[str, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    keyfile = directory / "db.key"
    certificate = directory / "db.crt"
    subprocess.check_call([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-days", "365",
        "-nodes",
        "-keyout", str(keyfile),
        "-out", str(certificate),
        # CN/SAN is 127.0.0.1 while the client connects via "localhost"; only safe because
        # cqlshrc sets validate = false below. Keep both in sync if validation is ever enabled.
        "-subj", "/CN=127.0.0.1",
    ])
    os.chmod(keyfile, 0o600)
    os.chmod(certificate, 0o644)
    return {"certificate": certificate, "keyfile": keyfile}


def patch_scylla_yaml(yaml_file: Path, certificate: Path, keyfile: Path) -> None:
    parsed = (yaml.safe_load(yaml_file.read_text()) if yaml_file.is_file() else None) or {}
    options = parsed.get("client_encryption_options") or {}
    if (options.get("enabled") is True
            and options.get("certificate") == str(certificate)
            and options.get("keyfile") == str(keyfile)):
        return

    parsed["client_encryption_options"] = {
        "enabled": True,
        "certificate": str(certificate),
        "keyfile": str(keyfile),
        "require_client_auth": False,
    }
    with yaml_file.open("w") as handle:
        yaml.safe_dump(parsed, handle, default_flow_style=False, sort_keys=False)


def configure_cqlshrc(cqlshrc: Path, certificate: Path, timeout_seconds: int = 600) -> None:
    # docker-entrypoint.py rewrites cqlshrc (without [ssl]) on every start, so a file that still
    # carries an [ssl] section is stale from a previous run: keep waiting for the rewrite instead
    # of returning early, or the entrypoint overwrites the section after we leave.
    deadline = time.time() + timeout_seconds
    while not (cqlshrc.is_file() and "[ssl]" not in cqlshrc.read_text()):
        if time.time() >= deadline:
            raise RuntimeError(f"{cqlshrc} was not (re)written by docker-entrypoint.py within {timeout_seconds}s")
        time.sleep(0.2)
    existing = cqlshrc.read_text()
    if not existing.endswith("\n"):
        existing += "\n"
    cqlshrc.write_text(
        existing
        + "[ssl]\n"
        f"certfile = {certificate}\n"
        "validate = false\n"
    )


def cmd_prepare() -> None:
    paths = generate_self_signed_certs(Path(DEFAULT_CERT_DIR))
    patch_scylla_yaml(Path(DEFAULT_SCYLLA_YAML), paths["certificate"], paths["keyfile"])


def cmd_configure_cqlsh() -> None:
    cqlshrc = Path.home() / ".cassandra" / "cqlshrc"
    configure_cqlshrc(cqlshrc, Path(DEFAULT_CERT_DIR) / "db.crt")


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "configure-cqlsh"))
    args = parser.parse_args(argv)
    if args.command == "prepare":
        cmd_prepare()
    else:
        cmd_configure_cqlsh()
    return 0


if __name__ == "__main__":
    sys.exit(main())
