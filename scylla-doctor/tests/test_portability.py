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

import tempfile
import shutil
import zipapp
import subprocess

import pytest


# Stripped (make portable) and full (make full) builds
@pytest.mark.parametrize('packages', [["models", "collectors"], ["models", "collectors", "analyzers"]])
def test_portable_launch(packages):
    tmpdir_src = tempfile.TemporaryDirectory()
    tmpdir_dst = tempfile.TemporaryDirectory()
    for f in ["scylla_doctor.py", "common.py", "utils.py", "analyzers_base.py", "collectors_base.py"]:
        shutil.copy(f, tmpdir_src.name)
    for package in packages:
        shutil.copytree(package, f"{tmpdir_src.name}/{package}")
    zipapp.create_archive(tmpdir_src.name, f"{tmpdir_dst.name}/scylla_doctor.pyz", "/opt/scylladb/python3/bin/python3",
                          "scylla_doctor:main")
    output = subprocess.run(f"{tmpdir_dst.name}/scylla_doctor.pyz", capture_output=True, text=True)
    assert output.returncode == 0, output.stderr
    assert not output.stderr
    # A zipapp whose package walk finds nothing still exits 0, so check collectors were discovered inside it
    assert "SDVersionCollector" in output.stdout
    assert "ClockSourceCollector" in output.stdout

    # The --help epilog lists every discovered class, so it shows whether analyzers were found inside the zipapp
    output = subprocess.run([f"{tmpdir_dst.name}/scylla_doctor.pyz", "--help"], capture_output=True, text=True)
    assert output.returncode == 0, output.stderr
    assert "ClockSourceCollector" in output.stdout
    if "analyzers" in packages:
        assert "ClockSourceAnalyzer" in output.stdout
    else:
        assert "Analyzers:" not in output.stdout
