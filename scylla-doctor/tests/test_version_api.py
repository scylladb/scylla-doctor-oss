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

import json
import os

import pytest

import scylla_doctor
import collectors
from collectors_base import CollectorStatus


def _sd_version_vitals(version: str) -> dict:
    return {
        "SDVersionCollector": {
            "status": CollectorStatus.PASSED.value,
            "data": {"version": version},
            "output": [],
            "message": f"SD version: {version}",
        }
    }


def _write_vitals(path: str, version: str) -> None:
    with open(path, 'w') as f:
        json.dump(_sd_version_vitals(version), f)


def test_read_vitals_file_version(tmp_path):
    vitals_file = tmp_path / "vitals.json"
    _write_vitals(str(vitals_file), "9.8.7")

    assert scylla_doctor.Doctor.read_vitals_file_version(str(vitals_file)) == "9.8.7"


def test_vitals_version_flag(capsys, tmp_path):
    vitals_file = tmp_path / "vitals.json"
    _write_vitals(str(vitals_file), "2.3.4")

    doctor_env = scylla_doctor.DoctorEnvironment(["--vitals-version", str(vitals_file)])
    doctor = scylla_doctor.Doctor(doctor_env)

    with pytest.raises(SystemExit) as exc_info:
        doctor.run()
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "version: 2.3.4"


def test_version_flag(capsys, doctor_factory, tmp_path, monkeypatch):
    version = "5.6.7"
    version_file = tmp_path / "version"
    version_file.write_text(f"{version}\n")

    monkeypatch.setattr(os.path, 'isfile', lambda p: p == str(version_file))
    monkeypatch.setattr(os.path, 'dirname', lambda _: str(tmp_path))

    doctor = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=())
    doctor.environment = scylla_doctor.DoctorEnvironment(["--version"])

    with pytest.raises(SystemExit) as exc_info:
        doctor.run()
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"version: {version}"


def test_vitals_version_mismatch_exits(doctor_factory, tmp_path, monkeypatch):
    tool_version = "1.0.0"
    version_file = tmp_path / "version"
    version_file.write_text(f"{tool_version}\n")

    vitals_file = tmp_path / "vitals.json"
    _write_vitals(str(vitals_file), "9.9.9")

    monkeypatch.setattr(os.path, 'isfile', lambda p: p == str(version_file))
    monkeypatch.setattr(os.path, 'dirname', lambda _: str(tmp_path))

    doctor = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=())
    doctor.environment = scylla_doctor.DoctorEnvironment(["--load-vitals", str(vitals_file)])

    with pytest.raises(SystemExit) as exc_info:
        doctor.run()
    assert exc_info.value.code == 1


def test_ignore_vitals_version_allows_mismatch(doctor_factory, tmp_path, monkeypatch):
    tool_version = "1.0.0"
    version_file = tmp_path / "version"
    version_file.write_text(f"{tool_version}\n")

    vitals_file = tmp_path / "vitals.json"
    _write_vitals(str(vitals_file), "9.9.9")

    monkeypatch.setattr(os.path, 'isfile', lambda p: p == str(version_file))
    monkeypatch.setattr(os.path, 'dirname', lambda _: str(tmp_path))

    doctor = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=())
    doctor.environment = scylla_doctor.DoctorEnvironment(
        ["--load-vitals", str(vitals_file), "--ignore-vitals-version", "--output", "short"])
    doctor.run()


def test_vitals_version_mismatch_with_disabled_collector(doctor_factory, tmp_path, monkeypatch):
    tool_version = "1.0.0"
    version_file = tmp_path / "version"
    version_file.write_text(f"{tool_version}\n")

    vitals_file = tmp_path / "vitals.json"
    _write_vitals(str(vitals_file), "9.9.9")

    monkeypatch.setattr(os.path, 'isfile', lambda p: p == str(version_file))
    monkeypatch.setattr(os.path, 'dirname', lambda _: str(tmp_path))

    doctor = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=(),
                            config_options=[("SDVersionCollector", "run", "no")])
    doctor.environment = scylla_doctor.DoctorEnvironment(["--load-vitals", str(vitals_file)])

    with pytest.raises(SystemExit) as exc_info:
        doctor.run()
    assert exc_info.value.code == 1


def test_version_flag_with_disabled_collector(capsys, doctor_factory, tmp_path, monkeypatch):
    version = "5.6.7"
    version_file = tmp_path / "version"
    version_file.write_text(f"{version}\n")

    monkeypatch.setattr(os.path, 'isfile', lambda p: p == str(version_file))
    monkeypatch.setattr(os.path, 'dirname', lambda _: str(tmp_path))

    doctor = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=(),
                            config_options=[("SDVersionCollector", "run", "no")])
    doctor.environment = scylla_doctor.DoctorEnvironment(["--version"])

    with pytest.raises(SystemExit) as exc_info:
        doctor.run()
    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == f"version: {version}"
