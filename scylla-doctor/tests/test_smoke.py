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

import io
import json
import inspect
import os.path

import analyzers
import scylla_doctor
from analyzers_base import Analyzer


def test_smoke(provider_identify_shorten_timeout_options, await_scylla_start):
    """
    Run all available checks together to make sure there are no crashes.
    """
    doctor_env = scylla_doctor.DoctorEnvironment(['--verbose'])
    for option in provider_identify_shorten_timeout_options:
        doctor_env.set_config_parameter(*option)
    doctor = scylla_doctor.Doctor(doctor_env)

    # Check that analyzers were successfully loaded
    analyzer_classes = [cls for _, cls in inspect.getmembers(analyzers, predicate=inspect.isclass)
                        if not inspect.isabstract(cls) and issubclass(cls, Analyzer)]
    assert len(doctor.analyzers) == len(analyzer_classes)

    # Run checkups
    doctor.run()

    # Print results
    doctor.print_results()

    # check that all dependencies were satisfied
    for analyzer in doctor.analyzers.values():
        assert "results not found" not in analyzer.message


def test_save_and_load_vitals(provider_identify_shorten_timeout_options):
    """
    Check that after collectors run, vitals can be saved to json, then restored and passed to analyzers.
    """
    doctor_env = scylla_doctor.DoctorEnvironment(["--save-vitals", "--output", "short"])
    for option in provider_identify_shorten_timeout_options:
        doctor_env.set_config_parameter(*option)
    doctor = scylla_doctor.Doctor(doctor_env)
    doctor.run()
    assert os.path.isfile("vitals.json")

    doctor_env = scylla_doctor.DoctorEnvironment(["--load-vitals"])
    doctor = scylla_doctor.Doctor(doctor_env)
    doctor.run()

    doctor.print_results(format=scylla_doctor.DoctorOutputFormat.SHORT)

    doctor_env = scylla_doctor.DoctorEnvironment(["--load-vitals", "-v"])
    doctor = scylla_doctor.Doctor(doctor_env)
    doctor.run()

    doctor.print_results(format=scylla_doctor.DoctorOutputFormat.FULL)


def test_output_json(provider_identify_shorten_timeout_options, monkeypatch):
    doctor_env = scylla_doctor.DoctorEnvironment(["--output", "json"])
    for option in provider_identify_shorten_timeout_options:
        doctor_env.set_config_parameter(*option)
    doctor = scylla_doctor.Doctor(doctor_env)
    doctor.run()

    with io.StringIO() as result:
        doctor.print_results(format=scylla_doctor.DoctorOutputFormat.JSON, file=result)
        assert json.loads(result.getvalue())
