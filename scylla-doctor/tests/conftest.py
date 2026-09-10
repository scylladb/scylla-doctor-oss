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

import glob
import os
import pytest
import subprocess
import time
from collections import OrderedDict
from typing import Tuple, Optional, Type

import scylla_doctor


@pytest.fixture(scope='session')
def doctor_factory():
    """
    Construct a doctor with given callectors, analyzers and configuration.
    Pass collectors/analyzers as None, if you want to leave them untouched (and leave it to auto-detection).
    """

    cql_config = scylla_doctor.Executor.cql_config
    paths = scylla_doctor.Executor.paths

    # https://github.com/python/mypy/issues/6556
    def factory(collectors: Optional[Tuple[Type[scylla_doctor.Collector]]] = (),  # type: ignore
                analyzers: Optional[Tuple[Type[scylla_doctor.Analyzer]]] = (),  # type: ignore
                config_options=()):

        doctor_env = scylla_doctor.DoctorEnvironment([])
        scylla_doctor.Executor.cql_config = doctor_env.get_config_section("CQL")
        scylla_doctor.Executor.cql_config = doctor_env.get_config_section("Paths")
        for option in config_options:
            doctor_env.set_config_parameter(*option)
        doctor = scylla_doctor.Doctor(doctor_env)

        if collectors is not None:
            doctor.collectors = OrderedDict()
            for collector in collectors:
                instance = collector(doctor.environment.configuration, doctor.environment.paths)
                # Tests assert on output entries; production Doctor still gates via should_store_output().
                instance.set_store_output(True)
                doctor.collectors[collector.__name__] = instance
        if analyzers is not None:
            doctor.analyzers = OrderedDict()
            for analyzer in analyzers:
                doctor.analyzers[analyzer.__name__] = analyzer(doctor.environment.configuration)
        return doctor

    yield factory
    scylla_doctor.Executor.cql_config = cql_config
    scylla_doctor.Executor.paths = paths


@pytest.fixture(scope='session')
def provider_identify_shorten_timeout_options():
    """
    Options to make CloudProvider.identify() fail faster.
    """
    return [
        ("InfrastructureProviderCollector", "timeout", "0.05"),
        ("InfrastructureProviderCollector", "retries", "0"),
        ("InfrastructureProviderCollector", "retry_interval", "0"),
    ]


@pytest.fixture(scope="session")
def await_scylla_start():
    attempts, delay = 120, 1
    for i in range(0, attempts):
        if subprocess.run("cqlsh localhost -e 'SELECT now() from system.local'",
                          check=False, shell=True).returncode == 0:
            return
        time.sleep(delay)
    assert False, 'Scylla did not start!'


@pytest.fixture(autouse=True, scope="function")
def cleanup():
    """
    Remove all files that may be produced by Scylla Doctor before and after each test execution.
    """
    def __cleanup():
        if os.path.isfile("vitals.json"):
            os.remove("vitals.json")
            log_files = glob.glob("scylla_logs_*")
            for file in log_files:
                os.remove(file)

    __cleanup()
    yield
    __cleanup()
