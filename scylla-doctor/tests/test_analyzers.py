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

import dataclasses
import copy
import json
import random
import pytest

import analyzers
from collectors_base import Output
from scylla_doctor import Analyzer, AnalyzerStatus, CollectorStatus, CollectorResult
from common import DictView, NodePlatform, AbortedException, GossipInfoInvariantValues

from typing import Any, Optional, List, Dict, Tuple


def assert_analyzer_result(analyzer: Analyzer, status: AnalyzerStatus, message: Optional[str]):
    assert analyzer.status == status, f"{analyzer.name}: {analyzer.message}"
    if message:
        assert analyzer.message
        assert message in analyzer.message


@dataclasses.dataclass
class AnalyzerResult:
    status: AnalyzerStatus
    message: str


def check_analyzer(analyzer: Analyzer, collector_name: str, testcases: List[Any],
                   initial_vitals: Optional[dict] = None):
    for case in testcases:
        (input, output) = case
        vitals = dict() if not initial_vitals else copy.deepcopy(initial_vitals)
        vitals[collector_name] = CollectorResult(CollectorStatus.PASSED, input, Output(), '')
        analyzer.analyze(vitals)
        assert_analyzer_result(analyzer, output.status, output.message)


def test_CPUInstructionSetAnalyzer():
    analyzer = analyzers.CPUInstructionSetAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "Required")

    # Non-x86 arch -> SKIPPED
    vitals = {
        "ComputerArchitectureCollector":
            CollectorResult(CollectorStatus.PASSED, {'architecture': 'aarch64'}, Output(), ''),
        "CPUSpecificationsCollector": CollectorResult(CollectorStatus.PASSED, {'flags': []}, Output(), ''),
    }
    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.SKIPPED, "not supported on aarch64")

    # x86_64 arch -> check flags
    check_analyzer(analyzer, "CPUSpecificationsCollector", [
        ({'flags': ["sse4_2"]}, AnalyzerResult(AnalyzerStatus.PASSED, "are present")),
        ({'flags': []}, AnalyzerResult(AnalyzerStatus.FAILED, "are not present")),
    ], initial_vitals={
        "ComputerArchitectureCollector":
            CollectorResult(CollectorStatus.PASSED, {'architecture': 'x86_64'}, Output(), ''),
    })


def test_ClockSourceAnalyzer():
    analyzer = analyzers.ClockSourceAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "Required ClockSourceCollector results not found")

    check_analyzer(analyzer, "ClockSourceCollector", [
        ({'clocksource': "tsc"}, AnalyzerResult(AnalyzerStatus.PASSED, "is used as clock source")),
        ({'clocksource': "kvm-clock"}, AnalyzerResult(AnalyzerStatus.PASSED, "is used as clock source")),
        ({'clocksource': "hyperv_clocksource_tsc_page"}, AnalyzerResult(AnalyzerStatus.PASSED,
                                                                        "is used as clock source")),
        ({'clocksource': "arch_sys_counter"}, AnalyzerResult(AnalyzerStatus.PASSED, "is used as clock source")),
        ({'clocksource': "some_new_clocksource"}, AnalyzerResult(AnalyzerStatus.WARNING, "not recommended")),
        ({'clocksource': None}, AnalyzerResult(AnalyzerStatus.FAILED, "Clock source setup was not done"))
    ])


def test_CPUScalingAnalyzer():
    analyzer = analyzers.CPUScalingAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "Required CPUScalingCollector results not found")

    check_analyzer(analyzer, "CPUScalingCollector", [
        ({'scaling_governor': None},
         AnalyzerResult(AnalyzerStatus.FAILED, "CPU does not support scaling")),
        ({'scaling_governor': "powersave", 'services': {}},
         AnalyzerResult(AnalyzerStatus.FAILED, "CPU scaling setup was not done")),
        ({'scaling_governor': "powersave", 'services': {'cpufrequtils': {'active': True}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "scaling services are active")),
    ])


# https://github.com/scylladb/field-engineering/issues/837#issuecomment-1228662607
def test_CoredumpAnalyzer():
    analyzer = analyzers.CoredumpAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "Required CoredumpCollector results not found")

    success_msg = "Coredump optimized"
    fail_msg = "Coredump setup was not done"

    def complex_fail_msg(filename, line, lineno):
        return f"Unexpected content in {filename}: " \
               f"line: {lineno}: {line}, please run scylla_coredump_setup.py"

    falsy_service = {
        analyzer._CoredumpAnalyzer__coredump_service: {
            'active': False
        }
    }

    truthy_service = {
        analyzer._CoredumpAnalyzer__coredump_service: {
            'active': True
        }
    }

    check_analyzer(analyzer, "CoredumpCollector", [
        ({'files': {}, 'services': {}},
         AnalyzerResult(AnalyzerStatus.FAILED, fail_msg)),
        ({
             'files': {},
             'services': falsy_service},
         AnalyzerResult(AnalyzerStatus.FAILED, fail_msg)),
        ({
             'files': {
                 analyzer._CoredumpAnalyzer__user_generated_filename: ["foo"]
             },
             'services': truthy_service
         },
         AnalyzerResult(AnalyzerStatus.PASSED, success_msg)),
        ({
             'files': {
                 analyzer._CoredumpAnalyzer__scylla_generated_filename: ["foo"]
             },
             'services': truthy_service,
        },
         AnalyzerResult(AnalyzerStatus.FAILED,
                        complex_fail_msg(analyzer._CoredumpAnalyzer__scylla_generated_filename, "foo", 1))),
        ({
             'files': {
                 analyzer._CoredumpAnalyzer__scylla_generated_filename:
                     ["# comment", "foo", analyzer._CoredumpAnalyzer__scylla_generated_file_content]
             },
             'services': truthy_service,
         },
         AnalyzerResult(AnalyzerStatus.FAILED,
                        complex_fail_msg(analyzer._CoredumpAnalyzer__scylla_generated_filename, "foo", 2))),
        ({
             'files': {
                 analyzer._CoredumpAnalyzer__scylla_generated_filename:
                     ["# comment", analyzer._CoredumpAnalyzer__scylla_generated_file_content, "foo"]
             },
             'services': truthy_service,
         },
         AnalyzerResult(AnalyzerStatus.FAILED,
                        complex_fail_msg(analyzer._CoredumpAnalyzer__scylla_generated_filename, "foo", 3))),
        ({
             'files': {
                 analyzer._CoredumpAnalyzer__user_generated_filename:
                     ["# comment", "  ", analyzer._CoredumpAnalyzer__scylla_generated_file_content]  # noqa: E501
             },
             'services': truthy_service
         },
         AnalyzerResult(AnalyzerStatus.PASSED, success_msg)),
    ])


def test_CPUSetAnalyzer():
    analyzer = analyzers.CPUSetAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required CPUSetCollector results not found")

    check_analyzer(analyzer, "CPUSetCollector", [
        ({'cpusetconf_mask': '0x0000fffe', 'cpusetconf_intersect_perftune_mask': '0x0000fefe'},
         AnalyzerResult(AnalyzerStatus.FAILED, "not a subset")),
        ({'cpusetconf_mask': '0x0000fffe', 'cpusetconf_intersect_perftune_mask': '0x0000fffe'},
         AnalyzerResult(AnalyzerStatus.PASSED, "configured properly")),
    ])


def test_DeveloperModeAnalyzer():
    analyzer = analyzers.DeveloperModeAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaExtraConfigurationFilesCollector results not found")

    check_analyzer(analyzer, "ScyllaExtraConfigurationFilesCollector", [
        ({'files': {'dev-mode.conf': {'DEV_MODE': "--develpoer-mode=1"}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "is enabled")),
        ({'files': {'cpuset.conf': {}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "is not enabled")),
    ])


def test_DriverVersionAnalyzer():
    """
    Tests the DriverVersionAnalyzer for specified minimum and latest driver version.

    - Test cases:
        - Below bounds, equal, and above the minimum/latest bounds.
        - Version format: v1.0 or 1.0 format, and invalid version formats.
        - Unrecognized driver names
        - Warnings and errors can appear together.
    """
    required_drivers_config = {
        'DriverVersionAnalyzer': {
            'minimum_version': json.dumps({
                'Python': '3.24.5',
                'Go': 'v1.7'
            }),
            'latest_version': json.dumps({
                'Python': '3.26',
                'Go': 'v1.8'
            })
        }
    }

    driver_version_analyzer = analyzers.DriverVersionAnalyzer(required_drivers_config)

    vitals = {
        'ScyllaVersionCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'version': '2024.1.4'}, Output(), '')
    }

    driver_version_tests = [
        # WARNINGS: UNKNOWN DRIVER, WRONG VERSION FORMAT, NON-RECOMMENDED DRIVER VERSION
        {'client_connections': [{'driver_name': 'Unknown Driver', 'driver_version': '3.25'}],
         'result': AnalyzerResult(AnalyzerStatus.WARNING, message="WARNING: Unknown driver name: Unknown Driver")},
        {'client_connections': [{'driver_name':  'Scylla Python Driver', 'driver_version': '3x.2a'}],
         'result': AnalyzerResult(AnalyzerStatus.WARNING, message="WARNING: Invalid driver version format by driver: "
                                                                  "Scylla Python Driver with version: 3x.2a")},
        {'client_connections': [{'driver_name': 'github.com/gocql/gocql', 'driver_version': 'v1.7'}],
         'result': AnalyzerResult(AnalyzerStatus.WARNING, message="WARNING: github.com/gocql/gocql with version 1.7 "
                                                                  "is below the latest driver version 1.8")},
        {'client_connections': [{'driver_name': 'Scylla Python Driver', 'driver_version': '3.24.5'}],
         'result': AnalyzerResult(AnalyzerStatus.WARNING, message="WARNING: Scylla Python Driver with version 3.24.5 "
                                                                  "is below the latest driver version 3.26")},
        # ERRORS: BELOW MINIMUM DRIVER
        {'client_connections': [{'driver_name':  'Scylla Python Driver', 'driver_version': '3.23-alpha'}],
         'result': AnalyzerResult(AnalyzerStatus.FAILED, message="ERROR: Scylla Python Driver with version 3.23-alpha"
                                                                 " is below the minimum driver version 3.24.5")},
        {'client_connections': [{'driver_name':  'Scylla Python Driver', 'driver_version': '3.11.3.4'}],
         'result': AnalyzerResult(AnalyzerStatus.FAILED, message="ERROR: Scylla Python Driver with version 3.11.3.4 "
                                                                 "is below the minimum driver version 3.24.5")},
        {'client_connections': [{'driver_name':  'Scylla Python Driver', 'driver_version': '3.21'}],
         'result': AnalyzerResult(AnalyzerStatus.FAILED, message="ERROR: Scylla Python Driver with version 3.21 "
                                                                 "is below the minimum driver version 3.24.5")},
        {'client_connections': [{'driver_name': 'Scylla Python Driver', 'driver_version': '3.24.4'}],
         'result': AnalyzerResult(AnalyzerStatus.FAILED, message="ERROR: Scylla Python Driver with version 3.24.4 "
                                                                 "is below the minimum driver version 3.24.5")},
        {'client_connections': [{'driver_name':  'github.com/gocql/gocql', 'driver_version': 'v1.6'}],
         'result': AnalyzerResult(AnalyzerStatus.FAILED, message="ERROR: github.com/gocql/gocql with version 1.6 "
                                                                 "is below the minimum driver version 1.7")},

        # WARNING AND ERROR CASE: BELOW MINIMUM AND NON-RECOMMENDED DRIVER
        {'client_connections': [{'driver_name': 'Scylla Python Driver', 'driver_version': '3.24.5'},
                                {'driver_name': 'github.com/gocql/gocql', 'driver_version': 'v1.6'}],
         'result': AnalyzerResult(AnalyzerStatus.FAILED, message="WARNING: Scylla Python Driver with version 3.24.5 "
                                                                 "is below the latest driver version 3.26")},

        {'client_connections': [{'driver_name': 'Scylla Python Driver', 'driver_version': '3.24.5'},
                                {'driver_name': 'github.com/gocql/gocql', 'driver_version': 'v1.6'}],
         'result': AnalyzerResult(AnalyzerStatus.FAILED, message="ERROR: github.com/gocql/gocql with version 1.6 "
                                                                 "is below the minimum driver version 1.7")},
        # SUCCESSFUL
        {'client_connections': [{'driver_name': 'Scylla Python Driver', 'driver_version': '3.26'}],
         'result': AnalyzerResult(AnalyzerStatus.PASSED, message="Client driver versions are within bounds.")},
        {'client_connections': [{'driver_name': 'Scylla Python Driver', 'driver_version': '3.26.0.1'}],
         'result': AnalyzerResult(AnalyzerStatus.PASSED, message="Client driver versions are within bounds.")},
        {'client_connections': [{'driver_name':  'Scylla Python Driver', 'driver_version': '3.26-alpha'}],
         'result': AnalyzerResult(AnalyzerStatus.PASSED, message="Client driver versions are within bounds.")},
        {'client_connections': [{'driver_name':  'github.com/gocql/gocql', 'driver_version': 'v1.8'}],
         'result': AnalyzerResult(AnalyzerStatus.PASSED, message="Client driver versions are within bounds.")},
        {'client_connections': [{'driver_name': 'github.com/gocql/gocql', 'driver_version': 'v1.11'}],
         'result': AnalyzerResult(AnalyzerStatus.PASSED, message="Client driver versions are within bounds.")},
        # ScyllaDB Python Driver alias
        {'client_connections': [{'driver_name': 'ScyllaDB Python Driver', 'driver_version': '3.23'}],
         'result': AnalyzerResult(AnalyzerStatus.FAILED, message="ERROR: ScyllaDB Python Driver with version 3.23 "
                                                                 "is below the minimum driver version 3.24.5")},
        {'client_connections': [{'driver_name': 'ScyllaDB Python Driver', 'driver_version': '3.24.5'}],
         'result': AnalyzerResult(AnalyzerStatus.WARNING, message="WARNING: ScyllaDB Python Driver with version 3.24.5 "
                                                                  "is below the latest driver version 3.26")},
        {'client_connections': [{'driver_name': 'ScyllaDB Python Driver', 'driver_version': '3.26'}],
         'result': AnalyzerResult(AnalyzerStatus.PASSED, message="Client driver versions are within bounds.")},
    ]

    for driver_version in driver_version_tests:
        test_vitals = {'127.0.0.1': driver_version['client_connections']}

        check_analyzer(driver_version_analyzer, "ClientConnectionCollector", [
                (test_vitals, driver_version['result']),
            ], initial_vitals=vitals)


def test_DriverVersionAnalyzer_InvalidAPI():
    vitals = {
        'ScyllaVersionCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'version': '2024.1.4'}, Output(), '')
    }

    required_drivers_config = {
        'DriverVersionAnalyzer': {
            'driver_api_endpoint': 'http://ThisIsAnInvalidURL93910230'
        }
    }

    driver_version_analyzer = analyzers.DriverVersionAnalyzer(required_drivers_config)

    test_vitals = {'127.0.0.1': [{'driver_name': 'github.com/gocql/gocql', 'driver_version': '1.11'}]}
    test_result = AnalyzerResult(AnalyzerStatus.FAILED,
                                 message="API call error occurred to retrieve the minimum or latest driver version")

    check_analyzer(driver_version_analyzer, "ClientConnectionCollector", [
        (test_vitals, test_result),
    ], initial_vitals=vitals)


def test_DriverVersionAnalyzer_AvailableAPI():
    vitals = {
        'ScyllaVersionCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'version': '2024.1.4'}, Output(), '')
    }

    # Version number so high it should be accepted as above latest or minimum version number.
    driver_version_analyzer = analyzers.DriverVersionAnalyzer({})
    test_vitals = {'127.0.0.1': [{'driver_name': 'github.com/gocql/gocql', 'driver_version': '1000'}]}
    test_result = AnalyzerResult(AnalyzerStatus.PASSED,
                                 message="Client driver versions are within bounds.")

    check_analyzer(driver_version_analyzer, "ClientConnectionCollector", [
        (test_vitals, test_result),
    ], initial_vitals=vitals)


def test_IOSetupAnalyzer():
    analyzer = analyzers.IOSetupAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'PathsCollector': CollectorResult(CollectorStatus.PASSED,
                                          {'scylla_directory_configs': '/etc/scylla.d'}, Output(), '')
    }

    check_analyzer(analyzer, "ScyllaExtraConfigurationFilesCollector", [
        ({'files': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "was not done")),
        ({'files': {'io.conf': {}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "was not done")),
        ({'files': {'io.conf': {"SEASTAR_IO": "--io-properties-file /etc/scylla.d/io_properties.yaml"}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "io_properties.yaml is missing")),
        ({'files': {'io.conf': {"SEASTAR_IO": "--io-properties-file /etc/scylla.d/io_properties.yaml"}, "io_properties.yaml": {"foo": "bar"}}},  # noqa: E501
         AnalyzerResult(AnalyzerStatus.PASSED, "was done")),
        ({'files': {'io.conf': {"SEASTAR_IO": "--io-properties-file=/etc/scylla.d/io_properties.yaml"},
                    "io_properties.yaml": {"foo": "bar"}}},  # noqa: E501
         AnalyzerResult(AnalyzerStatus.PASSED, "was done")),
        ({'files': {'io.conf': {"SEASTAR_IO": "--io-properties-file some_other_file.yaml"}, "io_properties.yaml": {"foo": "bar"}}},  # noqa: E501
         AnalyzerResult(AnalyzerStatus.WARNING, "io_properties.yaml isn't being used")),
        ({'files': {'io.conf': {"SEASTAR_IO": "--io-properties-file some_other_file.yaml"}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "was done")),
    ], initial_vitals=vitals)


def test_MemoryTuningAnalyzer():
    analyzer = analyzers.MemoryTuningAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaExtraConfigurationFilesCollector results not found")

    check_analyzer(analyzer, "ScyllaExtraConfigurationFilesCollector", [
        ({'files': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "was not done")),
        ({'files': {'memory.conf': {'foo': "bar"}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "was not done")),
        ({'files': {'memory.conf': {'MEM_CONF': "--lock-memory=1"}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "was done")),
    ])


def test_NICsAnalyzer():
    vitals = {
        'InfrastructureProviderCollector': CollectorResult(CollectorStatus.PASSED, {'provider': None}, Output(), '')
    }

    analyzer = analyzers.NICsAnalyzer({})
    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required NICsCollector results not found")

    # Non-cloud provider: NIC speed check is performed
    check_analyzer(analyzer, "NICsCollector", [
        ({'nics': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "There is no NIC available")),
        ({'nics': {'some_nic': {'speed': 100000}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "Networking setup is ok")),
    ], initial_vitals=vitals)

    vitals = {
        'NICsCollector': CollectorResult(CollectorStatus.PASSED,
                                         {'nics': {'some_nic': {'speed': 100000}}}, Output(), '')
    }

    # AWS: NIC speed check is skipped by default; only enhanced networking / VPC checks run
    check_analyzer(analyzer, "InfrastructureProviderCollector", [
        ({'provider': "AWS", 'extra': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "does not support enhanced networking")),
        ({'provider': "AWS", 'extra': {'enhanced_networking_nic_type': None}},
         AnalyzerResult(AnalyzerStatus.WARNING, "does not support enhanced networking")),
        ({'provider': "AWS", 'extra': {'enhanced_networking_nic_type': "ena"}},
         AnalyzerResult(AnalyzerStatus.WARNING, "VPC is not enabled")),
        ({'provider': "AWS", 'extra': {'enhanced_networking_nic_type': "ena", 'vpc_enabled_from_nics': True}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Enhanced networking is disabled")),
        ({'provider': "AWS", 'extra': {
            'enhanced_networking_nic_type': "ena",
            'vpc_enabled_from_nics': True,
            'enhanced_networking_driver_support': True
        }},
         AnalyzerResult(AnalyzerStatus.PASSED, "Networking setup is ok")),
        # GCP: NIC speed check is skipped by default; no provider-specific checks
        ({'provider': "GCP", 'extra': {}},
         AnalyzerResult(AnalyzerStatus.PASSED, "Networking setup is ok")),
    ], initial_vitals=vitals)

    # Explicit skip_nic_speed_check=True: speed check skipped even on non-cloud provider
    analyzer_skip = analyzers.NICsAnalyzer({'NICsAnalyzer': {'skip_nic_speed_check': True}})
    vitals_no_nics = {
        'InfrastructureProviderCollector': CollectorResult(CollectorStatus.PASSED,
                                                           {'provider': None, 'extra': {}}, Output(), ''),
        'NICsCollector': CollectorResult(CollectorStatus.PASSED, {'nics': {}}, Output(), ''),
    }
    analyzer_skip.analyze(vitals_no_nics)
    assert_analyzer_result(analyzer_skip, AnalyzerStatus.PASSED, "Networking setup is ok")

    # Explicit skip_nic_speed_check=False on AWS: speed check IS performed despite AWS default skip
    analyzer_no_skip = analyzers.NICsAnalyzer({'NICsAnalyzer': {'skip_nic_speed_check': False}})
    vitals_aws_slow = {
        'InfrastructureProviderCollector': CollectorResult(CollectorStatus.PASSED,
                                                           {'provider': "AWS", 'extra': {
                                                               'enhanced_networking_nic_type': "ena",
                                                               'vpc_enabled_from_nics': True,
                                                               'enhanced_networking_driver_support': True,
                                                           }}, Output(), ''),
        'NICsCollector': CollectorResult(CollectorStatus.PASSED, {'nics': {'eth0': {'speed': 100}}}, Output(), ''),
    }
    analyzer_no_skip.analyze(vitals_aws_slow)
    assert_analyzer_result(analyzer_no_skip, AnalyzerStatus.WARNING, "There is no NIC available")


def test_ComputerArchitectureAnalyzer():
    analyzer = analyzers.ComputerArchitectureAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ComputerArchitectureCollector results not found")

    check_analyzer(analyzer, "ComputerArchitectureCollector", [
        ({'architecture': "x86_64"},
         AnalyzerResult(AnalyzerStatus.PASSED, "is officially supported")),
        ({'architecture': "aarch64"},
         AnalyzerResult(AnalyzerStatus.PASSED, "is officially supported")),
        ({'architecture': "amd64"},
         AnalyzerResult(AnalyzerStatus.FAILED, "is not officially supported")),
    ])


def test_KernelVersionAnalyzer():
    analyzer = analyzers.KernelVersionAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ComputerArchitectureCollector results not found")

    check_analyzer(analyzer, "ComputerArchitectureCollector", [
        ({'kernel_version': "3.15"},
         AnalyzerResult(AnalyzerStatus.PASSED, "is supported")),
        ({'kernel_version': "3.10"},
         AnalyzerResult(AnalyzerStatus.FAILED, "is lower")),
    ])


def test_RaftTopologyEnablementAnalyzer():
    analyzer = analyzers.RaftTopologyEnablementAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required SystemTopologyCollector results not found")

    check_analyzer(analyzer, "SystemTopologyCollector", [
        ({'system_topology_rows': [], 'consistent_topology_supported': False},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Consistent Topology is not supported by Scylla")),
        ({'system_topology_rows': [{"upgrade_state": "done", "host_id": "1"},
                                   {"upgrade_state": "done", "host_id": "2"}],
          'consistent_topology_supported': True},
         AnalyzerResult(AnalyzerStatus.PASSED, "Consistent Topology is enabled on all hosts")),
        ({'system_topology_rows': [{"upgrade_state": "not done", "host_id": "1"}],
          'consistent_topology_supported': True},
         AnalyzerResult(AnalyzerStatus.FAILED, "Consistent Topology isn't properly enabled on the following hosts: 1")),
        ({'system_topology_rows':  [{"upgrade_state": "not done", "host_id": "1"},
                                    {"upgrade_state": "done", "host_id": "2"},
                                    {"upgrade_state": "not done", "host_id": "3"}],
          'consistent_topology_supported': True},
         AnalyzerResult(AnalyzerStatus.FAILED,
                        "Consistent Topology isn't properly enabled on the following hosts: 1, 3")),
    ])


def test_NTPStatusAnalyzer():
    analyzer = analyzers.NTPStatusAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required NTPStatusCollector results not found")

    check_analyzer(analyzer, "NTPStatusCollector", [
        ({'ntp_enabled': True, 'ntp_synchronized': False},
         AnalyzerResult(AnalyzerStatus.FAILED, "The system clock is not NTP synchronized.")),
        ({'ntp_enabled': False, 'ntp_synchronized': True},
         AnalyzerResult(AnalyzerStatus.FAILED, "NTP is not enabled.")),
        ({'ntp_enabled': False, 'ntp_synchronized': False},
         AnalyzerResult(AnalyzerStatus.FAILED, "NTP is not enabled.")),
        ({'ntp_enabled': True, 'ntp_synchronized': True},
         AnalyzerResult(AnalyzerStatus.PASSED, "NTP is enabled and the system clock is synchronized.")),
    ])


def test_NTPServicesAnalyzer():
    analyzer = analyzers.NTPServicesAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required NTPServicesCollector results not found")

    check_analyzer(analyzer, "NTPServicesCollector", [
        ({'services': {'ntp': {'active': False}}},
         AnalyzerResult(AnalyzerStatus.FAILED, "was not done")),
        ({'services': {'chrony': {'active': True}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "was done")),
    ])


def test_OSSupportAnalyzer():
    analyzer = analyzers.OSSupportAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required OSCollector results not found")

    check_analyzer(analyzer, "OSCollector", [
        ({'name': "gentoo", 'version': '17.1', 'version_minor': "17.1"},
         AnalyzerResult(AnalyzerStatus.FAILED, "is not officially supported")),
        ({'name': "ubuntu", "version": "19.04", 'version_minor': "19.04"},
         AnalyzerResult(AnalyzerStatus.FAILED, "is not officially supported")),
        ({'name': "centos", 'version': "7", 'version_minor': "7.1"},
         AnalyzerResult(AnalyzerStatus.FAILED, "is officially supported starting from")),
        ({'name': "rhel", 'version': "8", 'version_minor': "8.9"},
         AnalyzerResult(AnalyzerStatus.PASSED, "is officially supported")),
        ({'name': "ubuntu", 'version': "20.04", 'version_minor': "20.04"},
         AnalyzerResult(AnalyzerStatus.PASSED, "is officially supported")),
        ({'name': "rocky", 'version': "9", 'version_minor': "9.3"},
         AnalyzerResult(AnalyzerStatus.PASSED, "is officially supported")),
        ({'name': "rocky", 'version': "7", 'version_minor': "7.9"},
         AnalyzerResult(AnalyzerStatus.FAILED, "is not officially supported")),
    ])


def test_PerftuneAnalyzer():
    analyzer = analyzers.PerftuneAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required PerftuneSystemConfigurationCollector results not found")

    collector = "PerftuneSystemConfigurationCollector"

    # --- All files match (equal-length hex lists) ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/some/file': 'ff'}},
          'files': {'/sys/some/file': 'FF'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])

    # --- Files match via zero-padding (different-length hex lists) ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/some/file': '00,ff,00'}},
          'files': {'/sys/some/file': 'ff,00'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])

    # --- Files match via space-separated hex values ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/proc/sys/net/ipv4/tcp_mem': '493986 658648 987971'}},
          'files': {'/proc/sys/net/ipv4/tcp_mem': '493986 658648 987971'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])

    # --- Files mismatch (different-length space-separated hex lists - no zero-padding) ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/some/file': '00 ff 00'}},
          'files': {'/sys/some/file': 'ff 00'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Inconsistent value")),
    ])

    # --- Files mismatch (space-separated hex lists) ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/some/file': '01 ff 00'}},
          'files': {'/sys/some/file': 'ff 01'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Inconsistent value")),
    ])

    # --- Files mismatch (different-length hex lists that don't match after padding) ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/some/file': '01,ff,00'}},
          'files': {'/sys/some/file': 'ff,00'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Inconsistent value")),
    ])

    # --- No perftune files or sysctls ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {}, 'files': {}, 'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])

    # --- Sysctl mismatch ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'sysctl': {'net.core.somaxconn': '1024'}},
          'files': {},
          'sysctl': {'net.core.somaxconn': '512'}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Inconsistent value")),
    ])

    # --- Sysctl match ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'sysctl': {'net.core.somaxconn': '1024'}},
          'files': {},
          'sysctl': {'net.core.somaxconn': '1024'}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])

    # --- Scheduler file with correct bracket format ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/block/sda/queue/scheduler': 'none'}},
          'files': {'/sys/block/sda/queue/scheduler': 'mq-deadline kyber [none] bfq'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])

    # --- Scheduler file with mismatched value ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/block/sda/queue/scheduler': 'none'}},
          'files': {'/sys/block/sda/queue/scheduler': 'mq-deadline kyber [bfq] none'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Inconsistent value")),
    ])

    # --- Scheduler file with unexpected format ---
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/block/sda/queue/scheduler': 'none'}},
          'files': {'/sys/block/sda/queue/scheduler': 'no-brackets-here'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.FAILED, "Unexpected format")),
    ])


def test_PerftuneAnalyzer_skip_files():
    collector = "PerftuneSystemConfigurationCollector"

    # skip_files causes mismatched file to be ignored -> PASSED
    analyzer = analyzers.PerftuneAnalyzer(
        {'PerftuneAnalyzer': {'skip_files': '/sys/block/sda/queue/scheduler'}})
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/block/sda/queue/scheduler': 'none'}},
          'files': {'/sys/block/sda/queue/scheduler': 'mq-deadline kyber [bfq] none'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])

    # skip_files skips only the listed file; other mismatched files still reported
    analyzer = analyzers.PerftuneAnalyzer(
        {'PerftuneAnalyzer': {'skip_files': '/sys/block/sda/queue/scheduler'}})
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/block/sda/queue/scheduler': 'none',
                                 '/sys/some/other': 'aa'}},
          'files': {'/sys/block/sda/queue/scheduler': 'mq-deadline kyber [bfq] none',
                    '/sys/some/other': 'bb'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Inconsistent value")),
    ])

    # empty skip_files -> mismatch is still reported
    analyzer = analyzers.PerftuneAnalyzer({'PerftuneAnalyzer': {'skip_files': ''}})
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/block/sda/queue/scheduler': 'none'}},
          'files': {'/sys/block/sda/queue/scheduler': 'mq-deadline kyber [bfq] none'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Inconsistent value")),
    ])

    # multiple comma-separated files skipped
    analyzer = analyzers.PerftuneAnalyzer(
        {'PerftuneAnalyzer': {'skip_files': '/sys/block/sda/queue/scheduler,/sys/some/other'}})
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/block/sda/queue/scheduler': 'none',
                                 '/sys/some/other': 'aa'}},
          'files': {'/sys/block/sda/queue/scheduler': 'mq-deadline kyber [bfq] none',
                    '/sys/some/other': 'bb'},
          'sysctl': {}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])


def test_PerftuneAnalyzer_skip_sysctls():
    collector = "PerftuneSystemConfigurationCollector"

    # skip_sysctls causes mismatched sysctl to be ignored -> PASSED
    analyzer = analyzers.PerftuneAnalyzer(
        {'PerftuneAnalyzer': {'skip_sysctls': 'net.core.somaxconn'}})
    check_analyzer(analyzer, collector, [
        ({'perftune': {'sysctl': {'net.core.somaxconn': '1024'}},
          'files': {},
          'sysctl': {'net.core.somaxconn': '512'}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])

    # skip_sysctls skips only the listed param; other mismatched params still reported
    analyzer = analyzers.PerftuneAnalyzer(
        {'PerftuneAnalyzer': {'skip_sysctls': 'net.core.somaxconn'}})
    check_analyzer(analyzer, collector, [
        ({'perftune': {'sysctl': {'net.core.somaxconn': '1024', 'vm.swappiness': '1'}},
          'files': {},
          'sysctl': {'net.core.somaxconn': '512', 'vm.swappiness': '10'}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Inconsistent value")),
    ])

    # empty skip_sysctls -> mismatch is still reported
    analyzer = analyzers.PerftuneAnalyzer({'PerftuneAnalyzer': {'skip_sysctls': ''}})
    check_analyzer(analyzer, collector, [
        ({'perftune': {'sysctl': {'net.core.somaxconn': '1024'}},
          'files': {},
          'sysctl': {'net.core.somaxconn': '512'}},
         AnalyzerResult(AnalyzerStatus.WARNING, "Inconsistent value")),
    ])

    # multiple comma-separated sysctls skipped
    analyzer = analyzers.PerftuneAnalyzer(
        {'PerftuneAnalyzer': {'skip_sysctls': 'net.core.somaxconn,vm.swappiness'}})
    check_analyzer(analyzer, collector, [
        ({'perftune': {'sysctl': {'net.core.somaxconn': '1024', 'vm.swappiness': '1'}},
          'files': {},
          'sysctl': {'net.core.somaxconn': '512', 'vm.swappiness': '10'}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])


def test_PerftuneAnalyzer_skip_files_and_sysctls():
    collector = "PerftuneSystemConfigurationCollector"

    # Both skip_files and skip_sysctls active -> all mismatches suppressed -> PASSED
    analyzer = analyzers.PerftuneAnalyzer({'PerftuneAnalyzer': {
        'skip_files': '/sys/some/file',
        'skip_sysctls': 'net.core.somaxconn',
    }})
    check_analyzer(analyzer, collector, [
        ({'perftune': {'files': {'/sys/some/file': 'aa'}, 'sysctl': {'net.core.somaxconn': '1024'}},
          'files': {'/sys/some/file': 'bb'},
          'sysctl': {'net.core.somaxconn': '512'}},
         AnalyzerResult(AnalyzerStatus.PASSED, "modifications are intact")),
    ])


class TestPerftuneAnalyzer_compare_str_or_int16_list:
    """Tests for PerftuneAnalyzer.__compare_str_or_int16_list"""

    @staticmethod
    def _compare(a: str, b: str) -> bool:
        analyzer = analyzers.PerftuneAnalyzer({})  # type: ignore[arg-type]
        return analyzer._PerftuneAnalyzer__compare_str_or_int16_list(a, b)  # type: ignore[attr-defined]

    # --- Identical strings (fast path) ---
    def test_identical_strings(self):
        assert self._compare("abc", "abc")

    def test_identical_hex_strings(self):
        assert self._compare("ff", "ff")

    def test_identical_comma_separated(self):
        assert self._compare("0a,0b,0c", "0a,0b,0c")

    def test_identical_space_separated(self):
        assert self._compare("0a 0b 0c", "0a 0b 0c")

    # --- Plain hex values (case-insensitive via int parsing) ---
    def test_plain_hex_case_insensitive(self):
        assert self._compare("FF", "ff")

    def test_plain_hex_with_leading_zeros(self):
        assert self._compare("00ff", "ff")

    def test_plain_hex_different_values(self):
        assert not self._compare("ff", "fe")

    # --- Comma-separated hex lists of equal length ---
    def test_comma_separated_equal_length_match(self):
        assert self._compare("0a,0b,0c", "a, b, c")

    def test_comma_separated_equal_length_mismatch(self):
        assert not self._compare("0a,0b,0c", "0a,0b,0d")

    # --- Comma-separated hex lists of different lengths (zero-padding) ---
    def test_comma_shorter_b_padded_with_zeros(self):
        # "00,ff,00" == [0, 255, 0]; "ff,00" == [255, 0] -> padded to [0, 255, 0]
        assert self._compare("00,ff,00", "ff,00")

    def test_comma_shorter_a_padded_with_zeros(self):
        assert self._compare("ff,00", "00,ff,00")

    def test_comma_different_lengths_mismatch(self):
        # "01,ff,00" == [1, 255, 0]; "ff,00" padded to [0, 255, 0] != [1, 255, 0]
        assert not self._compare("01,ff,00", "ff,00")

    def test_comma_single_vs_list_match(self):
        assert self._compare("ff", "00,ff")

    def test_comma_single_vs_list_mismatch(self):
        assert not self._compare("ff", "01,ff")

    # --- Space-separated hex lists of equal length ---
    def test_space_separated_equal_length_match(self):
        assert self._compare("0a 0b 0c", "a b c")

    def test_space_separated_equal_length_mismatch(self):
        assert not self._compare("0a 0b 0c", "0a 0b 0d")

    # --- Space-separated hex lists of different lengths (NO zero-padding) ---
    def test_space_different_lengths_no_padding(self):
        # Space-separated lists are compared without zero-padding,
        # so different-length lists never match
        assert not self._compare("00 ff 00", "ff 00")

    def test_space_different_lengths_no_padding_reversed(self):
        assert not self._compare("ff 00", "00 ff 00")

    def test_space_different_lengths_mismatch(self):
        assert not self._compare("01 ff 00", "ff 00")

    # --- Real-world: multi-value echo pattern (e.g. /proc/sys/net/ipv4/tcp_mem) ---
    def test_space_separated_decimal_match(self):
        # Values like "493986 658648 987971" written by perftune and read back from the sysfs file.
        # They match via the fast-path string equality (a == b), not hex parsing.
        assert self._compare("493986 658648 987971", "493986 658648 987971")

    def test_space_separated_decimal_mismatch(self):
        assert not self._compare("493986 658648 987971", "493986 658648 999999")

    def test_space_separated_with_extra_whitespace(self):
        # split(None) handles multiple spaces/tabs
        assert self._compare("ff  0a", "ff 0a")

    # --- Invalid hex strings ---
    def test_invalid_hex_a(self):
        assert not self._compare("xyz", "ff")

    def test_invalid_hex_b(self):
        assert not self._compare("ff", "xyz")

    def test_invalid_hex_in_comma_list(self):
        assert not self._compare("0a,zz", "0a,0b")

    def test_invalid_hex_in_space_list(self):
        assert not self._compare("0a zz", "0a 0b")

    # --- Empty strings ---
    def test_empty_strings(self):
        assert self._compare("", "")

    def test_empty_vs_non_empty(self):
        assert not self._compare("", "ff")

    def test_non_empty_vs_empty(self):
        assert not self._compare("ff", "")

    # --- Symmetry ---
    @pytest.mark.parametrize("a, b", [
        ("ff", "FF"),
        ("0a,0b", "a,b"),
        ("00,ff,00", "ff,00"),
        ("ff,00", "00,ff,00"),
        ("0a 0b 0c", "a b c"),
        ("00 ff 00", "ff 00"),
    ])
    def test_symmetry(self, a, b):
        assert self._compare(a, b) == self._compare(b, a)


def test_ScyllaSystemConfigurationFilesAnalyzer():
    analyzer = analyzers.ScyllaSystemConfigurationFilesAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaSystemConfigurationFilesCollector results not found")

    scylla_version_collector_vitals_below_2025_1 = {
        'ScyllaVersionCollector': CollectorResult(
            CollectorStatus.PASSED,
            ({'version': '2024.2.0'}), Output(), '')
    }

    scylla_version_collector_vitals_above_2025_1 = {
        'ScyllaVersionCollector': CollectorResult(
            CollectorStatus.PASSED,
            ({'version': '2025.1.0'}), Output(), '')
    }

    required_files_before_2025_1 = {name: {'foo': 'bar'} for name in
                                    {"scylla-housekeeping", "scylla-jmx", "scylla-server"}}

    required_files_after_2025_1 = {name: {'foo': 'bar'} for name in {"scylla-housekeeping", "scylla-server"}}

    for vitals, required_files in [(scylla_version_collector_vitals_below_2025_1, required_files_before_2025_1),
                                   (scylla_version_collector_vitals_above_2025_1, required_files_after_2025_1)]:
        incomplete_files = copy.deepcopy(required_files)
        incomplete_files.pop(random.choice(list(required_files.keys())))

        check_analyzer(analyzer, "ScyllaSystemConfigurationFilesCollector", [
            ({'files': {}, 'directory': '/etc/default'},
             AnalyzerResult(AnalyzerStatus.FAILED, "not found")),
            ({'files': incomplete_files, 'directory': '/etc/default'},
             AnalyzerResult(AnalyzerStatus.FAILED, "not found")),
            ({'files': required_files},
             AnalyzerResult(AnalyzerStatus.PASSED, "are present")),
        ], initial_vitals=vitals)


def test_RAMAnalyzer():
    analyzer = analyzers.RAMAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'CPUSpecificationsCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'logical_cores': 2}, Output(), '')
    }

    check_analyzer(analyzer, "RAMCollector", [
        ({'total': 1000000},
         AnalyzerResult(AnalyzerStatus.FAILED, "minimum required")),
        ({'total': 4194304},
         AnalyzerResult(AnalyzerStatus.WARNING, "recommended")),
        ({'total': 16777216},
         AnalyzerResult(AnalyzerStatus.PASSED, "detected")),
    ], initial_vitals=vitals)

    analyzer = analyzers.RAMAnalyzer({
        'RAMAnalyzer': {
            'ram_minimum_total': '10',
            'ram_recommended_total': '5'
        }
    })

    vitals = {
        'CPUSpecificationsCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'logical_cores': 2}, Output(), ''),
        'RAMCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'total': 16777216}, Output(), '')

    }
    with pytest.raises(AbortedException) as e:
        analyzer.analyze(vitals)
    assert "Sanity check failed" in str(e)


def test_RsyslogAnalyzer():
    analyzer = analyzers.RsyslogAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'NodePlatformCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'platform': NodePlatform.CLOUD}, Output(), '')
    }

    check_analyzer(analyzer, "RsyslogCollector", [
        ({'files': {'/etc/rsyslog.d/scylla.conf': None}},
         AnalyzerResult(AnalyzerStatus.WARNING, "was not done")),
        ({'files': {'/etc/rsyslog.d/scylla.conf': "foo"}},
         AnalyzerResult(AnalyzerStatus.PASSED, "was done")),
    ], initial_vitals=vitals)

    vitals = {
        'NodePlatformCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'platform': NodePlatform.CONTAINER}, Output(), '')
    }

    check_analyzer(analyzer, "RsyslogCollector", [
        ({'files': {'/etc/rsyslog.d/scylla.conf': None}},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Not available for containers")),
    ], initial_vitals=vitals)


def test_AIOMAXNRAnalyzer():
    analyzer = analyzers.AIOMAXNRAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'CPUSpecificationsCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'logical_cores': 2}, Output(), '')
    }

    check_analyzer(analyzer, "SysctlCollector", [
        ({'fs.aio-max-nr': 50000},
         AnalyzerResult(AnalyzerStatus.FAILED, "is less than")),
        ({'fs.aio-max-nr': 100000},
         AnalyzerResult(AnalyzerStatus.PASSED, "is equal or greater than")),
    ], initial_vitals=vitals)


def test_PerftuneYamlAnalyzer():
    analyzer = analyzers.PerftuneYamlAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "results not found")

    perftune_yaml_content = {'cpu_mask': '0x0000ffff', 'mode': 'sq_split', 'nic': ['enp0s31f6'], 'tune': ['net']}
    vitals = {
        'ScyllaExtraConfigurationFilesCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'files': {'perftune.yaml': perftune_yaml_content}}, Output(), ''
        )
    }

    perftune_yaml_content_no_mode = copy.deepcopy(perftune_yaml_content)
    del perftune_yaml_content_no_mode['mode']

    check_analyzer(analyzer, "PerftuneYamlDefaultCollector", [
        ({'perftune.yaml': perftune_yaml_content},
         AnalyzerResult(AnalyzerStatus.PASSED, "content matches")),
        ({'perftune.yaml': perftune_yaml_content_no_mode},
         AnalyzerResult(AnalyzerStatus.PASSED, "content matches")),
        ({'perftune.yaml': {}},
         AnalyzerResult(AnalyzerStatus.FAILED, "content differs")),
    ], initial_vitals=vitals)


def test_PerftuneCpuMaskAnalyzer():
    analyzer = analyzers.PerftuneCpuMaskAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "results not found")

    vitals = {
        'CPUSetCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'perftune_mask': "0x00000003"}, Output(), ''
        )
    }

    check_analyzer(analyzer, "PerftuneYamlDefaultCollector", [
        ({'cpu_mask': "0x00000003"},
         AnalyzerResult(AnalyzerStatus.PASSED, "matches default")),
        ({'cpu_mask': "0x00000004"},
         AnalyzerResult(AnalyzerStatus.FAILED, "differs")),
    ], initial_vitals=vitals)


def test_StorageTypeAnalyzer():
    analyzer = analyzers.StorageTypeAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required StorageConfigurationCollector results not found")

    check_analyzer(analyzer, "StorageConfigurationCollector", [
        ({'data_file_directories': {'/my/path': {'devices': {'nvme': {}, 'non_nvme': {}}, 'storage_size_kb': 1024}}},
         AnalyzerResult(AnalyzerStatus.FAILED, "Storage type cannot be determined")),
        ({'data_file_directories': {'/my/path': {'devices': {'nvme': {'some'}, 'non_nvme': {}},
                                                 'storage_size_kb': 1024}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "detected (NVME)")),
        ({'data_file_directories': {'/my/path': {'devices': {'nvme': {}, 'non_nvme': {'some'}},
                                                 'storage_size_kb': 1024}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "detected (non-NVME)")),
        ({'data_file_directories': {'/my/path': {'devices': {'nvme': {'some'}, 'non_nvme': {'more'}},
                                                 'storage_size_kb': 1024}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "detected (NVME + non-NVME)")),
    ])


def test_RAIDSetupAnalyzer():
    analyzer = analyzers.RAIDSetupAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'StorageConfigurationCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'data_file_directories': {'/my/path': {'devices': {'nvme': {'nvme0n1p6'}, 'non_nvme': {}}}}}, Output(), '')
    }

    check_analyzer(analyzer, "RAIDSetupCollector", [
        ({'/proc/mdstat': ["Personalities :"]},
         AnalyzerResult(AnalyzerStatus.PASSED, "No RAID")),
        ({'/proc/mdstat': ["md1 : active raid1 nvme0n1p6"]},
         AnalyzerResult(AnalyzerStatus.WARNING, "RAID1 detected ")),
        ({'/proc/mdstat': ["md1 : active raid0 nvme0n1p6"]},
         AnalyzerResult(AnalyzerStatus.PASSED, "RAID0")),
        ({'/proc/mdstat': ["md1: active raid1 nvme0n1p6", "md1 : active raid4 nvme0n1p6"]},
         AnalyzerResult(AnalyzerStatus.WARNING, "Funny RAID")),
    ], initial_vitals=vitals)


def test_AssignedNICsAnalyzer():
    analyzer = analyzers.AssignedNICsAnalyzer({})
    vitals = {
        'NICsCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'nics': {'eth0': "foo", 'eth1': "bar"}}, Output(), ''),
        'ScyllaSystemConfigurationFilesCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'files': {'scylla-server': {'SET_NIC_AND_DISKS': "yes"}}}, Output(), ''),
        'ScyllaExtraConfigurationFilesCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'files': {'perftune.yaml': {'nic': ['eth0']}}}, Output(), '')
    }

    check_analyzer(analyzer, "IPRoutesCollector", [
        ({'localhost': "foo"},
         AnalyzerResult(AnalyzerStatus.WARNING, "not set up")),
        ({'localhost': "eth1 foo"},
         AnalyzerResult(AnalyzerStatus.WARNING, "not set up")),
        ({'localhost': "eth0 foo"},
         AnalyzerResult(AnalyzerStatus.PASSED, "NIC(s) are assigned")),
    ], initial_vitals=vitals)


def test_ScheduledMaintenanceEventAnalyzer():
    analyzer = analyzers.ScheduledMaintenanceEventAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "MaintenanceEventsCollector", [
        ({'scheduled_maintenance_events': None},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Pending maintenance events cannot be detected")),
        ({'scheduled_maintenance_events': []},
         AnalyzerResult(AnalyzerStatus.PASSED, "No pending maintenance event")),
        ({'scheduled_maintenance_events': [{"some_event": "some_event"}]},
         AnalyzerResult(AnalyzerStatus.FAILED, "The instance has a number of 1 pending maintenance events.")),
    ])


def test_ScyllaBroadcastAddressAnalyzer():
    analyzer = analyzers.ScyllaBroadcastAddressAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.FAILED, "neither broadcast_address nor listen_address were set")),
        ({'broadcast_address': "0.0.0.0", "resolved": {'broadcast_address': (["0.0.0.0"], [])}},
         AnalyzerResult(AnalyzerStatus.FAILED, "can't be used")),
        ({'broadcast_address': "::0", "resolved": {'broadcast_address': ([], ["::0"])}},
         AnalyzerResult(AnalyzerStatus.FAILED, "can't be used")),
        ({'broadcast_address': "localhost", "resolved": {'broadcast_address': (["127.0.0.1"], [])}},
         AnalyzerResult(AnalyzerStatus.WARNING, "not recommended")),
        ({'broadcast_address': "127.0.0.1", "resolved": {'broadcast_address': (["127.0.0.1"], [])}},
         AnalyzerResult(AnalyzerStatus.WARNING, "not recommended")),
        ({'listen_address': "192.168.1.1", "resolved": {'listen_address': (["192.168.1.1"], [])}},
         AnalyzerResult(AnalyzerStatus.PASSED, "is being used")),
        ({'broadcast_address': "192.168.1.1", "resolved": {'broadcast_address': (["192.168.1.1"], [])}},
         AnalyzerResult(AnalyzerStatus.PASSED, "is being used")),
    ])


def test_ScyllaClusterSystemKeyspacesReplicationAnalyzer():
    analyzer = analyzers.ScyllaClusterSystemKeyspacesReplicationAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'ScyllaClusterStatusCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'up': ["127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4"], 'down': []}, Output(), '')
    }

    replication = {
        'class': 'org.apache.cassandra.locator.NetworkTopologyStrategy',
        'us-central1_us': '3',
        'us-east4_us': '3'
    }
    bad_replication = copy.deepcopy(replication)
    bad_replication['us-central1_us'] = '1'
    good_keyspaces = {name: {'replication': repr(replication)}
                      for name in analyzer._ScyllaClusterSystemKeyspacesReplicationAnalyzer__keyspaces}
    good_keyspaces['system_traces']['replication'] = repr(bad_replication)
    good_keyspaces_with_audit = dict(good_keyspaces, **{"audit": {'replication': repr(replication)}})

    bad_replication = copy.deepcopy(replication)
    bad_replication['us-central1_us'] = '1'
    bad_keyspaces_with_audit = dict(good_keyspaces, **{"audit": {'replication': repr(bad_replication)}})

    broken_keyspaces = copy.deepcopy(good_keyspaces)
    replication['class'] = "SimpleStrategy"
    broken_keyspaces[random.choice(list(broken_keyspaces.keys()))]['replication'] = repr(replication)

    check_analyzer(analyzer, "ScyllaClusterSystemKeyspacesCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.FAILED, "is missing")),
        (broken_keyspaces,
         AnalyzerResult(AnalyzerStatus.FAILED, "is not using")),
        (good_keyspaces,
         AnalyzerResult(AnalyzerStatus.PASSED, "All system keyspaces")),
        (good_keyspaces_with_audit,
         AnalyzerResult(AnalyzerStatus.PASSED, "All system keyspaces")),
        (bad_keyspaces_with_audit,
         AnalyzerResult(AnalyzerStatus.FAILED, "audit keyspace has replication factor 1")),
    ], initial_vitals=vitals)


def test_ScyllaClusterSchemaAnalyzer():
    analyzer = analyzers.ScyllaClusterSchemaAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "ScyllaClusterSchemaCollector", [
        ([{'key': 'foo', 'value': ['127.0.0.1']}, {'key': 'bar', 'value': ['127.0.0.2']}],
         AnalyzerResult(AnalyzerStatus.WARNING, "mismatch")),
        ([{'key': 'foo', 'value': ['127.0.0.1']}],
         AnalyzerResult(AnalyzerStatus.PASSED, "synchronized")),
        ])


def test_ScyllaDeprecatedArgumentsAnalyzer():
    analyzer = analyzers.ScyllaDeprecatedArgumentsAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaSystemConfigurationFilesCollector results not found")

    check_analyzer(analyzer, "ScyllaSystemConfigurationFilesCollector", [
        ({'files': {}},
         AnalyzerResult(AnalyzerStatus.FAILED, "not found")),
        ({'files': {"scylla-server": {"SCYLLA_ARGS": "--join-ring foo"}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "deprecated argument(s) are in use")),
        ({'files': {"scylla-server": {"SCYLLA_ARGS": "--smp 1"}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "No deprecated arguments")),
    ])


def test_ScyllaLimitNOFILEAnalyzer():
    analyzer = analyzers.ScyllaLimitNOFILEAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaLimitNOFILECollector results not found")

    check_analyzer(analyzer, "ScyllaLimitNOFILECollector", [
        ({'limitnofile': 5000},
         AnalyzerResult(AnalyzerStatus.FAILED, "minimum value")),
        ({'limitnofile': 15000},
         AnalyzerResult(AnalyzerStatus.WARNING, "recommended value")),
        ({'limitnofile': 1000000},
         AnalyzerResult(AnalyzerStatus.PASSED, "greater than")),
    ])


def test_FSFILEMAXAnalyzer():
    analyzer = analyzers.FSFILEMAXAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'ScyllaLimitNOFILECollector': CollectorResult(
            CollectorStatus.PASSED,
            {'limitnofile': 1000000}, Output(), '')
    }

    check_analyzer(analyzer, "SysctlCollector", [
        ({'fs.file-max': 50000},
         AnalyzerResult(AnalyzerStatus.FAILED, "less than LimitNOFILE")),
        ({'fs.file-max': 1500000},
         AnalyzerResult(AnalyzerStatus.WARNING, "less than recommended value")),
        ({'fs.file-max': 10000000000000000000},
         AnalyzerResult(AnalyzerStatus.PASSED, "greater than recommended value")),
    ], initial_vitals=vitals)


def test_FSNROPENAnalyzer():
    analyzer = analyzers.FSNROPENAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'ScyllaLimitNOFILECollector': CollectorResult(
            CollectorStatus.PASSED,
            {'limitnofile': 1000000}, Output(), '')
    }

    check_analyzer(analyzer, "SysctlCollector", [
        ({'fs.nr_open': 50000},
         AnalyzerResult(AnalyzerStatus.FAILED, "less than LimitNOFILE")),
        ({'fs.nr_open': 1500000},
         AnalyzerResult(AnalyzerStatus.WARNING, "less than recommended value")),
        ({'fs.nr_open': 2000000000},
         AnalyzerResult(AnalyzerStatus.PASSED, "greater than recommended value")),
    ], initial_vitals=vitals)


def test_ScyllaInternodeCompressionAnalyzer():
    analyzer = analyzers.ScyllaInternodeCompressionAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaConfigurationFileCollector results not found")

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.WARNING, "should be 'all'")),
        ({'internode_compression': "none"},
         AnalyzerResult(AnalyzerStatus.WARNING, "should be 'all'")),
        ({'internode_compression': "all"},
         AnalyzerResult(AnalyzerStatus.PASSED, "Internode compression is set to 'all'")),
    ])

    # Check the case when we override the default recommended compression
    analyzer = analyzers.ScyllaInternodeCompressionAnalyzer({'ScyllaInternodeCompressionAnalyzer':
                                                            {'recommended_compression': 'dc'}})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaConfigurationFileCollector results not found")

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.WARNING, "should be 'dc'")),
        ({'internode_compression': "all"},
         AnalyzerResult(AnalyzerStatus.WARNING, "should be 'dc'")),
        ({'internode_compression': "dc"},
         AnalyzerResult(AnalyzerStatus.PASSED, "Internode compression is set to 'dc'")),
    ])


def test_ScyllaListenAddressAnalyzer():
    analyzer = analyzers.ScyllaListenAddressAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaConfigurationFileCollector results not found")

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.FAILED, "is not set")),
        ({'listen_address': "0.0.0.0", "resolved": {"listen_address": (["0.0.0.0"], [])}},
         AnalyzerResult(AnalyzerStatus.WARNING, "is not recommended for production")),
        ({'listen_address': "127.0.0.1", "resolved": {"listen_address": (["127.0.0.1"], [])}},
         AnalyzerResult(AnalyzerStatus.WARNING, "is not recommended for production")),
        ({'listen_address': "::1", "resolved": {"listen_address": ([], ["::1"])}},
         AnalyzerResult(AnalyzerStatus.WARNING, "is not recommended for production")),
        ({'listen_address': "192.168.1.1", "resolved": {"listen_address": (["192.168.1.1"], [])}},
         AnalyzerResult(AnalyzerStatus.PASSED, "is being used")),
    ])


def test_ScyllaNICsDisksSetupAnalyzer():
    analyzer = analyzers.ScyllaNICsDisksSetupAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaSystemConfigurationFilesCollector results not found")

    check_analyzer(analyzer, "ScyllaSystemConfigurationFilesCollector", [
        ({'files': {}},
         AnalyzerResult(AnalyzerStatus.FAILED, "not found")),
        ({'files': {'scylla-server': {'foo': 'bar'}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "should be set to 'yes'")),
        ({'files': {'scylla-server': {'SET_NIC_AND_DISKS': 'no'}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "should be set to 'yes'")),
        ({'files': {'scylla-server': {'SET_NIC_AND_DISKS': 'yes'}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "is enabled")),
    ])


def test_ScyllaRPCAddressAnalyzer():
    analyzer = analyzers.ScyllaRPCAddressAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaConfigurationFileCollector results not found")

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.FAILED, "is not set")),
        ({'rpc_address': "0.0.0.0", "resolved": {"rpc_address": (["0.0.0.0"], [])}},
         AnalyzerResult(AnalyzerStatus.WARNING, "is not recommended for production")),
        ({'rpc_address': "127.0.0.1", "resolved": {"rpc_address": (["127.0.0.1"], [])}},
         AnalyzerResult(AnalyzerStatus.WARNING, "is not recommended for production")),
        ({'rpc_address': "192.168.1.1", "resolved": {"rpc_address": (["192.168.1.1"], [])}},
         AnalyzerResult(AnalyzerStatus.PASSED, "is being used")),
    ])


def test_ScyllaRPCBroadcastRPCAddressAnalyzer():
    analyzer = analyzers.ScyllaBroadcastRPCAddressAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Required ScyllaConfigurationFileCollector results not found")

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.FAILED, "neither broadcast_rpc_address nor rpc_address are set")),
        ({'broadcast_rpc_address': "0.0.0.0", "resolved": {"broadcast_rpc_address": (["0.0.0.0"], [])}},
         AnalyzerResult(AnalyzerStatus.FAILED, "can't be used")),
        ({'broadcast_rpc_address': "127.0.0.1", "resolved": {"broadcast_rpc_address": (["127.0.0.1"], [])}},
         AnalyzerResult(AnalyzerStatus.WARNING, "is not recommended for production")),
        ({'broadcast_rpc_address': "192.168.1.1", "resolved": {"broadcast_rpc_address": (["192.168.1.1"], [])}},
         AnalyzerResult(AnalyzerStatus.PASSED, "is being used")),
        ({'rpc_address': "192.168.1.1", "resolved": {"rpc_address": (["192.168.1.1"], [])}},
         AnalyzerResult(AnalyzerStatus.PASSED, "is being used")),
    ])


def test_ScyllaServicesAnalyzer():
    analyzer = analyzers.ScyllaServicesAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "results not found")

    required_services_below_2025_1 = {service: {"active": True, "autostarts": True} for service in [
        "scylla-server",
        "scylla-jmx",
        "scylla-node-exporter",
        "scylla-housekeeping-daily",
        "scylla-fstrim.timer",
        "scylla-manager-agent"
    ]}

    required_services_above_2025_1 = {service: {"active": True, "autostarts": True} for service in [
        "scylla-server",
        "scylla-node-exporter",
        "scylla-housekeeping-daily",
        "scylla-fstrim.timer",
        "scylla-manager-agent"
    ]}

    scylla_version_collector_vitals_below_2025_1 = {
        'ScyllaVersionCollector': CollectorResult(
            CollectorStatus.PASSED,
            ({'version': '2024.2.0'}), Output(), '')
    }

    scylla_version_collector_vitals_above_2025_1 = {
        'ScyllaVersionCollector': CollectorResult(
            CollectorStatus.PASSED,
            ({'version': '2025.1.0'}), Output(), '')
    }

    for required_services, scylla_version_vitals in \
        [(required_services_below_2025_1, scylla_version_collector_vitals_below_2025_1),
         (required_services_above_2025_1, scylla_version_collector_vitals_above_2025_1)]:

        incomplete_services = copy.deepcopy(required_services)
        incomplete_services.pop(random.choice(list(incomplete_services.keys())))

        inactive_services = copy.deepcopy(required_services)
        inactive_services['scylla-housekeeping-daily']['active'] = False

        no_autostart_services = copy.deepcopy(required_services)
        no_autostart_services['scylla-node-exporter']['autostarts'] = False

        autostart_disabled_services = copy.deepcopy(required_services)
        autostart_disabled_services['scylla-server']['autostarts'] = False

        only_fstrim_disabled_services = copy.deepcopy(required_services)
        only_fstrim_disabled_services['scylla-fstrim.timer']['active'] = False

        vitals_discard = {
            'StorageConfigurationCollector': CollectorResult(
                CollectorStatus.PASSED,
                ({'data_file_directories': {'/my/path': {'mount_options': ['rw', 'discard']}}}), Output(), '')
        }
        vitals_discard.update(scylla_version_vitals)

        vitals_no_discard = {
            'StorageConfigurationCollector': CollectorResult(
                CollectorStatus.PASSED,
                ({'data_file_directories': {'/my/path': {'mount_options': ['rw', 'noatime']}}}), Output(), '')
        }
        vitals_no_discard.update(scylla_version_vitals)

        analyzer = analyzers.ScyllaServicesAnalyzer({})

        check_analyzer(analyzer, "ScyllaServicesCollector", [
            (required_services,
             AnalyzerResult(AnalyzerStatus.PASSED, "All services")),
            (only_fstrim_disabled_services,
             AnalyzerResult(AnalyzerStatus.PASSED, "All services"))
        ], initial_vitals=vitals_discard)

        check_analyzer(analyzer, "ScyllaServicesCollector", [
            (incomplete_services,
             AnalyzerResult(AnalyzerStatus.FAILED, "not found")),
            (inactive_services,
             AnalyzerResult(AnalyzerStatus.FAILED, "active - False")),
            (only_fstrim_disabled_services,
             AnalyzerResult(AnalyzerStatus.FAILED, "active - False")),
            (no_autostart_services,
             AnalyzerResult(AnalyzerStatus.FAILED, "autostarts - False")),
            (autostart_disabled_services,
             AnalyzerResult(AnalyzerStatus.FAILED, "autostarts - False")),
            (required_services,
             AnalyzerResult(AnalyzerStatus.PASSED, "All services")),
        ], initial_vitals=vitals_no_discard)

        analyzer = analyzers.ScyllaServicesAnalyzer({"ScyllaServicesAnalyzer": {
            "skip_active_check": "scylla-housekeeping-daily",
            "skip_autostarts_check": "scylla-housekeeping-daily,scylla-node-exporter",
        }})

        check_analyzer(analyzer, "ScyllaServicesCollector", [
            (inactive_services,
             AnalyzerResult(AnalyzerStatus.PASSED, "All services")),
            (no_autostart_services,
             AnalyzerResult(AnalyzerStatus.PASSED, "All services")),
        ], initial_vitals=vitals_no_discard)

        analyzer = analyzers.ScyllaServicesAnalyzer({"ScyllaServicesAnalyzer": {
            "disable_autostarts": "scylla-server"
        }})

        check_analyzer(analyzer, "ScyllaServicesCollector", [
            (autostart_disabled_services,
             AnalyzerResult(AnalyzerStatus.PASSED, "All services")),
        ], initial_vitals=vitals_no_discard)


def test_ScyllaSeedsAnalyzer():
    analyzer = analyzers.ScyllaSeedsAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "ScyllaSeedsCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.FAILED, "No seeds detected")),
        ({'localhost': 1, '127.0.0.1': 0},
         AnalyzerResult(AnalyzerStatus.WARNING, "Some seeds are unreachable")),
        ({'localhost': 0, '127.0.0.1': 0},
         AnalyzerResult(AnalyzerStatus.PASSED, "All seeds are reachable")),

    ])


def test_ScyllaSnitchAnalyzer():
    analyzer = analyzers.ScyllaSnitchAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'InfrastructureProviderCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'provider': None}, Output(), '')
    }

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.FAILED, "'endpoint_snitch' is not set")),
        ({'endpoint_snitch': 'SimpleSnitch'},
         AnalyzerResult(AnalyzerStatus.WARNING, "is not recommended")),
        ({'endpoint_snitch': 'GossipingPropertyFileSnitch'},
         AnalyzerResult(AnalyzerStatus.PASSED, "is used")),
    ], initial_vitals=vitals)

    vitals = {
        'InfrastructureProviderCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'provider': "GCP"}, Output(), '')
    }

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({'endpoint_snitch': 'SimpleSnitch'},
         AnalyzerResult(AnalyzerStatus.WARNING, "is not recommended")),
        ({'endpoint_snitch': 'GossipingPropertyFileSnitch'},
         AnalyzerResult(AnalyzerStatus.WARNING, "is used but it should be")),
        ({'endpoint_snitch': 'GoogleCloudSnitch'},
         AnalyzerResult(AnalyzerStatus.PASSED, "is used")),
    ], initial_vitals=vitals)

    analyzer = analyzers.ScyllaSnitchAnalyzer({'ScyllaSnitchAnalyzer': {'check_provider_snitch': 'no'}})
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({},
         AnalyzerResult(AnalyzerStatus.FAILED, "'endpoint_snitch' is not set")),
        ({'endpoint_snitch': 'SimpleSnitch'},
         AnalyzerResult(AnalyzerStatus.WARNING, "is not recommended")),
        ({'endpoint_snitch': 'GossipingPropertyFileSnitch'},
         AnalyzerResult(AnalyzerStatus.PASSED, "is used")),
    ], initial_vitals=vitals)


def test_ScyllaSSTablesAnalyzer():
    analyzer = analyzers.ScyllaSSTablesAnalyzer({'ScyllaSSTablesAnalyzer': {'recommended_format': 'md'}})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    empty_system_config = {
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, {}, Output(), '')
    }

    # recommended_format from config drives the check when set
    check_analyzer(analyzer, "ScyllaSSTablesCollector", [
        ({'files': []},
         AnalyzerResult(AnalyzerStatus.PASSED, "No SSTables found")),
        ({'files': ['/var/lib/scylla/data/some_table/mc-some-Data.db']},
         AnalyzerResult(AnalyzerStatus.WARNING, "SSTable format is not 'md'")),
        ({'files': [
            '/var/lib/scylla/data/some_table/md-some-Data.db',
            '/var/lib/scylla/data/some_table/mc-some-file-2-Data.db',
            '/var/lib/scylla/data/some_table/md-some-file-3-Data.db',
            ]},
         AnalyzerResult(AnalyzerStatus.WARNING, "SSTable format is not 'md'")),
        ({'files': ['/var/lib/scylla/data/md-some-file-Data.db',
                    '/var/lib/scylla/data/md-some-file-Index.db',
                    '/var/lib/scylla/data/md-some-file-Filter.db',
                    '/var/lib/scylla/data/md-some-file-CompressionInfo.db',
                    '/var/lib/scylla/data/md-some-file-Summary.db',
                    '/var/lib/scylla/data/md-some-file-Statistics.db',
                    '/var/lib/scylla/data/md-some-file-CRC.db',
                    '/var/lib/scylla/data/md-some-file-Scylla.db',
                    '/var/lib/scylla/data/md-some-file-Digest.crc32',
                    '/var/lib/scylla/data/md-some-file-Digest.adler32',
                    '/var/lib/scylla/data/md-some-file-Digest.sha1',
                    '/var/lib/scylla/data/md-some-file-TOC.txt',
                    '/var/lib/scylla/data/some-file.db']},
         AnalyzerResult(AnalyzerStatus.PASSED, "SSTable format is 'md'"))
    ], initial_vitals=empty_system_config)

    # recommended_format takes priority over SystemConfigCollector.sstable_format
    check_analyzer(analyzer, "ScyllaSSTablesCollector", [
        ({'files': ['/var/lib/scylla/data/some_table/mc-some-Data.db']},
         AnalyzerResult(AnalyzerStatus.WARNING, "SSTable format is not 'md'")),
        ({'files': ['/var/lib/scylla/data/md-some-file-Data.db']},
         AnalyzerResult(AnalyzerStatus.PASSED, "SSTable format is 'md'")),
    ], initial_vitals={
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED,
                                                 {'sstable_format': {'value': 'me', 'source': 'default',
                                                                     'type': 'string'}},
                                                 Output(), '')
    })

    analyzer_no_config = analyzers.ScyllaSSTablesAnalyzer({})

    # Without recommended_format, SystemConfigCollector.sstable_format is used
    check_analyzer(analyzer_no_config, "ScyllaSSTablesCollector", [
        ({'files': ['/var/lib/scylla/data/some_table/mc-some-Data.db']},
         AnalyzerResult(AnalyzerStatus.WARNING, "SSTable format is not 'md'")),
        ({'files': ['/var/lib/scylla/data/md-some-file-Data.db']},
         AnalyzerResult(AnalyzerStatus.PASSED, "SSTable format is 'md'")),
    ], initial_vitals={
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED,
                                                 {'sstable_format': {'value': 'md', 'source': 'config',
                                                                     'type': 'string'}},
                                                 Output(), '')
    })

    # Without recommended_format and sstable_format absent, fall back to 'me'
    check_analyzer(analyzer_no_config, "ScyllaSSTablesCollector", [
        ({'files': ['/var/lib/scylla/data/me-some-file-Data.db']},
         AnalyzerResult(AnalyzerStatus.PASSED, "SSTable format is 'me'")),
        ({'files': ['/var/lib/scylla/data/md-some-file-Data.db']},
         AnalyzerResult(AnalyzerStatus.WARNING, "SSTable format is not 'me'")),
    ], initial_vitals=empty_system_config)


def test_ScyllaSupportAnalyzer():
    analyzer = analyzers.ScyllaSupportAnalyzer({'ScyllaSupportAnalyzer': {
        'oss_minimum_version': '5.0',
        'enterprise_minimum_version': '2020.1'
    }})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "ScyllaVersionCollector", [
        ({'version': "5.1.dev", 'edition': 'development'},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "'Development' versions are not checked")),
        ({'version': "5.1", 'edition': 'oss'},
         AnalyzerResult(AnalyzerStatus.PASSED, "Currently supported")),
        ({'version': "2022.1", 'edition': 'enterprise'},
         AnalyzerResult(AnalyzerStatus.PASSED, "Currently supported")),
        ({'version': "4.2", 'edition': 'oss'},
         AnalyzerResult(AnalyzerStatus.WARNING, "Currently unsupported")),
        ({'version': "2018.1", 'edition': 'enterprise'},
         AnalyzerResult(AnalyzerStatus.WARNING, "Currently unsupported")),
    ])


def test_ScyllaUpdateAnalyzer():
    analyzer = analyzers.ScyllaUpdateAnalyzer({'ScyllaUpdateAnalyzer': {
        'oss_latest_version': "5.1",
        'enterprise_latest_version': "2022.1"
    }})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "ScyllaVersionCollector", [
        ({'version': "5.1", 'edition': 'oss'},
         AnalyzerResult(AnalyzerStatus.PASSED, "latest available version")),
        ({'version': "2022.1", 'edition': 'enterprise'},
         AnalyzerResult(AnalyzerStatus.PASSED, "latest available version")),
        ({'version': "4.2", 'edition': 'oss'},
         AnalyzerResult(AnalyzerStatus.WARNING, "can be upgraded")),
        ({'version': "2018.1", 'edition': 'enterprise'},
         AnalyzerResult(AnalyzerStatus.WARNING, "can be upgraded")),
    ])

    # check that online version can be retrieved
    vitals = {
        'ScyllaVersionCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'version': "5.0.2", 'edition': 'oss'}, Output(), '')
    }

    analyzer = analyzers.ScyllaUpdateAnalyzer({})
    analyzer.analyze(vitals)
    assert analyzer.status != AnalyzerStatus.FAILED, analyzer.message


def test_SELinuxAnalyzer():
    analyzer = analyzers.SELinuxAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "SELinuxCollector", [
        ({'files': {'/etc/selinux/config': None}},
         AnalyzerResult(AnalyzerStatus.PASSED, "SELinux is not present")),
        ({'files': {'/etc/selinux/config': ["SELINUX=permissive", "###"]}},
         AnalyzerResult(AnalyzerStatus.WARNING, "SELinux is working")),
        ({'files': {'/etc/selinux/config': ['SELINUX="disabled"']}},  # the most common error - extra quotes
         AnalyzerResult(AnalyzerStatus.WARNING, "SELinux is working")),
        ({'files': {'/etc/selinux/config': ["SELINUX=disabled"]}},
         AnalyzerResult(AnalyzerStatus.PASSED, "SELinux is disabled")),
    ])


def test_StorageRAMRatioAnalyzer():
    analyzer = analyzers.StorageRAMRatioAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'RAMCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'total': 1000000}, Output(), '')
    }

    check_analyzer(analyzer, "StorageConfigurationCollector", [
        ({'data_file_directories': {'/my/path': {'storage_size_kb': 100000000}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "lower than recommended")),
        ({'data_file_directories': {'/my/path': {'storage_size_kb': 110000000}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "higher than recommended")),
    ], initial_vitals=vitals)

    # Ratio supplied as a string (as configparser always returns strings) must not raise TypeError
    analyzer = analyzers.StorageRAMRatioAnalyzer({'StorageRAMRatioAnalyzer': {'ratio': '80'}})
    check_analyzer(analyzer, "StorageConfigurationCollector", [
        ({'data_file_directories': {'/my/path': {'storage_size_kb': 70000000}}},
         AnalyzerResult(AnalyzerStatus.PASSED, "lower than recommended")),
        ({'data_file_directories': {'/my/path': {'storage_size_kb': 90000000}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "higher than recommended")),
    ], initial_vitals=vitals)


def test_SwapAnalyzer():
    analyzer = analyzers.SwapAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    vitals = {
        'RAMCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'total': 24000000}, Output(), '')
    }

    check_analyzer(analyzer, "SwapCollector", [
        ({'total': 0},
         AnalyzerResult(AnalyzerStatus.FAILED, "No swap configuration detected")),
        ({'total': 16000000},
         AnalyzerResult(AnalyzerStatus.PASSED, "detected")),
        ({'total': 4000000},
         AnalyzerResult(AnalyzerStatus.WARNING, "less than")),
    ], initial_vitals=vitals)


def test_SwapAnalyzer_printout():
    analyzer = analyzers.SwapAnalyzer({})

    vitals = {
        'RAMCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'total': 15596277}, Output(), '')
    }

    check_analyzer(analyzer, "SwapCollector", [
        ({'total': 5197820},
         AnalyzerResult(AnalyzerStatus.WARNING, "5076.00 MiB were detected but it is less than 5076.91 (recommended)")),
        ({'total': 5198758},
         AnalyzerResult(AnalyzerStatus.WARNING,
                        "5198758.00 KiB were detected but it is less than 5198759.00 (recommended)")),
        ({'total': 6000000},
         AnalyzerResult(AnalyzerStatus.PASSED, "5.72 GiB were detected")),
    ], initial_vitals=vitals)


def test_SwapAnalyzer_parametrization():
    vitals = {
        'RAMCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'total': 15596284}, Output(), '')
    }

    analyzer = analyzers.SwapAnalyzer({})
    check_analyzer(analyzer, "SwapCollector", [
        ({'total': 5197820},
         AnalyzerResult(AnalyzerStatus.WARNING, "5076.00 MiB were detected but it is less than 5076.92 (recommended)")),
    ], initial_vitals=vitals)

    analyzer = analyzers.SwapAnalyzer({'SwapAnalyzer': {'ram_swap_ratio': "3.2"}})
    check_analyzer(analyzer, "SwapCollector", [
        ({'total': 5197820},
         AnalyzerResult(AnalyzerStatus.PASSED, "4.96 GiB were detected")),
    ], initial_vitals=vitals)

    analyzer = analyzers.SwapAnalyzer({'SwapAnalyzer': {'swap_minimum_total': "5197820"}})
    check_analyzer(analyzer, "SwapCollector", [
        ({'total': 5197820},
         AnalyzerResult(AnalyzerStatus.PASSED, "4.96 GiB were detected")),
    ], initial_vitals=vitals)


def test_XFSAnalyzer():
    analyzer = analyzers.XFSAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "StorageConfigurationCollector", [
        ({'data_file_directories': {'/my/path': {'filesystem': 'ext4'}}},
         AnalyzerResult(AnalyzerStatus.WARNING, "XFS setup was not done")),
        ({'data_file_directories': {'/my/path': {'filesystem': 'xfs'}}, 'commitlog_directories': {}},
         AnalyzerResult(AnalyzerStatus.PASSED, "XFS setup was done")),
    ])


def test_NodeInstanceTypeAnalyzer():
    analyzer = analyzers.NodeInstanceTypeAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "InfrastructureProviderCollector", [
        ({'provider': None},
         AnalyzerResult(AnalyzerStatus.PASSED, "Not a cloud instance")),
        ({'provider': "AWS", 'instance_type': "i3.metal"},
         AnalyzerResult(AnalyzerStatus.PASSED, "listed as recommended")),
        ({'provider': "AWS", 'instance_type': "i8g.metal-24xl"},
         AnalyzerResult(AnalyzerStatus.PASSED, "listed as recommended")),
        ({'provider': "AWS", 'instance_type': "i8ge.48xlarge"},
         AnalyzerResult(AnalyzerStatus.PASSED, "listed as recommended")),
        ({'provider': "GCP", 'instance_type': "Something fictional"},
         AnalyzerResult(AnalyzerStatus.WARNING, "not listed as recommended")),
    ])


def test_TokensGossipInfoConsistencyAnalyzer():
    CT_FEATURE = "SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES"
    FEATURES = GossipInfoInvariantValues.SUPPORTED_FEATURES.name  # "SUPPORTED_FEATURES"
    TOKENS = GossipInfoInvariantValues.TOKENS.name                # "TOKENS"
    CDC = GossipInfoInvariantValues.CDC_GENERATION_ID.name        # "CDC_GENERATION_ID"

    analyzer = analyzers.GossipInfoConsistencyAnalyzer({})

    # Missing dependency
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "Required GossipInfoCollector results not found")

    check_analyzer(analyzer, "GossipInfoCollector", [
        # SUPPORTED_FEATURES absent → cannot determine CT support → bad host
        ({'gossip_info': [('1.1.1.1', {})]},
         AnalyzerResult(AnalyzerStatus.FAILED, f"1.1.1.1: {FEATURES} is missing in the GossipInfo")),

        # Host supports Consistent Topology → TOKENS/CDC_GENERATION_ID not required
        ({'gossip_info': [('1.1.1.1', {FEATURES: ['ROLES', CT_FEATURE]})]},
         AnalyzerResult(AnalyzerStatus.PASSED, "All hosts have TOKENS and CDC_GENERATION_ID entries in GossipInfo when needed")),  # noqa: E501

        # No CT support, both TOKENS and CDC_GENERATION_ID present → PASSED
        ({'gossip_info': [('1.1.1.1', {FEATURES: ['ROLES'], TOKENS: ['t1'], CDC: 'some-cdc-id'})]},
         AnalyzerResult(AnalyzerStatus.PASSED, "All hosts have TOKENS and CDC_GENERATION_ID entries in GossipInfo when needed")),  # noqa: E501

        # No CT support, TOKENS absent → FAILED
        ({'gossip_info': [('1.1.1.1', {FEATURES: ['ROLES'], CDC: 'some-cdc-id'})]},
         AnalyzerResult(AnalyzerStatus.FAILED, f"1.1.1.1: {TOKENS} entry is missing or empty")),

        # No CT support, CDC_GENERATION_ID absent → FAILED
        ({'gossip_info': [('1.1.1.1', {FEATURES: ['ROLES'], TOKENS: ['t1']})]},
         AnalyzerResult(AnalyzerStatus.FAILED, f"1.1.1.1: {CDC} entry is missing or empty")),

        # No CT support, TOKENS present but empty → FAILED
        ({'gossip_info': [('1.1.1.1', {FEATURES: ['ROLES'], TOKENS: [], CDC: 'some-cdc-id'})]},
         AnalyzerResult(AnalyzerStatus.FAILED, f"1.1.1.1: {TOKENS} entry is missing or empty")),

        # Empty gossip_info (no hosts at all) → PASSED
        ({'gossip_info': []},
         AnalyzerResult(AnalyzerStatus.PASSED, "All hosts have TOKENS and CDC_GENERATION_ID entries in GossipInfo when needed")),  # noqa: E501
    ])

    # Mixed cluster: CT host needs no tokens, non-CT host has all required fields → PASSED
    analyzer.analyze({'GossipInfoCollector': CollectorResult(CollectorStatus.PASSED, {
        'gossip_info': [
            ('1.1.1.1', {FEATURES: ['ROLES', CT_FEATURE]}),
            ('1.1.1.2', {FEATURES: ['ROLES'], TOKENS: ['t1'], CDC: 'some-cdc-id'}),
        ]
    }, Output(), '')})
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, "All hosts have TOKENS and CDC_GENERATION_ID entries in GossipInfo when needed")  # noqa: E501

    # Mixed cluster: CT host is fine, non-CT host is missing TOKENS → FAILED for non-CT host only
    analyzer.analyze({'GossipInfoCollector': CollectorResult(CollectorStatus.PASSED, {
        'gossip_info': [
            ('1.1.1.1', {FEATURES: ['ROLES', CT_FEATURE]}),
            ('1.1.1.2', {FEATURES: ['ROLES'], CDC: 'some-cdc-id'}),
        ]
    }, Output(), '')})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, f"1.1.1.2: {TOKENS} entry is missing or empty")


def test_TopologyConsistencyAnalyzer_verify_gossip_info_consistency():
    """
    Unit tests for TopologyConsistencyAnalyzer.__verify_gossip_info_consistency().

    Exercises the duplicate-address and None-address detection logic in isolation by
    providing pre-built gossip_info lists together with all other required collectors
    in a valid state.
    """
    def make_vitals(gossip_info):
        host_ids = {
            "127.0.0.1": "aaaa0001-0000-0000-0000-000000000001",
            "127.0.0.2": "aaaa0002-0000-0000-0000-000000000002",
        }
        return {
            'GossipInfoCollector': CollectorResult(
                CollectorStatus.PASSED, {'gossip_info': gossip_info}, Output(), ''),
            'TokenMetadataHostsMappingCollector': CollectorResult(
                CollectorStatus.PASSED, {'hosts': host_ids}, Output(), ''),
            'RaftGroup0Collector': CollectorResult(
                CollectorStatus.PASSED,
                {'group0_id': 'some-group0-id', 'hosts': list(host_ids.values())},
                Output(), ''),
            'SystemPeersLocalCollector': CollectorResult(
                CollectorStatus.PASSED,
                {'hosts': {k: {'host_id': v} for k, v in host_ids.items()}},
                Output(), ''),
            'SystemClusterStatusCollector': CollectorResult(
                CollectorStatus.PASSED,
                {'hosts': {k: {'host_id': v} for k, v in host_ids.items()}},
                Output(), ''),
        }

    analyzer = analyzers.TopologyConsistencyAnalyzer({})

    # Clean gossip → no consistency errors added
    analyzer.analyze(make_vitals([
        ('127.0.0.1', {'HOST_ID': 'aaaa0001-0000-0000-0000-000000000001'}),
        ('127.0.0.2', {'HOST_ID': 'aaaa0002-0000-0000-0000-000000000002'}),
    ]))
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, None)

    # Duplicate address, same UUID → FAILED
    analyzer.analyze(make_vitals([
        ('127.0.0.1', {'HOST_ID': 'aaaa0001-0000-0000-0000-000000000001'}),
        ('127.0.0.1', {'HOST_ID': 'aaaa0001-0000-0000-0000-000000000001'}),
        ('127.0.0.2', {'HOST_ID': 'aaaa0002-0000-0000-0000-000000000002'}),
    ]))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Host with the address 127.0.0.1 appears more than once in the Gossip state")

    # Duplicate address, different UUIDs (e.g. after node replacement) → FAILED
    analyzer.analyze(make_vitals([
        ('127.0.0.1', {'HOST_ID': 'aaaa0001-0000-0000-0000-000000000001'}),
        ('127.0.0.1', {'HOST_ID': 'bbbb0001-0000-0000-0000-000000000001'}),
        ('127.0.0.2', {'HOST_ID': 'aaaa0002-0000-0000-0000-000000000002'}),
    ]))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Host with the address 127.0.0.1 appears more than once in the Gossip state")

    # Same address triplicated, mixed UUIDs → reported only once
    analyzer.analyze(make_vitals([
        ('127.0.0.1', {'HOST_ID': 'aaaa0001-0000-0000-0000-000000000001'}),
        ('127.0.0.1', {'HOST_ID': 'bbbb0001-0000-0000-0000-000000000001'}),
        ('127.0.0.1', {'HOST_ID': 'cccc0001-0000-0000-0000-000000000001'}),
        ('127.0.0.2', {'HOST_ID': 'aaaa0002-0000-0000-0000-000000000002'}),
    ]))
    assert analyzer.message.count("127.0.0.1 appears more than once") == 1

    # None address → FAILED
    analyzer.analyze(make_vitals([
        (None,        {'HOST_ID': 'aaaa0001-0000-0000-0000-000000000001'}),
        ('127.0.0.2', {'HOST_ID': 'aaaa0002-0000-0000-0000-000000000002'}),
    ]))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Gossip state has an entry with a None address")

    # Multiple None addresses with different UUIDs → error reported only once
    analyzer.analyze(make_vitals([
        (None,        {'HOST_ID': 'aaaa0001-0000-0000-0000-000000000001'}),
        (None,        {'HOST_ID': 'bbbb0001-0000-0000-0000-000000000001'}),
        ('127.0.0.2', {'HOST_ID': 'aaaa0002-0000-0000-0000-000000000002'}),
    ]))
    assert analyzer.message.count("None address") == 1

    # Both None and duplicate (different UUIDs) in same gossip → both errors reported
    analyzer.analyze(make_vitals([
        (None,        {'HOST_ID': 'aaaa0001-0000-0000-0000-000000000001'}),
        ('127.0.0.2', {'HOST_ID': 'aaaa0002-0000-0000-0000-000000000002'}),
        ('127.0.0.2', {'HOST_ID': 'bbbb0002-0000-0000-0000-000000000002'}),
    ]))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "None address")
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           "Host with the address 127.0.0.2 appears more than once")


def test_TopologyConsistencyAnalyzer(test_case_raft_enabled=True):
    """
    This test function checks for various cases:
    - It checks whether the required collectors are listed as dependencies in the Analyzer.
      (e.g. missing GossipInfoCollector, missing SystemPeersLocalCollector, et.c)
    - It generates and tests different cases of vitals, with one collector each time having a bad host UUID.
    - It generates and tests different cases vitals, with one collector each time missing a pair of IP and UUID value.

    :param: test_case_raft_enabled (bool): If disabled, we exclude the RaftGroup0 collector from the comparisons.
    """
    def gen_gossip_vitals(addr_uuid_map: DictView[str, str]) -> Dict:
        return {'gossip_info': [(k, {'HOST_ID': v}) for k, v in addr_uuid_map.items()]}

    def gen_raft_vitals(addr_uuid_map: DictView[str, str]) -> Dict:
        if test_case_raft_enabled:
            return {
                'group0_id': '65356de0-08c3-11ef-b073-4d3c564923dd',
                'hosts': list(addr_uuid_map.values())
            }
        else:
            return {
                'group0_id': None,
                'hosts': []
            }

    def gen_system_ks_vitals(addr_uuid_map: DictView[str, str]) -> Dict:
        return {'hosts': {k: {'host_id': v} for k, v in addr_uuid_map.items()}}

    def gen_tm_vitals(addr_uuid_map: DictView[str, str]) -> Dict:
        return {'hosts': addr_uuid_map}

    test_addr_uuid_map = {
        "127.0.0.3": "0ba70f29-8d04-4d20-a518-dc8a58bcd9e3",
        "127.0.0.2": "afb59447-469b-4db4-9184-afa2be26b974",
        "127.0.0.1": "385ccf0b-a24d-4b55-944c-0004b4b6a1ab"
    }

    gossip_vitals = {
        'GossipInfoCollector':
            CollectorResult(CollectorStatus.PASSED, gen_gossip_vitals(test_addr_uuid_map), Output(), '')
    }

    tm_vitals = {
        'TokenMetadataHostsMappingCollector':
            CollectorResult(CollectorStatus.PASSED, gen_tm_vitals(test_addr_uuid_map), Output(), '')
    }

    raft_vitals = {
        'RaftGroup0Collector':
            CollectorResult(CollectorStatus.PASSED, gen_raft_vitals(test_addr_uuid_map), Output(), '')
    }

    system_peers_vitals = {
        'SystemPeersLocalCollector':
            CollectorResult(CollectorStatus.PASSED, gen_system_ks_vitals(test_addr_uuid_map), Output(), '')
    }

    system_cluster_status_vitals = {
        'SystemClusterStatusCollector':
            CollectorResult(CollectorStatus.PASSED, gen_system_ks_vitals(test_addr_uuid_map), Output(), '')
    }

    required_collectors = [
        ('GossipInfoCollector', gossip_vitals),
        ('TokenMetadataHostsMappingCollector', tm_vitals),
        ('RaftGroup0Collector', raft_vitals),
        ('SystemClusterStatusCollector', system_cluster_status_vitals),
        ('SystemPeersLocalCollector', system_peers_vitals)
    ]

    vitals_generators = {
        'GossipInfoCollector': (lambda m: gen_gossip_vitals(m), "GossipInfo"),
        'TokenMetadataHostsMappingCollector': (lambda m: gen_tm_vitals(m), "TokenMetadata"),
        'SystemPeersLocalCollector': (lambda m: gen_system_ks_vitals(m), "SystemPeersLocal"),
        'SystemClusterStatusCollector': (lambda m: gen_system_ks_vitals(m), "SystemClusterStatus")
    }

    # If raft is enabled, we include a variation of its vitals for comparison in the test cases.
    if test_case_raft_enabled:
        vitals_generators['RaftGroup0Collector'] = (lambda m: gen_raft_vitals(m), "RaftGroup0")

    analyzer = analyzers.TopologyConsistencyAnalyzer({})

    #################################################################################################################
    # Check missing dependencies report
    for i in range(len(required_collectors) - 1):
        vitals = {}
        for j in range(i):
            vitals.update(required_collectors[j][1])
        analyzer.analyze(vitals)
        for missing_collector_idx in range(i + 1, len(required_collectors)):
            assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                                   f"Required {required_collectors[missing_collector_idx][0]} results not found")

    #################################################################################################################
    # Check a good case
    vitals = {}
    for v_name, v in required_collectors:
        vitals.update(v)

    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, "Topology is consistent")

    #################################################################################################################
    # Check inconsistent UUID.
    # In this case an Analyzer is going to report a UUID inconsistency in the analyzer.message between each pair of
    # Collectors.
    # In addition to that it's going to report inconsistency of UUID for a specific IP for each Collector
    # that has an IP -> UUID mapping which is all but RaftGroup0Collector collectors.
    bad_test_addr_uuid_map = dict(test_addr_uuid_map)
    bad_addr = "127.0.0.2"
    bad_uuid = "afb59447-469b-4db4-9184-afa2be26b975"
    good_uuid = "afb59447-469b-4db4-9184-afa2be26b974"
    bad_test_addr_uuid_map[bad_addr] = bad_uuid

    # Create all possible combinations when there is an inconsistent host ID in one of the Collectors' vitals
    for bad_collector_name, bad_vitals_generator in vitals_generators.items():
        testcases = []
        bad_collector_name_met = False
        bad_collector_label = bad_vitals_generator[1]

        for collector_name, collector_gen in vitals_generators.items():
            collector_label = collector_gen[1]

            if bad_collector_name == collector_name:
                bad_collector_name_met = True
                continue

            testcases.append((bad_vitals_generator[0](bad_test_addr_uuid_map),
                              AnalyzerResult(AnalyzerStatus.FAILED,
                                             f"{bad_collector_label} items not present in {collector_label}: "
                                             f"{bad_uuid}")))
            testcases.append((bad_vitals_generator[0](bad_test_addr_uuid_map),
                              AnalyzerResult(AnalyzerStatus.FAILED,
                                             f"{collector_label} items not present in {bad_collector_label}: "
                                             f"{good_uuid}")))

            # RaftGroup0Collector vitals have no address component
            if 'RaftGroup0Collector' in [bad_collector_name, collector_name]:
                continue

            if bad_collector_name_met:
                error_message = (f"{bad_addr} has different host IDs in {bad_collector_label} ({bad_uuid}) "
                                 f"and in {collector_label} ({good_uuid})")
            else:
                error_message = (f"{bad_addr} has different host IDs in {collector_label} ({good_uuid}) "
                                 f"and in {bad_collector_label} ({bad_uuid})")

            testcases.append((bad_vitals_generator[0](bad_test_addr_uuid_map),
                              AnalyzerResult(AnalyzerStatus.FAILED, error_message)))

        check_analyzer(analyzer, bad_collector_name, testcases, initial_vitals=vitals)

    #################################################################################################################
    # Check a missing IP
    # Analyzer is going to report in the analyzer.message every pair of Collectors that collected a different set of IPs
    bad_test_addr_uuid_map = dict(test_addr_uuid_map)
    missing_addr = "127.0.0.2"
    missing_uuid = "afb59447-469b-4db4-9184-afa2be26b974"
    del bad_test_addr_uuid_map[bad_addr]

    # Create all possible combinations when there is a missing host IP in one of the Collectors' vitals
    for bad_collector_name, bad_vitals_generator in vitals_generators.items():
        testcases = []
        bad_collector_label = bad_vitals_generator[1]

        for collector_name, collector_gen in vitals_generators.items():
            collector_label = collector_gen[1]

            if bad_collector_name == collector_name:
                continue

            testcases.append((bad_vitals_generator[0](bad_test_addr_uuid_map),
                              AnalyzerResult(AnalyzerStatus.FAILED,
                                             f"{collector_label} items not present in {bad_collector_label}: "
                                             f"{missing_uuid}")))

            # RaftGroup0Collector vitals have no address component
            if 'RaftGroup0Collector' in [bad_collector_name, collector_name]:
                continue

            error_message = f"{missing_addr} is present in {collector_label} but not in {bad_collector_label}"

            testcases.append((bad_vitals_generator[0](bad_test_addr_uuid_map),
                              AnalyzerResult(AnalyzerStatus.FAILED, error_message)))

        check_analyzer(analyzer, bad_collector_name, testcases, initial_vitals=vitals)


def test_TopologyConsistencyAnalyzer_raft_disabled():
    """
    This calls the TopologyConsistencyAnalyzer test function with the raft set to disabled
    for the RaftGroup0Collector.
    """
    test_TopologyConsistencyAnalyzer(test_case_raft_enabled=False)


def test_CloudCPUPlatformAnalyzer_expected_cpu_platform_specified():
    """
    Tests CloudCPUPlatformAnalyzer invocations with 'expected_cpu_platform' specified
    """
    good_CPU_platform = 'good CPU platform'
    bad_CPU_platform = 'bad CPU platform'

    analyzer = analyzers.CloudCPUPlatformAnalyzer({'CloudCPUPlatformAnalyzer':
                                                  {'expected_cpu_platform': good_CPU_platform}})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "InfrastructureProviderCollector", [
        ({'provider': 'Some Cloud', 'cpu_platform': bad_CPU_platform},
         AnalyzerResult(AnalyzerStatus.FAILED,
                        f"CPU platform is '{bad_CPU_platform}' while expecting '{good_CPU_platform}'")),
        ({'provider': 'Some Cloud', 'cpu_platform': good_CPU_platform},
         AnalyzerResult(AnalyzerStatus.PASSED,
                        f"CPU platform is '{good_CPU_platform}'")),
        ({'provider': 'Some Cloud', 'cpu_platform': None},
         AnalyzerResult(AnalyzerStatus.SKIPPED,
                        "'expected_cpu_platform' is not specified or CPU Platform is not dynamic")),
        ({'provider': None},
         AnalyzerResult(AnalyzerStatus.SKIPPED,
                        "'expected_cpu_platform' is not specified or CPU Platform is not dynamic"))
    ])


def test_CloudCPUPlatformAnalyzer_expected_cpu_platform_not_specified():
    """
    Tests CloudCPUPlatformAnalyzer invocations with 'expected_cpu_platform' unspecified
    """
    good_CPU_platform = 'good CPU platform'
    bad_CPU_platform = 'bad CPU platform'

    analyzer = analyzers.CloudCPUPlatformAnalyzer({})

    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "InfrastructureProviderCollector", [
        ({'provider': 'Some Cloud', 'cpu_platform': bad_CPU_platform},
         AnalyzerResult(AnalyzerStatus.SKIPPED,
                        "'expected_cpu_platform' is not specified or CPU Platform is not dynamic")),
        ({'provider': 'Some Cloud', 'cpu_platform': good_CPU_platform},
         AnalyzerResult(AnalyzerStatus.SKIPPED,
                        "'expected_cpu_platform' is not specified or CPU Platform is not dynamic")),
        ({'provider': 'Some Cloud', 'cpu_platform': None},
         AnalyzerResult(AnalyzerStatus.SKIPPED,
                        "'expected_cpu_platform' is not specified or CPU Platform is not dynamic")),
        ({'provider': None},
         AnalyzerResult(AnalyzerStatus.SKIPPED,
                        "'expected_cpu_platform' is not specified or CPU Platform is not dynamic"))
    ])


def test_ScyllaConfigurationConsistencyAnalyzer_ignore_unknown_values():
    """
    scylla.yaml may have unknown, erroneous, or unsupported parameters.
    These parameters will thus not be present in system.config.
    This test checks that we ignore such parameters present in scylla.yaml.
    """
    good_values = [
        {'int_value': 1},
        {'bool_value': True},
        {'string_value': 'good value'},
        {'dict_value':
         {'k1': 'v1',
          'k2': {'k2': 'v2'},
          'k3': ['v4', 'v5']
          }},
        {'list_value': [1, 2, 3]},
    ]

    config_source_value = 'config'
    scylla_config_state = {}
    for good_value in good_values:
        for key, value in good_value.items():
            scylla_config_state[key] = {
                'value': value,
                'source': config_source_value,
                'type': 'irrelevant'
            }

    scylla_config_vitals = {
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, scylla_config_state, Output(), '')
    }

    scylla_yaml_conf = {'pure_scylla_yaml': {}}
    scylla_yaml_conf_pure_yaml = scylla_yaml_conf['pure_scylla_yaml']
    for good_value in good_values:
        scylla_yaml_conf_pure_yaml.update(good_value)

    # Add unknown value to scylla.yaml
    scylla_yaml_conf_pure_yaml['unknown_key'] = "some value"

    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer({})
    success_message = "Scylla configuration is consistent"
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf, AnalyzerResult(AnalyzerStatus.PASSED, success_message))
    ], initial_vitals=scylla_config_vitals)


def test_ScyllaConfigurationConsistencyAnalyzer_object_storage_endpoints_skipped():
    """
    Ref https://scylladb.atlassian.net/browse/SCYLLADB-1658
    'object_storage_endpoints' has a non-JSON value and must be skipped in consistency checks.
    """
    scylla_config_vitals = {
        'SystemConfigCollector': CollectorResult(
            CollectorStatus.PASSED,
            {
                'cluster_name': {'value': 'test', 'source': 'config', 'type': 'string'},
                'object_storage_endpoints': {'value': 'some-raw-value', 'source': 'config', 'type': 'string'},
            },
            Output(), '',
        )
    }

    scylla_yaml_conf = {
        'pure_scylla_yaml': {
            'cluster_name': 'test',
            'object_storage_endpoints': 'different-raw-value',
        }
    }

    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer({})
    success_message = "Scylla configuration is consistent"
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf, AnalyzerResult(AnalyzerStatus.PASSED, success_message))
    ], initial_vitals=scylla_config_vitals)


def test_ScyllaConfigurationConsistencyAnalyzer_properly_handle_tri_state_values():
    """
    Ref https://github.com/scylladb/scylladb/issues/22785

    tri_mode_restriction configuration parameters are allowed to be configured to: case-sensitive strings
    'true', 'false', 'warn', '0', '1'; integers 0, 1; booleans True, False.
    Thus, such values are going to be parsed into True, False booleans; 0, 1 integers or '1', '0', 'warn' strings.
    However, the corresponding value in system.config is going to be one of the following strings '1', '0',
    'warn'.

    Let's test that ScyllaConfigurationConsistencyAnalyzer properly handles different 'interesting' combinations above
    correctly.
    """

    # The only 'interesting' configuration of a tri-state value in system.config is either '1' or '0'.
    # Value 'warn' is just a regular string value that we covered in other ScyllaConfigurationConsistencyAnalyzer tests
    # above.
    scylla_config_tri_state_true = {
        'tri_state': {
            'value': '1',
            'type': 'restriction mode',
            'source': 'config'
        }
    }

    scylla_config_tri_state_false = {
        'tri_state': {
            'value': '0',
            'type': 'restriction mode',
            'source': 'config'
        }
    }

    scylla_config_vitals_true = {
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, scylla_config_tri_state_true, Output(), '')
    }

    scylla_config_vitals_false = {
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, scylla_config_tri_state_false, Output(), '')
    }

    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer({})
    success_message = "Scylla configuration is consistent"
    failure_message = f"Scylla configuration differs from the one present in scylla.yaml for keys: {['tri_state']}."

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({'pure_scylla_yaml': {'tri_state': True}}, AnalyzerResult(AnalyzerStatus.PASSED, success_message)),
        ({'pure_scylla_yaml': {'tri_state': 'true'}}, AnalyzerResult(AnalyzerStatus.PASSED, success_message)),
        ({'pure_scylla_yaml': {'tri_state': '1'}}, AnalyzerResult(AnalyzerStatus.PASSED, success_message)),
        ({'pure_scylla_yaml': {'tri_state': 1}}, AnalyzerResult(AnalyzerStatus.PASSED, success_message)),
        ({'pure_scylla_yaml': {'tri_state': False}}, AnalyzerResult(AnalyzerStatus.FAILED, failure_message)),
        ({'pure_scylla_yaml': {'tri_state': 'false'}}, AnalyzerResult(AnalyzerStatus.FAILED, failure_message)),
        ({'pure_scylla_yaml': {'tri_state': 0}}, AnalyzerResult(AnalyzerStatus.FAILED, failure_message)),
        ({'pure_scylla_yaml': {'tri_state': '0'}}, AnalyzerResult(AnalyzerStatus.FAILED, failure_message)),
    ], initial_vitals=scylla_config_vitals_true)

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        ({'pure_scylla_yaml': {'tri_state': True}}, AnalyzerResult(AnalyzerStatus.FAILED, failure_message)),
        ({'pure_scylla_yaml': {'tri_state': 'true'}}, AnalyzerResult(AnalyzerStatus.FAILED, failure_message)),
        ({'pure_scylla_yaml': {'tri_state': '1'}}, AnalyzerResult(AnalyzerStatus.FAILED, failure_message)),
        ({'pure_scylla_yaml': {'tri_state': 1}}, AnalyzerResult(AnalyzerStatus.FAILED, failure_message)),
        ({'pure_scylla_yaml': {'tri_state': False}}, AnalyzerResult(AnalyzerStatus.PASSED, success_message)),
        ({'pure_scylla_yaml': {'tri_state': 'false'}}, AnalyzerResult(AnalyzerStatus.PASSED, success_message)),
        ({'pure_scylla_yaml': {'tri_state': 0}}, AnalyzerResult(AnalyzerStatus.PASSED, success_message)),
        ({'pure_scylla_yaml': {'tri_state': '0'}}, AnalyzerResult(AnalyzerStatus.PASSED, success_message)),
    ], initial_vitals=scylla_config_vitals_false)


def test_ScyllaConfigurationFileFormatAnalyzer_tri_state():
    """
    tri_mode_restriction configuration parameters are allowed to be configured to: case-sensitive strings
    'true', 'false', 'warn', '0', '1'; integers 0, 1; booleans (lower-case) true, false.

    Let's verify that ScyllaConfigurationFileFormatAnalyzer is able to validate a format of these values.
    """

    scylla_config_tri_state = {
        'tri_state0': {
            'value': 'irrelevant',
            'type': 'restriction mode',
            'source': 'irrelevant'
        },
        'tri_state1': {
            'value': 'irrelevant',
            'type': 'restriction mode',
            'source': 'irrelevant'
        }
    }

    scylla_config_vitals_true = {
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, scylla_config_tri_state, Output(), '')
    }

    analyzer = analyzers.ScyllaConfigurationFileFormatAnalyzer({})

    allowed_values = ['true', 'false', '0', '1', 'warn']

    # Let's build a list of all allowed YAML ways to set values in unquoted, quoted and double-quoted ways.
    allowed_config_values = []
    for value in allowed_values:
        allowed_config_values += [value, f"'{value}'", f'"{value}"']

    def error_message(bad_values: List[Tuple[str, str]]) -> str:
        msg = ", ".join([f"{field[0]} has an invalid value: [{field[1]}]" for field in bad_values])
        msg += f", while allowed values are {allowed_config_values}."
        return msg

    success_message = "Scylla Configuration is well-formed"

    check_analyzer(analyzer, "ScyllaConfigurationFileNoParsingCollector", [
        ({'tri_state0': 'True'}, AnalyzerResult(AnalyzerStatus.FAILED, error_message([('tri_state0', 'True')]))),
        ({'tri_state0': 'True', 'tri_state1': 'False'},
         AnalyzerResult(AnalyzerStatus.FAILED, error_message([('tri_state0', 'True'), ('tri_state1', 'False')]))),
    ], initial_vitals=scylla_config_vitals_true)

    good_tests = []
    for good_value in allowed_config_values:
        good_tests.append(({'tri_state0': good_value}, AnalyzerResult(AnalyzerStatus.PASSED, success_message)))

    check_analyzer(analyzer, "ScyllaConfigurationFileNoParsingCollector", good_tests,
                   initial_vitals=scylla_config_vitals_true)


def test_ScyllaConfigurationConsistencyAnalyzer_bool_normalization():
    """
    Refs https://github.com/scylladb/scylladb/issues/21355, https://scylladb.atlassian.net/browse/SCT-253

    Several keys have boolean sub-fields that system.config may report as int (0/1) or string
    ('0','1','true','false') while scylla.yaml has a Python bool.  Verify to_bool normalizes all forms.

    Keys with 'enabled' sub-field: client_encryption_options, system_info_encryption, user_info_encryption.
    Keys with aws_use_ec2_credentials / aws_use_ec2_region sub-fields: kms_hosts.
    """
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer({})
    success = "Scylla configuration is consistent"

    # --- client_encryption_options / system_info_encryption / user_info_encryption ---
    for key in ("client_encryption_options", "system_info_encryption", "user_info_encryption"):
        failure = f"keys: ['{key}']"
        for truthy in (1, '1', 'true'):
            vitals = {
                'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, {
                    key: {'value': {'enabled': truthy}, 'source': 'config', 'type': 'irrelevant'}
                }, Output(), '')
            }
            check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
                ({'pure_scylla_yaml': {key: {'enabled': True}}},
                 AnalyzerResult(AnalyzerStatus.PASSED, success)),
                ({'pure_scylla_yaml': {key: {'enabled': False}}},
                 AnalyzerResult(AnalyzerStatus.FAILED, failure)),
            ], initial_vitals=vitals)

        for falsy in (0, '0', 'false'):
            vitals = {
                'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, {
                    key: {'value': {'enabled': falsy}, 'source': 'config', 'type': 'irrelevant'}
                }, Output(), '')
            }
            check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
                ({'pure_scylla_yaml': {key: {'enabled': False}}},
                 AnalyzerResult(AnalyzerStatus.PASSED, success)),
                ({'pure_scylla_yaml': {key: {'enabled': True}}},
                 AnalyzerResult(AnalyzerStatus.FAILED, failure)),
            ], initial_vitals=vitals)

    # --- kms_hosts ---
    for sub_key in ("aws_use_ec2_credentials", "aws_use_ec2_region"):
        for truthy in (1, '1', 'true'):
            vitals = {
                'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, {
                    'kms_hosts': {'value': {sub_key: truthy}, 'source': 'config', 'type': 'irrelevant'}
                }, Output(), '')
            }
            check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
                ({'pure_scylla_yaml': {'kms_hosts': {sub_key: True}}},
                 AnalyzerResult(AnalyzerStatus.PASSED, success)),
                ({'pure_scylla_yaml': {'kms_hosts': {sub_key: False}}},
                 AnalyzerResult(AnalyzerStatus.FAILED, "keys: ['kms_hosts']")),
            ], initial_vitals=vitals)

        for falsy in (0, '0', 'false'):
            vitals = {
                'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, {
                    'kms_hosts': {'value': {sub_key: falsy}, 'source': 'config', 'type': 'irrelevant'}
                }, Output(), '')
            }
            check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
                ({'pure_scylla_yaml': {'kms_hosts': {sub_key: False}}},
                 AnalyzerResult(AnalyzerStatus.PASSED, success)),
                ({'pure_scylla_yaml': {'kms_hosts': {sub_key: True}}},
                 AnalyzerResult(AnalyzerStatus.FAILED, "keys: ['kms_hosts']")),
            ], initial_vitals=vitals)


def test_ScyllaConfigurationConsistencyAnalyzer_values_test():
    """
    Test the validation of configuration values
    """
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer({})

    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    good_values = [
        {'int_value': 1},
        {'bool_value': True},
        {'string_value': 'good value'},
        {'dict_value':
         {'k1': 'v1',
          'k2': {'k2': 'v2'},
          'k3': ['v4', 'v5']
          }},
        {'list_value': [1, 2, 3]},
    ]

    # In-memory state
    config_source_value = 'config'
    scylla_config_state: Dict[str, Dict[str, Any]] = {}
    for good_value in good_values:
        for key, value in good_value.items():
            scylla_config_state[key] = {
                'value': value,
            }

    # Add special values:
    scylla_config_state.update({'hinted_handoff_enabled': {'value': 'false'}})
    scylla_config_state.update({'max_memory_for_unlimited_query_hard_limit': {'value': 12345}})

    for k, v in scylla_config_state.items():
        scylla_config_state[k]['source'] = config_source_value
        scylla_config_state[k]['type'] = 'irrelevant'

    scylla_config_vitals = {
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, scylla_config_state, Output(), '')
    }

    good_values.append({'hinted_handoff_enabled': False})
    good_values.append({'max_memory_for_unlimited_query': 12345})

    bad_values = [
        {'int_value': 2},
        {'bool_value': False},
        {'string_value': 'bad value'},
        {'dict_value': {'k1': 'v1'}},
        {'list_value': [1]},
        {'hinted_handoff_enabled': True},
        {'max_memory_for_unlimited_query': 54321}
    ]

    def failure_message(divergent_keys: List) -> str:
        return f"Scylla configuration differs from the one present in scylla.yaml for keys: {divergent_keys}."

    # Let's generate a few random test cases with good and bad values.
    # The test sets will always include the same keys in scylla.yaml as in the in-memory
    samples_count = 30  # Number of test samples to generate
    test_cases = []
    for sample_id in range(samples_count):
        good_values_count = len(good_values)
        bad_values_count = random.randint(1, len(bad_values))
        good_batch = random.sample(good_values, good_values_count)
        bad_batch = random.sample(bad_values, bad_values_count)

        scylla_yaml_conf = {'pure_scylla_yaml': {}}
        scylla_yaml_conf_pure_yaml = scylla_yaml_conf['pure_scylla_yaml']
        divergent_keys = []
        for good_value in good_batch:
            scylla_yaml_conf_pure_yaml.update(good_value)

        for bad_value in bad_batch:
            scylla_yaml_conf_pure_yaml.update(bad_value)
            divergent_keys.extend(list(bad_value.keys()))

        # max_memory_for_unlimited_query is a shortcut for max_memory_for_unlimited_query_hard_limit
        if 'max_memory_for_unlimited_query' in divergent_keys:
            divergent_keys.remove('max_memory_for_unlimited_query')
            divergent_keys.append('max_memory_for_unlimited_query_hard_limit')

        message = failure_message(sorted(divergent_keys))

        test_cases.append((scylla_yaml_conf, AnalyzerResult(AnalyzerStatus.FAILED, message)))

    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", test_cases,
                   initial_vitals=scylla_config_vitals)

    # Good case ################################################
    good_batch = random.sample(good_values, len(good_values))
    scylla_yaml_conf = {'pure_scylla_yaml': {}}
    scylla_yaml_conf_pure_yaml = scylla_yaml_conf['pure_scylla_yaml']
    for good_value in good_batch:
        scylla_yaml_conf_pure_yaml.update(good_value)

    success_message = "Scylla configuration is consistent"
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf, AnalyzerResult(AnalyzerStatus.PASSED, success_message))
    ], initial_vitals=scylla_config_vitals)


def test_ScyllaConfigurationConsistencyAnalyzer_source_test():
    """
    Test validation of configuration sources
    """
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer({})

    config_values = [
        {'int_value': 1},
        {'bool_value': True},
        {'string_value': 'good value'},
        {'dict_value':
         {'k1': 'v1',
          'k2': {'k2': 'v2'},
          'k3': ['v4', 'v5']
          }},
        {'list_value': [1, 2, 3]},
    ]

    # In-memory state
    config_source_value = 'config'
    scylla_config_state: Dict[str, Dict[str, Any]] = {}
    for good_value in config_values:
        for key, value in good_value.items():
            scylla_config_state[key] = {
                'value': value
            }

    # Add special values:
    scylla_config_state.update({'hinted_handoff_enabled': {'value': 'false'}})
    scylla_config_state.update({'max_memory_for_unlimited_query_hard_limit': {'value': 12345}})

    for k, v in scylla_config_state.items():
        scylla_config_state[k]['source'] = random.choice(['default', 'internal'])
        scylla_config_state[k]['type'] = 'irrelevant'

    config_values.append({'hinted_handoff_enabled': False})
    config_values.append({'max_memory_for_unlimited_query': 12345})

    def failure_message(divergent_keys: List) -> str:
        return f"Keys with the inconsistent configuration source: {divergent_keys}"

    success_message = "Scylla configuration is consistent"

    # Let's generate a few random test cases with good and bad values. #################################################
    samples_count = 30  # Number of test samples to generate
    test_cases = []
    for sample_id in range(samples_count):
        yaml_values_count = random.randint(1, len(config_values))
        yaml_values_batch = random.sample(config_values, yaml_values_count)

        scylla_yaml_conf = {'pure_scylla_yaml': {}}
        scylla_yaml_conf_pure_yaml = scylla_yaml_conf['pure_scylla_yaml']
        current_scylla_config_state = copy.deepcopy(scylla_config_state)
        divergent_keys = []

        # Setup scylla.yaml representation and update the source of corresponding keys to be 'config'
        for value in yaml_values_batch:
            scylla_yaml_conf_pure_yaml.update(value)
            for k in value.keys():
                # max_memory_for_unlimited_query is a shortcut for max_memory_for_unlimited_query_hard_limit
                if k == 'max_memory_for_unlimited_query':
                    k = 'max_memory_for_unlimited_query_hard_limit'
                current_scylla_config_state[k]['source'] = config_source_value

        # Test a good configuration
        test_cases.append((copy.deepcopy(scylla_yaml_conf), copy.deepcopy(current_scylla_config_state), []))

        # Randomly generate bad configuration for keys that are not in scylla.yaml
        for non_scylla_yaml_key in list(filter(lambda k: k not in scylla_yaml_conf_pure_yaml,
                                               current_scylla_config_state.keys())):
            # max_memory_for_unlimited_query is a shortcut for max_memory_for_unlimited_query_hard_limit
            if (non_scylla_yaml_key == 'max_memory_for_unlimited_query_hard_limit' and
                    'max_memory_for_unlimited_query' in scylla_yaml_conf_pure_yaml):
                continue

            if random.choice([True, False]):
                divergent_keys.append(non_scylla_yaml_key)
                current_scylla_config_state[non_scylla_yaml_key]['source'] = 'some_source'

        # Randomly generate bad sources for keys that are in scylla.yaml
        for scylla_yaml_key in scylla_yaml_conf_pure_yaml:
            if random.choice([True, False]):
                # max_memory_for_unlimited_query is a shortcut for max_memory_for_unlimited_query_hard_limit
                if scylla_yaml_key == 'max_memory_for_unlimited_query':
                    scylla_yaml_key = 'max_memory_for_unlimited_query_hard_limit'
                divergent_keys.append(scylla_yaml_key)
                current_scylla_config_state[scylla_yaml_key]['source'] = 'some_source'

        test_cases.append((scylla_yaml_conf, current_scylla_config_state, divergent_keys))

    # Execute tests ####################################################################################################
    for current_scylla_yaml_conf, current_in_memory_conf, bad_keys in test_cases:
        scylla_config_vitals = {
            'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, current_in_memory_conf, Output(), '')
        }

        expected_result = AnalyzerStatus.PASSED
        message = success_message
        if bad_keys:
            expected_result = AnalyzerStatus.FAILED
            message = failure_message(sorted(bad_keys))

        check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
            (current_scylla_yaml_conf, AnalyzerResult(expected_result, message))
        ], initial_vitals=scylla_config_vitals)


def test_ScyllaConfigurationConsistencyAnalyzer_skip_source_validation_keys():
    """
    Test that skip_source_validation_keys config option allows suppressing source validation
    for specific keys, including comma-separated lists with surrounding whitespace.
    """
    scylla_config_state = {
        'key_in_yaml':      {'value': 'v', 'source': 'config',   'type': 'irrelevant'},
        'key_not_in_yaml':  {'value': 'v', 'source': 'bad_src',  'type': 'irrelevant'},
        'another_bad_key':  {'value': 'v', 'source': 'bad_src',  'type': 'irrelevant'},
    }
    scylla_config_vitals = {
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, scylla_config_state, Output(), '')
    }
    scylla_yaml_conf = {'pure_scylla_yaml': {'key_in_yaml': 'v'}}

    # Without skip_source_validation_keys both bad-source keys are flagged
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer({})
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf,
         AnalyzerResult(AnalyzerStatus.FAILED,
                        "Keys with the inconsistent configuration source: ['another_bad_key', 'key_not_in_yaml']"))
    ], initial_vitals=scylla_config_vitals)

    # With skip_source_validation_keys both keys are suppressed (whitespace around comma is stripped)
    # and the success message names the skipped keys.
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer(
        {'ScyllaConfigurationConsistencyAnalyzer': {
            'skip_source_validation_keys': 'key_not_in_yaml, another_bad_key'
        }}
    )
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf, AnalyzerResult(AnalyzerStatus.PASSED,
                                          "Scylla configuration is consistent"
                                          ". Keys excluded from a source check validation: "
                                          "['another_bad_key', 'key_not_in_yaml']"))
    ], initial_vitals=scylla_config_vitals)

    # Suppressing only one of the two bad keys still fails on the other;
    # the failure message also names the skipped key.
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer(
        {'ScyllaConfigurationConsistencyAnalyzer': {
            'skip_source_validation_keys': 'key_not_in_yaml'
        }}
    )
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf,
         AnalyzerResult(AnalyzerStatus.FAILED,
                        "Keys with the inconsistent configuration source: ['another_bad_key']"
                        ". Keys excluded from a source check validation: ['key_not_in_yaml']"))
    ], initial_vitals=scylla_config_vitals)

    # A key that IS present in scylla.yaml but has a bad source must also be
    # suppressible via skip_source_validation_keys.
    # Bug fix: the skip check was previously nested inside `if not key_in_scylla_yaml`,
    # so keys that exist in scylla.yaml were never skipped and were falsely flagged.
    # Ref https://scylladb.atlassian.net/browse/DOCTOR-57.
    scylla_config_state_yaml_bad_src = {
        'key_in_yaml_bad_src': {'value': 'v', 'source': 'bad_src', 'type': 'irrelevant'},
    }
    scylla_config_vitals_yaml_bad_src = {
        'SystemConfigCollector': CollectorResult(
            CollectorStatus.PASSED, scylla_config_state_yaml_bad_src, Output(), '')
    }
    scylla_yaml_conf_yaml_bad_src = {'pure_scylla_yaml': {'key_in_yaml_bad_src': 'v'}}

    # Without skipping: flagged because source != 'config' and key is in scylla.yaml
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer({})
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf_yaml_bad_src,
         AnalyzerResult(AnalyzerStatus.FAILED,
                        "Keys with the inconsistent configuration source: ['key_in_yaml_bad_src']"))
    ], initial_vitals=scylla_config_vitals_yaml_bad_src)

    # With skipping: the key is in scylla.yaml but must still be suppressed
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer(
        {'ScyllaConfigurationConsistencyAnalyzer': {
            'skip_source_validation_keys': 'key_in_yaml_bad_src'
        }}
    )
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf_yaml_bad_src,
         AnalyzerResult(AnalyzerStatus.PASSED,
                        "Scylla configuration is consistent"
                        ". Keys excluded from a source check validation: "
                        "['key_in_yaml_bad_src']"))
    ], initial_vitals=scylla_config_vitals_yaml_bad_src)


def test_ScyllaConfigurationConsistencyAnalyzer_skip_persisted_validation_keys():
    """
    Test that skip_persisted_validation_keys config option allows suppressing value consistency
    checks for specific keys, including comma-separated lists with surrounding whitespace.
    """
    scylla_config_state = {
        'key_match':     {'value': 'good',  'source': 'config', 'type': 'irrelevant'},
        'key_mismatch':  {'value': 'wrong', 'source': 'config', 'type': 'irrelevant'},
        'another_mismatch': {'value': 'wrong', 'source': 'config', 'type': 'irrelevant'},
    }
    scylla_config_vitals = {
        'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, scylla_config_state, Output(), '')
    }
    scylla_yaml_conf = {'pure_scylla_yaml': {
        'key_match': 'good',
        'key_mismatch': 'expected',
        'another_mismatch': 'expected',
    }}

    # Without skip_persisted_validation_keys both mismatched keys are flagged
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer({})
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf,
         AnalyzerResult(AnalyzerStatus.FAILED,
                        "Scylla configuration differs from the one present in scylla.yaml"
                        " for keys: ['another_mismatch', 'key_mismatch']."))
    ], initial_vitals=scylla_config_vitals)

    # With skip_persisted_validation_keys both keys are suppressed (whitespace around comma is stripped)
    # and the success message names the skipped keys.
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer(
        {'ScyllaConfigurationConsistencyAnalyzer': {
            'skip_persisted_validation_keys': 'key_mismatch, another_mismatch'
        }}
    )
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf, AnalyzerResult(AnalyzerStatus.PASSED,
                                          "Scylla configuration is consistent"
                                          ". Keys excluded from a validation against scylla.yaml: "
                                          "['another_mismatch', 'key_mismatch']"))
    ], initial_vitals=scylla_config_vitals)

    # Suppressing only one of the two mismatched keys still fails on the other;
    # the failure message also names the skipped key.
    analyzer = analyzers.ScyllaConfigurationConsistencyAnalyzer(
        {'ScyllaConfigurationConsistencyAnalyzer': {
            'skip_persisted_validation_keys': 'key_mismatch'
        }}
    )
    check_analyzer(analyzer, "ScyllaConfigurationFileCollector", [
        (scylla_yaml_conf,
         AnalyzerResult(AnalyzerStatus.FAILED,
                        "Scylla configuration differs from the one present in scylla.yaml"
                        " for keys: ['another_mismatch']."
                        ". Keys excluded from a validation against scylla.yaml: ['key_mismatch']"))
    ], initial_vitals=scylla_config_vitals)


def test_RaftEnablementAnalyzer_raft_enabled():
    """
    Tests RaftEnablementAnalyzer invocations when Raft is enabled
    """
    analyzer = analyzers.RaftEnablementAnalyzer({})

    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    raft_enabled_config = {
        'SystemConfigCollector':
            CollectorResult(CollectorStatus.PASSED, {'consistent_cluster_management': {'value': True}}, Output(), '')
    }

    raft_group0_id = "8958fdf0-8004-11ef-9bc5-d721f3ca4896"
    good_raft_upgrade_value = 'use_post_raft_procedures'
    bad_raft_upgrade_value = 'use_post_raft_procedures_and_something_else'
    disabled_group0_id = None

    check_analyzer(analyzer, "RaftGroup0Collector", [
        ({'group0_id': raft_group0_id, 'hosts': [],
          'group0_upgrade_state': good_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.PASSED,
                        f"Raft enabled: group0 ID: {raft_group0_id}")),
        ({'group0_id': disabled_group0_id, 'hosts': [],
          'group0_upgrade_state': good_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.FAILED,
                        f"Raft isn't properly enabled: group0 {disabled_group0_id}, "
                        f"upgrade_state {good_raft_upgrade_value}")),
        ({'group0_id': raft_group0_id, 'hosts': [],
          'group0_upgrade_state': bad_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.FAILED,
                        f"Raft isn't properly enabled: group0 {raft_group0_id}, "
                        f"upgrade_state {bad_raft_upgrade_value}")),
        ({'group0_id': disabled_group0_id, 'hosts': [],
          'group0_upgrade_state': bad_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.FAILED,
                        f"Raft isn't properly enabled: group0 {disabled_group0_id}, "
                        f"upgrade_state {bad_raft_upgrade_value}")),
    ], initial_vitals=raft_enabled_config)


def test_RaftEnablementAnalyzer_raft_disabled():
    """
    Tests RaftEnablementAnalyzer invocations when Raft is disabled
    """
    analyzer = analyzers.RaftEnablementAnalyzer({})

    raft_disabled_config = {
        'SystemConfigCollector':
            CollectorResult(CollectorStatus.PASSED, {'consistent_cluster_management': {'value': False}},
                            Output(), '')
    }

    raft_group0_id = "8958fdf0-8004-11ef-9bc5-d721f3ca4896"
    good_raft_upgrade_value = 'use_post_raft_procedures'
    bad_raft_upgrade_value = 'use_post_raft_procedures_and_something_else'
    disabled_group0_id = None

    check_analyzer(analyzer, "RaftGroup0Collector", [
        ({'group0_id': raft_group0_id, 'hosts': [],
          'group0_upgrade_state': good_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Raft is disabled")),
        ({'group0_id': disabled_group0_id, 'hosts': [],
          'group0_upgrade_state': good_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Raft is disabled")),
        ({'group0_id': raft_group0_id, 'hosts': [],
          'group0_upgrade_state': bad_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Raft is disabled")),
        ({'group0_id': disabled_group0_id, 'hosts': [],
          'group0_upgrade_state': bad_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Raft is disabled")),
    ], initial_vitals=raft_disabled_config)


def test_RaftEnablementAnalyzer_pre_raft():
    """
    Tests RaftEnablementAnalyzer invocations with Scylla that doesn't have Raft implemented
    """
    analyzer = analyzers.RaftEnablementAnalyzer({})

    raft_missing_config = {
        'SystemConfigCollector':
            CollectorResult(CollectorStatus.PASSED, {}, Output(), '')
    }

    raft_group0_id = "8958fdf0-8004-11ef-9bc5-d721f3ca4896"
    good_raft_upgrade_value = 'use_post_raft_procedures'
    bad_raft_upgrade_value = 'use_post_raft_procedures_and_something_else'
    disabled_group0_id = None

    check_analyzer(analyzer, "RaftGroup0Collector", [
        ({'group0_id': raft_group0_id, 'hosts': [],
          'group0_upgrade_state': good_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Raft is disabled")),
        ({'group0_id': disabled_group0_id, 'hosts': [],
          'group0_upgrade_state': good_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Raft is disabled")),
        ({'group0_id': raft_group0_id, 'hosts': [],
          'group0_upgrade_state': bad_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Raft is disabled")),
        ({'group0_id': disabled_group0_id, 'hosts': [],
          'group0_upgrade_state': bad_raft_upgrade_value},
         AnalyzerResult(AnalyzerStatus.SKIPPED, "Raft is disabled")),
    ], initial_vitals=raft_missing_config)


def test_RaftTopologyRPCStatusAnalyzer():
    analyzer = analyzers.RaftTopologyRPCStatusAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    ongoing_rpc_report = "SomeRPC[17]: 1.2.3.4,2.3.4.5"

    check_analyzer(analyzer, "RaftTopologyRPCStatusCollector", [
        ("none",
         AnalyzerResult(AnalyzerStatus.PASSED, "No ongoing Raft Topology RPCs.")),
        (ongoing_rpc_report,
         AnalyzerResult(AnalyzerStatus.FAILED, f"There is an ongoing Raft Topology RPC: {ongoing_rpc_report}.")),
    ])


def test_DisabledCompactionAnalyzer():
    analyzer = analyzers.DisabledCompactionAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")

    check_analyzer(analyzer, "ScyllaClusterTablesDescriptionCollector", [
        # All tables have compactions enabled
        (
            {"ks1": {"t1": {"compaction": "{'class': 'IncrementalCompactionStrategy', 'enabled': 'true'}"}}},
            AnalyzerResult(AnalyzerStatus.PASSED, "All tables have compactions enabled"),
        ),
        # Table using NullCompactionStrategy
        (
            {"ks1": {"t1": {"compaction": "{'class': 'NullCompactionStrategy'}"}}},
            AnalyzerResult(AnalyzerStatus.FAILED, "ks1:t1"),
        ),
        # Case-insensitive NullCompactionStrategy match
        (
            {"ks1": {"t1": {"compaction": "{'class': 'nullcompactionstrategy'}"}}},
            AnalyzerResult(AnalyzerStatus.FAILED, "ks1:t1"),
        ),
        # Table with compaction explicitly disabled
        (
            {"ks1": {"t1": {"compaction": "{'class': 'IncrementalCompactionStrategy', 'enabled': 'false'}"}}},
            AnalyzerResult(AnalyzerStatus.FAILED, "ks1:t1"),
        ),
        # Missing compaction field entirely (parses to empty dict)
        (
            {"ks1": {"t1": {}}},
            AnalyzerResult(AnalyzerStatus.FAILED, "ks1:t1"),
        ),
        # Compaction field present but empty (parses to empty dict)
        (
            {"ks1": {"t1": {"compaction": "{}"}}},
            AnalyzerResult(AnalyzerStatus.FAILED, "ks1:t1"),
        ),
        # Compaction class is an empty string
        (
            {"ks1": {"t1": {"compaction": "{'class': ''}"}}},
            AnalyzerResult(AnalyzerStatus.FAILED, "ks1:t1"),
        ),
    ])

    # Multiple tables failing across keyspaces: verify only offending tables are reported
    multi_ks_data = {
        "ks1": {"t1": {"compaction": "{'class': 'NullCompactionStrategy'}"}},
        "ks2": {"t2": {"compaction": "{'class': 'IncrementalCompactionStrategy', 'enabled': 'false'}"}},
        "ks3": {"t3": {"compaction": "{'class': 'SizeTieredCompactionStrategy', 'enabled': 'true'}"}},
    }
    vitals = {"ScyllaClusterTablesDescriptionCollector": CollectorResult(CollectorStatus.PASSED, multi_ks_data,
                                                                         Output(), '')}
    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "have compactions disabled")
    assert "ks1:t1" in analyzer.message
    assert "ks2:t2" in analyzer.message
    assert "ks3:t3" not in analyzer.message


def _make_disabled_compaction_analyzer_ignored_tables_string(ignored_tables_list: List[str] | None) -> str:
    if ignored_tables_list:
        return ",".join(ignored_tables_list)
    else:
        return ""


def _make_disabled_compaction_analyzer(ignored_tables_list: List[str] | None) -> analyzers.DisabledCompactionAnalyzer:
    return analyzers.DisabledCompactionAnalyzer(
        DictView({"DisabledCompactionAnalyzer": {
            "ignored_tables": _make_disabled_compaction_analyzer_ignored_tables_string(ignored_tables_list)}})
    )


def _make_disabled_compaction_analyzer_success_message(ignored_tables_list: List[str] | None = None) -> str:
    msg = "All tables have compactions enabled."
    if ignored_tables_list is None:
        ignored_tables_list = []

    # Ref https://scylladb.atlassian.net/browse/SCYLLADB-1372
    ignored_tables_list.append("system.hints")

    if ignored_tables_list:
        msg += f" Ignored tables: {', '.join(sorted(ignored_tables_list))}"
    return msg


def test_DisabledCompactionAnalyzer_ignored_table_null_strategy():
    """
    A table listed in ignored_tables that uses NullCompactionStrategy must be
    skipped entirely, so the analyzer should report PASSED even though compaction
    is effectively disabled for that table.
    """
    ignored_tables_list = ["ks1.t1"]
    check_analyzer(
        _make_disabled_compaction_analyzer(ignored_tables_list),
        "ScyllaClusterTablesDescriptionCollector",
        [(
            {"ks1": {"t1": {"compaction": "{'class': 'NullCompactionStrategy'}"}}},
            AnalyzerResult(AnalyzerStatus.PASSED,
                           _make_disabled_compaction_analyzer_success_message(ignored_tables_list)),
        )],
    )


def test_DisabledCompactionAnalyzer_ignored_table_disabled_enabled_flag():
    """
    A table listed in ignored_tables that has a valid compaction class but
    'enabled': 'false' must be skipped, so the analyzer should report PASSED.
    """
    ignored_tables_list = ["ks1.t1"]
    check_analyzer(
        _make_disabled_compaction_analyzer(ignored_tables_list),
        "ScyllaClusterTablesDescriptionCollector",
        [(
            {"ks1": {"t1": {"compaction": "{'class': 'IncrementalCompactionStrategy', 'enabled': 'false'}"}}},
            AnalyzerResult(AnalyzerStatus.PASSED,
                           _make_disabled_compaction_analyzer_success_message(ignored_tables_list)),
        )],
    )


def test_DisabledCompactionAnalyzer_ignored_table_does_not_suppress_other_failures():
    """
    When one table is in ignored_tables and another non-ignored table has compaction
    disabled, the analyzer must still report FAILED for the non-ignored table only.
    The ignored table must not appear in the failure message.
    """
    data = {
        "ks1": {"t1": {"compaction": "{'class': 'NullCompactionStrategy'}"}},
        "ks2": {"t2": {"compaction": "{'class': 'IncrementalCompactionStrategy', 'enabled': 'false'}"}},
    }
    ignored_tables_list = ["ks1.t1"]
    analyzer = _make_disabled_compaction_analyzer(ignored_tables_list)
    vitals = {"ScyllaClusterTablesDescriptionCollector": CollectorResult(CollectorStatus.PASSED, data, Output(), '')}
    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "have compactions disabled")
    assert "ks1:t1" not in analyzer.message
    assert "ks2:t2" in analyzer.message


def test_DisabledCompactionAnalyzer_multiple_ignored_tables():
    """
    A comma-separated ignored_tables list must cause all listed tables to be skipped.
    When all disabled-compaction tables are ignored, the analyzer should report PASSED.
    """
    data = {
        "ks1": {"t1": {"compaction": "{'class': 'NullCompactionStrategy'}"}},
        "ks2": {"t2": {"compaction": "{'class': 'IncrementalCompactionStrategy', 'enabled': 'false'}"}},
        "ks3": {"t3": {"compaction": "{'class': 'SizeTieredCompactionStrategy', 'enabled': 'true'}"}},
    }
    ignored_tables_list = ["ks1.t1", "ks2.t2"]
    analyzer = _make_disabled_compaction_analyzer(ignored_tables_list)
    vitals = {"ScyllaClusterTablesDescriptionCollector": CollectorResult(CollectorStatus.PASSED, data, Output(), '')}
    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED,
                           _make_disabled_compaction_analyzer_success_message(ignored_tables_list))


def test_DisabledCompactionAnalyzer_ignoring_healthy_table_does_not_suppress_failures():
    """
    Listing a table with compaction properly enabled in ignored_tables is harmless,
    but must not prevent the analyzer from detecting compaction issues in other tables
    that are not in the ignore list.
    """
    data = {
        "ks1": {"t1": {"compaction": "{'class': 'SizeTieredCompactionStrategy', 'enabled': 'true'}"}},
        "ks2": {"t2": {"compaction": "{'class': 'NullCompactionStrategy'}"}},
    }
    analyzer = _make_disabled_compaction_analyzer(["ks1.t1"])
    vitals = {"ScyllaClusterTablesDescriptionCollector": CollectorResult(CollectorStatus.PASSED, data, Output(), '')}
    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "ks2:t2")


def test_DisabledCompactionAnalyzer_system_hints_always_ignored():
    """
    'system.hints' is hardcoded as an always-ignored table (workaround for SCYLLADB-1372).
    Even without any ignored_tables config, a NullCompactionStrategy on system.hints
    must not trigger FAILED.
    """
    data = {"system": {"hints": {"compaction": "{'class': 'NullCompactionStrategy'}"}}}
    analyzer = analyzers.DisabledCompactionAnalyzer({})
    vitals = {"ScyllaClusterTablesDescriptionCollector": CollectorResult(CollectorStatus.PASSED, data, Output(), '')}
    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, _make_disabled_compaction_analyzer_success_message())


def test_DisabledCompactionAnalyzer_passed_message_always_includes_system_hints():
    """
    On PASSED, the message must always list 'system.hints' in the ignored tables
    section, since it is unconditionally added even without any user config.
    """
    data = {"ks1": {"t1": {"compaction": "{'class': 'SizeTieredCompactionStrategy', 'enabled': 'true'}"}}}
    analyzer = analyzers.DisabledCompactionAnalyzer({})
    vitals = {"ScyllaClusterTablesDescriptionCollector": CollectorResult(CollectorStatus.PASSED, data, Output(), '')}
    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, _make_disabled_compaction_analyzer_success_message())


def test_DisabledCompactionAnalyzer_passed_message_includes_user_and_builtin_ignored_tables():
    """
    On PASSED, when the user configures additional ignored_tables, the message must
    list both the user-supplied table and the hardcoded 'system.hints'.
    """
    data = {
        "ks1": {"t1": {"compaction": "{'class': 'NullCompactionStrategy'}"}},
        "ks2": {"t2": {"compaction": "{'class': 'SizeTieredCompactionStrategy', 'enabled': 'true'}"}},
    }
    ignored_tables_list = ["ks1.t1"]
    analyzer = _make_disabled_compaction_analyzer(ignored_tables_list)
    vitals = {"ScyllaClusterTablesDescriptionCollector": CollectorResult(CollectorStatus.PASSED, data, Output(), '')}
    analyzer.analyze(vitals)
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED,
                           _make_disabled_compaction_analyzer_success_message(ignored_tables_list))


###############################################################################
# BrokenRolePermissionsAnalyzer ################################################
###############################################################################

def _make_role_permissions_vitals(rows):
    return {"RolePermissionsCollector": CollectorResult(CollectorStatus.PASSED, rows, Output(), '')}


def test_BrokenRolePermissionsAnalyzer_passes_when_all_permissions_non_null():
    """
    All rows with non-empty permissions must yield PASSED.
    """
    rows = [
        {'role': 'cassandra', 'resource': 'data/ks',  'permissions': 'SELECT'},
        {'role': 'admin',     'resource': 'data/ks2', 'permissions': 'ALTER'},
    ]
    analyzer = analyzers.BrokenRolePermissionsAnalyzer({})
    analyzer.analyze(_make_role_permissions_vitals(rows))
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, "No null permissions")


def test_BrokenRolePermissionsAnalyzer_passes_when_table_empty():
    """
    An empty table (no rows) must yield PASSED — nothing is broken.
    """
    analyzer = analyzers.BrokenRolePermissionsAnalyzer({})
    analyzer.analyze(_make_role_permissions_vitals([]))
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, "No null permissions")


def test_BrokenRolePermissionsAnalyzer_fails_on_null_permissions():
    """
    A row whose 'permissions' value is an empty string (null in CQL) must trigger FAILED.
    """
    rows = [
        {'role': 'broken_role', 'resource': 'data/ks', 'permissions': ''},
    ]
    analyzer = analyzers.BrokenRolePermissionsAnalyzer({})
    analyzer.analyze(_make_role_permissions_vitals(rows))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "broken_role")


def test_BrokenRolePermissionsAnalyzer_fails_on_missing_permissions_key():
    """
    A row that is missing the 'permissions' key entirely is treated as null.
    """
    rows = [
        {'role': 'broken_role', 'resource': 'data/ks'},
    ]
    analyzer = analyzers.BrokenRolePermissionsAnalyzer({})
    analyzer.analyze(_make_role_permissions_vitals(rows))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "broken_role")


def test_BrokenRolePermissionsAnalyzer_reports_all_broken_roles():
    """
    All broken roles are included in the failure message.
    """
    rows = [
        {'role': 'role_a', 'resource': 'data/ks',  'permissions': ''},
        {'role': 'role_b', 'resource': 'data/ks2', 'permissions': 'SELECT'},
        {'role': 'role_c', 'resource': 'data/ks3', 'permissions': ''},
    ]
    analyzer = analyzers.BrokenRolePermissionsAnalyzer({})
    analyzer.analyze(_make_role_permissions_vitals(rows))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "role_a")
    assert "role_c" in analyzer.message
    assert "role_b" not in analyzer.message


def _make_stcs_vitals(schema: dict) -> dict:
    return {"ScyllaClusterTablesDescriptionCollector": CollectorResult(CollectorStatus.PASSED, schema, Output(), '')}


def _stcs_error_message(tables: List[str]) -> str:
    return "Tables that use STCS: " + ", ".join(tables)


def _stcs_success_message() -> str:
    return "There are no tables that use STCS."


def test_STCSInSchemaAnalyzer_no_collector():
    """
    Missing collector data results in FAILED.
    """
    analyzer = analyzers.STCSInSchemaAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")


def test_STCSInSchemaAnalyzer_no_stcs():
    """
    Tables using non-STCS strategies pass.
    """
    analyzer = analyzers.STCSInSchemaAnalyzer({})
    schema = {
        "ks1": {"t1": {"compaction": "{'class': 'IncrementalCompactionStrategy'}"}},
        "ks2": {"t2": {"compaction": "{'class': 'LeveledCompactionStrategy'}"}},
    }
    analyzer.analyze(_make_stcs_vitals(schema))
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, _stcs_success_message())


def test_STCSInSchemaAnalyzer_stcs_detected():
    """
    A single table using STCS results in FAILED listing that table.
    """
    analyzer = analyzers.STCSInSchemaAnalyzer({})
    schema = {
        "ks1": {"t1": {"compaction": "{'class': 'SizeTieredCompactionStrategy'}"}},
    }
    analyzer.analyze(_make_stcs_vitals(schema))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, _stcs_error_message(["ks1.t1"]))


def test_STCSInSchemaAnalyzer_mixed_tables():
    """
    Only STCS tables are reported; non-STCS tables in the same keyspace are ignored.
    """
    analyzer = analyzers.STCSInSchemaAnalyzer({})
    schema = {
        "ks1": {"t1": {"compaction": "{'class': 'SizeTieredCompactionStrategy'}"},
                "t2": {"compaction": "{'class': 'LeveledCompactionStrategy'}"}},
        "ks2": {"t3": {"compaction": "{'class': 'SizeTieredCompactionStrategy'}"}},
    }
    analyzer.analyze(_make_stcs_vitals(schema))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, _stcs_error_message(["ks1.t1", "ks2.t3"]))


def test_STCSInSchemaAnalyzer_system_tables_included():
    """
    System keyspace tables using STCS are also reported.
    """
    analyzer = analyzers.STCSInSchemaAnalyzer({})
    schema = {
        "system": {"local": {"compaction": "{'class': 'SizeTieredCompactionStrategy'}"}},
    }
    analyzer.analyze(_make_stcs_vitals(schema))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, _stcs_error_message(["system.local"]))


def test_STCSInSchemaAnalyzer_empty_schema():
    """
    Empty schema (no tables at all) passes.
    """
    analyzer = analyzers.STCSInSchemaAnalyzer({})
    analyzer.analyze(_make_stcs_vitals({}))
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, _stcs_success_message())


def _make_ks_replication_vitals(schema: dict) -> dict:
    return {"ScyllaClusterSystemKeyspacesCollector": CollectorResult(CollectorStatus.PASSED, schema, Output(), '')}


def _ks_replication_error_message(ks: str, actual: str, expected: str) -> str:
    return f"'{ks}' is using '{actual}', expected '{expected}'"


def _ks_replication_success_message() -> str:
    return "All keyspaces are ok"


def test_ScyllaKeyspacesReplicationAnalyzer_no_collector():
    """
    Missing collector data results in FAILED.
    """
    analyzer = analyzers.ScyllaKeyspacesReplicationAnalyzer({})
    analyzer.analyze({})
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED, "results not found")


def test_ScyllaKeyspacesReplicationAnalyzer_empty_schema():
    """
    Empty schema (no keyspaces) passes.
    """
    analyzer = analyzers.ScyllaKeyspacesReplicationAnalyzer({})
    analyzer.analyze(_make_ks_replication_vitals({}))
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, _ks_replication_success_message())


def test_ScyllaKeyspacesReplicationAnalyzer_all_ok():
    """
    Known system keyspaces with their expected strategies and a user keyspace with
    NetworkTopologyStrategy all pass.
    """
    analyzer = analyzers.ScyllaKeyspacesReplicationAnalyzer({})
    schema = {
        "system": {"replication": "{'class': 'org.apache.cassandra.locator.LocalStrategy'}"},
        "system_schema": {"replication": "{'class': 'org.apache.cassandra.locator.LocalStrategy'}"},
        "system_replicated_keys": {"replication": "{'class': 'org.apache.cassandra.locator.EverywhereStrategy'}"},
        "system_distributed_everywhere": {"replication": "{'class': 'org.apache.cassandra.locator.EverywhereStrategy'}"},  # noqa: E501
        "my_ks": {"replication": "{'class': 'org.apache.cassandra.locator.NetworkTopologyStrategy', 'dc1': '3'}"},
    }
    analyzer.analyze(_make_ks_replication_vitals(schema))
    assert_analyzer_result(analyzer, AnalyzerStatus.PASSED, _ks_replication_success_message())


def test_ScyllaKeyspacesReplicationAnalyzer_user_ks_wrong_strategy():
    """
    A user keyspace using SimpleStrategy instead of NetworkTopologyStrategy results in FAILED.
    """
    analyzer = analyzers.ScyllaKeyspacesReplicationAnalyzer({})
    schema = {
        "my_ks": {"replication": "{'class': 'org.apache.cassandra.locator.SimpleStrategy', 'replication_factor': '1'}"},
    }
    analyzer.analyze(_make_ks_replication_vitals(schema))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           _ks_replication_error_message(  # noqa: E501
                               "my_ks", "org.apache.cassandra.locator.SimpleStrategy", "NetworkTopologyStrategy"))


def test_ScyllaKeyspacesReplicationAnalyzer_system_ks_wrong_strategy():
    """
    A system keyspace using the wrong strategy (NetworkTopologyStrategy instead of LocalStrategy)
    results in FAILED.
    """
    analyzer = analyzers.ScyllaKeyspacesReplicationAnalyzer({})
    schema = {
        "system": {"replication": "{'class': 'org.apache.cassandra.locator.NetworkTopologyStrategy'}"},
    }
    analyzer.analyze(_make_ks_replication_vitals(schema))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           _ks_replication_error_message(  # noqa: E501
                               "system", "org.apache.cassandra.locator.NetworkTopologyStrategy", "LocalStrategy"))


def test_ScyllaKeyspacesReplicationAnalyzer_missing_replication_field():
    """
    A keyspace with no replication field defaults to empty class and results in FAILED.
    """
    analyzer = analyzers.ScyllaKeyspacesReplicationAnalyzer({})
    schema = {
        "my_ks": {},
    }
    analyzer.analyze(_make_ks_replication_vitals(schema))
    assert_analyzer_result(analyzer, AnalyzerStatus.FAILED,
                           _ks_replication_error_message("my_ks", "", "NetworkTopologyStrategy"))
