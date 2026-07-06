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

import copy
import json
import pytest
import random

from models.output_entry import OutputEntryType
from utils import Executor
from unittest.mock import patch
from collectors_base import UnableToReadScyllaRestApi, UnsupportedRestApiEndpoint, CollectorStatus, CollectorResult
from tests.helpers import DummyBaseCollector, DummyCollector, DummyFailedCollector, \
    DummyDependsOnFailedCollector, DummyCycle1Collector, DummyCycle2Collector, DummyRaisesCollector, \
    DummySkippedCollector, DummyDependsOnSkippedCollector, assert_output_gathered, DummyScyllaRestAPIAwareCollector


def test_dependencies(doctor_factory):
    doctor = doctor_factory(collectors=[DummyCollector], analyzers={})

    with pytest.raises(Exception) as e:
        doctor.run()
    assert "Dependencies are not available for" in str(e)

    doctor = doctor_factory(collectors=[DummyCollector, DummyBaseCollector], analyzers={})
    doctor.run()

    assert doctor.collectors['DummyBaseCollector'].launched_ts < doctor.collectors['DummyCollector'].launched_ts, \
        "DummyBaseCollector should have bee collected first"

    doctor = doctor_factory(collectors=[DummyCycle1Collector, DummyCycle2Collector], analyzers={})
    with pytest.raises(RecursionError) as e:
        doctor.run()
    assert "Endless dependency cycle detected for DummyCycle1Collector" in str(e)

    doctor = doctor_factory(collectors=[DummyFailedCollector, DummyDependsOnFailedCollector], analyzers={})
    doctor.run()
    assert doctor.vitals['DummyDependsOnFailedCollector'].status == CollectorStatus.FAILED

    # A Collector that depends on a SKIPPED Collector should be SKIPPED too, even if another dependency FAILED
    doctor = doctor_factory(collectors=[DummySkippedCollector, DummyFailedCollector, DummyDependsOnSkippedCollector],
                            analyzers={})
    doctor.run()
    assert doctor.vitals['DummyDependsOnSkippedCollector'].status == CollectorStatus.SKIPPED

    # Verify that DummyDependsOnSkippedCollector has the information about both failed and skipped dependencies
    assert (f"Required {DummyFailedCollector.name} Collector has not run successfully" in
            doctor.vitals['DummyDependsOnSkippedCollector'].message)
    assert (f"Required {DummySkippedCollector.name} Collector was skipped" in
            doctor.vitals['DummyDependsOnSkippedCollector'].message)


def test_config_skip(doctor_factory):
    # all collectors and no analyzers
    doctor = doctor_factory(collectors=[], analyzers=None)
    disable_all_config = [(collector.id, "run", random.choice(["False", "no", "0", "off"]))
                          for collector in doctor.collectors.values()]
    doctor = doctor_factory(collectors=[], analyzers=None, config_options=disable_all_config)
    doctor.run()
    for collector in doctor.collectors.values():
        assert collector.status == CollectorStatus.SKIPPED


def test_collector_raises(doctor_factory):
    """
    Check that raising Collector does not break overall launch.
    """
    doctor = doctor_factory(collectors=[DummyRaisesCollector], analyzers={})
    doctor.run()
    assert doctor.vitals['DummyRaisesCollector'].status == CollectorStatus.FAILED
    assert "horrible" in doctor.vitals['DummyRaisesCollector'].message


def test_executor_parse_config_file_yaml():
    """
    Test loading a YAML file. Make sure the result dictionary is sorted.
    """
    with open('/tmp/perftune.yaml', 'w') as f:
        f.writelines(["tune:\n", "- system\n", "- net\n"])
        f.writelines(["dirs:\n", "- /dir/2\n", "- /dir/1\n"])
        f.writelines(["tune_clock: True\n"])

    # Test deep sort
    file_content = Executor.parse_config_file_to_dict('/tmp/perftune.yaml', 'yaml')
    assert (file_content and 'tune' in file_content and file_content['tune'] == ['net', 'system'])
    assert ('dirs' in file_content and file_content['dirs'] == ['/dir/1', '/dir/2'])
    assert ('tune_clock' in file_content and file_content['tune_clock'] is True)
    assert (list(file_content) == ['dirs', 'tune', 'tune_clock'])

    # Test raw parsing with deep sort
    file_content = Executor.parse_config_file_to_dict('/tmp/perftune.yaml', 'yaml', no_yaml_values_parsing=True)
    assert (file_content and 'tune' in file_content and file_content['tune'] == ['net', 'system'])
    assert ('dirs' in file_content and file_content['dirs'] == ['/dir/1', '/dir/2'])
    assert ('tune_clock' in file_content and file_content['tune_clock'] == 'True')
    assert (list(file_content) == ['dirs', 'tune', 'tune_clock'])

    # Test shallow sort
    file_content = Executor.parse_config_file_to_dict('/tmp/perftune.yaml', 'yaml', deep_sort=False)
    assert (file_content and 'tune' in file_content and file_content['tune'] == ['system', 'net'])
    assert ('dirs' in file_content and file_content['dirs'] == ['/dir/2', '/dir/1'])
    assert ('tune_clock' in file_content and file_content['tune_clock'] is True)
    assert (list(file_content) == ['dirs', 'tune', 'tune_clock'])

    # Test non-existing file parsing
    file_content = Executor.parse_config_file_to_dict('/tmp/perftune_no_such_file.yaml', 'yaml')
    assert file_content is None

    # Test invalid format file parsing
    with open('/tmp/invalid_format.yaml', 'w') as f:
        f.writelines(["{tune: {system : net}\n"])

    file_content = Executor.parse_config_file_to_dict('/tmp/invalid_format.yaml', 'yaml')
    assert file_content is None


def test_executor_parse_config_file_json():
    """
    Test loading a JSON file. Make sure the result dictionary is sorted.
    """
    with open('/tmp/perftune.json', 'w') as f:
        json.dump({'tune': {'status2': '1', 'status1': '2'}, 'dirs': {'key2': '2', 'key1': '1'}}, f)

    # Test deep sort
    file_content = Executor.parse_config_file_to_dict('/tmp/perftune.json', 'json')
    assert (file_content and 'tune' in file_content and list(file_content['tune']) == ['status1', 'status2'])
    assert ('dirs' in file_content and list(file_content['dirs']) == ['key1', 'key2'])
    assert (list(file_content) == ['dirs', 'tune'])

    # Test shallow sort
    file_content = Executor.parse_config_file_to_dict('/tmp/perftune.json', 'json', deep_sort=False)
    assert (file_content and 'tune' in file_content and list(file_content['tune']) == ['status2', 'status1'])
    assert ('dirs' in file_content and list(file_content['dirs']) == ['key2', 'key1'])
    assert (list(file_content) == ['dirs', 'tune'])

    # Test non-existing file parsing
    file_content = Executor.parse_config_file_to_dict('/tmp/perftune_no_such_file.json', 'json')
    assert file_content is None

    # Test invalid format file parsing
    with open('/tmp/invalid_format.json', 'w') as f:
        f.writelines(["{tune: {system : net}\n"])

    file_content = Executor.parse_config_file_to_dict('/tmp/invalid_format.json', 'json')
    assert file_content is None


def test_executor_parse_config_file_ini():
    """
    Test loading an INI file. Make sure the result dictionary is sorted.
    """
    with open('/tmp/conf.ini', 'w') as f:
        f.writelines(["val2=1\n"])
        f.writelines(["val1=2"])

    # Test deep sort
    file_content = Executor.parse_config_file_to_dict('/tmp/conf.ini')
    assert (file_content and list(file_content) == ['val1', 'val2'])

    # Test shallow sort
    file_content = Executor.parse_config_file_to_dict('/tmp/conf.ini', deep_sort=False)
    assert (file_content and list(file_content) == ['val1', 'val2'])

    # Test non-existing file parsing
    file_content = Executor.parse_config_file_to_dict('/tmp/no_such_file.ini')
    assert file_content is None

    # Test invalid format file parsing
    with open('/tmp/invalid_format.ini', 'w') as f:
        f.writelines(["key ~ val\n"])

    file_content = Executor.parse_config_file_to_dict('/tmp/invalid_format.ini')
    assert file_content is None


def test_do_filter_nested_key():
    d = {
        "k0": {"k2": "6",
               "k3": {"k2": "3",
                      "k3": "4"}
               },
        "k1": {"k2": {"k2": "3",
                      "k4": "4"},
               "k3": {"k2": "3",
                      "k3": "4"}
               },
        "k3": {},
        "k2": "4",
    }

    test_d = copy.deepcopy(d)
    CollectorResult.do_filter_nested_key(test_d, ("*"))
    assert test_d == {}

    test_d = copy.deepcopy(d)
    CollectorResult.do_filter_nested_key(test_d, ("*", "*"))
    assert test_d == {
        'k0': {},
        'k1': {},
        'k3': {},
        'k2': '4'
    }

    test_d = copy.deepcopy(d)
    CollectorResult.do_filter_nested_key(test_d, ("*", "*", "*"))
    assert test_d == {
        'k0': {'k2': '6',
               'k3': {}
               },
        'k1': {'k2': {},
               'k3': {}
               },
        'k3': {},
        'k2': '4'
    }

    test_d = copy.deepcopy(d)
    CollectorResult.do_filter_nested_key(test_d, ("k1", "*", "k3"))
    assert test_d == {
        'k0': {'k2': '6',
               'k3': {'k2': '3',
                      'k3': '4'}
               },
        'k1': {'k2': {'k2': '3',
                      'k4': '4'},
               'k3': {'k2': '3'}
               },
        'k3': {},
        'k2': '4'
    }


class TestScyllaRestApiReading:
    swagger_response = """
    {
        "apiVersion": "0.0.1",
        "swaggerVersion": "1.2",
        "apis": [
            {
                "path": "/system"
            },
            {
                "path": "/shmistem"
            },
            {
                "path": "/system/my_endpoint"
            }
        ]
    }
    """

    @patch('utils.Executor.get_url_content')
    def test_read_scylla_rest_api_supported(self, mock_get_url_content):
        """
        Test reading a supported Scylla REST API
        """
        mock_get_url_content.return_value = self.swagger_response
        test_collector = DummyScyllaRestAPIAwareCollector({}, {})
        api_address = "127.0.0.1"
        api_port = 10000
        rest_output = test_collector._read_scylla_rest_api("/system/my_endpoint", api_address, api_port)
        assert rest_output == json.loads(self.swagger_response)
        test_collector.collect({}, {})
        # Verify that the API endpoint output is gathered in the collector output
        assert_output_gathered(test_collector.result, OutputEntryType.API,
                               name=f"http://{api_address}:{api_port}/system/my_endpoint")

    @patch('utils.Executor.get_url_content')
    def test_read_scylla_rest_api_unsupported(self, mock_get_url_content):
        """
        Test reading an unsupported Scylla REST API
        """
        mock_get_url_content.return_value = self.swagger_response
        # Unsupported endpoint base
        test_collector = DummyScyllaRestAPIAwareCollector({}, {})
        with pytest.raises(UnsupportedRestApiEndpoint) as exc_info:
            test_collector._read_scylla_rest_api("/pystem/my_endpoint", "127.0.0.1", 10000)
        assert str(exc_info.value) == "Unsupported REST API endpoint base: /pystem"
        assert test_collector.status == CollectorStatus.SKIPPED

        # Base is supported but the whole endpoint is not supported
        test_collector = DummyScyllaRestAPIAwareCollector({}, {})
        with pytest.raises(UnsupportedRestApiEndpoint) as exc_info:
            test_collector._read_scylla_rest_api("/system/not_my_endpoint", "127.0.0.1", 10000)
        assert str(exc_info.value) == "Unsupported REST API endpoint: /system/not_my_endpoint"
        assert test_collector.status == CollectorStatus.SKIPPED

    @patch('utils.Executor.get_url_content')
    def test_read_scylla_rest_api_url_unresponsive(self, mock_get_url_content):
        """
        Test reading a Scylla REST API when REST API is unresponsive
        """
        mock_get_url_content.return_value = None
        api_address = "127.0.0.1"
        api_port = 10000
        test_collector = DummyScyllaRestAPIAwareCollector({}, {})
        with pytest.raises(UnableToReadScyllaRestApi) as exc_info:
            test_collector._read_scylla_rest_api("/pystem/my_endpoint", api_address, api_port)
        assert str(exc_info.value) == f"Unable to read Scylla REST API: http://{api_address}:{api_port}/api-doc/"
        assert test_collector.status == CollectorStatus.FAILED

    @patch('utils.Executor.get_url_content')
    def test_read_scylla_rest_api_bad_formats(self, mock_get_url_content):
        """
        Test reading a supported Scylla REST API
        """
        bad_swagger_response = """
        {
            "apiVersion": "0.0.1",
            "swaggerVersion": "1.2",
            "shmipis": [
                {
                    "path": "/system"
                },
                {
                    "path": "/shmistem"
                },
                {
                    "path": "/system/my_endpoint"
                }
            ]
        }
        """
        mock_get_url_content.return_value = bad_swagger_response
        api_address = "127.0.0.1"
        api_port = 10000
        test_collector = DummyScyllaRestAPIAwareCollector({}, {})

        # Bad swagger response format - 'apis' field is missing
        with pytest.raises(ValueError) as exc_info:
            test_collector._read_scylla_rest_api("/system/my_endpoint", api_address, api_port)
        assert str(exc_info.value) == (f"Unexpected output format of http://{api_address}:{api_port}/api-doc/ endpoint:"
                                       f" 'apis' field is missing")
        assert test_collector.status == CollectorStatus.FAILED

        # Bad endpoint formats:
        # No leading slash
        test_collector = DummyScyllaRestAPIAwareCollector({}, {})
        with pytest.raises(ValueError) as exc_info:
            test_collector._read_scylla_rest_api("system/my_endpoint", api_address, api_port)
        assert str(exc_info.value) == ("Invalid endpoint: system/my_endpoint. Endpoint must be an absolute path "
                                       "starting with '/'")
        assert test_collector.status == CollectorStatus.FAILED

        # Empty endpoint
        test_collector = DummyScyllaRestAPIAwareCollector({}, {})
        with pytest.raises(ValueError) as exc_info:
            test_collector._read_scylla_rest_api("/", api_address, api_port)
        assert str(exc_info.value) == "Invalid endpoint: /"
        assert test_collector.status == CollectorStatus.FAILED
