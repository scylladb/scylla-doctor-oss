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
import tests.helpers
import numbers
import os
import re
import socket
from typing import Tuple, List, Dict
from unittest.mock import patch, Mock

import pytest
import shutil
import subprocess

import collectors
from collectors_base import Collector, CollectorStatus, CollectorResult, Output
from common import GossipInfoInvariantValues
from models.output_entry import OutputEntryType
from utils import Executor
import scylla_doctor

from tests.helpers import assert_output_gathered, assert_output_not_gathered


def is_podman_container():
    """
    Checks if the runtime environment is a Podman container.
    Certain tests can be excluded on the basis of this.
    """
    if os.path.isfile("/run/.containerenv"):
        with open("/run/.containerenv") as f:
            for line in f:
                if line.startswith("engine="):
                    return "podman" in line
    return os.getenv("container") == "podman"


def is_docker_container():
    """
    Checks if the runtime environment is a Docker container.
    Certain tests can be excluded on the basis of this.
    """
    return os.path.isfile("/run/.dockerenv") or os.path.isfile("/.dockerenv")


def is_container():
    """
    Checks if the runtime environment is a general container.
    Certain tests can be excluded on the basis of this.
    """
    return (is_podman_container() or is_docker_container() or os.getenv("container") == "oci"
            or os.path.isfile("/run/.containerenv"))


def monkeypatch_path(path, dir, collector_classes, monkeypatch):
    def init(self, configuration, paths):
        Collector.__init__(self, configuration, paths)
        paths = copy.deepcopy(self._paths._DictView__source)
        paths['scylla_directory_configs'] = "/tmp"
        self._paths = paths

    for cls in collector_classes:
        monkeypatch.setattr(cls, '__init__', init, raising=False)


def test_CPUSpecificationsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.CPUSpecificationsCollector])
    doctor.run()

    result = doctor.vitals['CPUSpecificationsCollector']
    assert result.status == CollectorStatus.PASSED
    for key in ['flags', 'logical_cores']:
        assert key in result.data

    assert_output_gathered(result, OutputEntryType.STDOUT, "lscpu")
    assert_output_gathered(result, OutputEntryType.FILE, "/proc/cpuinfo")


@pytest.mark.skipif(os.getuid() > 0,
                    reason="requires root access")
@pytest.mark.skipif(not shutil.which("iptables"),
                    reason="requires iptables")
def test_FirewallRulesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.FirewallRulesCollector])
    doctor.run()

    result = doctor.vitals['FirewallRulesCollector']
    assert result.status == CollectorStatus.PASSED
    assert_output_gathered(result, OutputEntryType.STDOUT, "iptables -L -v")


def test_InfrastructureProviderCollector(doctor_factory, provider_identify_shorten_timeout_options):
    doctor = doctor_factory(collectors=[collectors.NICsCollector,
                                        collectors.InfrastructureProviderCollector],
                            config_options=provider_identify_shorten_timeout_options)
    doctor.run()
    result = doctor.vitals['InfrastructureProviderCollector']
    assert result.status == CollectorStatus.PASSED
    assert 'provider' in result.data
    if result.data['provider'] is not None:
        assert 'instance_type' in result.data
        assert len(result.data['instance_type'])
        assert 'cpu_platform' in result.data
        if result.data['provider'] == "GCP":
            assert len(result.data['cpu_platform'])
    # TODO: add more stubs to test most popular cloud providers


def test_MaintenanceEventsCollector(doctor_factory, provider_identify_shorten_timeout_options):
    doctor = doctor_factory(collectors=[collectors.MaintenanceEventsCollector],
                            config_options=provider_identify_shorten_timeout_options)
    doctor.run()
    result = doctor.vitals['MaintenanceEventsCollector']
    assert result.status == CollectorStatus.PASSED or result.status == CollectorStatus.SKIPPED
    assert result.status == CollectorStatus.SKIPPED or 'scheduled_maintenance_events' in result.data


def test_NodePlatformCollector(doctor_factory, monkeypatch):
    doctor = doctor_factory(collectors=[collectors.NodePlatformCollector])
    with pytest.raises(Exception) as e:
        doctor.run()
    assert "Dependencies are not available" in str(e)

    doctor = doctor_factory(collectors=[
        collectors.NodePlatformCollector,
        collectors.NICsCollector,
        collectors.InfrastructureProviderCollector,
        collectors.CPUSpecificationsCollector
    ])

    def freeze_vitals(self, name, value):
        if name == "vitals":
            return
        super().__setattr__(name, value)

    monkeypatch.setattr(scylla_doctor.Doctor, '__setattr__', freeze_vitals)

    infra_result = CollectorResult(CollectorStatus.PASSED, {'provider': None}, Output(), None)
    doctor.vitals['InfrastructureProviderCollector'] = infra_result

    cpu_result = CollectorResult(CollectorStatus.PASSED, {'flags': []}, Output(), None)
    doctor.vitals['CPUSpecificationsCollector'] = cpu_result

    monkeypatch.setattr(os.path, 'isfile', lambda x: True)
    doctor.run()
    result = doctor.vitals['NodePlatformCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data['platform'] == collectors.NodePlatform.CONTAINER
    del doctor.vitals['NodePlatformCollector']

    monkeypatch.setattr(os.path, 'isfile', lambda x: False)
    doctor.run()
    result = doctor.vitals['NodePlatformCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data['platform'] == collectors.NodePlatform.BAREMETAL
    del doctor.vitals['NodePlatformCollector']

    cpu_result.data['flags'] = ["hypervisor"]
    doctor.run()
    result = doctor.vitals['NodePlatformCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data['platform'] == collectors.NodePlatform.VM
    del doctor.vitals['NodePlatformCollector']

    infra_result = CollectorResult(CollectorStatus.PASSED,
                                   {'provider': "AWS"}, Output(), None)
    doctor.vitals['InfrastructureProviderCollector'] = infra_result
    doctor.run()
    result = doctor.vitals['NodePlatformCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data['platform'] == collectors.NodePlatform.CLOUD


def test_ServiceManagerCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ServiceManagerCollector])
    doctor.run()

    result = doctor.vitals['ServiceManagerCollector']
    assert result.status == CollectorStatus.PASSED
    assert isinstance(result.data['service_manager'], collectors.ServiceManager.Interface)


def test_ClockSourceCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ClockSourceCollector])
    doctor.run()

    result = doctor.vitals['ClockSourceCollector']
    assert result.status == CollectorStatus.PASSED
    assert 'clocksource' in result.data


def test_CPUScalingCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.CPUScalingCollector])
    doctor.run()

    result = doctor.vitals['CPUScalingCollector']
    assert result.status == CollectorStatus.PASSED
    assert 'scaling_governor' in result.data
    assert len(result.data['services']) > 0


def test_CoredumpCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.CoredumpCollector])

    doctor.run()

    result = doctor.vitals['CoredumpCollector']
    assert result.status == CollectorStatus.PASSED
    assert len(result.data['services']) > 0
    assert 'files' in result.data


def test_ClientConnectionCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.ClientConnectionCollector])

    doctor.run()

    result = doctor.vitals['ClientConnectionCollector']

    # Query successful test
    command = Executor.read_cql_table_command('system.clients')
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.CQL, command)

    # Query data stores per client IP its client connections
    client_connections = result.data

    for client_ip in client_connections:
        for client_connection in client_connections[client_ip]:
            assert client_connection['address'] == client_ip


def test_GossipInfoCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.GossipInfoCollector,
                                        collectors.SystemPeersLocalCollector])

    doctor.run()
    result = doctor.vitals['GossipInfoCollector']

    assert result.status == CollectorStatus.PASSED, result.message
    gossip_info = result.data['gossip_info']
    assert len(gossip_info) > 0
    assert any(addr == '127.0.0.1' for addr, _ in gossip_info)


def _make_gossip_entry(host_address: str, with_tokens: bool = True, supported_features: str = "ROLES") -> dict:
    """
    Build a gossipinfo application_state entry for the given host.

    :param host_address: Host broadcast address
    :param with_tokens: If True, include a TOKENS entry with unsorted values
    :param supported_features: Comma-separated string of supported features for SUPPORTED_FEATURES
    """
    states = [
        {"application_state": GossipInfoInvariantValues.STATUS,             "value": "NORMAL,0",         "version": 1},
        {"application_state": GossipInfoInvariantValues.SCHEMA,             "value": "abc-schema-id",    "version": 1},
        {"application_state": GossipInfoInvariantValues.DC,                 "value": "dc1",              "version": 1},
        {"application_state": GossipInfoInvariantValues.RACK,               "value": "rack1",            "version": 1},
        {"application_state": GossipInfoInvariantValues.RELEASE_VERSION,    "value": "5.0.0",            "version": 1},
        {"application_state": GossipInfoInvariantValues.NET_VERSION,        "value": "12",               "version": 1},
        {"application_state": GossipInfoInvariantValues.HOST_ID,            "value": "host-id-1",        "version": 1},
        {"application_state": GossipInfoInvariantValues.SUPPORTED_FEATURES, "value": supported_features, "version": 1},
        {"application_state": GossipInfoInvariantValues.SCHEMA_TABLES_VERSION, "value": "schema-tables-ver", "version": 1},  # noqa: E501
        {"application_state": GossipInfoInvariantValues.RPC_READY,          "value": "true",             "version": 1},
        {"application_state": GossipInfoInvariantValues.SHARD_COUNT,        "value": "4",                "version": 1},
        {"application_state": GossipInfoInvariantValues.IGNORE_MSB_BITS,    "value": "12",               "version": 1},
        {"application_state": GossipInfoInvariantValues.CDC_GENERATION_ID,  "value": "some-cdc-gen-id",  "version": 1},
        {"application_state": GossipInfoInvariantValues.SNITCH_NAME,        "value": "SimpleSnitch",     "version": 1},
    ]
    if with_tokens:
        # Use deliberately unsorted tokens to verify sorting behaviour
        states.append({"application_state": GossipInfoInvariantValues.TOKENS,
                       "value": "token_c;token_a;token_b", "version": 1})
    return {"addrs": host_address, "application_state": states}


def _make_gossip_info_collector(doctor_factory) -> collectors.GossipInfoCollector:
    """Instantiate a GossipInfoCollector without running it (no Scylla required)."""
    doctor = doctor_factory(collectors=[collectors.GossipInfoCollector], analyzers={})
    return doctor.collectors['GossipInfoCollector']


def test_GossipInfoCollectorParseEntry_TokensSorted(doctor_factory):
    """
    When TOKENS are present they must be sorted in the result so that
    gossipinfo from different nodes can be compared consistently.
    """
    collector = _make_gossip_info_collector(doctor_factory)
    entry = _make_gossip_entry("127.0.0.1", with_tokens=True, supported_features="ROLES")

    addr, result = collector._GossipInfoCollector__parse_one_gossipinfo_entry(entry)

    assert addr == "127.0.0.1"
    assert "TOKENS" in result
    assert result["TOKENS"] == sorted(["token_c", "token_a", "token_b"])


def test_GossipInfoCollectorParseEntry_TokensMissing(doctor_factory):
    """
    When TOKENS is absent from gossipinfo, parsing must succeed and TOKENS must not appear
    in the result. Missing application_state entries are silently skipped regardless of the
    Scylla version or supported features.
    """
    collector = _make_gossip_info_collector(doctor_factory)
    entry = _make_gossip_entry("127.0.0.1", with_tokens=False,
                               supported_features="ROLES,SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES")

    addr, result = collector._GossipInfoCollector__parse_one_gossipinfo_entry(entry)

    assert addr == "127.0.0.1"
    assert "TOKENS" not in result
    assert "SUPPORTED_FEATURES" in result


def test_GossipInfoCollector_DataSortedByAddress(doctor_factory, monkeypatch):
    """
    After _collect(), self._data['gossip_info'] must be sorted by the first tuple element
    (host address) regardless of the order returned by the REST API.
    """
    from unittest.mock import patch as _patch
    from collectors_base import CollectorResult, CollectorStatus, Output

    collector = _make_gossip_info_collector(doctor_factory)

    raw_entries = [
        _make_gossip_entry("10.0.0.3"),
        _make_gossip_entry("10.0.0.1"),
        _make_gossip_entry("10.0.0.2"),
    ]

    system_config_vitals = {
        'SystemConfigCollector': CollectorResult(
            CollectorStatus.PASSED,
            {
                'api_address': {'value': '127.0.0.1'},
                'api_port': {'value': '10000'},
            },
            Output(), '',
        ),
    }

    with _patch.object(collector, '_read_scylla_rest_api', return_value=raw_entries):
        collector._collect(system_config_vitals)

    assert collector.status == CollectorStatus.PASSED
    addresses = [addr for addr, _ in collector._data['gossip_info']]
    assert addresses == sorted(addresses)


def test_GossipInfoCollectorParseEntry_MissingAddrs(doctor_factory):
    """
    When 'addrs' key is absent from a gossipinfo entry, parsing must succeed and return
    None as the host address rather than raising an exception.
    """
    collector = _make_gossip_info_collector(doctor_factory)
    entry = _make_gossip_entry("127.0.0.1", with_tokens=False)
    del entry['addrs']

    addr, result = collector._GossipInfoCollector__parse_one_gossipinfo_entry(entry)

    assert addr is None
    assert isinstance(result, dict)


def test_TokenMetadataHostsMappingCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.TokenMetadataHostsMappingCollector])

    doctor.run()
    result = doctor.vitals['TokenMetadataHostsMappingCollector']

    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data['hosts']) > 0
    assert '127.0.0.1' in result.data['hosts']


def test_RaftGroup0Collector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.RaftGroup0Collector])

    doctor.run()

    result = doctor.vitals['RaftGroup0Collector']

    # Query successful test
    scylla_local_command = Executor.read_cql_table_command("system.scylla_local")
    raft_state_command = Executor.read_cql_table_command("system.raft_state")
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.CQL, scylla_local_command)
    assert_output_gathered(result, OutputEntryType.CQL, raft_state_command)

    # Let's check that all required values were collected
    assert len(result.data['group0_id']) > 0
    assert len(result.data['group0_upgrade_state']) > 0
    assert len(result.data['hosts']) > 0


def test_SystemPeersLocalCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemPeersLocalCollector])

    doctor.run()

    result = doctor.vitals['SystemPeersLocalCollector']

    # Query successful test
    system_peers_command = Executor.read_cql_table_command("system.peers")
    system_local_command = Executor.read_cql_table_command("system.local")
    assert result.status == CollectorStatus.PASSED, result.message
    # system.peers table is going to empty for a single-node cluster
    assert_output_gathered(result, OutputEntryType.CQL, system_peers_command, empty_value_allowed=True)
    assert_output_gathered(result, OutputEntryType.CQL, system_local_command)

    # Let's check that Group0 and host IDs were collected
    assert len(result.data['hosts']) > 0
    assert len(result.data['local']) > 0
    assert '127.0.0.1' in result.data['hosts']
    assert '127.0.0.1' == result.data['local']['listen_address']
    assert len(result.data['hosts']['127.0.0.1']) > 0


def test_SystemClusterStatusCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemClusterStatusCollector])

    doctor.run()

    result = doctor.vitals['SystemClusterStatusCollector']

    # Query successful test
    system_cluster_status_command = Executor.read_cql_table_command("system.cluster_status")
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.CQL, system_cluster_status_command)

    assert len(result.data['hosts']) > 0
    assert '127.0.0.1' in result.data['hosts']
    assert len(result.data['hosts']['127.0.0.1']) > 0


def test_SystemConfigCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector])

    doctor.run()

    # Check for successful completion
    result = doctor.vitals['SystemConfigCollector']
    system_config = result.data
    assert result.status == CollectorStatus.PASSED, result.message

    # Check if the query was successful
    system_config_command = Executor.read_cql_table_command("system.config")
    assert_output_gathered(result, OutputEntryType.CQL, system_config_command)

    # Check if basic config parameters are present
    assert len(system_config.keys()) > 0
    assert 'cluster_name' in system_config.keys()
    assert system_config['broadcast_rpc_address']['value'] == "127.0.0.1"


###############################################################################
# SystemConfigCollector unit tests (string_value_keys) ########################
###############################################################################

def _make_system_config_collector(doctor_factory, config_options=()):
    doctor = doctor_factory(collectors=[collectors.SystemConfigCollector], analyzers=(),
                            config_options=config_options)
    return doctor.collectors['SystemConfigCollector']


# Required keys the collector fills defaults for; supply non-empty values to bypass that branch.
_SYSTEM_CONFIG_REQUIRED_ROWS = [
    {'name': 'rpc_address',           'value': '"127.0.0.1"',              'source': 'default', 'type': 'string'},
    {'name': 'listen_address',        'value': '"127.0.0.1"',              'source': 'default', 'type': 'string'},
    {'name': 'api_address',           'value': '"127.0.0.1"',              'source': 'default', 'type': 'string'},
    {'name': 'api_port',              'value': '10000',                    'source': 'default', 'type': 'int'},
    {'name': 'broadcast_address',     'value': '"127.0.0.1"',              'source': 'default', 'type': 'string'},
    {'name': 'broadcast_rpc_address', 'value': '"127.0.0.1"',              'source': 'default', 'type': 'string'},
    {'name': 'workdir,W',             'value': '"/var/lib/scylla"',        'source': 'default', 'type': 'string'},
    {'name': 'data_file_directories', 'value': '["/var/lib/scylla/data"]', 'source': 'default', 'type': 'string'},
    {'name': 'commitlog_directory',   'value': '"/var/lib/scylla/commitlog"', 'source': 'default', 'type': 'string'},
    {'name': 'hints_directory',       'value': '"/var/lib/scylla/hints"',  'source': 'default', 'type': 'string'},
    {'name': 'view_hints_directory',  'value': '"/var/lib/scylla/view_hints"', 'source': 'default', 'type': 'string'},
]


def _make_system_config_vitals():
    """
    Build minimal dependency vitals for SystemConfigCollector.
    """
    config_data = {'host': 'localhost', 'port': 9042, 'username': None, 'password': None}
    return {
        'ScyllaConfigurationFileCollector': CollectorResult(
            CollectorStatus.PASSED, config_data, Output(), '',
        ),
        'CqlshCollector': CollectorResult(
            CollectorStatus.PASSED, {}, Output(), '',
        ),
        'SystemPeersLocalCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'local': {'listen_address': '127.0.0.1', 'rpc_address': '127.0.0.1'}},
            Output(), '',
        ),
    }


def test_SystemConfigCollector_json_values_parsed_by_default(doctor_factory):
    """
    Without string_value_keys config, all parameter values must be JSON-parsed.
    """
    rows = [
        {'name': 'cluster_name', 'value': '"test_cluster"', 'source': 'default', 'type': 'string'},
        {'name': 'num_tokens',   'value': '256',            'source': 'default', 'type': 'int'},
        *[dict(r) for r in _SYSTEM_CONFIG_REQUIRED_ROWS],
    ]

    collector = _make_system_config_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', return_value=('SELECT * FROM system.config', rows)):
        collector._collect(_make_system_config_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['cluster_name']['value'] == 'test_cluster'
    assert collector._data['num_tokens']['value'] == 256


def test_SystemConfigCollector_string_value_key_not_json_parsed(doctor_factory):
    """
    A key listed in string_value_keys must keep its raw string value
    instead of being JSON-decoded.
    """
    raw_value = 'not-valid-json'
    rows = [
        {'name': 'some_param', 'value': raw_value, 'source': 'default', 'type': 'string'},
        {'name': 'num_tokens', 'value': '256',     'source': 'default', 'type': 'int'},
        *[dict(r) for r in _SYSTEM_CONFIG_REQUIRED_ROWS],
    ]

    collector = _make_system_config_collector(
        doctor_factory,
        config_options=[('SystemConfigCollector', 'string_value_keys', 'some_param')],
    )
    with patch.object(Executor, 'read_cql_table', return_value=('SELECT * FROM system.config', rows)):
        collector._collect(_make_system_config_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['some_param']['value'] == raw_value
    assert collector._data['num_tokens']['value'] == 256


def test_SystemConfigCollector_multiple_string_value_keys(doctor_factory):
    """
    All keys in the comma-separated string_value_keys list must skip JSON parsing
    and retain their raw string values.
    """
    rows = [
        {'name': 'param_a',    'value': 'raw-a', 'source': 'default', 'type': 'string'},
        {'name': 'param_b',    'value': 'raw-b', 'source': 'default', 'type': 'string'},
        {'name': 'num_tokens', 'value': '256',   'source': 'default', 'type': 'int'},
        *[dict(r) for r in _SYSTEM_CONFIG_REQUIRED_ROWS],
    ]

    collector = _make_system_config_collector(
        doctor_factory,
        config_options=[('SystemConfigCollector', 'string_value_keys', 'param_a,param_b')],
    )
    with patch.object(Executor, 'read_cql_table', return_value=('SELECT * FROM system.config', rows)):
        collector._collect(_make_system_config_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['param_a']['value'] == 'raw-a'
    assert collector._data['param_b']['value'] == 'raw-b'
    assert collector._data['num_tokens']['value'] == 256


def test_SystemConfigCollector_unlisted_param_still_json_parsed(doctor_factory):
    """
    Keys not listed in string_value_keys must still be JSON-decoded,
    even when other keys in the same response are exempted.
    """
    rows = [
        {'name': 'json_param', 'value': '"hello"', 'source': 'default', 'type': 'string'},
        {'name': 'str_param',  'value': 'raw',     'source': 'default', 'type': 'string'},
        *[dict(r) for r in _SYSTEM_CONFIG_REQUIRED_ROWS],
    ]

    collector = _make_system_config_collector(
        doctor_factory,
        config_options=[('SystemConfigCollector', 'string_value_keys', 'str_param')],
    )
    with patch.object(Executor, 'read_cql_table', return_value=('SELECT * FROM system.config', rows)):
        collector._collect(_make_system_config_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['json_param']['value'] == 'hello'
    assert collector._data['str_param']['value'] == 'raw'


def test_SystemConfigCollector_object_storage_endpoints_always_raw(doctor_factory):
    """
    'object_storage_endpoints' has a non-JSON value (SCYLLADB-1658).
    It must be kept as a raw string even without any string_value_keys config.
    """
    raw_value = 'non-json-endpoint-value'
    rows = [
        {'name': 'object_storage_endpoints', 'value': raw_value, 'source': 'default', 'type': 'string'},
        {'name': 'num_tokens', 'value': '256', 'source': 'default', 'type': 'int'},
        *[dict(r) for r in _SYSTEM_CONFIG_REQUIRED_ROWS],
    ]

    collector = _make_system_config_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', return_value=('SELECT * FROM system.config', rows)):
        collector._collect(_make_system_config_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['object_storage_endpoints']['value'] == raw_value
    assert collector._data['num_tokens']['value'] == 256


def test_SystemConfigCollector_cql_failure_sets_failed_status(doctor_factory):
    """
    A CQL failure must set FAILED status and propagate the error message,
    regardless of the string_value_keys config.
    """
    from utils import CqlFailedException

    collector = _make_system_config_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', side_effect=CqlFailedException("connection refused")):
        collector._collect(_make_system_config_vitals())

    assert collector.status == CollectorStatus.FAILED
    assert "connection refused" in collector.result.message


def __test_SystemTopologyCollector(doctor_factory, feature_supported: bool, feature_enabled: bool):
    """
    Test SystemTopologyCollector given provided expected properties of the result.

    :param doctor_factory: Factory to create a Doctor instance
    :param feature_supported: If True, the collector should return that Consistent Topology is supported
    :param feature_enabled: If True, Consistent Topology is enabled and system.topology is not empty
    """
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.GossipInfoCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.SystemTopologyCollector])

    doctor.run()

    # Check for successful completion
    result = doctor.vitals['SystemTopologyCollector']
    system_topology_rows = result.data['system_topology_rows']
    consistent_topology_supported = result.data['consistent_topology_supported']
    assert result.status == CollectorStatus.PASSED, result.message
    expected_empty_table = not (feature_enabled and feature_supported)

    # Check if the query was successful — system.topology is always queried regardless of CT support
    system_topology_query = Executor.read_cql_table_command("system.topology")
    assert_output_gathered(result, OutputEntryType.CQL, system_topology_query,
                           empty_value_allowed=expected_empty_table)

    # Check that the system topology content — only meaningful when the CQL mock controls the table
    if feature_supported:
        if expected_empty_table:
            assert len(system_topology_rows) == 0
        else:
            assert len(system_topology_rows) > 0

    # Check if consistent topology is supported
    assert consistent_topology_supported is feature_supported


def consistent_topology_not_supported_get_url_mock(url, headers=None, timeout=2, retries=3, retry_interval=2,
                                                   check=False) -> str:
    """
    Mock the situation when Consistent Topology feature is not supported.
    :param url: URL to fetch the content from
    :return: URL response content with SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES replaced
    """
    content = tests.helpers.orig_get_url_content(url=url, headers=headers, timeout=timeout, retries=retries,
                                                 retry_interval=retry_interval, check=check)
    consistent_topology_feature_name = 'SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES'
    # Rename SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES to SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES_MOCK
    return re.sub(consistent_topology_feature_name, f'{consistent_topology_feature_name}_MOCK', content)


def consistent_topology_supported_get_url_mock(url, headers=None, timeout=2, retries=3, retry_interval=2,
                                               check=False) -> str:
    """
    Mock the situation when Consistent Topology feature is supported
    according to the .../failure_detector/endpoints URL content.
    :param url: URL to fetch the content from
    :return: URL response content with SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES added to features
    """
    content = tests.helpers.orig_get_url_content(url=url, headers=headers, timeout=timeout, retries=retries,
                                                 retry_interval=retry_interval, check=check)
    if r'/failure_detector/endpoints' in url:
        consistent_topology_feature_name = 'SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES'
        always_present_feature_name = 'ROLES'
        # If SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES not present - add it to features
        if consistent_topology_feature_name not in content:
            content = re.sub(always_present_feature_name,
                             f'{always_present_feature_name},{consistent_topology_feature_name}', content)
    return content


def return_empty_system_topology_table(config, table_name) -> Tuple[str, List[Dict[str, str]]]:
    """
    Mock the read_cql_table method to return an empty result for the given table.
    :param config: Configuration required for the read_cql_table method
    :param table_name: Name of the table to read
    """
    if table_name == "system.topology":
        return Executor.read_cql_table_command(table_name), []
    return tests.helpers.orig_read_cql_table(config, table_name)


def return_not_empty_system_topology_table(config, table_name) -> Tuple[str, List[Dict[str, str]]]:
    """
    Mock the read_cql_table method to return a non-empty result for the system.topology table.
    :param config: Configuration required for the read_cql_table method
    :param table_name: Name of the table to read
    """
    if table_name == "system.topology":
        return Executor.read_cql_table_command(table_name), [{'some_row': 'data'}]
    return tests.helpers.orig_read_cql_table(config, table_name)


def _make_system_topology_gossip_mock(gossip_info_override):
    """
    Return a get_url_content mock that replaces the /failure_detector/endpoints response
    with a crafted gossip_info JSON while leaving all other URLs untouched.
    The gossip_info_override is a list of raw gossipinfo entry dicts.
    """
    import json as _json

    def _mock(url, headers=None, timeout=2, retries=3, retry_interval=2, check=False):
        if r'/failure_detector/endpoints' in url:
            return _json.dumps(gossip_info_override)
        return tests.helpers.orig_get_url_content(url=url, headers=headers, timeout=timeout,
                                                  retries=retries, retry_interval=retry_interval,
                                                  check=check)
    return _mock


def _run_system_topology_collector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.GossipInfoCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.SystemTopologyCollector])
    doctor.run()
    return doctor.vitals['SystemTopologyCollector']


def test_SystemTopologyCollectorMock_MissingBroadcastAddress(doctor_factory, await_scylla_start, monkeypatch):
    """
    When the local broadcast_address is absent from gossip_info the collector must still
    PASS (degraded mode) and include an informational message — it must not hard-fail.
    system.topology is still read.
    """
    monkeypatch.setattr(tests.helpers, "orig_get_url_content", Executor.get_url_content)
    monkeypatch.setattr(tests.helpers, "orig_read_cql_table", Executor.read_cql_table)
    monkeypatch.setattr(Executor, "read_cql_table", return_empty_system_topology_table)
    # Serve an empty gossip list so no address matches broadcast_address
    monkeypatch.setattr(Executor, "get_url_content", _make_system_topology_gossip_mock([]))

    result = _run_system_topology_collector(doctor_factory)

    assert result.status == CollectorStatus.PASSED, result.message
    assert result.data['consistent_topology_supported'] is None
    assert "not found in gossip_info" in result.message


def test_SystemTopologyCollectorMock_MultipleBroadcastAddressEntries(doctor_factory, await_scylla_start, monkeypatch):
    """
    When the local broadcast_address appears more than once in gossip_info the collector
    must still PASS, use the first entry to determine CT support, and include an
    informational message about the duplicates.
    """
    monkeypatch.setattr(tests.helpers, "orig_get_url_content", Executor.get_url_content)
    monkeypatch.setattr(tests.helpers, "orig_read_cql_table", Executor.read_cql_table)
    monkeypatch.setattr(Executor, "read_cql_table", return_empty_system_topology_table)
    monkeypatch.setattr(Executor, "get_url_content", consistent_topology_supported_get_url_mock)

    # Inject a duplicate for the local broadcast address by doubling the gossip response
    orig_get = consistent_topology_supported_get_url_mock

    def _double_gossip(url, headers=None, timeout=2, retries=3, retry_interval=2, check=False):
        content = orig_get(url=url, headers=headers, timeout=timeout, retries=retries,
                           retry_interval=retry_interval, check=check)
        if r'/failure_detector/endpoints' in url:
            import json as _json
            entries = _json.loads(content)
            content = _json.dumps(entries + entries)
        return content

    monkeypatch.setattr(Executor, "get_url_content", _double_gossip)

    result = _run_system_topology_collector(doctor_factory)

    assert result.status == CollectorStatus.PASSED, result.message
    assert "Multiple broadcast address" in result.message


def test_SystemTopologyCollectorMockNotSupported(doctor_factory, await_scylla_start, monkeypatch):
    monkeypatch.setattr(tests.helpers, "orig_get_url_content", Executor.get_url_content)
    monkeypatch.setattr(Executor, "get_url_content", consistent_topology_not_supported_get_url_mock)
    __test_SystemTopologyCollector(doctor_factory, feature_supported=False, feature_enabled=False)


def test_SystemTopologyCollectorMockSupportedNotEnabled(doctor_factory, await_scylla_start, monkeypatch):
    monkeypatch.setattr(tests.helpers, "orig_get_url_content", Executor.get_url_content)
    monkeypatch.setattr(tests.helpers, "orig_read_cql_table", Executor.read_cql_table)
    monkeypatch.setattr(Executor, "get_url_content", consistent_topology_supported_get_url_mock)
    monkeypatch.setattr(Executor, "read_cql_table", return_empty_system_topology_table)

    __test_SystemTopologyCollector(doctor_factory, feature_supported=True, feature_enabled=False)


def test_SystemTopologyCollectorMockSupportedEnabled(doctor_factory, await_scylla_start, monkeypatch):
    monkeypatch.setattr(tests.helpers, "orig_get_url_content", Executor.get_url_content)
    monkeypatch.setattr(tests.helpers, "orig_read_cql_table", Executor.read_cql_table)
    monkeypatch.setattr(Executor, "get_url_content", consistent_topology_supported_get_url_mock)
    monkeypatch.setattr(Executor, "read_cql_table", return_not_empty_system_topology_table)

    __test_SystemTopologyCollector(doctor_factory, feature_supported=True, feature_enabled=True)


def test_SystemTopologyCollector(doctor_factory, await_scylla_start):
    """
    Test SystemTopologyCollector without mocking.
    """
    # Check if Consistent Topology feature is available and enabled
    res = subprocess.run(
        ["curl", "-f", "-X", "GET", "http://localhost:10000/storage_service/raft_topology/upgrade"],
        capture_output=True, encoding="utf-8", check=False)

    feature_enabled = False
    feature_supported = True
    if res.returncode != 0:
        feature_supported = False
    elif "done" == res.stdout.strip('"\'\n'):
        feature_enabled = True

    __test_SystemTopologyCollector(doctor_factory, feature_supported=feature_supported, feature_enabled=feature_enabled)


def return_system_topology_table_with_unsorted_tokens(config, table_name) -> Tuple[str, List[Dict[str, str]]]:
    """
    Mock that returns a system.topology row whose 'tokens' value is intentionally unsorted.
    Used to verify that SystemTopologyCollector sorts tokens before storing them.
    """
    if table_name == "system.topology":
        return Executor.read_cql_table_command(table_name), [
            {'host_id': 'some-host-id', 'tokens': "{'token_c', 'token_a', 'token_b'}"}
        ]
    return tests.helpers.orig_read_cql_table(config, table_name)


def test_SystemTopologyCollectorMockSupportedEnabled_TokensSorted(doctor_factory, await_scylla_start, monkeypatch):
    """
    When system.topology rows contain a 'tokens' field with unsorted values the collector must
    sort them so that data collected on different nodes of the same cluster is directly comparable.
    """
    monkeypatch.setattr(tests.helpers, "orig_get_url_content", Executor.get_url_content)
    monkeypatch.setattr(tests.helpers, "orig_read_cql_table", Executor.read_cql_table)
    monkeypatch.setattr(Executor, "get_url_content", consistent_topology_supported_get_url_mock)
    monkeypatch.setattr(Executor, "read_cql_table", return_system_topology_table_with_unsorted_tokens)

    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.GossipInfoCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.SystemTopologyCollector])
    doctor.run()

    result = doctor.vitals['SystemTopologyCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert result.data['consistent_topology_supported'] is True

    rows = result.data['system_topology_rows']
    assert len(rows) == 1
    # Tokens must be sorted alphabetically so cross-node comparison is deterministic
    assert rows[0]['tokens'] == "{'token_a', 'token_b', 'token_c'}"


def test_ScyllaExtraConfigurationFilesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaExtraConfigurationFilesCollector])
    doctor.run()

    result = doctor.vitals['ScyllaExtraConfigurationFilesCollector']
    assert result.status == CollectorStatus.PASSED
    assert len(result.data) > 0
    assert all(isinstance(v, dict) for v in result.data.values())
    for filename in doctor.collectors['ScyllaExtraConfigurationFilesCollector']._ScyllaExtraConfigurationFilesCollector__identical_files:  # noqa: E501
        if filename in result.data:
            assert_output_gathered(result, OutputEntryType.PARSED_FILE, filename)


@pytest.mark.skipif(os.getuid() > 0,
                    reason="requires root access")
@pytest.mark.skipif(is_podman_container(),
                    reason="podman environment cannot read the kernel buffer")
def test_KernelRingBufferCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.KernelRingBufferCollector])
    doctor.run()

    result = doctor.vitals['KernelRingBufferCollector']
    assert result.status == CollectorStatus.PASSED
    assert_output_gathered(result, OutputEntryType.STDOUT, "dmesg -T")


def test_PathsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.PathsCollector])

    doctor.run()

    result = doctor.vitals['PathsCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data == doctor.environment.paths


def test_NICsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.NICsCollector])
    doctor.run()

    result = doctor.vitals['NICsCollector']
    assert result.status == CollectorStatus.PASSED
    nics = result.data['nics']
    for nic_data in nics.values():
        for key in ['speed', 'driver']:
            assert key in nic_data
    assert len([nic for nic in nics if nics[nic]['speed'] is not None]) > 0, "Speed not detected for any NIC"


def test_NICsCollector_skips_default_virtual_nics(doctor_factory):
    """Common virtual/tunnel NICs are skipped by default without calling ethtool."""
    doctor = doctor_factory(collectors=[collectors.NICsCollector])
    collector = doctor.collectors['NICsCollector']

    def fake_run_command(command, check=True, **kwargs):
        assert "erspan0" not in command
        result = Mock()
        if command == "ethtool -i eth0":
            result.returncode = 0
            result.stdout = "driver: virtio_net\n"
        elif command == "ethtool eth0":
            result.returncode = 0
            result.stdout = "Speed: 10000Mb/s\n"
        else:
            result.returncode = 0
            result.stdout = ""
        return result

    with patch.object(collectors.shutil, 'which', return_value="/usr/sbin/ethtool"), \
            patch.object(collectors.glob, 'glob',
                         return_value=["/sys/class/net/eth0", "/sys/class/net/erspan0"]), \
            patch.object(collectors.pathlib.Path, 'is_symlink', return_value=True), \
            patch.object(Executor, 'run_command', side_effect=fake_run_command):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector.result.message
    nics = collector.result.data['nics']
    assert nics['eth0'] == {'driver': 'virtio_net', 'speed': 10000}
    assert 'erspan0' not in nics


def test_NICsCollector_skips_configured_nics(doctor_factory):
    """Configured skip_nics extends the built-in defaults."""
    doctor = doctor_factory(
        collectors=[collectors.NICsCollector],
        config_options=[('NICsCollector', 'skip_nics', 'dummy0')],
    )
    collector = doctor.collectors['NICsCollector']

    def fake_run_command(command, check=True, **kwargs):
        assert "dummy0" not in command
        result = Mock()
        result.returncode = 0
        result.stdout = ""
        return result

    with patch.object(collectors.shutil, 'which', return_value="/usr/sbin/ethtool"), \
            patch.object(collectors.glob, 'glob',
                         return_value=["/sys/class/net/eth0", "/sys/class/net/dummy0"]), \
            patch.object(collectors.pathlib.Path, 'is_symlink', return_value=True), \
            patch.object(Executor, 'run_command', side_effect=fake_run_command):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector.result.message
    assert 'dummy0' not in collector.result.data['nics']


def test_NICsCollector_fails_when_ethtool_errors_on_real_nic(doctor_factory):
    """ethtool failure on a non-skipped NIC must fail the collector."""
    doctor = doctor_factory(collectors=[collectors.NICsCollector])
    collector = doctor.collectors['NICsCollector']

    def fake_run_command(command, check=True, **kwargs):
        if command.startswith("ethtool eth0"):
            raise subprocess.CalledProcessError(1, command, "Device not supported\n")
        result = Mock()
        result.returncode = 0
        result.stdout = "driver: virtio_net\n"
        return result

    with patch.object(collectors.shutil, 'which', return_value="/usr/sbin/ethtool"), \
            patch.object(collectors.glob, 'glob', return_value=["/sys/class/net/eth0"]), \
            patch.object(collectors.pathlib.Path, 'is_symlink', return_value=True), \
            patch.object(Executor, 'run_command', side_effect=fake_run_command):
        collector.collect({}, doctor.collectors)

    assert collector.status == CollectorStatus.FAILED
    assert "ethtool eth0" in collector.result.message


def test_IPAddressesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.IPAddressesCollector, collectors.NICsCollector])
    doctor.run()

    result = doctor.vitals['IPAddressesCollector']
    assert result.status == CollectorStatus.PASSED
    for nic in doctor.vitals['NICsCollector'].data['nics']:
        assert_output_gathered(result, OutputEntryType.STDOUT, f"ip addr show {nic}")


def test_ComputerArchitectureCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ComputerArchitectureCollector])
    doctor.run()

    result = doctor.vitals['ComputerArchitectureCollector']
    assert result.status == CollectorStatus.PASSED
    for key in ["architecture", "kernel_version"]:
        assert key in result.data


@pytest.mark.skipif(is_container(),
                    reason="container environment does not feature systemd and timedatectl functionality")
def test_NTPStatusCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.NTPStatusCollector])
    doctor.run()

    result = doctor.vitals['NTPStatusCollector']
    assert result.status == CollectorStatus.PASSED
    assert 'ntp_enabled' in result.data and 'ntp_synchronized' in result.data


def test_NTPServicesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.NTPServicesCollector])
    doctor.run()

    result = doctor.vitals['NTPServicesCollector']
    assert result.status == CollectorStatus.PASSED
    assert all(['active' in result.data['services'][service] for service in result.data['services']])


def test_ChronyStatusCollector_skipped_without_chronyc():
    collector = collectors.ChronyStatusCollector({}, {})
    with patch('collectors.shutil.which', return_value=None):
        collector._collect({})

    assert collector.status == CollectorStatus.SKIPPED
    assert 'chronyc is not installed' in collector.message


def test_ChronyStatusCollector_skipped_when_tracking_fails():
    collector = collectors.ChronyStatusCollector({}, {})
    with patch('collectors.shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=1, stdout='506 Cannot talk to daemon\n')):
        collector._collect({})

    assert collector.status == CollectorStatus.SKIPPED
    assert 'chronyc tracking failed' in collector.message


def test_ChronyStatusCollector_failed_without_leap_status():
    collector = collectors.ChronyStatusCollector({}, {})
    with patch('collectors.shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout='Reference ID    : CB00710F\n')):
        collector._collect({})

    assert collector.status == CollectorStatus.FAILED
    assert 'leap status' in collector.message


def test_ChronyStatusCollector_synchronized():
    tracking_output = (
        "Reference ID    : CB00710F (foo.example.net)\n"
        "Stratum         : 2\n"
        "Leap status     : Normal\n"
    )
    collector = collectors.ChronyStatusCollector({}, {})
    with patch('collectors.shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=tracking_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['chrony_synchronized'] is True
    assert collector._data['leap_status'] == 'Normal'


def test_ChronyStatusCollector_not_synchronized():
    tracking_output = "Leap status     : Not synchronised\n"
    collector = collectors.ChronyStatusCollector({}, {})
    with patch('collectors.shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=tracking_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['chrony_synchronized'] is False
    assert collector._data['leap_status'] == 'Not synchronised'


@pytest.mark.parametrize('leap_status', ['Insert second', 'Delete second'])
def test_ChronyStatusCollector_synchronized_leap_second(leap_status):
    tracking_output = f"Leap status     : {leap_status}\n"
    collector = collectors.ChronyStatusCollector({}, {})
    with patch('collectors.shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=tracking_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['chrony_synchronized'] is True
    assert collector._data['leap_status'] == leap_status


def test_ChronyStatusCollector_unknown_leap_status_treated_as_synchronized():
    tracking_output = "Leap status     : Future status\n"
    collector = collectors.ChronyStatusCollector({}, {})
    with patch('collectors.shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=tracking_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['chrony_synchronized'] is True


def test_ChronyServicesCollector():
    collector = collectors.ChronyServicesCollector({}, {})
    with patch('collectors.ServiceManager') as mock_sm_class:
        mock_sm = mock_sm_class.return_value
        mock_sm.service_active.side_effect = lambda name: name == 'chronyd'
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['services'] == {
        'chronyd': {'active': True},
        'chrony': {'active': False},
    }


def test_OSCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.OSCollector])
    doctor.run()

    result = doctor.vitals['OSCollector']
    assert result.status == CollectorStatus.PASSED
    for key in ['name', 'version', 'version_minor']:
        assert key in result.data
    assert_output_gathered(result, OutputEntryType.FILE, '/etc/os-release')


def test_PerftuneSystemConfigurationCollector(doctor_factory, monkeypatch,
                                              provider_identify_shorten_timeout_options, await_scylla_start):
    # TODO: find a way to run perftune in docker in a more meaningful way
    with open('/tmp/perftune.yaml', 'w') as f:
        f.writelines(["tune:\r\n", "  - system"])

    monkeypatch_path("scylla_directory_configs", "/tmp",
                     [collectors.PerftuneSystemConfigurationCollector], monkeypatch)

    doctor = doctor_factory(collectors=[collectors.NICsCollector,
                                        collectors.CPUSpecificationsCollector,
                                        collectors.ScyllaExtraConfigurationFilesCollector,
                                        collectors.CPUSetCollector,
                                        collectors.InfrastructureProviderCollector,
                                        collectors.NodePlatformCollector,
                                        collectors.ScyllaConfigurationFileCollector,
                                        collectors.StorageConfigurationCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.HypervisorTypeCollector,
                                        collectors.PerftuneSystemConfigurationCollector],
                            config_options=provider_identify_shorten_timeout_options)
    doctor.run()

    result = doctor.vitals['PerftuneSystemConfigurationCollector']
    assert result.status == CollectorStatus.PASSED, result.message


def test_ScyllaSystemConfigurationFilesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaSystemConfigurationFilesCollector])
    doctor.run()

    result = doctor.vitals['ScyllaSystemConfigurationFilesCollector']
    assert result.status == CollectorStatus.PASSED
    assert (result.data['directory'])
    assert len(result.data['files']) > 0
    assert all(isinstance(v, dict) for v in result.data['files'].values())
    for filename in result.data['files']:
        assert_output_gathered(result, OutputEntryType.PARSED_FILE, filename)

    # Files content must be stored at VERBOSE level so it is excluded from strict cross-node
    # comparison (e.g. IFNAME may differ between hosts).
    result.strip()
    for filename in result.data['files']:
        assert_output_not_gathered(result, OutputEntryType.PARSED_FILE, filename)


def test_RAMCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.RAMCollector])
    doctor.run()

    result = doctor.vitals['RAMCollector']
    assert result.status == CollectorStatus.PASSED
    assert_output_gathered(result, OutputEntryType.STDOUT, 'free')
    assert_output_gathered(result, OutputEntryType.FILE, '/proc/meminfo')
    assert isinstance(result.data['total'], numbers.Number)


def test_RsyslogCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.RsyslogCollector])
    doctor.run()

    result = doctor.vitals['RsyslogCollector']
    assert result.status == CollectorStatus.PASSED
    assert "/etc/rsyslog.d/scylla.conf" in result.data['files']


def test_ScyllaConfigurationFileCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector])
    doctor.run()

    result = doctor.vitals['ScyllaConfigurationFileCollector']
    assert result.status == CollectorStatus.PASSED
    assert 'storage_port' in result.data
    assert 'pure_scylla_yaml' in result.data


def test_PerftuneYamlDefaultCollector(doctor_factory, provider_identify_shorten_timeout_options):
    doctor = doctor_factory(collectors=[collectors.NICsCollector,
                                        collectors.InfrastructureProviderCollector,
                                        collectors.CPUSpecificationsCollector,
                                        collectors.NodePlatformCollector,
                                        collectors.ScyllaSystemConfigurationFilesCollector,
                                        collectors.ScyllaExtraConfigurationFilesCollector,
                                        collectors.PerftuneYamlDefaultCollector],
                            config_options=provider_identify_shorten_timeout_options)
    doctor.run()

    result = doctor.vitals['PerftuneYamlDefaultCollector']
    if not is_container():
        assert result.status == CollectorStatus.PASSED, result.message
    else:
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "not available" in result.message


def test_StorageConfigurationCollector(doctor_factory, provider_identify_shorten_timeout_options, await_scylla_start):
    doctor = doctor_factory(collectors=[
                                collectors.NodePlatformCollector,
                                collectors.NICsCollector,
                                collectors.InfrastructureProviderCollector,
                                collectors.CPUSpecificationsCollector,
                                collectors.StorageConfigurationCollector,
                                collectors.ScyllaConfigurationFileCollector,
                                collectors.CqlshCollector,
                                collectors.SystemConfigCollector,
                                collectors.SystemPeersLocalCollector],
                            config_options=provider_identify_shorten_timeout_options)
    doctor.run()

    result = doctor.vitals['StorageConfigurationCollector']
    assert result.status == CollectorStatus.PASSED
    for dirs_stats in result.data.values():
        for dir_stats in dirs_stats.values():
            assert any([len(dir_stats['devices']['nvme']) > 0, len(dir_stats['devices']['non_nvme']) > 0])
            assert isinstance(dir_stats['filesystem'], str)
            assert isinstance(dir_stats['mountpoint'], str)
            assert isinstance(dir_stats['storage_size_kb'], float)
            assert isinstance(dir_stats['free_storage_size_kb'], float)
            assert (len(dir_stats['mount_options']) > 0)

    result.strip()
    for dirs_stats in result.data.values():
        for dir_stats in dirs_stats.values():
            assert any([len(dir_stats['devices']['nvme']) > 0, len(dir_stats['devices']['non_nvme']) > 0])
            assert isinstance(dir_stats['filesystem'], str)
            assert isinstance(dir_stats['mountpoint'], str)
            assert isinstance(dir_stats['storage_size_kb'], float)
            assert 'free_storage_size_kb' not in dir_stats
            assert (len(dir_stats['mount_options']) > 0)


def test_RAIDSetupCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.RAIDSetupCollector])
    doctor.run()

    result = doctor.vitals['RAIDSetupCollector']
    # /proc/mdstat is only present when the md kernel module is available - absence is a valid SKIPPED outcome.
    if os.path.isfile("/proc/mdstat"):
        assert result.status == CollectorStatus.PASSED, result.message
        assert set(result.data) == {'personalities', 'arrays', 'unused_devices'}
        assert isinstance(result.data['personalities'], list)
        assert isinstance(result.data['arrays'], dict)
        assert isinstance(result.data['unused_devices'], list)
    else:
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "not present" in result.message


def test_RAIDSetupCollector_skips_when_mdstat_absent(doctor_factory):
    """When /proc/mdstat is missing (md module not loaded) the collector must SKIP, not crash."""
    doctor = doctor_factory(collectors=[collectors.RAIDSetupCollector])
    collector = doctor.collectors['RAIDSetupCollector']

    with patch.object(Executor, 'read_file_content', side_effect=FileNotFoundError("/proc/mdstat")):
        collector._collect({})

    assert collector.status == CollectorStatus.SKIPPED
    assert "not present" in collector.result.message


def test_RAIDSetupCollector_passes_when_mdstat_present(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.RAIDSetupCollector])
    collector = doctor.collectors['RAIDSetupCollector']

    mdstat_content = [
        "Personalities : [raid1]\n",
        "md0 : active raid1 sda1[0] sdb1[1]\n",
        "      1024 blocks super 1.2 512k chunks\n",
        "\n",
        "unused devices: <none>\n",
    ]
    with patch.object(Executor, 'read_file_content', return_value=mdstat_content):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector.result.message
    assert collector.result.data == {
        'personalities': ['raid1'],
        'arrays': {
            'md0': {
                'state': 'active',
                'level': 'raid1',
                'members': ['sda1', 'sdb1'],
            }
        },
        'unused_devices': [],
    }
    # Structured data is intended for cluster drift; do not mask the whole collector.
    assert collector.mask == []


def test_RAIDSetupCollector_parse_sorts_members_for_comparability():
    """Member order in /proc/mdstat can differ across nodes; parsed data must not."""
    content_a = [
        "Personalities : [raid0] \n",
        "md0 : active raid0 nvme0n2[1] nvme0n1[0]\n",
        "      786167808 blocks super 1.2 1024k chunks\n",
        "\n",
        "unused devices: <none>\n",
    ]
    content_b = [
        "Personalities : [raid0]\n",
        "md0 : active raid0 nvme0n1[0] nvme0n2[1]\n",
        "      786167808 blocks super 1.2 1024k chunks\n",
        "unused devices: <none>\n",
    ]

    parsed_a = collectors.RAIDSetupCollector._parse_mdstat(content_a)
    parsed_b = collectors.RAIDSetupCollector._parse_mdstat(content_b)

    assert parsed_a == parsed_b
    assert parsed_a == {
        'personalities': ['raid0'],
        'arrays': {
            'md0': {
                'state': 'active',
                'level': 'raid0',
                'members': ['nvme0n1', 'nvme0n2'],
            }
        },
        'unused_devices': [],
    }


def test_RAIDSetupCollector_parse_inactive_and_flags():
    content = [
        "Personalities : [raid1] [raid0]\n",
        "md1 : active (auto-read-only) raid1 sda1[0] sdb1[1]\n",
        "md2 : inactive nvme0n1[0](S) nvme1n1[1](S)\n",
        "unused devices: sdc1 sdd1\n",
    ]

    assert collectors.RAIDSetupCollector._parse_mdstat(content) == {
        'personalities': ['raid0', 'raid1'],
        'arrays': {
            'md1': {
                'state': 'active',
                'level': 'raid1',
                'members': ['sda1', 'sdb1'],
            },
            'md2': {
                'state': 'inactive',
                'level': None,
                'members': ['nvme0n1', 'nvme1n1'],
            },
        },
        'unused_devices': ['sdc1', 'sdd1'],
    }


def test_RAIDSetupCollector_parse_non_raid_personality():
    """Personalities like 'linear'/'multipath'/'faulty' aren't prefixed with 'raid' but must still
    be captured as the array's level instead of being silently dropped as an unmatched member."""
    content = [
        "Personalities : [linear]\n",
        "md3 : active linear sdc1[0] sdd1[1]\n",
        "unused devices: <none>\n",
    ]

    assert collectors.RAIDSetupCollector._parse_mdstat(content) == {
        'personalities': ['linear'],
        'arrays': {
            'md3': {
                'state': 'active',
                'level': 'linear',
                'members': ['sdc1', 'sdd1'],
            },
        },
        'unused_devices': [],
    }


def test_NVMeDevicesCollector():
    raid_data = {
        'personalities': ['raid0'],
        'arrays': {
            'md127': {
                'state': 'active',
                'level': 'raid0',
                'members': ['nvme0n1', 'nvme1n1'],
            }
        },
        'unused_devices': [],
    }
    vitals = {
        'RAIDSetupCollector': CollectorResult(
            CollectorStatus.PASSED,
            raid_data,
            Output(),
            '',
        ),
        'InfrastructureProviderCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'provider': None},
            Output(),
            '',
        ),
    }

    def fake_listdir(path):
        if path == '/sys/block':
            return ['sda', 'nvme0n1', 'nvme1n1', 'nvme2n1', 'nvme0n1p1']
        raise AssertionError(path)

    def fake_isdir(path):
        return path == '/sys/block'

    def fake_run(command, shell=True, check=False):
        mountpoints = {
            'lsblk -rno MOUNTPOINT /dev/nvme0n1': '',
            'lsblk -rno MOUNTPOINT /dev/nvme1n1': '',
            'lsblk -rno MOUNTPOINT /dev/nvme2n1': '',
        }
        return Mock(returncode=0, stdout=mountpoints[command])

    collector = collectors.NVMeDevicesCollector({}, {})
    with patch('collectors.os.listdir', side_effect=fake_listdir), \
         patch('collectors.os.path.isdir', side_effect=fake_isdir), \
         patch.object(Executor, 'run_command', side_effect=fake_run):
        collector._collect(vitals)

    assert collector.status == CollectorStatus.PASSED, collector.message
    assert collector._data['nvme_devices'] == ['nvme0n1', 'nvme1n1', 'nvme2n1']
    assert collector._data['used_nvme_devices'] == ['nvme0n1', 'nvme1n1']
    assert collector._data['unused_nvme_devices'] == ['nvme2n1']


def test_NVMeDevicesCollector_mounted_partition():
    raid_data = {'personalities': [], 'arrays': {}, 'unused_devices': []}
    vitals = {
        'RAIDSetupCollector': CollectorResult(
            CollectorStatus.PASSED,
            raid_data,
            Output(),
            '',
        ),
        'InfrastructureProviderCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'provider': None},
            Output(),
            '',
        ),
    }

    def fake_listdir(path):
        if path == '/sys/block':
            return ['nvme0n1', 'nvme1n1']
        raise AssertionError(path)

    def fake_isdir(path):
        return path == '/sys/block'

    def fake_run(command, shell=True, check=False):
        mountpoints = {
            'lsblk -rno MOUNTPOINT /dev/nvme0n1': '/var/lib/scylla\n',
            'lsblk -rno MOUNTPOINT /dev/nvme1n1': '',
        }
        return Mock(returncode=0, stdout=mountpoints[command])

    collector = collectors.NVMeDevicesCollector({}, {})
    with patch('collectors.os.listdir', side_effect=fake_listdir), \
         patch('collectors.os.path.isdir', side_effect=fake_isdir), \
         patch.object(Executor, 'run_command', side_effect=fake_run):
        collector._collect(vitals)

    assert collector.status == CollectorStatus.PASSED, collector.message
    assert collector._data['used_nvme_devices'] == ['nvme0n1']
    assert collector._data['unused_nvme_devices'] == ['nvme1n1']


@pytest.mark.parametrize('root_source', ['/dev/nvme0n1p1', '/dev/nvme0n1'])
def test_NVMeDevicesCollector_aws_root_volume_excluded(root_source):
    raid_data = {'personalities': [], 'arrays': {}, 'unused_devices': []}
    vitals = {
        'RAIDSetupCollector': CollectorResult(
            CollectorStatus.PASSED,
            raid_data,
            Output(),
            '',
        ),
        'InfrastructureProviderCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'provider': 'AWS'},
            Output(),
            '',
        ),
    }

    def fake_listdir(path):
        if path == '/sys/block':
            return ['nvme0n1', 'nvme1n1']
        raise AssertionError(path)

    def fake_isdir(path):
        return path == '/sys/block'

    def fake_run(command, shell=True, check=False):
        if command == 'findmnt -n -o SOURCE /':
            return Mock(returncode=0, stdout=f'{root_source}\n')
        mountpoints = {
            'lsblk -rno MOUNTPOINT /dev/nvme1n1': '',
        }
        return Mock(returncode=0, stdout=mountpoints[command])

    collector = collectors.NVMeDevicesCollector({}, {})
    with patch('collectors.os.listdir', side_effect=fake_listdir), \
         patch('collectors.os.path.isdir', side_effect=fake_isdir), \
         patch.object(Executor, 'run_command', side_effect=fake_run):
        collector._collect(vitals)

    assert collector.status == CollectorStatus.PASSED, collector.message
    assert collector._data['nvme_devices'] == ['nvme1n1']
    assert collector._data['unused_nvme_devices'] == ['nvme1n1']


# DiskPerformanceExceededCollector unit tests ################################

_AMZN_STATS_JSON = """{
  "total_read_ops": 100,
  "total_write_ops": 200,
  "ebs_volume_performance_exceeded_iops": 0,
  "ebs_volume_performance_exceeded_tp": 0,
  "ec2_instance_performance_exceeded_iops": 42,
  "ec2_instance_performance_exceeded_tp": 0,
  "volume_queue_length": 1
}"""


def _disk_performance_vitals(provider='AWS', used_devices=None):
    return {
        'InfrastructureProviderCollector': CollectorResult(
            CollectorStatus.PASSED, {'provider': provider}, Output(), ''),
        'NVMeDevicesCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'nvme_devices': ['nvme0n1'],
             'used_nvme_devices': ['nvme0n1'] if used_devices is None else used_devices,
             'unused_nvme_devices': []},
            Output(), ''),
    }


def test_DiskPerformanceExceededCollector():
    collector = collectors.DiskPerformanceExceededCollector({}, {})
    with patch('collectors.shutil.which', return_value='/usr/sbin/nvme'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=_AMZN_STATS_JSON)):
        collector._collect(_disk_performance_vitals())

    assert collector.status == CollectorStatus.PASSED, collector.message
    # Only the "performance exceeded" counters are stored.
    assert collector._data['devices'] == {'nvme0n1': {'ebs_volume_performance_exceeded_iops': 0,
                                                      'ebs_volume_performance_exceeded_tp': 0,
                                                      'ec2_instance_performance_exceeded_iops': 42,
                                                      'ec2_instance_performance_exceeded_tp': 0}}


# Key-name variants documented by AWS for the same counters - the collector must match the
# "performance exceeded" suffix regardless of the prefix, so each of these is picked up.
_ALTERNATE_EXCEEDED_KEYS = [
    'ec2_instance_ebs_performance_exceeded_iops',
    'ec2_instance_ebs_performance_exceeded_tp',
    'instance_store_volume_performance_exceeded_iops',
    'instance_store_volume_performance_exceeded_tp',
    'ebs_volume_performance_exceeded_iops',
    'ebs_volume_performance_exceeded_tp',
    'ec2_instance_performance_exceeded_iops',
    'ec2_instance_performance_exceeded_tp',
]


@pytest.mark.parametrize('key', _ALTERNATE_EXCEEDED_KEYS)
def test_DiskPerformanceExceededCollector_alternate_key_names(key):
    stats_json = json.dumps({'total_read_ops': 1, key: 7, 'volume_queue_length': 1})
    collector = collectors.DiskPerformanceExceededCollector({}, {})
    with patch('collectors.shutil.which', return_value='/usr/sbin/nvme'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=stats_json)):
        collector._collect(_disk_performance_vitals())

    assert collector.status == CollectorStatus.PASSED, collector.message
    # The alternate key is captured, and the non-matching counter is not.
    assert collector._data['devices'] == {'nvme0n1': {key: 7}}


@pytest.mark.parametrize('provider,which,used_devices,run_result,message', [
    ('GCP', '/usr/sbin/nvme', None, Mock(returncode=0, stdout=_AMZN_STATS_JSON), "AWS Nitro instances only"),
    ('AWS', None, None, Mock(returncode=0, stdout=_AMZN_STATS_JSON), "'nvme' utility is not installed"),
    ('AWS', '/usr/sbin/nvme', [], Mock(returncode=0, stdout=_AMZN_STATS_JSON), "No NVMe devices in use"),
    ('AWS', '/usr/sbin/nvme', None, Mock(returncode=1, stdout="Unknown plugin: amzn\n"), "are not reported"),
    ('AWS', '/usr/sbin/nvme', None, Mock(returncode=0, stdout="Total Ops:\n  Read: 1\n"), "are not reported"),
])
def test_DiskPerformanceExceededCollector_skipped(provider, which, used_devices, run_result, message):
    collector = collectors.DiskPerformanceExceededCollector({}, {})
    with patch('collectors.shutil.which', return_value=which), \
         patch.object(Executor, 'run_command', return_value=run_result):
        collector._collect(_disk_performance_vitals(provider=provider, used_devices=used_devices))

    assert collector.status == CollectorStatus.SKIPPED
    assert message in collector.message


def test_CPUSetCollector(doctor_factory, monkeypatch):
    with open('/tmp/perftune.yaml', 'w') as f:
        f.writelines(["tune:\r\n", "  - system"])

    with open('/tmp/cpuset.conf', 'w') as f:
        f.writelines(['CPUSET="--cpuset 1-7 --smp 1"'])

    monkeypatch_path("scylla_directory_configs", "/tmp",
                     [collectors.CPUSetCollector, collectors.ScyllaExtraConfigurationFilesCollector],
                     monkeypatch)

    doctor = doctor_factory(collectors=[collectors.ScyllaExtraConfigurationFilesCollector,
                                        collectors.CPUSetCollector])
    doctor.run()

    result = doctor.vitals['CPUSetCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    for key in ['cpusetconf_mask', 'perftune_mask', 'cpusetconf_intersect_perftune_mask']:
        assert key in result.data

    with open('/tmp/cpuset.conf', 'w') as f:
        f.writelines(['CPUSET="--smp 1"'])

    doctor = doctor_factory(collectors=[collectors.ScyllaExtraConfigurationFilesCollector,
                                        collectors.CPUSetCollector])
    doctor.run()

    result = doctor.vitals['CPUSetCollector']
    assert result.status == CollectorStatus.SKIPPED, result.message
    assert result.message == "cpuset setup was not performed using Scylla tools: '--cpuset' is not used in CPUSET"


def test_IPRoutesCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.IPRoutesCollector])
    doctor.run()

    result = doctor.vitals['IPRoutesCollector']
    assert result.status == CollectorStatus.PASSED

    for address in result.data:
        assert result.data[address]


def test_CqlshCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector])

    doctor.run()

    result = doctor.vitals['CqlshCollector']
    assert result.status == CollectorStatus.PASSED, result.message


def test_ServiceLevelsCollector(doctor_factory, await_scylla_start):
    sl_name = 'sd_test_service_level'
    Executor.paths = {'scylla_directory': '/opt/scylladb'}
    created = Executor.cqlsh(
        f"CREATE SERVICE LEVEL {sl_name} WITH SHARES = 200",
        {'rpc_address': 'localhost'}) is not None
    try:
        doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                            collectors.CqlshCollector,
                                            collectors.ServiceLevelsCollector])
        doctor.run()

        result = doctor.vitals['ServiceLevelsCollector']
        if result.status == CollectorStatus.SKIPPED:
            pytest.skip(result.message)
        if not created and result.status == CollectorStatus.FAILED:
            pytest.skip(result.message)
        assert result.status == CollectorStatus.PASSED, result.message
        command = Executor.read_cql_table_command('system.service_levels_v2')
        assert_output_gathered(result, OutputEntryType.CQL, command, empty_value_allowed=True)
        if created:
            assert sl_name in result.data
            assert result.data[sl_name].get('shares') == '200'
    finally:
        if created:
            Executor.cqlsh(f"DROP SERVICE LEVEL {sl_name}", {'rpc_address': 'localhost'})


@pytest.fixture(autouse=True, scope="function")
def setup_temp_keyspace():
    # Create a keyspace so that DESC SCHEMA command returns something
    Executor.paths = {'scylla_directory': '/opt/scylladb'}
    temp_ks_existed = Executor.cqlsh("CREATE KEYSPACE test_keyspace WITH "
                                     "replication = {'class': 'SimpleStrategy', 'replication_factor': '1'} ",
                                     {'rpc_address': 'localhost'}) is None
    yield
    if not temp_ks_existed:
        Executor.cqlsh("DROP KEYSPACE test_keyspace", {'rpc_address': 'localhost'})


def test_ScyllaClusterSchemaDescriptionCollector(doctor_factory, await_scylla_start, setup_temp_keyspace):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.ScyllaClusterSchemaDescriptionCollector])
    doctor.run()

    result = doctor.vitals['ScyllaClusterSchemaDescriptionCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.CQL, "DESC SCHEMA", value_content="test_keyspace")
    assert "test_keyspace" in result.data['schema']


def test_ScyllaClusterSystemKeyspacesCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.ScyllaClusterSystemKeyspacesCollector])

    doctor.run()

    result = doctor.vitals['ScyllaClusterSystemKeyspacesCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    for keyspace in ["system_auth", "system_distributed", "system_traces"]:
        assert keyspace in result.data


def test_ScyllaClusterStatusCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.ScyllaClusterStatusCollector])

    doctor.run()

    result = doctor.vitals['ScyllaClusterStatusCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    for status in ["up", "down", "joining", "leaving", "moving"]:
        assert status in result.data


def test_ScyllaClusterSchemaCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.ScyllaClusterSchemaCollector])

    doctor.run()

    result = doctor.vitals['ScyllaClusterSchemaCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data) > 0


@pytest.fixture
def setup_views_cdc_keyspace():
    # Create a keyspace with a CDC-enabled table and a materialized view
    Executor.paths = {'scylla_directory': '/opt/scylladb'}
    temp_ks_existed = Executor.cqlsh("CREATE KEYSPACE test_views_keyspace WITH "
                                     "replication = {'class': 'SimpleStrategy', 'replication_factor': '1'} ",
                                     {'rpc_address': 'localhost'}) is None
    try:
        assert Executor.cqlsh("CREATE TABLE test_views_keyspace.base (pk int PRIMARY KEY, v text) "
                              "WITH cdc = {'enabled': true}", {'rpc_address': 'localhost'}) is not None
        assert Executor.cqlsh(
            "CREATE MATERIALIZED VIEW test_views_keyspace.mv AS SELECT * FROM test_views_keyspace.base "
            "WHERE pk IS NOT NULL AND v IS NOT NULL PRIMARY KEY (v, pk)", {'rpc_address': 'localhost'}) is not None
        yield
    finally:
        if not temp_ks_existed:
            Executor.cqlsh("DROP KEYSPACE test_views_keyspace", {'rpc_address': 'localhost'})


def test_ScyllaClusterTablesDescriptionCollector(doctor_factory, await_scylla_start, setup_views_cdc_keyspace):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.ScyllaClusterTablesDescriptionCollector])

    doctor.run()

    result = doctor.vitals['ScyllaClusterTablesDescriptionCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    system_schema_tables_query = Executor.read_cql_table_command("system_schema.tables")
    assert_output_gathered(result, OutputEntryType.CQL, system_schema_tables_query)
    system_schema_views_query = Executor.read_cql_table_command("system_schema.views")
    assert_output_gathered(result, OutputEntryType.CQL, system_schema_views_query)
    assert len(result.data) > 1
    assert "system" in result.data

    ks_data = result.data['test_views_keyspace']
    assert ks_data['base']['table_kind'] == 'table'
    assert ks_data['base_scylla_cdc_log']['table_kind'] == 'table'
    assert ks_data['mv']['table_kind'] == 'view'


def test_ScyllaClusterTablesDescriptionCollector_merges_tables_and_views(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaClusterTablesDescriptionCollector], analyzers=())
    collector = doctor.collectors['ScyllaClusterTablesDescriptionCollector']
    vitals = {'ScyllaConfigurationFileCollector': CollectorResult(CollectorStatus.PASSED, {}, Output(), '')}

    schema_rows = {
        'system_schema.tables': [{'keyspace_name': 'ks', 'table_name': 'base'},
                                 {'keyspace_name': 'ks', 'table_name': 'base_scylla_cdc_log'}],
        'system_schema.views':  [{'keyspace_name': 'ks', 'view_name': 'mv'}],
    }

    def fake_read_cql_table(scylla_config, table_name, max_rows=-1):
        return f'SELECT * FROM {table_name}', schema_rows[table_name]

    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table):
        collector._collect(vitals)

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['ks']['base']['table_kind'] == 'table'
    assert collector._data['ks']['base_scylla_cdc_log']['table_kind'] == 'table'
    assert collector._data['ks']['mv']['table_kind'] == 'view'


def test_ScyllaClusterTablesDescriptionCollector_cql_failure(doctor_factory):
    from utils import CqlFailedException

    doctor = doctor_factory(collectors=[collectors.ScyllaClusterTablesDescriptionCollector], analyzers=())
    collector = doctor.collectors['ScyllaClusterTablesDescriptionCollector']
    vitals = {'ScyllaConfigurationFileCollector': CollectorResult(CollectorStatus.PASSED, {}, Output(), '')}

    with patch.object(Executor, 'read_cql_table', side_effect=CqlFailedException("boom")):
        collector._collect(vitals)

    assert collector.status == CollectorStatus.FAILED
    assert "boom" in collector._message


def test_ScyllaVersionCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaVersionCollector])
    doctor.run()

    result = doctor.vitals['ScyllaVersionCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert result.data['version']
    assert result.data['edition'] in ["oss", "enterprise", "development"]
    assert isinstance(result.data['packages'], list)
    assert any(["scylla" in package for package in result.data['packages']])


def test_ScyllaVersionCollector_edition(doctor_factory, monkeypatch):
    for edition, version, packages in [
        ("enterprise", "2021.1.5-0.20210818.fc817c0cd",
         "scylla-enterprise-server-2021.1.5-0.20210818.fc817c0cd.x86_64"),
        ("development", "5.1.dev-0.20220606.605ee74c39b2",
         "ii  scylla 5.1.dev-0.20220606.605ee74c39b2-1       amd64        Scylla database metapackage"),
        ("oss", "5.0.5-0.20221009.5a97a1060",
         "ii  scylla-server 5.0.5-0.20221009.5a97a1060-1      amd64        Scylla database server binaries"),
        # 2025.1+ no longer uses "enterprise" in the package name (DOCTOR-112)
        ("enterprise", "2026.1.9-0.20260716.66fb4eb48e87",
         "ii  scylla-server 2026.1.9-0.20260716.66fb4eb48e87-1 amd64 Scylla database server binaries"),
        ("enterprise", "2025.1.0", "scylla-server-2025.1.0.x86_64"),
        ("oss", "2024.2.0", "scylla-server-2024.2.0.x86_64"),
        # nightly/dev builds on 2025.1+ should still classify as development, not enterprise
        ("development", "2026.1.dev-0.20260716.66fb4eb48e87",
         "ii  scylla 2026.1.dev-0.20260716.66fb4eb48e87-1 amd64 Scylla database metapackage"),
    ]:
        doctor = doctor_factory(collectors=[collectors.ScyllaVersionCollector])

        def mock_run(command, shell=True, check=False, _version=version, _packages=packages):
            if "--version" in command:
                return subprocess.CompletedProcess(command, 0, stdout=_version + "\n")
            return subprocess.CompletedProcess(command, 0, stdout=_packages)

        monkeypatch.setattr(Executor, "run_command", mock_run)
        doctor.run()
        result = doctor.vitals['ScyllaVersionCollector']
        assert result.data['edition'] == edition
        assert result.data['version'] == version
        assert result.data['packages'] == [' '.join(packages.split())]


def test_ScyllaLimitNOFILECollector(doctor_factory, provider_identify_shorten_timeout_options):
    doctor = doctor_factory(collectors=[
        collectors.CPUSpecificationsCollector,
        collectors.NICsCollector,
        collectors.InfrastructureProviderCollector,
        collectors.NodePlatformCollector,
        collectors.ScyllaLimitNOFILECollector],
        config_options=provider_identify_shorten_timeout_options)

    doctor.run()

    result = doctor.vitals['ScyllaLimitNOFILECollector']
    if not is_container():
        assert result.status == CollectorStatus.PASSED, result.message
        assert result.data['limitnofile'] == "infinity" or result.data['limitnofile'].isdigit()
    else:
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available" in result.message


SYSTEMCTL_SHOW_TEMPLATE = """Type=simple
LimitNOFILE={limitnofile}
LimitNOFILESoft={limitnofile}
LimitNPROC=infinity
"""


def _run_limitnofile_collector(limitnofile):
    collector = collectors.ScyllaLimitNOFILECollector({}, {})
    vitals = {'NodePlatformCollector': CollectorResult(
        CollectorStatus.PASSED, {'platform': collectors.NodePlatform.BAREMETAL}, Output(), '')}

    with patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout="2000\n")), \
         patch('collectors.ServiceManager') as mock_sm_class:
        mock_sm_class.return_value.service_environment.return_value = \
            SYSTEMCTL_SHOW_TEMPLATE.format(limitnofile=limitnofile)
        collector._collect(vitals)

    return collector


@pytest.mark.parametrize("limitnofile", ["800000", " 800000 "])
def test_ScyllaLimitNOFILECollector_numeric_value(limitnofile):
    collector = _run_limitnofile_collector(limitnofile)

    assert collector.status == CollectorStatus.PASSED, collector._message
    assert collector._data == {'limitnofile': "800000"}


def test_ScyllaLimitNOFILECollector_infinity():
    # scylla-server.service ships 'LimitNOFILE=infinity' since scylladb/scylladb@78c8598 (DOCTOR-119)
    collector = _run_limitnofile_collector("infinity")

    assert collector.status == CollectorStatus.PASSED, collector._message
    assert collector._data == {'limitnofile': "infinity"}


@pytest.mark.parametrize("limitnofile", ["not-a-number", "", "-1"])
def test_ScyllaLimitNOFILECollector_unexpected_value(limitnofile):
    collector = _run_limitnofile_collector(limitnofile)

    assert collector.status == CollectorStatus.FAILED
    assert f"'{limitnofile}'" in collector._message


def test_SysctlCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.SysctlCollector])

    doctor.run()

    result = doctor.vitals['SysctlCollector']
    assert result.status == CollectorStatus.PASSED, result.message

    for value in ["fs.aio-max-nr", "fs.file-max", "fs.nr_open"]:
        assert value in result.data
    assert_output_gathered(result, OutputEntryType.STDOUT, "sysctl -a")


def test_ScyllaBinaryCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaBinaryCollector])

    doctor.run()

    result = doctor.vitals['ScyllaBinaryCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert 'scylla_bin' in result.data


def test_ScyllaLogsCollector(doctor_factory, provider_identify_shorten_timeout_options):
    doctor = doctor_factory(collectors=[collectors.NICsCollector,
                                        collectors.InfrastructureProviderCollector,
                                        collectors.CPUSpecificationsCollector,
                                        collectors.NodePlatformCollector,
                                        collectors.ScyllaLogsCollector],
                            config_options=provider_identify_shorten_timeout_options)

    doctor.run()

    result = doctor.vitals['ScyllaLogsCollector']
    if not is_container():
        assert result.status == CollectorStatus.PASSED, result.message
    else:
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available" in result.message


def _make_manager_agent_logs_collector(doctor_factory) -> collectors.ScyllaManagerAgentLogsCollector:
    """Instantiate a ScyllaManagerAgentLogsCollector without running it (no Scylla required)."""
    doctor = doctor_factory(collectors=[collectors.ScyllaManagerAgentLogsCollector], analyzers={})
    return doctor.collectors['ScyllaManagerAgentLogsCollector']


def _make_node_platform_vitals(platform) -> dict:
    return {
        'NodePlatformCollector': CollectorResult(CollectorStatus.PASSED, {'platform': platform}, Output(), ''),
    }


def test_ScyllaManagerAgentLogsCollector_skips_on_container(doctor_factory):
    collector = _make_manager_agent_logs_collector(doctor_factory)

    collector._collect(_make_node_platform_vitals(collectors.NodePlatform.CONTAINER))

    assert collector.status == CollectorStatus.SKIPPED
    assert "Not available" in collector.result.message


def test_ScyllaManagerAgentLogsCollector_skips_when_service_missing(doctor_factory):
    collector = _make_manager_agent_logs_collector(doctor_factory)

    with patch.object(collectors.ServiceManager, 'service_exists', return_value=False):
        collector._collect(_make_node_platform_vitals(collectors.NodePlatform.VM))

    assert collector.status == CollectorStatus.SKIPPED
    assert "not installed" in collector.result.message


def test_ScyllaManagerAgentLogsCollector_passes(doctor_factory):
    collector = _make_manager_agent_logs_collector(doctor_factory)

    with patch.object(collectors.ServiceManager, 'service_exists', return_value=True), \
            patch.object(Executor, 'generate_output_filename',
                         return_value="scylla_manager_agent_logs_test.txt"), \
            patch.object(Executor, 'run_command', return_value=Mock()) as mock_run:
        collector._collect(_make_node_platform_vitals(collectors.NodePlatform.BAREMETAL))

    assert collector.status == CollectorStatus.PASSED
    result = collector.result
    assert result.message == "Scylla Manager Agent logs gathered successfully"
    assert "scylla_manager_agent_logs_test.txt" not in result.message
    assert "scylla_manager_agent_logs_test.txt" in result.output.output[0].value
    result.strip()
    assert result.output.output == []
    command = mock_run.call_args.args[0]
    assert "--unit=scylla-manager-agent" in command


def test_ScyllaManagerAgentLogsCollector_passes_with_since_date(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaManagerAgentLogsCollector], analyzers={},
                            config_options=[('ScyllaManagerAgentLogsCollector', 'since_date', '2024-01-01')])
    collector = doctor.collectors['ScyllaManagerAgentLogsCollector']

    with patch.object(collectors.ServiceManager, 'service_exists', return_value=True), \
            patch.object(Executor, 'generate_output_filename', return_value="scylla_manager_agent_logs_test.txt"), \
            patch.object(Executor, 'run_command', return_value=Mock()) as mock_run:
        collector._collect(_make_node_platform_vitals(collectors.NodePlatform.VM))

    assert collector.status == CollectorStatus.PASSED
    command = mock_run.call_args.args[0]
    assert "--since=2024-01-01" in command


def test_ScyllaManagerAgentLogsCollector_fails_when_no_output(doctor_factory):
    collector = _make_manager_agent_logs_collector(doctor_factory)

    with patch.object(collectors.ServiceManager, 'service_exists', return_value=True), \
            patch.object(Executor, 'generate_output_filename', return_value="scylla_manager_agent_logs_test.txt"), \
            patch.object(Executor, 'run_command', return_value=None):
        collector._collect(_make_node_platform_vitals(collectors.NodePlatform.VM))

    assert collector.status == CollectorStatus.FAILED
    assert "Cannot gather Scylla Manager Agent logs" in collector.result.message


def test_ScyllaServicesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaServicesCollector])

    doctor.run()

    result = doctor.vitals['ScyllaServicesCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data) > 0
    for service in result.data.values():
        for key in ['active', 'autostarts']:
            assert key in service
            assert isinstance(service[key], bool)


def test_ScyllaSeedsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.ScyllaSeedsCollector])

    doctor.run()

    result = doctor.vitals['ScyllaSeedsCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data) > 0
    for seed in result.data:
        assert isinstance(result.data[seed], int)


def _seeds_config_vitals(seeds: str, storage_port: int = 7000) -> Dict:
    return {
        'ScyllaConfigurationFileCollector': CollectorResult(
            CollectorStatus.PASSED,
            {
                'seed_provider': [{'parameters': [{'seeds': seeds}]}],
                'storage_port': storage_port,
                'ssl_storage_port': 7001,
            },
            Output(), '',
        ),
    }


@pytest.mark.parametrize("seed,resolved_host", [
    ("127.0.0.1", "127.0.0.1"),
    ("2001:db8::1", "2001:db8::1"),
    ("[::1]", "::1"),
])
def test_ScyllaSeedsCollector_address_families(doctor_factory, seed, resolved_host):
    doctor = doctor_factory(collectors=[collectors.ScyllaSeedsCollector])
    collector = doctor.collectors['ScyllaSeedsCollector']

    fake_sock = Mock()
    fake_sock.__enter__ = Mock(return_value=fake_sock)
    fake_sock.__exit__ = Mock(return_value=False)

    with patch("collectors.socket.create_connection", return_value=fake_sock) as create_conn:
        collector._collect(_seeds_config_vitals(seed))

    assert collector.status == CollectorStatus.PASSED
    assert collector._data[seed] == 0
    create_conn.assert_called_once_with((resolved_host, 7000), timeout=2.0)


def test_ScyllaSeedsCollector_ipv6_connect_failure_errno(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaSeedsCollector])
    collector = doctor.collectors['ScyllaSeedsCollector']

    with patch("collectors.socket.create_connection",
               side_effect=ConnectionRefusedError(111, "Connection refused")):
        collector._collect(_seeds_config_vitals("2001:db8::1"))

    assert collector.status == CollectorStatus.PASSED
    assert collector._data["2001:db8::1"] == 111


def test_ScyllaSeedsCollector_gaierror_unreachable(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaSeedsCollector])
    collector = doctor.collectors['ScyllaSeedsCollector']

    with patch("collectors.socket.create_connection",
               side_effect=socket.gaierror(socket.EAI_NONAME, "unknown host")):
        collector._collect(_seeds_config_vitals("not-a-real-host.invalid"))

    assert collector.status == CollectorStatus.PASSED
    assert collector._data["not-a-real-host.invalid"] == -1


def test_ScyllaSeedsCollector_skips_empty_seed_entries(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaSeedsCollector])
    collector = doctor.collectors['ScyllaSeedsCollector']

    fake_sock = Mock()
    fake_sock.__enter__ = Mock(return_value=fake_sock)
    fake_sock.__exit__ = Mock(return_value=False)

    with patch("collectors.socket.create_connection", return_value=fake_sock):
        collector._collect(_seeds_config_vitals("2001:db8::1,"))

    assert collector.status == CollectorStatus.PASSED
    assert list(collector._data) == ["2001:db8::1"]
    assert collector._data["2001:db8::1"] == 0


def test_ScyllaSSTablesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ScyllaSSTablesCollector])

    doctor.run()

    result = doctor.vitals['ScyllaSSTablesCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert isinstance(result.data['files'], list)


def test_SELinuxCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.SELinuxCollector])

    doctor.run()

    result = doctor.vitals['SELinuxCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert "/etc/selinux/config" in result.data['files']


def test_SwapCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.SwapCollector])

    doctor.run()

    result = doctor.vitals['SwapCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert isinstance(result.data['total'], int)
    assert_output_gathered(result, OutputEntryType.FILE, '/proc/swaps')


def test_TCPConnectionsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.TCPConnectionsCollector])

    doctor.run()

    result = doctor.vitals['TCPConnectionsCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, 'ss --all --tcp')


def test_HypervisorTypeCollector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.HypervisorTypeCollector])

    doctor.run()

    result = doctor.vitals['HypervisorTypeCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, 'systemd-detect-virt')
    assert ('hypervisor' in result.data and isinstance(result.data['hypervisor'], str) and
            len(result.data['hypervisor']) > 0)


def test_NodetoolCFStatsCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.NodetoolCFStatsCollector])

    doctor.run()

    result = doctor.vitals['NodetoolCFStatsCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, 'nodetool cfstats',
                           value_content="Keyspace : system_traces")


def test_RaftTopologyRPCStatusCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.RaftTopologyRPCStatusCollector,
                                        collectors.CqlshCollector,
                                        collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.ScyllaConfigurationFileCollector])

    doctor.run()

    result = doctor.vitals['RaftTopologyRPCStatusCollector']
    if result.status == CollectorStatus.SKIPPED:
        pytest.skip(f"{result.message}")

    assert result.status == CollectorStatus.PASSED, result.message
    # There should be no Raft Topology operations in the air during CI/CD execution
    assert result.data == "none"


def test_ScyllaTablesCompressionInfoCollector(doctor_factory, await_scylla_start, setup_views_cdc_keyspace):
    doctor = doctor_factory(collectors=[collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.ScyllaTablesCompressionInfoCollector,
                                        collectors.ScyllaClusterTablesDescriptionCollector])

    doctor.run()
    result = doctor.vitals['ScyllaTablesCompressionInfoCollector']

    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data) > 0
    assert 'system_traces' in result.data and 'sessions' in result.data['system_traces'] and \
           result.data['system_traces']['sessions'] >= 0.0
    assert result.data['test_views_keyspace']['mv'] >= 0.0
    assert result.data['test_views_keyspace']['base_scylla_cdc_log'] >= 0.0


def test_ScyllaTablesUsedDiskCollector(doctor_factory, await_scylla_start, setup_views_cdc_keyspace):
    doctor = doctor_factory(collectors=[collectors.SystemConfigCollector,
                                        collectors.SystemPeersLocalCollector,
                                        collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.ScyllaTablesUsedDiskCollector,
                                        collectors.ScyllaClusterTablesDescriptionCollector])

    doctor.run()
    result = doctor.vitals['ScyllaTablesUsedDiskCollector']

    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data) > 0
    assert 'system_traces' in result.data and 'sessions' in result.data['system_traces'] and \
           result.data['system_traces']['sessions'] >= 0
    assert result.data['test_views_keyspace']['mv'] >= 0
    assert result.data['test_views_keyspace']['base_scylla_cdc_log'] >= 0


###############################################################################
# PerftuneSystemConfigurationCollector unit tests #############################
###############################################################################

def _make_perftune_collector(doctor_factory) -> collectors.PerftuneSystemConfigurationCollector:
    """Instantiate a PerftuneSystemConfigurationCollector without running it."""
    doctor = doctor_factory(collectors=[collectors.PerftuneSystemConfigurationCollector], analyzers=())
    return doctor.collectors['PerftuneSystemConfigurationCollector']


def _make_perftune_vitals(storage_data=None, hypervisor_data=None) -> dict:
    """Build minimal dependency vitals for PerftuneSystemConfigurationCollector."""
    return {
        'StorageConfigurationCollector': CollectorResult(
            CollectorStatus.PASSED,
            storage_data or {'/dev/sda': {'/var/lib/scylla': {'devices': {'nvme': []}}}},
            Output(),
            '',
        ),
        # Use 'xen' so the collector skips the extra NVMe smp_affinity probing step,
        # keeping the mock surface minimal.
        'HypervisorTypeCollector': CollectorResult(
            CollectorStatus.PASSED,
            hypervisor_data or {'hypervisor': 'xen'},
            Output(),
            '',
        ),
    }


def test_PerftuneSystemConfigurationCollector_missing_perftune_yaml(doctor_factory, monkeypatch):
    """Collector must FAIL immediately when perftune.yaml is not found."""
    collector = _make_perftune_collector(doctor_factory)

    monkeypatch.setattr(os.path, 'isfile', lambda _: False)
    collector._collect(_make_perftune_vitals())

    assert collector.status == CollectorStatus.FAILED
    assert "perftune.yaml is not found" in collector.result.message


def test_PerftuneSystemConfigurationCollector_all_files_readable(doctor_factory, monkeypatch):
    """Collector must PASS and populate data correctly when all sysfs files are readable."""
    sysfs_file = '/sys/class/net/eth0/queues/rx-0/rps_cpus'
    perftune_value = 'ff'
    current_value = '01'
    perftune_stdout = f"echo {perftune_value} > {sysfs_file}"

    collector = _make_perftune_collector(doctor_factory)
    monkeypatch.setattr(os.path, 'isfile', lambda _: True)

    with patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=perftune_stdout)), \
         patch.object(Executor, 'read_file_content', return_value=[f"{current_value}\n"]):
        collector._collect(_make_perftune_vitals())

    assert collector.status == CollectorStatus.PASSED
    # perftune's expected value and the actual current value must both be recorded
    assert collector._data['perftune']['files'][sysfs_file] == perftune_value
    assert collector._data['files'][sysfs_file] == current_value


def test_PerftuneSystemConfigurationCollector_unreadable_sysfs_file_does_not_fail(doctor_factory, monkeypatch):
    """
    When reading a sysfs file raises an exception the collector must still PASS,
    log the error to the output, and leave the failing file absent from the
    collected data. Files that can be read successfully must still be collected.
    """
    good_file = '/sys/class/net/eth0/queues/rx-0/rps_cpus'
    bad_file = '/sys/class/net/eth0/queues/rx-1/rps_cpus'
    error_msg = 'Permission denied'

    perftune_stdout = "\n".join([
        f"echo ff > {bad_file}",
        f"echo ff > {good_file}",
    ])

    def fake_read_file_content(path):
        if path == bad_file:
            raise OSError(error_msg)
        return ['ff\n']

    collector = _make_perftune_collector(doctor_factory)
    monkeypatch.setattr(os.path, 'isfile', lambda _: True)

    with patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=perftune_stdout)), \
         patch.object(Executor, 'read_file_content', side_effect=fake_read_file_content):
        collector._collect(_make_perftune_vitals())

    # Collector must still succeed despite the read error
    assert collector.status == CollectorStatus.PASSED

    # The unreadable file must be absent from the collected data
    assert bad_file not in collector._data['files']
    assert bad_file not in collector._data['perftune']['files']

    # The file that could be read must still be present
    assert good_file in collector._data['files']
    assert good_file in collector._data['perftune']['files']

    # The read error must have been logged to the output
    assert_output_gathered(collector.result, OutputEntryType.STDOUT, f"cat {bad_file}",
                           value_content=error_msg)

    # Good file content should be gathered as the file content
    assert_output_gathered(collector.result, OutputEntryType.FILE, good_file,
                           value_content=fake_read_file_content(good_file)[0])


def test_ProcInterruptsCollector(doctor_factory):
    """
    Verifies that ProcInterruptsCollector collects the content of /proc/interrupts
    """
    doctor = doctor_factory(collectors=[collectors.ProcInterruptsCollector])

    doctor.run()

    result = doctor.vitals['ProcInterruptsCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.FILE, '/proc/interrupts')


def test_LSPCICollector(doctor_factory, await_scylla_start):
    """
    Verifies that LSPCICollector collects the output of 'lspci -vvv' and it's not empty
    """
    doctor = doctor_factory(collectors=[collectors.LSPCICollector])

    doctor.run()

    result = doctor.vitals['LSPCICollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, 'lspci -vvv')


def test_SeastarCPUMapCollector(doctor_factory, await_scylla_start):
    """
    Verifies that SeastarCPUMapCollector collects the output of 'seastar-cpu-map.sh -n scylla' and it's not empty
    """
    doctor = doctor_factory(collectors=[collectors.SeastarCPUMapCollector])

    doctor.run()

    result = doctor.vitals['SeastarCPUMapCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, 'seastar-cpu-map.sh -n scylla',
                           value_content="shard: 0")
    assert result.data['shard_cpu_map'], "shard to CPU mapping is missing from the collector data"
    assert '0' in result.data['shard_cpu_map'], f"shard 0 is missing: {result.data['shard_cpu_map']}"


def test_SeastarCPUMapCollector_parses_shard_cpu_map():
    """
    Verifies that the shard to CPU mapping is parsed out of the 'seastar-cpu-map.sh' output into the collector data
    """
    cpu_map_output = (
        "shard: 0, cpu: 0\n"
        "shard: 1, cpu: 1,17\n"
    )
    collector = collectors.SeastarCPUMapCollector({}, {'scylla_directory_scripts': '/opt/scylladb/scripts'})
    with patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=cpu_map_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector.message
    assert collector._data['shard_cpu_map'] == {'0': '0', '1': '1,17'}
    assert_output_gathered(collector, OutputEntryType.VALUE, 'shard to CPU mapping', value_content='shard 1: CPU 1,17')


def test_SeastarCPUMapCollector_failed_without_shard_cpu_map():
    """
    Verifies that the collector fails when no shard to CPU mapping can be parsed, e.g. when Scylla is not running
    """
    collector = collectors.SeastarCPUMapCollector({}, {'scylla_directory_scripts': '/opt/scylladb/scripts'})
    with patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout='no scylla process found\n')):
        collector._collect({})

    assert collector.status == CollectorStatus.FAILED
    assert 'No shard to CPU mapping' in collector.message


def test_PerftuneSystemConfigurationCollector_multi_value_echo_line(doctor_factory, monkeypatch):
    """
    The new regex and parsing must capture the full space-separated value from echo lines
    that contain more than one token before the '>' — e.g.:
        echo 493986 658648 987971 > /proc/sys/net/ipv4/tcp_mem
    The perftune-expected value stored in _data['perftune']['files'] must be the entire
    string '493986 658648 987971', not just the first token.
    """
    sysfs_file = '/proc/sys/net/ipv4/tcp_mem'
    perftune_value = '493986 658648 987971'
    current_value = '185794 247726 371588'
    perftune_stdout = f"echo {perftune_value} > {sysfs_file}"

    collector = _make_perftune_collector(doctor_factory)
    monkeypatch.setattr(os.path, 'isfile', lambda _: True)

    with patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=perftune_stdout)), \
         patch.object(Executor, 'read_file_content', return_value=[f"{current_value}\n"]):
        collector._collect(_make_perftune_vitals())

    assert collector.status == CollectorStatus.PASSED
    # The full space-separated value must be stored, not just the first token
    assert collector._data['perftune']['files'][sysfs_file] == perftune_value
    assert collector._data['files'][sysfs_file] == current_value


def test_PerftuneSystemConfigurationCollector_value_and_path_are_stripped(doctor_factory, monkeypatch):
    """
    Value and file path must be stripped of surrounding whitespace after splitting on '>'.
    This covers any incidental extra spaces introduced by perftune output formatting.
    """
    sysfs_file = '/sys/class/net/eth0/queues/rx-0/rps_cpus'
    perftune_value = 'ff'
    # Extra spaces around '>' that can appear in perftune output
    perftune_stdout = f"echo  {perftune_value}  >  {sysfs_file}  "

    collector = _make_perftune_collector(doctor_factory)
    monkeypatch.setattr(os.path, 'isfile', lambda _: True)

    with patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=perftune_stdout)), \
         patch.object(Executor, 'read_file_content', return_value=[f"{perftune_value}\n"]):
        collector._collect(_make_perftune_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['perftune']['files'][sysfs_file] == perftune_value
    assert collector._data['files'][sysfs_file] == perftune_value


def test_PerftuneSystemConfigurationCollector_mixed_single_and_multi_value_lines(doctor_factory, monkeypatch):
    """
    A realistic perftune --dry-run output may mix single-value and multi-value echo lines.
    Both kinds must be parsed correctly in a single _collect() call.
    """
    single_value_file = '/sys/class/net/eth0/queues/rx-0/rps_cpus'
    single_value = 'ff'

    multi_value_file = '/proc/sys/net/ipv4/tcp_mem'
    multi_value = '493986 658648 987971'

    perftune_stdout = "\n".join([
        f"echo {single_value} > {single_value_file}",
        f"echo {multi_value} > {multi_value_file}",
    ])

    def fake_read(path):
        return [f"{single_value}\n"] if path == single_value_file else [f"{multi_value}\n"]

    collector = _make_perftune_collector(doctor_factory)
    monkeypatch.setattr(os.path, 'isfile', lambda _: True)

    with patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=perftune_stdout)), \
         patch.object(Executor, 'read_file_content', side_effect=fake_read):
        collector._collect(_make_perftune_vitals())

    assert collector.status == CollectorStatus.PASSED

    assert collector._data['perftune']['files'][single_value_file] == single_value
    assert collector._data['files'][single_value_file] == single_value

    assert collector._data['perftune']['files'][multi_value_file] == multi_value
    assert collector._data['files'][multi_value_file] == multi_value


def _make_sd_version_collector(doctor_factory) -> collectors.SDVersionCollector:
    doctor = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=())
    return doctor.collectors['SDVersionCollector']


def test_SDVersionCollector_version_file_present(doctor_factory, tmp_path, monkeypatch):
    """
    Version file on disk → PASSED with message containing the version string.
    """
    version = "1.2.3"
    version_file = tmp_path / "version"
    version_file.write_text(f"{version}\n")

    collector = _make_sd_version_collector(doctor_factory)
    monkeypatch.setattr(os.path, 'isfile', lambda p: p == str(version_file))
    monkeypatch.setattr(os.path, 'dirname', lambda _: str(tmp_path))

    collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['version'] == version
    assert version in collector._message


def test_SDVersionCollector_version_file_missing(doctor_factory, tmp_path, monkeypatch):
    """
    No version file → FAILED with hint to run 'make version'.
    """
    collector = _make_sd_version_collector(doctor_factory)
    monkeypatch.setattr(os.path, 'isfile', lambda _: False)
    monkeypatch.setattr(os.path, 'dirname', lambda _: str(tmp_path))

    collector._collect({})

    assert collector.status == CollectorStatus.FAILED
    assert "make version" in collector._message


###############################################################################
# SystemTabletsCollector unit tests ###########################################
###############################################################################

def _make_system_tablets_collector(doctor_factory, config_options=()):
    doctor = doctor_factory(collectors=[collectors.SystemTabletsCollector], analyzers=(),
                            config_options=config_options)
    return doctor.collectors['SystemTabletsCollector']


def _make_system_tablets_vitals():
    config_data = {'host': 'localhost', 'port': 9042, 'username': None, 'password': None}
    return {
        'ScyllaConfigurationFileCollector': CollectorResult(
            CollectorStatus.PASSED, config_data, Output(), '',
        ),
        'CqlshCollector': CollectorResult(
            CollectorStatus.PASSED, {}, Output(), '',
        ),
    }


_SYSTEM_TABLETS_COLUMNS = ['table_id', 'last_token', 'keyspace_name', 'table_name', 'replicas', 'base_table']


def test_SystemTabletsCollector_stores_nested_tables(doctor_factory):
    """
    Groups flat CQL rows under data.tables; shared table characteristics once;
    tablets sorted by last_token within each table.
    """
    rows = [
        {'table_id': 'bbbb', 'keyspace_name': 'ks_b', 'table_name': 't1', 'last_token': '200',
         'replicas': '[(bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb, 1)]', 'base_table': ''},
        {'table_id': 'aaaa', 'keyspace_name': 'ks_a', 'table_name': 't1', 'last_token': '100',
         'replicas': '[(aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 0)]', 'base_table': ''},
        {'table_id': 'aaaa', 'keyspace_name': 'ks_a', 'table_name': 't1', 'last_token': '50',
         'replicas': '[(aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 0)]', 'base_table': ''},
    ]
    # last_token sort is lexicographic (CQL COPY returns strings): '100' < '50'
    expected = {
        'tables': [
            {
                'keyspace_name': 'ks_a',
                'table_name': 't1',
                'table_id': 'aaaa',
                'base_table': '',
                'tablets': [
                    {'last_token': '100',
                     'replicas': '[(aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 0)]'},
                    {'last_token': '50',
                     'replicas': '[(aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 0)]'},
                ],
            },
            {
                'keyspace_name': 'ks_b',
                'table_name': 't1',
                'table_id': 'bbbb',
                'base_table': '',
                'tablets': [
                    {'last_token': '200',
                     'replicas': '[(bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb, 1)]'},
                ],
            },
        ]
    }

    seen = {}

    def fake_read_cql_table(scylla_config, table_name, columns=None, max_rows=-1):
        seen['table_name'] = table_name
        seen['columns'] = columns
        return ('COPY system.tablets ...', rows)

    collector = _make_system_tablets_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table):
        collector._collect(_make_system_tablets_vitals())

    assert seen['table_name'] == 'system.tablets'
    assert seen['columns'] == _SYSTEM_TABLETS_COLUMNS
    assert collector.status == CollectorStatus.PASSED
    assert collector._data == expected


def test_SystemTabletsCollector_empty_tablets(doctor_factory):
    """
    Empty system.tablets (no tablet-replicated tables) is a valid PASSED result.
    """
    collector = _make_system_tablets_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', return_value=('COPY system.tablets ...', [])):
        collector._collect(_make_system_tablets_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == {'tables': []}


def test_SystemTabletsCollector_max_rows_forwarded(doctor_factory):
    """
    Positive max_rows config value is forwarded to read_cql_table.
    """
    collector = _make_system_tablets_collector(
        doctor_factory,
        config_options=[('SystemTabletsCollector', 'max_rows', '10')],
    )
    seen = {}

    def fake_read_cql_table(scylla_config, table_name, columns=None, max_rows=-1):
        seen['columns'] = columns
        seen['max_rows'] = max_rows
        return ('COPY system.tablets ...', [])

    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table):
        collector._collect(_make_system_tablets_vitals())

    assert seen['max_rows'] == 10
    assert seen['columns'] == _SYSTEM_TABLETS_COLUMNS
    assert collector.status == CollectorStatus.PASSED
    assert "Collected 0 rows" in collector._message


def test_SystemTabletsCollector_cql_failure_sets_failed_status(doctor_factory):
    """
    CqlFailedException sets FAILED status with the error message.
    """
    from utils import CqlFailedException

    collector = _make_system_tablets_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', side_effect=CqlFailedException("no tablets table")):
        collector._collect(_make_system_tablets_vitals())

    assert collector.status == CollectorStatus.FAILED
    assert "no tablets table" in collector.result.message


def test_SystemTabletsCollector_missing_table_sets_skipped_status(doctor_factory):
    """
    system.tablets not existing (pre-tablets Scylla) is SKIPPED, not FAILED.
    """
    from utils import CqlFailedException

    collector = _make_system_tablets_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table',
                      side_effect=CqlFailedException("unconfigured table tablets")):
        collector._collect(_make_system_tablets_vitals())

    assert collector.status == CollectorStatus.SKIPPED


def test_SystemTabletsCollector_masks_all_data_from_drift(doctor_factory):
    """
    Masks all data so tablet maps are excluded from cluster drift comparison.
    """
    rows = [
        {'table_id': 'aaaa', 'keyspace_name': 'ks_a', 'table_name': 't1', 'last_token': '100',
         'replicas': '[(aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 0)]', 'base_table': ''},
    ]

    collector = _make_system_tablets_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', return_value=('COPY system.tablets ...', rows)):
        collector._collect(_make_system_tablets_vitals())

    assert collector.mask == ['*']

    result = collector.result
    assert result.data
    result.strip()
    assert result.data == {}


###############################################################################
# LargePartitionsCellsRowsCollector unit tests ################################
###############################################################################

def _make_large_partitions_collector(doctor_factory, config_options=()):
    doctor = doctor_factory(collectors=[collectors.LargePartitionsCellsRowsCollector], analyzers=(),
                            config_options=config_options)
    return doctor.collectors['LargePartitionsCellsRowsCollector']


def _make_large_partitions_vitals():
    config_data = {'host': 'localhost', 'port': 9042, 'username': None, 'password': None}
    return {
        'ScyllaConfigurationFileCollector': CollectorResult(
            CollectorStatus.PASSED, config_data, Output(), '',
        ),
        'CqlshCollector': CollectorResult(
            CollectorStatus.PASSED, {}, Output(), '',
        ),
    }


def _make_large_table_rows(n: int, table_suffix: str):
    return [{'keyspace_name': 'ks', 'table_name': f't_{table_suffix}_{i}',
             'sstable_data_size': str(i * 1000)} for i in range(n)]


def test_LargePartitionsCellsRowsCollector_collects_all_three_tables(doctor_factory):
    """
    All three tables are collected and stored under their full name.
    """
    collector = _make_large_partitions_collector(doctor_factory)

    large_partitions_rows = _make_large_table_rows(3, 'lp')
    large_cells_rows = _make_large_table_rows(2, 'lc')
    large_rows_rows = _make_large_table_rows(1, 'lr')

    table_data = {
        'system.large_partitions': large_partitions_rows,
        'system.large_cells':      large_cells_rows,
        'system.large_rows':       large_rows_rows,
    }

    def fake_read_cql_table(scylla_config, table_name, max_rows=-1):
        return (f'SELECT * FROM {table_name}', table_data[table_name])

    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table):
        collector._collect(_make_large_partitions_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['system.large_partitions'] == large_partitions_rows
    assert collector._data['system.large_cells'] == large_cells_rows
    assert collector._data['system.large_rows'] == large_rows_rows


def test_LargePartitionsCellsRowsCollector_default_max_rows_passes_minus_one(doctor_factory):
    """
    Default max_rows=-1 is passed as-is to read_cql_table, which treats negative values as no limit.
    """
    collector = _make_large_partitions_collector(doctor_factory)
    seen_max_rows = []

    def fake_read_cql_table(scylla_config, table_name, max_rows=-1):
        seen_max_rows.append(max_rows)
        return (f'SELECT * FROM {table_name}', [])

    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table):
        collector._collect(_make_large_partitions_vitals())

    assert all(mr == -1 for mr in seen_max_rows), f"Expected -1 for all, got {seen_max_rows}"


def test_LargePartitionsCellsRowsCollector_max_rows_forwarded(doctor_factory):
    """
    Positive max_rows config value is forwarded to read_cql_table.
    """
    collector = _make_large_partitions_collector(
        doctor_factory,
        config_options=[('LargePartitionsCellsRowsCollector', 'max_rows', '5')],
    )
    seen_max_rows = []

    def fake_read_cql_table(scylla_config, table_name, max_rows=-1):
        seen_max_rows.append(max_rows)
        return (f'SELECT * FROM {table_name}', [])

    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table):
        collector._collect(_make_large_partitions_vitals())

    assert all(mr == 5 for mr in seen_max_rows), f"Expected 5 for all, got {seen_max_rows}"
    assert collector.status == CollectorStatus.PASSED
    assert "Collected 5 rows per table (user configuration)" in collector._message


def test_LargePartitionsCellsRowsCollector_cql_failure_raises(doctor_factory):
    """
    CqlFailedException propagates out of _collect uncaught.
    """
    from utils import CqlFailedException

    collector = _make_large_partitions_collector(doctor_factory)

    with patch.object(Executor, 'read_cql_table', side_effect=CqlFailedException("boom")):
        with pytest.raises(CqlFailedException, match="boom"):
            collector._collect(_make_large_partitions_vitals())


def test_LargePartitionsCellsRowsCollector_masks_all_data_from_drift(doctor_factory):
    """
    The collector masks all its data so it is excluded from cluster drift comparison.
    """
    collector = _make_large_partitions_collector(doctor_factory)

    def fake_read_cql_table(scylla_config, table_name, max_rows=-1):
        return (f'SELECT * FROM {table_name}', _make_large_table_rows(2, table_name))

    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table):
        collector._collect(_make_large_partitions_vitals())

    assert collector.mask == ['*']

    result = collector.result
    assert result.data  # data was collected
    result.strip()
    assert result.data == {}  # all data stripped for comparison


###############################################################################
# RolePermissionsCollector unit tests #########################################
###############################################################################

def _make_role_permissions_collector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.RolePermissionsCollector], analyzers=())
    return doctor.collectors['RolePermissionsCollector']


def _make_role_permissions_vitals():
    config_data = {'host': 'localhost', 'port': 9042, 'username': None, 'password': None}
    return {
        'ScyllaConfigurationFileCollector': CollectorResult(
            CollectorStatus.PASSED, config_data, Output(), '',
        ),
        'CqlshCollector': CollectorResult(
            CollectorStatus.PASSED, {}, Output(), '',
        ),
    }


def test_RolePermissionsCollector_stores_rows(doctor_factory):
    """
    Collected rows are stored directly in _data.
    """
    rows = [
        {'role': 'cassandra', 'resource': 'data', 'permissions': {'ALTER', 'SELECT'}},
        {'role': 'admin',     'resource': 'data', 'permissions': {'DROP'}},
    ]

    collector = _make_role_permissions_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table',
                      return_value=('SELECT * FROM system.role_permissions', rows)):
        collector._collect(_make_role_permissions_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == sorted(rows, key=lambda r: r['role'])


def test_RolePermissionsCollector_cql_failure_raises(doctor_factory):
    """
    CqlFailedException propagates out of _collect uncaught.
    """
    from utils import CqlFailedException

    collector = _make_role_permissions_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', side_effect=CqlFailedException("auth error")):
        with pytest.raises(CqlFailedException, match="auth error"):
            collector._collect(_make_role_permissions_vitals())


# RolesCollector / DefaultCredentialsCollector unit tests #####################
###############################################################################

def _make_roles_collector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.RolesCollector], analyzers=())
    return doctor.collectors['RolesCollector']


def _make_default_credentials_collector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.DefaultCredentialsCollector], analyzers=())
    return doctor.collectors['DefaultCredentialsCollector']


def _make_auth_collector_vitals(authenticator='PasswordAuthenticator'):
    config_data = {'rpc_address': '127.0.0.1', 'authenticator': authenticator}
    return {
        'ScyllaConfigurationFileCollector': CollectorResult(
            CollectorStatus.PASSED, config_data, Output(), '',
        ),
        'CqlshCollector': CollectorResult(
            CollectorStatus.PASSED, {}, Output(), '',
        ),
    }


def test_RolesCollector_stores_sorted_rows_without_salted_hash(doctor_factory):
    """
    Roles are stored sorted by role name; collector requests non-sensitive columns only.
    """
    rows = [
        {'role': 'cassandra', 'is_superuser': 'True', 'can_login': 'True', 'member_of': ''},
        {'role': 'admin', 'is_superuser': 'True', 'can_login': 'True', 'member_of': ''},
    ]
    expected_columns = ['role', 'is_superuser', 'can_login', 'member_of']

    collector = _make_roles_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table',
                      return_value=('COPY system.roles ...', rows)) as mock_read:
        collector._collect(_make_auth_collector_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == sorted(rows, key=lambda r: r['role'])
    _, kwargs = mock_read.call_args
    assert kwargs.get('columns') == expected_columns


def test_RolesCollector_cql_failure_raises(doctor_factory):
    """
    CqlFailedException propagates out of _collect uncaught.
    """
    from utils import CqlFailedException

    collector = _make_roles_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', side_effect=CqlFailedException("auth error")):
        with pytest.raises(CqlFailedException, match="auth error"):
            collector._collect(_make_auth_collector_vitals())


# ServiceLevelsCollector unit tests ###########################################
###############################################################################

def _make_service_levels_collector(doctor_factory):
    doctor = doctor_factory(collectors=[collectors.ServiceLevelsCollector], analyzers=())
    return doctor.collectors['ServiceLevelsCollector']


def test_ServiceLevelsCollector_stores_rows_keyed_by_name(doctor_factory):
    rows = [
        {'service_level': 'olap', 'shares': '100', 'timeout': 'null', 'workload_type': 'batch'},
        {'service_level': 'oltp', 'shares': '1000', 'timeout': 'null', 'workload_type': 'interactive'},
    ]
    query = Executor.read_cql_table_command('system.service_levels_v2')

    collector = _make_service_levels_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', return_value=(query, rows)) as mock_read:
        collector._collect(_make_auth_collector_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == {
        'olap': rows[0],
        'oltp': rows[1],
    }
    mock_read.assert_called_once()
    assert mock_read.call_args.args[1] == 'system.service_levels_v2'


def test_ServiceLevelsCollector_empty_result(doctor_factory):
    query = Executor.read_cql_table_command('system.service_levels_v2')
    collector = _make_service_levels_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', return_value=(query, [])):
        collector._collect(_make_auth_collector_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == {}


def test_ServiceLevelsCollector_cql_failure(doctor_factory):
    from utils import CqlFailedException

    collector = _make_service_levels_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', side_effect=CqlFailedException("auth error")):
        collector._collect(_make_auth_collector_vitals())

    assert collector.status == CollectorStatus.FAILED
    assert "auth error" in collector.message


def test_ServiceLevelsCollector_missing_table_sets_skipped_status(doctor_factory):
    from utils import CqlFailedException

    collector = _make_service_levels_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table',
                      side_effect=CqlFailedException("unconfigured table service_levels_v2")):
        collector._collect(_make_auth_collector_vitals())

    assert collector.status == CollectorStatus.SKIPPED


def test_DefaultCredentialsCollector_skips_probe_when_auth_disabled(doctor_factory):
    """
    When authenticator does not require credentials, probe is not attempted.
    """
    collector = _make_default_credentials_collector(doctor_factory)
    with patch.object(Executor, 'cqlsh') as mock_cqlsh:
        collector._collect(_make_auth_collector_vitals(authenticator='AllowAllAuthenticator'))

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == {'default_user_login': 'not_verified'}
    mock_cqlsh.assert_not_called()


@pytest.mark.parametrize("authenticator", [
    'com.scylladb.auth.TransitionalAuthenticator',
    'TransitionalAuthenticator',
])
def test_DefaultCredentialsCollector_skips_probe_under_transitional_authenticator(doctor_factory, authenticator):
    """
    TransitionalAuthenticator lets bad passwords in anonymously, so the probe would always
    report allowed; it must be skipped rather than trusted.
    """
    collector = _make_default_credentials_collector(doctor_factory)
    with patch.object(Executor, 'cqlsh') as mock_cqlsh:
        collector._collect(_make_auth_collector_vitals(authenticator=authenticator))

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == {'default_user_login': 'not_verified'}
    mock_cqlsh.assert_not_called()


@pytest.mark.parametrize("authenticator", [
    'org.apache.cassandra.auth.PasswordAuthenticator',
    'PasswordAuthenticator',
    # CertificateOrPasswordAuthenticator falls back to password auth for clients without a
    # certificate, and rejects a bad password, so the probe is meaningful there too.
    'CertificateOrPasswordAuthenticator',
    'com.scylladb.auth.CertificateOrPasswordAuthenticator',
])
def test_DefaultCredentialsCollector_probes_password_authenticator_aliases(doctor_factory, authenticator):
    """
    Scylla resolves the authenticator by its case-insensitive short name, so FQN and short
    spellings of a password-capable authenticator are both probed.
    """
    collector = _make_default_credentials_collector(doctor_factory)
    mock_output = Mock()
    mock_output.returncode = 0
    with patch.object(Executor, 'cqlsh', return_value=mock_output) as mock_cqlsh:
        collector._collect(_make_auth_collector_vitals(authenticator=authenticator))

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == {'default_user_login': 'allowed'}
    mock_cqlsh.assert_called_once()


def test_DefaultCredentialsCollector_reports_allowed_default_user_login(doctor_factory):
    """
    Successful cqlsh with cassandra/cassandra marks default_user_login=allowed.
    """
    collector = _make_default_credentials_collector(doctor_factory)
    mock_output = Mock()
    mock_output.returncode = 0
    with patch.object(Executor, 'cqlsh', return_value=mock_output) as mock_cqlsh:
        collector._collect(_make_auth_collector_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == {'default_user_login': 'allowed'}
    mock_cqlsh.assert_called_once()
    assert mock_cqlsh.call_args.kwargs['user'] == 'cassandra'
    assert mock_cqlsh.call_args.kwargs['password'] == 'cassandra'


def test_DefaultCredentialsCollector_reports_denied_default_user_login(doctor_factory):
    """
    Failed cqlsh with cassandra/cassandra marks default_user_login=denied.
    """
    collector = _make_default_credentials_collector(doctor_factory)
    with patch.object(Executor, 'cqlsh', return_value=None):
        collector._collect(_make_auth_collector_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == {'default_user_login': 'denied'}
