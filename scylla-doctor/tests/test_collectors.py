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
import tests.helpers
import numbers
import os
import re
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
    assert result.status == CollectorStatus.PASSED
    assert '/proc/mdstat' in result.data


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


def test_ScyllaClusterTablesDescriptionCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[collectors.ScyllaConfigurationFileCollector,
                                        collectors.CqlshCollector,
                                        collectors.ScyllaClusterTablesDescriptionCollector])

    doctor.run()

    result = doctor.vitals['ScyllaClusterTablesDescriptionCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    system_schema_tables_query = Executor.read_cql_table_command("system_schema.tables")
    assert_output_gathered(result, OutputEntryType.CQL, system_schema_tables_query)
    assert len(result.data) > 1
    assert "system" in result.data


def test_ScyllaVersionCollector(doctor_factory, monkeypatch):
    doctor = doctor_factory(collectors=[collectors.ScyllaVersionCollector])
    doctor.run()

    result = doctor.vitals['ScyllaVersionCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert result.data['version']
    assert result.data['edition'] in ["oss", "enterprise", "development"]
    assert isinstance(result.data['packages'], list)
    assert any(["scylla" in package for package in result.data['packages']])

    for edition, packages in [
        ("enterprise", "scylla-enterprise-server-2021.1.5-0.20210818.fc817c0cd.x86_64"),
        ("development", "ii  scylla 5.1.dev-0.20220606.605ee74c39b2-1       amd64        Scylla database metapackage"),
        ("oss", "ii  scylla-server 5.0.5-0.20221009.5a97a1060-1      amd64        Scylla database server binaries")
    ]:
        doctor = doctor_factory(collectors=[collectors.ScyllaVersionCollector])

        def mock_run(command, shell=True, check=False):
            return subprocess.CompletedProcess(None, None, stdout=packages)

        monkeypatch.setattr(Executor, "run_command", mock_run)
        doctor.run()
        result = doctor.vitals['ScyllaVersionCollector']
        assert result.data['edition'] == edition
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
        assert result.data['limitnofile']
    else:
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available" in result.message


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


def test_ScyllaTablesCompressionInfoCollector(doctor_factory, await_scylla_start):
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


def test_ScyllaTablesUsedDiskCollector(doctor_factory, await_scylla_start):
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
