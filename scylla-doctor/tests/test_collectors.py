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
import datetime
import glob
import json
import tests.helpers
import numbers
import os
import pathlib
import re
import socket
from typing import Tuple, List, Dict
from unittest.mock import patch, Mock

import pytest
import shutil
import subprocess

from collectors.clients import ClientConnectionCollector, ServiceLevelsCollector
from collectors.cloud import (
    HypervisorTypeCollector,
    InfrastructureProviderCollector,
    MaintenanceEventsCollector,
    NodePlatformCollector,
)
from collectors.config import (
    ScyllaConfigurationFileCollector,
    ScyllaConfigurationFileNoParsingCollector,
    ScyllaSystemConfigurationFilesCollector,
    SystemConfigCollector,
)
from collectors.hardware import (
    CPUSpecificationsCollector,
    ComputerArchitectureCollector,
    LSPCICollector,
    ProcInterruptsCollector,
    RAMCollector,
)
from collectors.install import (
    CollectionTimeCollector,
    PathsCollector,
    SDVersionCollector,
    ScyllaBinaryCollector,
    ScyllaServicesCollector,
    ScyllaVersionCollector,
)
from collectors.logs import KernelRingBufferCollector, ScyllaLogsCollector, ScyllaManagerAgentLogsCollector
from collectors.network import (
    FirewallRulesCollector,
    IPAddressesCollector,
    IPRoutesCollector,
    NICsCollector,
    ScyllaSeedsCollector,
    TCPConnectionsCollector,
)
from collectors.operating_system import (
    CPUScalingCollector,
    ClockSourceCollector,
    CoredumpCollector,
    OSCollector,
    RsyslogCollector,
    SELinuxCollector,
    ScyllaLimitNOFILECollector,
    ServiceManagerCollector,
    SwapCollector,
    SysctlCollector,
)
from collectors.schema import (
    LargePartitionsCellsRowsCollector,
    NodetoolCFStatsCollector,
    ScyllaClusterSchemaCollector,
    ScyllaClusterSchemaDescriptionCollector,
    ScyllaClusterSystemKeyspacesCollector,
    ScyllaClusterTablesDescriptionCollector,
    ScyllaTablesCompressionInfoCollector,
    ScyllaTablesUsedDiskCollector,
)
from collectors.security import CqlshCollector, DefaultCredentialsCollector, RolePermissionsCollector, RolesCollector
from collectors.storage import (
    NVMeDevicesCollector,
    NitroDetailedStatsCollector,
    RAIDSetupCollector,
    ScyllaSSTablesCollector,
    StorageConfigurationCollector,
)
from collectors.time_sync import (
    ChronyStatusCollector,
    NTPServicesCollector,
    NTPStatusCollector,
)
from collectors.topology import (
    GossipInfoCollector,
    RaftGroup0Collector,
    RaftTopologyRPCStatusCollector,
    ScyllaClusterStatusCollector,
    SystemClusterStatusCollector,
    SystemPeersLocalCollector,
    SystemTabletsCollector,
    SystemTopologyCollector,
    TokenMetadataHostsMappingCollector,
)
from collectors.tuning import (
    CPUSetCollector,
    PerftuneSystemConfigurationCollector,
    PerftuneYamlDefaultCollector,
    ScyllaExtraConfigurationFilesCollector,
    SeastarCPUMapCollector,
)
from collectors_base import Collector, CollectorStatus, CollectorResult, Output
from common import GossipInfoInvariantValues, NodePlatform
from models.output_entry import OutputEntryType
from utils import Executor, ServiceManager, running_in_container, CQL_REQUEST_TIMEOUT_SECONDS
import scylla_doctor

from tests.helpers import assert_output_gathered, assert_output_not_gathered, live_scylla_cql_config


def monkeypatch_path(path, dir, collector_classes, monkeypatch):
    def init(self, configuration, paths):
        Collector.__init__(self, configuration, paths)
        paths = copy.deepcopy(self._paths._DictView__source)
        paths['scylla_directory_configs'] = "/tmp"
        self._paths = paths

    for cls in collector_classes:
        monkeypatch.setattr(cls, '__init__', init, raising=False)


def test_CPUSpecificationsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[CPUSpecificationsCollector])
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
    doctor = doctor_factory(collectors=[FirewallRulesCollector])
    doctor.run()

    result = doctor.vitals['FirewallRulesCollector']
    # Privileged containers (CI) can run iptables, unprivileged and rootless ones are refused.
    if running_in_container() and result.status == CollectorStatus.SKIPPED:
        assert "iptables needs CAP_NET_ADMIN" in result.message
        return
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, "iptables -L -v")


IPTABLES_REFUSED = \
    "iptables v1.8.10 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)\n"


@pytest.mark.parametrize("in_container,returncode,stderr,expected_status,expected_message", [
    (False, 0, "", CollectorStatus.PASSED, ""),
    (True, 0, "", CollectorStatus.PASSED, "the node's only with --network host"),
    (True, 4, IPTABLES_REFUSED, CollectorStatus.SKIPPED, "iptables needs CAP_NET_ADMIN"),
    (False, 4, IPTABLES_REFUSED, CollectorStatus.FAILED, "`iptables` call failed"),
    # Errors other than a refusal stay FAILED inside a container too.
    (True, 3, "iptables v1.8.10 (legacy): can't initialize iptables table `filter': Table does not exist\n",
     CollectorStatus.FAILED, "`iptables` call failed"),
])
def test_FirewallRulesCollector_refused(in_container, returncode, stderr, expected_status, expected_message):
    collector = FirewallRulesCollector({}, {})
    stdout = "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\n" if returncode == 0 else ""
    completed = subprocess.CompletedProcess(["iptables", "-L", "-v"], returncode, stdout=stdout, stderr=stderr)

    with patch('collectors.network.running_in_container', return_value=in_container), \
         patch.object(Executor, 'run_command', return_value=completed) as run_command:
        collector._collect({})

    run_command.assert_called_once_with("iptables -L -v", check=False)
    result = collector.result
    assert result.status == expected_status, result.message
    assert expected_message in result.message
    if returncode != 0:
        assert stderr.strip() in result.message
    else:
        assert_output_gathered(result, OutputEntryType.STDOUT, "iptables -L -v")


@pytest.mark.parametrize("in_container", [False, True])
def test_FirewallRulesCollector_empty_output(in_container):
    collector = FirewallRulesCollector({}, {})
    completed = subprocess.CompletedProcess(["iptables", "-L", "-v"], 0, stdout="", stderr="")

    with patch('collectors.network.running_in_container', return_value=in_container), \
         patch.object(Executor, 'run_command', return_value=completed):
        collector._collect({})

    result = collector.result
    assert result.status == CollectorStatus.PASSED, result.message
    assert ("network namespace" in result.message) == in_container


@pytest.mark.parametrize("collector_class,tool", [
    (FirewallRulesCollector, 'iptables'),
    (HypervisorTypeCollector, 'systemd-detect-virt'),
])
def test_missing_command_at_run_time(collector_class, tool):
    """Collectors that run their tool directly rely on the base class to skip it when it is not installed."""
    collector = collector_class({}, {})
    vitals: dict = {}
    with patch('collectors_base.os.getuid', return_value=0), \
         patch.object(Executor, 'run_command',
                      side_effect=FileNotFoundError(2, "No such file or directory", tool)):
        collector.collect(vitals, {})

    assert vitals[collector.id].status == CollectorStatus.SKIPPED, vitals[collector.id].message
    assert vitals[collector.id].message == f"'{tool}' not installed"


@pytest.mark.parametrize("collector_class,tools", [
    (NICsCollector, ['ethtool']),
    (SeastarCPUMapCollector, ['pgrep', 'taskset']),
    (SeastarCPUMapCollector, ['taskset']),
])
def test_missing_tool(collector_class, tools):
    """A tool that is not installed skips the collector and names every missing tool, and only those."""
    collector = collector_class({}, {})
    with patch('collectors_base.shutil.which',
               side_effect=lambda tool: None if tool in tools else '/usr/bin/' + tool), \
         patch.object(Executor, 'run_command', side_effect=AssertionError("must not run")):
        collector._collect({})

    assert collector.status == CollectorStatus.SKIPPED, collector.result.message
    assert collector.result.message == f"{', '.join(repr(tool) for tool in tools)} not installed"


def test_InfrastructureProviderCollector(doctor_factory, provider_identify_shorten_timeout_options):
    doctor = doctor_factory(collectors=[NICsCollector,
                                        InfrastructureProviderCollector],
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


@pytest.mark.parametrize("provider,expected_status,expected_data", [
    (None, CollectorStatus.SKIPPED, {}),
    (Mock(scheduled_maintenance_events=[]), CollectorStatus.PASSED, {'scheduled_maintenance_events': []}),
])
def test_MaintenanceEventsCollector(doctor_factory, provider, expected_status, expected_data):
    # Provider detection is patched: on real cloud hosts (e.g. GitHub-hosted runners on Azure) the scheduled
    # events endpoint can be slow or unreachable, which made this test environment-dependent.
    with patch('utils.InfrastructureProvider.identify', return_value=provider):
        doctor = doctor_factory(collectors=[MaintenanceEventsCollector])
        doctor.run()
    result = doctor.vitals['MaintenanceEventsCollector']
    assert result.status == expected_status
    assert result.data == expected_data


def test_NodePlatformCollector(doctor_factory, monkeypatch):
    doctor = doctor_factory(collectors=[NodePlatformCollector])
    # Outside a container the platform needs the provider and CPU collectors.
    monkeypatch.setattr('collectors.cloud.running_in_container', lambda: False)
    with pytest.raises(Exception) as e:
        doctor.run()
    assert "Dependencies are not available" in str(e)

    doctor = doctor_factory(collectors=[
        NodePlatformCollector,
        NICsCollector,
        InfrastructureProviderCollector,
        CPUSpecificationsCollector
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

    monkeypatch.setattr('collectors.cloud.running_in_container', lambda: True)
    doctor.run()
    result = doctor.vitals['NodePlatformCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data['platform'] == NodePlatform.CONTAINER
    del doctor.vitals['NodePlatformCollector']

    monkeypatch.setattr('collectors.cloud.running_in_container', lambda: False)
    doctor.run()
    result = doctor.vitals['NodePlatformCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data['platform'] == NodePlatform.BAREMETAL
    del doctor.vitals['NodePlatformCollector']

    cpu_result.data['flags'] = ["hypervisor"]
    doctor.run()
    result = doctor.vitals['NodePlatformCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data['platform'] == NodePlatform.VM
    del doctor.vitals['NodePlatformCollector']

    infra_result = CollectorResult(CollectorStatus.PASSED,
                                   {'provider': "AWS"}, Output(), None)
    doctor.vitals['InfrastructureProviderCollector'] = infra_result
    doctor.run()
    result = doctor.vitals['NodePlatformCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data['platform'] == NodePlatform.CLOUD


def test_NodePlatformCollector_container_without_dependencies(doctor_factory, monkeypatch):
    """
    In a container the platform is known from the marker file alone, so NodePlatformCollector must not depend on
    collectors that need ethtool or lscpu (absent from the stock Scylla image).
    """
    doctor = doctor_factory(collectors=[NodePlatformCollector])
    monkeypatch.setattr('collectors.cloud.running_in_container', lambda: True)

    assert doctor.collectors['NodePlatformCollector'].depends_on == set()
    doctor.run()

    result = doctor.vitals['NodePlatformCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert result.data['platform'] == NodePlatform.CONTAINER


def test_ServiceManagerCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ServiceManagerCollector])
    doctor.run()

    result = doctor.vitals['ServiceManagerCollector']
    assert result.status == CollectorStatus.PASSED
    assert isinstance(result.data['service_manager'], ServiceManager.Interface)


def test_ClockSourceCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ClockSourceCollector])
    doctor.run()

    result = doctor.vitals['ClockSourceCollector']
    assert result.status == CollectorStatus.PASSED
    assert 'clocksource' in result.data


def test_CPUScalingCollector(doctor_factory):
    doctor = doctor_factory(collectors=[CPUScalingCollector])
    doctor.run()

    result = doctor.vitals['CPUScalingCollector']
    if running_in_container():
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available for containers" in result.message
        return
    assert result.status == CollectorStatus.PASSED, result.message
    assert 'scaling_governor' in result.data
    assert len(result.data['services']) > 0


def test_CoredumpCollector(doctor_factory):
    doctor = doctor_factory(collectors=[CoredumpCollector])

    doctor.run()

    result = doctor.vitals['CoredumpCollector']
    if running_in_container():
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available for containers" in result.message
        return
    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data['services']) > 0
    assert 'files' in result.data


def test_ClientConnectionCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        ClientConnectionCollector])

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
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        SystemConfigCollector,
                                        GossipInfoCollector,
                                        SystemPeersLocalCollector])

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


def _make_gossip_info_collector(doctor_factory) -> GossipInfoCollector:
    """Instantiate a GossipInfoCollector without running it (no Scylla required)."""
    doctor = doctor_factory(collectors=[GossipInfoCollector], analyzers={})
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
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        TokenMetadataHostsMappingCollector])

    doctor.run()
    result = doctor.vitals['TokenMetadataHostsMappingCollector']

    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data['hosts']) > 0
    assert '127.0.0.1' in result.data['hosts']


def test_RaftGroup0Collector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        RaftGroup0Collector])

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
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        SystemPeersLocalCollector])

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


_SYSTEM_CLUSTER_STATUS_QUERY = f"SELECT * FROM system.cluster_status USING TIMEOUT {CQL_REQUEST_TIMEOUT_SECONDS}s"

# cqlsh table output of system.cluster_status: one live node and one decommissioned node still in gossip.
_SYSTEM_CLUSTER_STATUS_STDOUT = (
    "\n"
    " peer      | dc          | host_id                              | load   | owns | status | tokens | up\n"
    "-----------+-------------+--------------------------------------+--------+------+--------+--------+-------\n"
    " 127.0.0.1 | datacenter1 | 33ad8814-05c8-4d4d-b072-871a8dbe00b8 | 229724 | null | NORMAL |    256 |  True\n"
    " 10.0.0.2  |        null | 7b5c1c8e-0d35-4e0f-9a2c-1f1b7e2b9a11 |   null |    0 |   LEFT |    256 | False\n"
    "\n"
    "(2 rows)\n")


def _make_system_cluster_status_collector(doctor_factory):
    doctor = doctor_factory(collectors=[SystemClusterStatusCollector], analyzers=())
    return doctor.collectors['SystemClusterStatusCollector']


def _make_system_cluster_status_vitals():
    return {
        'ScyllaConfigurationFileCollector': CollectorResult(CollectorStatus.PASSED, {'rpc_address': '127.0.0.1'},
                                                            Output(), ''),
        'CqlshCollector': CollectorResult(CollectorStatus.PASSED, {}, Output(), ''),
    }


def test_SystemClusterStatusCollector_reads_with_a_server_side_timeout(doctor_factory):
    """
    The virtual table is read with a SELECT carrying USING TIMEOUT (COPY cannot), parsed like COPY output:
    'load' dropped, decommissioned (LEFT) nodes skipped; a null cell is '' as COPY printed it, not cqlsh's 'null'.
    """
    collector = _make_system_cluster_status_collector(doctor_factory)
    output = Mock(returncode=0, stdout=_SYSTEM_CLUSTER_STATUS_STDOUT)
    with patch.object(Executor, 'cqlsh', return_value=output) as mock_cqlsh:
        collector._collect(_make_system_cluster_status_vitals())

    assert collector.status == CollectorStatus.PASSED, collector._message
    assert mock_cqlsh.call_args.args[0] == _SYSTEM_CLUSTER_STATUS_QUERY
    assert collector._data == {'hosts': {
        '127.0.0.1': {'dc': 'datacenter1', 'host_id': '33ad8814-05c8-4d4d-b072-871a8dbe00b8', 'owns': '',
                      'status': 'NORMAL', 'tokens': '256', 'up': 'True'},
    }}


def test_SystemClusterStatusCollector_fails_when_the_read_fails(doctor_factory):
    collector = _make_system_cluster_status_collector(doctor_factory)
    with patch.object(Executor, 'cqlsh', return_value=None):
        collector._collect(_make_system_cluster_status_vitals())

    assert collector.status == CollectorStatus.FAILED
    assert collector._message == f"{_SYSTEM_CLUSTER_STATUS_QUERY} failed"


def test_SystemClusterStatusCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        SystemClusterStatusCollector])

    doctor.run()

    result = doctor.vitals['SystemClusterStatusCollector']

    # Query successful test
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.CQL, _SYSTEM_CLUSTER_STATUS_QUERY)

    assert len(result.data['hosts']) > 0
    assert '127.0.0.1' in result.data['hosts']
    assert len(result.data['hosts']['127.0.0.1']) > 0


def test_SystemConfigCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        SystemConfigCollector,
                                        SystemPeersLocalCollector])

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
    doctor = doctor_factory(collectors=[SystemConfigCollector], analyzers=(),
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
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        GossipInfoCollector,
                                        SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        SystemTopologyCollector])

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
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        GossipInfoCollector,
                                        SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        SystemTopologyCollector])
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

    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        GossipInfoCollector,
                                        SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        SystemTopologyCollector])
    doctor.run()

    result = doctor.vitals['SystemTopologyCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert result.data['consistent_topology_supported'] is True

    rows = result.data['system_topology_rows']
    assert len(rows) == 1
    # Tokens must be sorted alphabetically so cross-node comparison is deterministic
    assert rows[0]['tokens'] == "{'token_a', 'token_b', 'token_c'}"


def test_ScyllaExtraConfigurationFilesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaExtraConfigurationFilesCollector])
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
def test_KernelRingBufferCollector(doctor_factory):
    doctor = doctor_factory(collectors=[KernelRingBufferCollector])
    doctor.run()

    result = doctor.vitals['KernelRingBufferCollector']
    # Unprivileged and rootless containers are refused by the kernel, privileged ones can read the buffer.
    if running_in_container() and result.status == CollectorStatus.SKIPPED:
        assert "dmesg needs CAP_SYSLOG" in result.message
        return
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, "dmesg -T")


DMESG_REFUSED = "dmesg: read kernel buffer failed: Operation not permitted\n"


@pytest.mark.parametrize("marker,returncode,stderr,expected_status,expected_message", [
    (None, 0, "", CollectorStatus.PASSED, ""),
    ("/.dockerenv", 0, "", CollectorStatus.PASSED, ""),                 # privileged Docker
    ("/run/.containerenv", 0, "", CollectorStatus.PASSED, ""),          # privileged rootful Podman
    ("/.dockerenv", 1, DMESG_REFUSED, CollectorStatus.SKIPPED, "dmesg needs CAP_SYSLOG"),
    # rootless Podman
    ("/run/.containerenv", 1, DMESG_REFUSED, CollectorStatus.SKIPPED, "dmesg needs CAP_SYSLOG"),
    (None, 1, DMESG_REFUSED, CollectorStatus.FAILED, "Cannot collect `dmesg -T`"),
    # Errors other than a refusal stay FAILED inside a container too.
    ("/.dockerenv", 1, "dmesg: unrecognized option: T\n", CollectorStatus.FAILED, "Cannot collect `dmesg -T`"),
])
def test_KernelRingBufferCollector_refused(monkeypatch, marker, returncode, stderr, expected_status,
                                           expected_message):
    collector = KernelRingBufferCollector({}, {})
    # run_command pipes stdout and stderr separately, dmesg reports the refusal on stderr.
    stdout = "[Thu Oct 15 07:00:00 2026] Linux version 6.8.0\n" if returncode == 0 else ""
    completed = subprocess.CompletedProcess(["dmesg", "-T"], returncode, stdout=stdout, stderr=stderr)
    # Drive the real detection through the Docker or Podman marker file, with no container variable to fall back on.
    monkeypatch.setattr(os.path, 'isfile', lambda path: path == marker)
    monkeypatch.delenv("container", raising=False)

    with patch('builtins.open', Mock(side_effect=PermissionError("/proc/1/environ"))), \
         patch.object(Executor, 'run_command', return_value=completed) as run_command:
        collector._collect({})

    run_command.assert_called_once_with("dmesg -T", check=False)
    result = collector.result
    assert result.status == expected_status, result.message
    assert expected_message in result.message
    if returncode != 0:
        assert stderr.strip() in result.message


def test_CollectionTimeCollector(doctor_factory):
    doctor = doctor_factory(collectors=[CollectionTimeCollector])
    before = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    doctor.run()
    after = datetime.datetime.now(datetime.timezone.utc)

    result = doctor.vitals['CollectionTimeCollector']
    assert result.status == CollectorStatus.PASSED
    collected_at = datetime.datetime.fromisoformat(result.data['collected_at'])
    assert collected_at.tzinfo is not None, "the UTC offset must be recorded"
    assert before <= collected_at <= after
    assert result.message == "Collection time recorded"
    # collection times always differ between nodes: keep them out of the cluster diff
    assert result.mask == ['*']
    result.strip()
    assert result.data == {}


def test_PathsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[PathsCollector])

    doctor.run()

    result = doctor.vitals['PathsCollector']
    assert result.status == CollectorStatus.PASSED
    assert result.data == doctor.environment.paths


def test_NICsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[NICsCollector])
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
    doctor = doctor_factory(collectors=[NICsCollector])
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

    with patch.object(shutil, 'which', return_value="/usr/sbin/ethtool"), \
            patch.object(glob, 'glob',
                         return_value=["/sys/class/net/eth0", "/sys/class/net/erspan0"]), \
            patch.object(pathlib.Path, 'is_symlink', return_value=True), \
            patch.object(Executor, 'run_command', side_effect=fake_run_command):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector.result.message
    nics = collector.result.data['nics']
    assert nics['eth0'] == {'driver': 'virtio_net', 'speed': 10000}
    assert 'erspan0' not in nics


def test_NICsCollector_skips_configured_nics(doctor_factory):
    """Configured skip_nics extends the built-in defaults."""
    doctor = doctor_factory(
        collectors=[NICsCollector],
        config_options=[('NICsCollector', 'skip_nics', 'dummy0')],
    )
    collector = doctor.collectors['NICsCollector']

    def fake_run_command(command, check=True, **kwargs):
        assert "dummy0" not in command
        result = Mock()
        result.returncode = 0
        result.stdout = ""
        return result

    with patch.object(shutil, 'which', return_value="/usr/sbin/ethtool"), \
            patch.object(glob, 'glob',
                         return_value=["/sys/class/net/eth0", "/sys/class/net/dummy0"]), \
            patch.object(pathlib.Path, 'is_symlink', return_value=True), \
            patch.object(Executor, 'run_command', side_effect=fake_run_command):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector.result.message
    assert 'dummy0' not in collector.result.data['nics']


def test_NICsCollector_fails_when_ethtool_errors_on_real_nic(doctor_factory):
    """ethtool failure on a non-skipped NIC must fail the collector."""
    doctor = doctor_factory(collectors=[NICsCollector])
    collector = doctor.collectors['NICsCollector']

    def fake_run_command(command, check=True, **kwargs):
        if command.startswith("ethtool eth0"):
            raise subprocess.CalledProcessError(1, command, "Device not supported\n")
        result = Mock()
        result.returncode = 0
        result.stdout = "driver: virtio_net\n"
        return result

    with patch.object(shutil, 'which', return_value="/usr/sbin/ethtool"), \
            patch.object(glob, 'glob', return_value=["/sys/class/net/eth0"]), \
            patch.object(pathlib.Path, 'is_symlink', return_value=True), \
            patch.object(Executor, 'run_command', side_effect=fake_run_command):
        collector.collect({}, doctor.collectors)

    assert collector.status == CollectorStatus.FAILED
    assert "ethtool eth0" in collector.result.message


def test_IPAddressesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[IPAddressesCollector, NICsCollector])
    doctor.run()

    result = doctor.vitals['IPAddressesCollector']
    assert result.status == CollectorStatus.PASSED
    for nic in doctor.vitals['NICsCollector'].data['nics']:
        assert_output_gathered(result, OutputEntryType.STDOUT, f"ip addr show {nic}")


def test_ComputerArchitectureCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ComputerArchitectureCollector])
    doctor.run()

    result = doctor.vitals['ComputerArchitectureCollector']
    assert result.status == CollectorStatus.PASSED
    for key in ["architecture", "kernel_version"]:
        assert key in result.data


def test_NTPStatusCollector(doctor_factory):
    doctor = doctor_factory(collectors=[NTPStatusCollector])
    doctor.run()

    result = doctor.vitals['NTPStatusCollector']
    if running_in_container():
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available" in result.message
    else:
        assert result.status == CollectorStatus.PASSED, result.message
        assert 'ntp_enabled' in result.data and 'ntp_synchronized' in result.data


@pytest.mark.parametrize("stdout,expected_data", [
    ("yes\n", {'ntp_enabled': True, 'ntp_synchronized': True}),
    ("no\n", {'ntp_enabled': False, 'ntp_synchronized': False}),
])
def test_NTPStatusCollector_mocked(stdout, expected_data):
    collector = NTPStatusCollector({}, {})
    completed = subprocess.CompletedProcess(["timedatectl"], 0, stdout=stdout)

    with patch.object(Executor, 'run_command', return_value=completed):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector.result.message
    assert collector.result.data == expected_data


def test_NTPServicesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[NTPServicesCollector])
    doctor.run()

    result = doctor.vitals['NTPServicesCollector']
    if running_in_container():
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available for containers" in result.message
        return
    assert result.status == CollectorStatus.PASSED, result.message
    assert all(['active' in result.data['services'][service] for service in result.data['services']])
    assert isinstance(result.data['chrony_installed'], bool)


@pytest.mark.parametrize("chronyd_path, installed", [("/usr/sbin/chronyd", True), (None, False)])
def test_NTPServicesCollector_chrony_installed(chronyd_path, installed):
    collector = NTPServicesCollector({}, {})
    with patch('collectors.time_sync.ServiceManager') as mock_sm_class, \
         patch('shutil.which', return_value=chronyd_path):
        mock_sm_class.return_value.service_active.return_value = False
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['chrony_installed'] is installed


def test_ChronyStatusCollector_skipped_without_chronyc():
    collector = ChronyStatusCollector({}, {})
    with patch('shutil.which', return_value=None):
        collector._collect({})

    assert collector.status == CollectorStatus.SKIPPED
    assert 'chronyc is not installed' in collector.message


def test_ChronyStatusCollector_skipped_when_tracking_fails():
    collector = ChronyStatusCollector({}, {})
    with patch('shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=1, stdout='506 Cannot talk to daemon\n')):
        collector._collect({})

    assert collector.status == CollectorStatus.SKIPPED
    assert 'chronyc tracking failed' in collector.message


def test_ChronyStatusCollector_failed_without_leap_status():
    collector = ChronyStatusCollector({}, {})
    with patch('shutil.which', return_value='/usr/bin/chronyc'), \
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
    collector = ChronyStatusCollector({}, {})
    with patch('shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=tracking_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['chrony_synchronized'] is True
    assert collector._data['leap_status'] == 'Normal'


def test_ChronyStatusCollector_not_synchronized():
    tracking_output = "Leap status     : Not synchronised\n"
    collector = ChronyStatusCollector({}, {})
    with patch('shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=tracking_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['chrony_synchronized'] is False
    assert collector._data['leap_status'] == 'Not synchronised'


@pytest.mark.parametrize('leap_status', ['Insert second', 'Delete second'])
def test_ChronyStatusCollector_synchronized_leap_second(leap_status):
    tracking_output = f"Leap status     : {leap_status}\n"
    collector = ChronyStatusCollector({}, {})
    with patch('shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=tracking_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['chrony_synchronized'] is True
    assert collector._data['leap_status'] == leap_status


def test_ChronyStatusCollector_unknown_leap_status_treated_as_synchronized():
    tracking_output = "Leap status     : Future status\n"
    collector = ChronyStatusCollector({}, {})
    with patch('shutil.which', return_value='/usr/bin/chronyc'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=tracking_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['chrony_synchronized'] is True


@pytest.mark.parametrize("collector_class", [
    NTPStatusCollector,
    NTPServicesCollector,
    CoredumpCollector,
    CPUScalingCollector,
    NVMeDevicesCollector,
    PerftuneYamlDefaultCollector,
    ScyllaLimitNOFILECollector,
    ScyllaLogsCollector,
    ScyllaManagerAgentLogsCollector,
])
def test_skip_in_container_collectors(doctor_factory, collector_class):
    """
    These collectors read host state a container usually cannot see: in a container the base class skips them with
    their reason, before their dependencies are resolved or _collect runs.
    """
    doctor = doctor_factory(collectors=[collector_class], analyzers={})
    reason = doctor.collectors[collector_class.__name__].skip_in_container
    assert isinstance(reason, str) and reason

    with patch('collectors_base.running_in_container', return_value=True), \
         patch.object(collector_class, '_collect', side_effect=AssertionError("_collect must not run")):
        doctor.run()

    result = doctor.vitals[collector_class.__name__]
    assert result.status == CollectorStatus.SKIPPED
    assert result.message == f"Not available for containers: {reason}"
    assert result.data == {}


def test_OSCollector(doctor_factory):
    doctor = doctor_factory(collectors=[OSCollector])
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
                     [PerftuneSystemConfigurationCollector], monkeypatch)

    doctor = doctor_factory(collectors=[NICsCollector,
                                        CPUSpecificationsCollector,
                                        ScyllaExtraConfigurationFilesCollector,
                                        CPUSetCollector,
                                        InfrastructureProviderCollector,
                                        NodePlatformCollector,
                                        ScyllaConfigurationFileCollector,
                                        StorageConfigurationCollector,
                                        CqlshCollector,
                                        SystemPeersLocalCollector,
                                        SystemConfigCollector,
                                        HypervisorTypeCollector,
                                        PerftuneSystemConfigurationCollector],
                            config_options=provider_identify_shorten_timeout_options)
    doctor.run()

    result = doctor.vitals['PerftuneSystemConfigurationCollector']
    assert result.status == CollectorStatus.PASSED, result.message


def test_ScyllaSystemConfigurationFilesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaSystemConfigurationFilesCollector])
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
    doctor = doctor_factory(collectors=[RAMCollector])
    doctor.run()

    result = doctor.vitals['RAMCollector']
    assert result.status == CollectorStatus.PASSED
    assert_output_gathered(result, OutputEntryType.STDOUT, 'free')
    assert_output_gathered(result, OutputEntryType.FILE, '/proc/meminfo')
    assert isinstance(result.data['total'], numbers.Number)


def test_RsyslogCollector(doctor_factory):
    doctor = doctor_factory(collectors=[RsyslogCollector])
    doctor.run()

    result = doctor.vitals['RsyslogCollector']
    assert result.status == CollectorStatus.PASSED
    assert "/etc/rsyslog.d/scylla.conf" in result.data['files']


def test_ScyllaConfigurationFileCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector])
    doctor.run()

    result = doctor.vitals['ScyllaConfigurationFileCollector']
    assert result.status == CollectorStatus.PASSED
    assert 'storage_port' in result.data
    assert 'pure_scylla_yaml' in result.data


def test_PerftuneYamlDefaultCollector(doctor_factory, provider_identify_shorten_timeout_options):
    doctor = doctor_factory(collectors=[NICsCollector,
                                        InfrastructureProviderCollector,
                                        CPUSpecificationsCollector,
                                        NodePlatformCollector,
                                        ScyllaSystemConfigurationFilesCollector,
                                        ScyllaExtraConfigurationFilesCollector,
                                        PerftuneYamlDefaultCollector],
                            config_options=provider_identify_shorten_timeout_options)
    doctor.run()

    result = doctor.vitals['PerftuneYamlDefaultCollector']
    if not running_in_container():
        assert result.status == CollectorStatus.PASSED, result.message
    else:
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available for containers" in result.message


def test_StorageConfigurationCollector(doctor_factory, provider_identify_shorten_timeout_options, await_scylla_start):
    doctor = doctor_factory(collectors=[
                                NodePlatformCollector,
                                NICsCollector,
                                InfrastructureProviderCollector,
                                CPUSpecificationsCollector,
                                StorageConfigurationCollector,
                                ScyllaConfigurationFileCollector,
                                CqlshCollector,
                                SystemConfigCollector,
                                SystemPeersLocalCollector],
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


def test_StorageConfigurationCollector_is_network_backed(monkeypatch):
    models = {
        '/sys/block/nvme0n1/device/model': ['Amazon Elastic Block Store              \n'],
        '/sys/block/nvme1n1/device/model': ['Amazon EC2 NVMe Instance Storage        \n'],
    }

    def fake_read(path):
        try:
            return models[path]
        except KeyError:
            raise FileNotFoundError(path)

    monkeypatch.setattr(Executor, 'read_file_content', fake_read)

    assert StorageConfigurationCollector._is_network_backed('nvme0n1') is True
    # partition names resolve to the parent disk
    assert StorageConfigurationCollector._is_network_backed('nvme0n1p1') is True
    assert StorageConfigurationCollector._is_network_backed('nvme1n1') is False
    # unknown device (no model file) is not treated as network-backed
    assert StorageConfigurationCollector._is_network_backed('sda') is False


def test_StorageConfigurationCollector_collect_wires_network_backed(doctor_factory, monkeypatch):
    """
    _collect() must expose _is_network_backed()'s verdict through devices['network_backed'],
    not just the standalone helper. The locality check spans both the nvme and the non_nvme list.
    """
    doctor = doctor_factory(collectors=[StorageConfigurationCollector])
    collector = doctor.collectors['StorageConfigurationCollector']

    perftune_stdout = (
        "Setting NVMe disks: nvme0n1, nvme1n1XXX\n"
        "Setting non-NVMe disks: sdaXXX\n"
    )
    mount_stdout = "/dev/nvme0n1 on /var/lib/scylla/data type xfs (rw,noatime)\n"
    df_stdout = (
        "Filesystem   Type 1K-blocks Used Available Use% Mounted on\n"
        "/dev/nvme0n1 xfs  100       10   90        10%  /var/lib/scylla/data\n"
    )

    def fake_run_command(command, *args, **kwargs):
        if "perftune.py" in command:
            stdout = perftune_stdout
        elif command == "mount":
            stdout = mount_stdout
        elif command.startswith("df -T"):
            stdout = df_stdout
        else:
            raise AssertionError(f"unexpected command: {command}")
        return subprocess.CompletedProcess(args=command, returncode=0, stdout=stdout)

    models = {
        '/sys/block/nvme0n1/device/model': ['Amazon Elastic Block Store              \n'],
        '/sys/block/nvme1n1/device/model': ['Amazon EC2 NVMe Instance Storage        \n'],
        '/sys/block/sda/device/model': ['Amazon Elastic Block Store              \n'],
    }

    def fake_read_file_content(path):
        try:
            return models[path]
        except KeyError:
            raise FileNotFoundError(path)

    fake_statvfs = os.statvfs_result((4096, 4096, 1000, 900, 900, 0, 0, 0, 0, 255))

    monkeypatch.setattr(Executor, 'run_command', fake_run_command)
    monkeypatch.setattr(Executor, 'read_file_content', fake_read_file_content)
    monkeypatch.setattr(os, 'statvfs', lambda path: fake_statvfs)

    vitals = {
        'SystemConfigCollector': CollectorResult(
            CollectorStatus.PASSED,
            {
                'workdir,W': {'value': ''},
                'data_file_directories': {'value': ['/var/lib/scylla/data']},
                'commitlog_directory': {'value': '/var/lib/scylla/commitlog'},
                'hints_directory': {'value': '/var/lib/scylla/hints'},
                'view_hints_directory': {'value': '/var/lib/scylla/view_hints'},
            },
            Output(), '',
        ),
    }

    collector._collect(vitals)

    assert collector.status == CollectorStatus.PASSED
    devices = collector._data['data_file_directories']['/var/lib/scylla/data']['devices']
    assert devices['nvme'] == ['nvme0n1', 'nvme1n1']
    assert devices['non_nvme'] == ['sda']
    assert devices['network_backed'] == ['nvme0n1', 'sda']


def test_RAIDSetupCollector(doctor_factory):
    doctor = doctor_factory(collectors=[RAIDSetupCollector])
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
    doctor = doctor_factory(collectors=[RAIDSetupCollector])
    collector = doctor.collectors['RAIDSetupCollector']

    with patch.object(Executor, 'read_file_content', side_effect=FileNotFoundError("/proc/mdstat")):
        collector._collect({})

    assert collector.status == CollectorStatus.SKIPPED
    assert "not present" in collector.result.message


def test_RAIDSetupCollector_passes_when_mdstat_present(doctor_factory):
    doctor = doctor_factory(collectors=[RAIDSetupCollector])
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

    parsed_a = RAIDSetupCollector._parse_mdstat(content_a)
    parsed_b = RAIDSetupCollector._parse_mdstat(content_b)

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

    assert RAIDSetupCollector._parse_mdstat(content) == {
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

    assert RAIDSetupCollector._parse_mdstat(content) == {
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

    collector = NVMeDevicesCollector({}, {})
    with patch('os.listdir', side_effect=fake_listdir), \
         patch('os.path.isdir', side_effect=fake_isdir), \
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

    collector = NVMeDevicesCollector({}, {})
    with patch('os.listdir', side_effect=fake_listdir), \
         patch('os.path.isdir', side_effect=fake_isdir), \
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

    collector = NVMeDevicesCollector({}, {})
    with patch('os.listdir', side_effect=fake_listdir), \
         patch('os.path.isdir', side_effect=fake_isdir), \
         patch.object(Executor, 'run_command', side_effect=fake_run):
        collector._collect(vitals)

    assert collector.status == CollectorStatus.PASSED, collector.message
    assert collector._data['nvme_devices'] == ['nvme1n1']
    assert collector._data['unused_nvme_devices'] == ['nvme1n1']


###############################################################################
# ScyllaConfigurationCollector: credential redaction (DOCTOR-130) #############
###############################################################################

# Credentials a Scylla configuration may carry (encryption at rest KMS, Azure and KMIP hosts, LDAP role manager).
# None of them may reach the vitals or the verbose output, and none is a substring of a key or flag name. Plain mock
# values: a real-looking key (e.g. the AWS documentation examples) trips secret scanners on the test file.
_REDACTED = '<redacted>'
_SECRET_VALUES = ('mock-aws-key-id', 'mock-aws-key-secret', 'mock-ldap-pass', 'mock-azure-secret', 'mock-kmip-pass')
_KMS_HOST = {'aws_region': 'eu-west-1', 'aws_access_key_id': _SECRET_VALUES[0],
             'aws_secret_access_key': _SECRET_VALUES[1], 'aws_session_token': ''}
_KMS_HOST_REDACTED = {'aws_region': 'eu-west-1', 'aws_access_key_id': _REDACTED, 'aws_secret_access_key': _REDACTED,
                      'aws_session_token': ''}
# A plain value, a flow-style mapping and a block scalar (the credential on a line of its own).
_SCYLLA_YAML_WITH_SECRETS = (
    "cluster_name: test_cluster\n"
    "kms_hosts:\n"
    "  prod:\n"
    f"    aws_region: {_KMS_HOST['aws_region']}\n"
    f"    aws_access_key_id: {_KMS_HOST['aws_access_key_id']}\n"
    f"    aws_secret_access_key: {_KMS_HOST['aws_secret_access_key']}\n"
    "    aws_session_token: ''\n"
    f"azure_hosts: {{vault: {{azure_tenant_id: tenant, azure_client_secret: {_SECRET_VALUES[3]}}}}}\n"
    "kmip_hosts:\n"
    "  kmip1:\n"
    "    hosts: kmip.example.com\n"
    "    username: scylla\n"
    "    password: |-\n"
    f"      {_SECRET_VALUES[4]}\n"
    f"ldap_bind_passwd: {_SECRET_VALUES[2]}\n"
)
_KMIP_HOST_REDACTED = {'hosts': 'kmip.example.com', 'username': 'scylla', 'password': _REDACTED}


def _make_config_collector(doctor_factory, collector_class):
    return doctor_factory(collectors=[collector_class], analyzers=()).collectors[collector_class.__name__]


def _make_scylla_yaml_collector(doctor_factory, tmp_path, collector_class):
    (tmp_path / "scylla.yaml").write_text(_SCYLLA_YAML_WITH_SECRETS)
    collector = _make_config_collector(doctor_factory, collector_class)
    collector._paths = {'scylla_directory_config': str(tmp_path)}
    return collector


def _assert_no_secret_in_output(collector):
    for entry in collector._output:
        for secret in _SECRET_VALUES:
            assert secret not in str(entry.value), f"{secret} leaked into {entry.type} {entry.name}"


@pytest.mark.parametrize("text, redacted", [
    # Command line flags, e.g. SCYLLA_ARGS in sysconfig: a quoted value goes whole, spaces included; a bare one up to
    # the next flag, whatever it contains (the sysconfig parser removes double quotes, so `"a b"` arrives as `a b`).
    ("--smp 2 --ldap-bind-passwd=pass --x 1", "--smp 2 --ldap-bind-passwd=<redacted> --x 1"),
    ("--ldap-bind-passwd pass", "--ldap-bind-passwd <redacted>"),
    ("--smp 2 --ldap-bind-passwd='a b' --x 1", "--smp 2 --ldap-bind-passwd=<redacted> --x 1"),
    ('--ldap-bind-passwd "a b" --x 1', "--ldap-bind-passwd <redacted> --x 1"),
    ("--ldap-bind-passwd=a b --x 1", "--ldap-bind-passwd=<redacted> --x 1"),
    ("--ldap-bind-passwd=pa,ss]it'sme --x 1", "--ldap-bind-passwd=<redacted> --x 1"),
    ("--ldap-bind-passwd=--secret --x 1", "--ldap-bind-passwd=<redacted> --x 1"),
    ("-Djavax.net.ssl.keyStorePassword=x -Dfoo=bar", "-Djavax.net.ssl.keyStorePassword=<redacted> -Dfoo=bar"),
    # An environment file line, whatever the case.
    ("AWS_SECRET_ACCESS_KEY=mock", "AWS_SECRET_ACCESS_KEY=<redacted>"),
    # JSON, JSON inside a JSON string and flow-style YAML, as system.config prints object_storage_endpoints: a quoted
    # value goes whole, escaped quotes included.
    ('{"aws_access_key_id": "mock", "aws_region": "eu"}', '{"aws_access_key_id": <redacted>, "aws_region": "eu"}'),
    ('{"aws_secret_access_key": "ab\\"cd", "aws_region": "eu"}',
     '{"aws_secret_access_key": <redacted>, "aws_region": "eu"}'),
    ('{"s3": "{\\"aws_access_key_id\\":\\"mo\\\\\\"ck\\",\\"region\\":\\"eu\\"}"}',
     '{"s3": "{\\"aws_access_key_id\\":<redacted>,\\"region\\":\\"eu\\"}"}'),
    # The same once cqlsh COPY, behind read_cql_table, has doubled every backslash: the form the vitals hold.
    ('{"s3": "{ \\\\"aws_access_key_id\\\\": \\\\"mo\\\\\\\\\\\\"ck\\\\", \\\\"region\\\\": \\\\"eu\\\\" }"}',
     '{"s3": "{ \\\\"aws_access_key_id\\\\": <redacted>, \\\\"region\\\\": \\\\"eu\\\\" }"}'),
    ('{"s3": "{ \\\\"aws_session_token\\\\": \\\\"\\\\", \\\\"region\\\\": \\\\"eu\\\\" }"}',
     '{"s3": "{ \\\\"aws_session_token\\\\": \\\\"\\\\", \\\\"region\\\\": \\\\"eu\\\\" }"}'),
    ("{aws_access_key_id: mock, aws_region: eu}", "{aws_access_key_id: <redacted>, aws_region: eu}"),
    ("{aws_access_key_id: ab cd , aws_region: eu}", "{aws_access_key_id: <redacted> , aws_region: eu}"),
    ("aws_access_key_id: ab cd\naws_region: eu", "aws_access_key_id: <redacted>\naws_region: eu"),
    ("{aws_access_key_id: 'it''s', aws_region: eu}", "{aws_access_key_id: <redacted>, aws_region: eu}"),
    # A bare flag value stays on its line.
    ("--ldap-bind-passwd=x\nkeep me", "--ldap-bind-passwd=<redacted>\nkeep me"),
    ("--ldap-bind-passwd x y\n--smp 2", "--ldap-bind-passwd <redacted>\n--smp 2"),
    # A bare `key=value` value does not stop at a comma (a password may hold one): the rest of a comma-separated
    # mapping goes with it.
    ("{name=s3, aws_secret_access_key=ABC, region=eu}", "{name=s3, aws_secret_access_key=<redacted>"),
    # Already redacted: unchanged.
    ("--ldap-bind-passwd=<redacted> --x 1", "--ldap-bind-passwd=<redacted> --x 1"),
    # An unset value, and a word that only contains a secret key's name, are kept.
    ("aws_session_token: ''", "aws_session_token: ''"),
    ('{"aws_session_token": null, "aws_region": "eu"}', '{"aws_session_token": null, "aws_region": "eu"}'),
    ('{"s3": "{\\"aws_access_key_id\\":\\"\\"}"}', '{"s3": "{\\"aws_access_key_id\\":\\"\\"}"}'),
    ('{"s3": "{\\"aws_access_key_id\\":\\"\\",\\"region\\":\\"eu\\"}"}',
     '{"s3": "{\\"aws_access_key_id\\":\\"\\",\\"region\\":\\"eu\\"}"}'),
    ("AWS_SESSION_TOKEN=", "AWS_SESSION_TOKEN="),
    ("--ldap-bind-passwd= --smp 2", "--ldap-bind-passwd= --smp 2"),
    ("my_aws_secret_access_key: keep", "my_aws_secret_access_key: keep"),
    ("--authenticator PasswordAuthenticator", "--authenticator PasswordAuthenticator"),
    # A secret key's name followed by a space is a value only after a flag, not in prose.
    ("Change the password for user x", "Change the password for user x"),
    ("-keystore-password secret -x", "-keystore-password <redacted> -x"),
])
def test_ScyllaConfigurationCollector_redacts_text(doctor_factory, text, redacted):
    collector = _make_config_collector(doctor_factory, ScyllaConfigurationFileCollector)
    assert collector._redact_credentials(text) == redacted


def test_ScyllaConfigurationCollector_redacts_entries(doctor_factory):
    config = {
        'kms_hosts': {'prod': _KMS_HOST},
        'object_storage_endpoints': [{'name': 's3', 'aws_access_key_id': _SECRET_VALUES[0]}],
        'AWS_SECRET_ACCESS_KEY': _SECRET_VALUES[1],  # sysconfig keeps the case of its keys
        'client_encryption_options': {'keystore_password': 'x', 'keystore': '/etc/scylla/keystore'},
        # yaml.BaseLoader keeps a null and an empty value as strings: the credential is still unset.
        'ldap_bind_passwd': 'null', 'azure_hosts': {'vault': {'azure_client_secret': "''"}}, 'password': '~',
        'kmip_password': 'NULL', 'keystore_password': 'Null',
        # An environment file line written as a shell `export`.
        'export AWS_ACCESS_KEY_ID': _SECRET_VALUES[0],
        'num_tokens': 256, 1: 'a non-string key',
    }
    assert _make_config_collector(doctor_factory, ScyllaConfigurationFileCollector)._redact_credentials(config) == {
        'kms_hosts': {'prod': _KMS_HOST_REDACTED},
        'object_storage_endpoints': [{'name': 's3', 'aws_access_key_id': _REDACTED}],
        'AWS_SECRET_ACCESS_KEY': _REDACTED,
        'client_encryption_options': {'keystore_password': _REDACTED, 'keystore': '/etc/scylla/keystore'},
        'ldap_bind_passwd': 'null', 'azure_hosts': {'vault': {'azure_client_secret': "''"}}, 'password': '~',
        'kmip_password': 'NULL', 'keystore_password': 'Null',
        'export AWS_ACCESS_KEY_ID': _REDACTED,
        'num_tokens': 256, 1: 'a non-string key',
    }


def test_ScyllaConfigurationFileCollector_redacts_secrets(doctor_factory, tmp_path):
    collector = _make_scylla_yaml_collector(doctor_factory, tmp_path, ScyllaConfigurationFileCollector)
    collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector._message
    for config in (collector._data, collector._data['pure_scylla_yaml']):
        assert config['cluster_name'] == 'test_cluster'
        assert config['kms_hosts']['prod'] == _KMS_HOST_REDACTED
        assert config['azure_hosts']['vault'] == {'azure_tenant_id': 'tenant', 'azure_client_secret': _REDACTED}
        assert config['kmip_hosts']['kmip1'] == _KMIP_HOST_REDACTED
        assert config['ldap_bind_passwd'] == _REDACTED
    _assert_no_secret_in_output(collector)
    # The verbose output is the parsed file, before the defaults and the resolved addresses are added.
    parsed_file = next(entry.value for entry in collector._output if entry.type == OutputEntryType.PARSED_FILE)
    assert parsed_file['kms_hosts']['prod'] == _KMS_HOST_REDACTED
    assert 'pure_scylla_yaml' not in parsed_file and 'resolved' not in parsed_file


def test_ScyllaConfigurationFileNoParsingCollector_redacts_secrets(doctor_factory, tmp_path):
    collector = _make_scylla_yaml_collector(doctor_factory, tmp_path, ScyllaConfigurationFileNoParsingCollector)
    collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector._message
    assert collector._data['cluster_name'] == 'test_cluster'
    assert collector._data['kms_hosts']['prod'] == _KMS_HOST_REDACTED
    assert collector._data['kmip_hosts']['kmip1'] == _KMIP_HOST_REDACTED
    assert collector._data['ldap_bind_passwd'] == _REDACTED


def test_ScyllaSystemConfigurationFilesCollector_redacts_secrets(doctor_factory, tmp_path):
    sysconfig = tmp_path / "etc" / "sysconfig"
    sysconfig.mkdir(parents=True)
    # A double-quoted flag value with a space (the parser removes the quotes) and a '%' in a value (no interpolation).
    (sysconfig / "scylla-server").write_text(
        f'SCYLLA_ARGS="--log-to-syslog 1 --ldap-bind-passwd \\"{_SECRET_VALUES[2]} x\\" --smp 2"\n'
        f'AWS_ACCESS_KEY_ID={_SECRET_VALUES[0]}\n'
        f'AWS_SECRET_ACCESS_KEY={_SECRET_VALUES[1]}%(x\n'
        'AWS_SESSION_TOKEN=\n')
    collector = _make_config_collector(doctor_factory, ScyllaSystemConfigurationFilesCollector)
    collector._paths = {'scylla_directory': str(tmp_path)}
    real_isdir = os.path.isdir

    # Only the per-user directory under tmp_path, never the host's /etc.
    with patch('os.path.isdir', side_effect=lambda d: not d.startswith('/etc') and real_isdir(d)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector._message
    assert collector._data['files']['scylla-server'] == {
        'SCYLLA_ARGS': f'--log-to-syslog 1 --ldap-bind-passwd {_REDACTED} --smp 2', 'AWS_ACCESS_KEY_ID': _REDACTED,
        'AWS_SECRET_ACCESS_KEY': _REDACTED, 'AWS_SESSION_TOKEN': ''}
    _assert_no_secret_in_output(collector)


def test_ScyllaExtraConfigurationFilesCollector_redacts_secrets(doctor_factory, tmp_path):
    # scylla-server.service reads every /etc/scylla.d/*.conf as an environment file.
    (tmp_path / "aws.conf").write_text(f'AWS_SECRET_ACCESS_KEY={_SECRET_VALUES[1]}\n'
                                       f'SCYLLA_ARGS="--ldap-bind-passwd={_SECRET_VALUES[2]} --smp 2"\n')
    (tmp_path / "cpuset.conf").write_text('CPUSET="--cpuset 0-3"\n')
    collector = _make_config_collector(doctor_factory, ScyllaExtraConfigurationFilesCollector)
    collector._paths = {'scylla_directory_configs': str(tmp_path)}
    collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector._message
    assert collector._data['files'] == {
        'aws.conf': {'AWS_SECRET_ACCESS_KEY': _REDACTED, 'SCYLLA_ARGS': f'--ldap-bind-passwd={_REDACTED} --smp 2'},
        'cpuset.conf': {'CPUSET': '--cpuset 0-3'}}
    _assert_no_secret_in_output(collector)


def test_SystemConfigCollector_redacts_secrets(doctor_factory):
    """
    A secret parameter (ldap_bind_passwd), a secret nested in one (kms_hosts) and one inside the text value of
    object_storage_endpoints are redacted in the data and in the printed rows. An unset secret stays empty.
    """
    # object_storage_endpoints as read_cql_table returns it: a JSON string inside a JSON string, every backslash
    # doubled by cqlsh COPY. Scylla puts no credential there today; the hypothetical key proves the text path.
    endpoints = '{"s3": "{ \\\\"type\\\\": \\\\"s3\\\\", \\\\"aws_access_key_id\\\\": \\\\"%s\\\\" }"}' % \
        _SECRET_VALUES[0]
    rows = [
        {'name': 'kms_hosts', 'value': json.dumps({'prod': _KMS_HOST}), 'source': 'config', 'type': 'string map'},
        {'name': 'ldap_bind_passwd', 'value': json.dumps(_SECRET_VALUES[2]), 'source': 'config', 'type': 'string'},
        {'name': 'auth_superuser_salted_password', 'value': '""', 'source': 'default', 'type': 'string'},
        {'name': 'object_storage_endpoints', 'value': endpoints, 'source': 'config', 'type': 'string'},
        *[dict(r) for r in _SYSTEM_CONFIG_REQUIRED_ROWS],
    ]

    collector = _make_system_config_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', return_value=('SELECT * FROM system.config', rows)):
        collector._collect(_make_system_config_vitals())

    assert collector.status == CollectorStatus.PASSED
    assert collector._data['kms_hosts']['value'] == {'prod': _KMS_HOST_REDACTED}
    assert collector._data['ldap_bind_passwd']['value'] == _REDACTED
    assert collector._data['auth_superuser_salted_password']['value'] == ''
    # The value is read up to its closing escaped quote, the rest is kept.
    assert collector._data['object_storage_endpoints']['value'] == \
        '{"s3": "{ \\\\"type\\\\": \\\\"s3\\\\", \\\\"aws_access_key_id\\\\": <redacted> }"}'
    _assert_no_secret_in_output(collector)
    printed_rows = next(entry.value for entry in collector._output if entry.type == OutputEntryType.CQL)
    assert {'name': 'ldap_bind_passwd', 'value': _REDACTED, 'source': 'config', 'type': 'string'} in printed_rows


def test_SystemConfigCollector_invalid_json_value(doctor_factory):
    """A value that is not JSON fails the collector, naming the parameter but not its value."""
    rows = [
        {'name': 'ldap_bind_passwd', 'value': _SECRET_VALUES[2], 'source': 'config', 'type': 'string'},
        *[dict(r) for r in _SYSTEM_CONFIG_REQUIRED_ROWS],
    ]

    collector = _make_system_config_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', return_value=('SELECT * FROM system.config', rows)):
        collector._collect(_make_system_config_vitals())

    assert collector.status == CollectorStatus.FAILED
    assert "'ldap_bind_passwd'" in collector._message
    assert _SECRET_VALUES[2] not in collector._message
    _assert_no_secret_in_output(collector)


# NitroDetailedStatsCollector unit tests ##############################
###############################################################################

_AMZN_STATS_JSON = json.dumps({
    'total_read_ops': 100,
    'total_write_ops': 200,
    'ebs_volume_performance_exceeded_iops': 0,
    'ebs_volume_performance_exceeded_tp': 0,
    'ec2_instance_performance_exceeded_iops': 42,
    'ec2_instance_performance_exceeded_tp': 0,
    'volume_queue_length': 1,
    'read_io_latency_histogram': {'num_bins': 1, 'bins': [{'lower': 0, 'upper': 1, 'count': 100}]},
})


def _nitro_vitals(provider='AWS', used_nvme_devices=('nvme0n1', 'nvme1n1')):
    return {
        'InfrastructureProviderCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'provider': provider},
            Output(),
            '',
        ),
        'NVMeDevicesCollector': CollectorResult(
            CollectorStatus.PASSED,
            {'used_nvme_devices': list(used_nvme_devices)},
            Output(),
            '',
        ),
    }


_AMZN_HELP = """nvme-2.11
usage: nvme amzn <command> [<device>] [<args>]

Amazon vendor specific extensions

The following are all implemented sub-commands:
  id-ctrl         Send NVMe Identify Controller
  stats           Get EBS volume and instance store stats
  version         Shows the program version
  help            Display this help
"""

_AMZN_STATS_HELP = """Usage: nvme amzn stats <device> [OPTIONS]

Options:
  [  --output-format=<FMT>, -o <FMT> ]  --- Output format: normal|json|binary
  [  --details, -d ]                    --- Detailed IO latency histograms
"""

# nvme-cli 1.16 on Ubuntu: the `amzn` plugin exists but has no `stats` sub-command, `nvme amzn stats --help`
# fails and prints the plugin's sub-command list instead of the `stats` options.
_AMZN_STATS_HELP_UNSUPPORTED = Mock(returncode=1, stdout="ERROR: Invalid sub-command\n" + _AMZN_HELP.replace(
    "  stats           Get EBS volume and instance store stats\n", ""))


# nvme-cli 1.x exits non-zero after printing the help of a supported command, the exit code must not matter.
def _nitro_run(device_results, stats_help=Mock(returncode=234, stdout=_AMZN_STATS_HELP), calls=None):
    """`Executor.run_command` stub: `nvme amzn stats --help` probe and `nvme amzn stats` results per device."""
    def fake_run(command, shell=False, check=True, **kwargs):
        if calls is not None:
            calls.append(command)
        if command == 'nvme amzn stats --help':
            return stats_help
        return device_results[command.split()[-2].replace('/dev/', '')]
    return fake_run


def _collect_nitro(fake_run, **vitals_kwargs):
    collector = NitroDetailedStatsCollector({}, {})
    with patch('shutil.which', return_value='/usr/bin/nvme'), \
         patch.object(Executor, 'run_command', side_effect=fake_run):
        collector._collect(_nitro_vitals(**vitals_kwargs))
    return collector


def test_NitroDetailedStatsCollector_collected_on_aws():
    """Only the NVMe devices used by Scylla are queried and the complete statistics are kept."""
    calls: List[str] = []
    collector = _collect_nitro(_nitro_run({
        'nvme0n1': Mock(returncode=0, stdout=_AMZN_STATS_JSON),
        'nvme1n1': Mock(returncode=0, stdout=json.dumps({'reads': {'bytes': 200}, 'writes': {'bytes': 300}})),
    }, calls=calls))

    assert collector.status == CollectorStatus.PASSED, collector.message
    assert collector._data['devices'] == {
        'nvme0n1': json.loads(_AMZN_STATS_JSON),
        'nvme1n1': {'reads': {'bytes': 200}, 'writes': {'bytes': 300}},
    }
    assert calls == ['nvme amzn stats --help',
                     'nvme amzn stats --details /dev/nvme0n1 --output-format=json',
                     'nvme amzn stats --details /dev/nvme1n1 --output-format=json']
    assert 'devices' in collector.mask


def test_NitroDetailedStatsCollector_without_details():
    """nvme-cli versions shipping `stats` but not `--details` are queried without it."""
    calls: List[str] = []
    collector = _collect_nitro(_nitro_run({'nvme0n1': Mock(returncode=0, stdout=_AMZN_STATS_JSON)},
                                          stats_help=Mock(returncode=0,
                                                          stdout=_AMZN_STATS_HELP.replace('--details', '')),
                                          calls=calls),
                               used_nvme_devices=('nvme0n1',))

    assert collector.status == CollectorStatus.PASSED, collector.message
    assert collector._data['devices'] == {'nvme0n1': json.loads(_AMZN_STATS_JSON)}
    assert calls[-1] == 'nvme amzn stats /dev/nvme0n1 --output-format=json'


def test_NitroDetailedStatsCollector_json_with_stderr_noise():
    """Executor merges stderr into stdout: warnings around the JSON object must not break decoding."""
    stdout = f"Failed to read /etc/nvme/hostnqn: No such file or directory\n{_AMZN_STATS_JSON}\nwarning: foo\n"
    collector = _collect_nitro(_nitro_run({'nvme0n1': Mock(returncode=0, stdout=stdout)}),
                               used_nvme_devices=('nvme0n1',))

    assert collector.status == CollectorStatus.PASSED, collector.message
    assert collector._data['devices'] == {'nvme0n1': json.loads(_AMZN_STATS_JSON)}


@pytest.mark.parametrize('result,message', [
    (Mock(returncode=1, stdout='[ERROR] /dev/nvme1n1: Not an EC2 device'),
     "nvme1n1: [ERROR] /dev/nvme1n1: Not an EC2 device"),
    (Mock(returncode=0, stdout="Total Ops:\n  Read: 1\n"), "nvme1n1: output is not JSON"),
])
def test_NitroDetailedStatsCollector_device_failure(result, message):
    """`stats` is supported, so a device it fails for is a FAILED collection, not a SKIPPED one."""
    collector = _collect_nitro(_nitro_run({'nvme0n1': Mock(returncode=0, stdout=_AMZN_STATS_JSON),
                                           'nvme1n1': result}))

    assert collector.status == CollectorStatus.FAILED
    assert message in collector.message
    assert set(collector._data['devices']) == {'nvme0n1'}


@pytest.mark.parametrize('stats_help', [
    _AMZN_STATS_HELP_UNSUPPORTED,
    # a `stats` usage without the relied upon `--output-format` option is not usable either
    Mock(returncode=234, stdout="Usage: nvme amzn stats <device>\n"),
])
def test_NitroDetailedStatsCollector_stats_unsupported(stats_help):
    """The `amzn` plugin without a usable `stats` sub-command is detected up front, no device is queried."""
    calls: List[str] = []
    collector = _collect_nitro(_nitro_run({}, stats_help=stats_help, calls=calls))

    assert collector.status == CollectorStatus.SKIPPED
    assert "'nvme amzn stats --help' does not list its options" in collector.message
    assert calls == ['nvme amzn stats --help']


@pytest.mark.parametrize('provider,which,used_devices,message', [
    ('GCP', '/usr/bin/nvme', ('nvme0n1',), "AWS Nitro instances only"),
    ('AWS', None, ('nvme0n1',), "'nvme' utility (nvme-cli package) is not installed"),
    ('AWS', '/usr/bin/nvme', (), "No NVMe devices are used by Scylla"),
])
def test_NitroDetailedStatsCollector_skipped(provider, which, used_devices, message):
    collector = NitroDetailedStatsCollector({}, {})
    with patch('shutil.which', return_value=which), \
         patch.object(Executor, 'run_command') as mock_run:
        collector._collect(_nitro_vitals(provider=provider, used_nvme_devices=used_devices))

    assert collector.status == CollectorStatus.SKIPPED
    assert message in collector.message
    mock_run.assert_not_called()


###############################################################################


def test_CPUSetCollector(doctor_factory, monkeypatch):
    with open('/tmp/perftune.yaml', 'w') as f:
        f.writelines(["tune:\r\n", "  - system"])

    with open('/tmp/cpuset.conf', 'w') as f:
        f.writelines(['CPUSET="--cpuset 1-7 --smp 1"'])

    monkeypatch_path("scylla_directory_configs", "/tmp",
                     [CPUSetCollector, ScyllaExtraConfigurationFilesCollector],
                     monkeypatch)

    doctor = doctor_factory(collectors=[ScyllaExtraConfigurationFilesCollector,
                                        CPUSetCollector])
    doctor.run()

    result = doctor.vitals['CPUSetCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    for key in ['cpusetconf_mask', 'perftune_mask', 'cpusetconf_intersect_perftune_mask']:
        assert key in result.data

    with open('/tmp/cpuset.conf', 'w') as f:
        f.writelines(['CPUSET="--smp 1"'])

    doctor = doctor_factory(collectors=[ScyllaExtraConfigurationFilesCollector,
                                        CPUSetCollector])
    doctor.run()

    result = doctor.vitals['CPUSetCollector']
    assert result.status == CollectorStatus.SKIPPED, result.message
    assert result.message == "cpuset setup was not performed using Scylla tools: '--cpuset' is not used in CPUSET"


def test_IPRoutesCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        IPRoutesCollector])
    doctor.run()

    result = doctor.vitals['IPRoutesCollector']
    assert result.status == CollectorStatus.PASSED

    for address in result.data:
        assert result.data[address]


def test_CqlshCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector])

    doctor.run()

    result = doctor.vitals['CqlshCollector']
    assert result.status == CollectorStatus.PASSED, result.message


def test_ServiceLevelsCollector(doctor_factory, await_scylla_start):
    sl_name = 'sd_test_service_level'
    Executor.paths = {'scylla_directory': '/opt/scylladb'}
    created = Executor.cqlsh(
        f"CREATE SERVICE LEVEL {sl_name} WITH SHARES = 200",
        live_scylla_cql_config()) is not None
    try:
        doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                            CqlshCollector,
                                            ServiceLevelsCollector])
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
            Executor.cqlsh(f"DROP SERVICE LEVEL {sl_name}", live_scylla_cql_config())


@pytest.fixture(autouse=True, scope="function")
def setup_temp_keyspace():
    # Create a keyspace so that DESC SCHEMA command returns something
    Executor.paths = {'scylla_directory': '/opt/scylladb'}
    temp_ks_existed = Executor.cqlsh("CREATE KEYSPACE test_keyspace WITH "
                                     "replication = {'class': 'SimpleStrategy', 'replication_factor': '1'} ",
                                     live_scylla_cql_config()) is None
    yield
    if not temp_ks_existed:
        Executor.cqlsh("DROP KEYSPACE test_keyspace", live_scylla_cql_config())


def test_ScyllaClusterSchemaDescriptionCollector(doctor_factory, await_scylla_start, setup_temp_keyspace):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        ScyllaClusterSchemaDescriptionCollector])
    doctor.run()

    result = doctor.vitals['ScyllaClusterSchemaDescriptionCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.CQL, "DESC SCHEMA", value_content="test_keyspace")
    assert "test_keyspace" in result.data['schema']


def test_ScyllaClusterSchemaDescriptionCollector_masks_schema(doctor_factory):
    """The schema text is masked, so `strip()` drops it before the cluster diff."""
    doctor = doctor_factory(collectors=[ScyllaClusterSchemaDescriptionCollector])
    collector = doctor.collectors['ScyllaClusterSchemaDescriptionCollector']
    vitals = {'ScyllaConfigurationFileCollector': Mock(data={'rpc_address': 'localhost'})}

    with patch.object(Executor, 'cqlsh', return_value=Mock(stdout="CREATE KEYSPACE a...;")):
        collector._collect(vitals)

    result = collector.result
    assert result.data['schema']           # collected into data ...
    result.strip()
    assert 'schema' not in result.data     # ... but masked out before diffing


def test_ScyllaClusterSystemKeyspacesCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        ScyllaClusterSystemKeyspacesCollector])

    doctor.run()

    result = doctor.vitals['ScyllaClusterSystemKeyspacesCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    for keyspace in ["system_auth", "system_distributed", "system_traces"]:
        assert keyspace in result.data


def test_ScyllaClusterStatusCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        ScyllaClusterStatusCollector])

    doctor.run()

    result = doctor.vitals['ScyllaClusterStatusCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    for status in ["up", "down", "joining", "leaving", "moving"]:
        assert status in result.data


def test_ScyllaClusterSchemaCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        ScyllaClusterSchemaCollector])

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
                                     live_scylla_cql_config()) is None
    try:
        assert Executor.cqlsh("CREATE TABLE test_views_keyspace.base (pk int PRIMARY KEY, v text) "
                              "WITH cdc = {'enabled': true}", live_scylla_cql_config()) is not None
        assert Executor.cqlsh(
            "CREATE MATERIALIZED VIEW test_views_keyspace.mv AS SELECT * FROM test_views_keyspace.base "
            "WHERE pk IS NOT NULL AND v IS NOT NULL PRIMARY KEY (v, pk)", live_scylla_cql_config()) is not None
        yield
    finally:
        if not temp_ks_existed:
            Executor.cqlsh("DROP KEYSPACE test_views_keyspace", live_scylla_cql_config())


def test_ScyllaClusterTablesDescriptionCollector(doctor_factory, await_scylla_start, setup_views_cdc_keyspace):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        ScyllaClusterTablesDescriptionCollector])

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
    doctor = doctor_factory(collectors=[ScyllaClusterTablesDescriptionCollector], analyzers=())
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

    doctor = doctor_factory(collectors=[ScyllaClusterTablesDescriptionCollector], analyzers=())
    collector = doctor.collectors['ScyllaClusterTablesDescriptionCollector']
    vitals = {'ScyllaConfigurationFileCollector': CollectorResult(CollectorStatus.PASSED, {}, Output(), '')}

    with patch.object(Executor, 'read_cql_table', side_effect=CqlFailedException("boom")):
        collector._collect(vitals)

    assert collector.status == CollectorStatus.FAILED
    assert "boom" in collector._message


def test_ScyllaVersionCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaVersionCollector])
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
        doctor = doctor_factory(collectors=[ScyllaVersionCollector])

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
        CPUSpecificationsCollector,
        NICsCollector,
        InfrastructureProviderCollector,
        NodePlatformCollector,
        ScyllaLimitNOFILECollector],
        config_options=provider_identify_shorten_timeout_options)

    doctor.run()

    result = doctor.vitals['ScyllaLimitNOFILECollector']
    if not running_in_container():
        assert result.status == CollectorStatus.PASSED, result.message
        assert result.data['limitnofile'] == "infinity" or result.data['limitnofile'].isdigit()
    else:
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available" in result.message


SYSTEMCTL_SHOW_TEMPLATE = """Type=simple
LimitNOFILE={limitnofile}
LimitNOFILESoft={limitnofile}
LimitNPROC=infinity
Environment=AWS_SECRET_ACCESS_KEY=mock-aws-key-secret
"""


def _run_limitnofile_collector(limitnofile):
    collector = ScyllaLimitNOFILECollector({}, {})
    vitals = {'NodePlatformCollector': CollectorResult(
        CollectorStatus.PASSED, {'platform': NodePlatform.BAREMETAL}, Output(), '')}

    with patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout="2000\n")), \
         patch('collectors.operating_system.ServiceManager') as mock_sm_class:
        mock_sm_class.return_value.service_environment.return_value = \
            SYSTEMCTL_SHOW_TEMPLATE.format(limitnofile=limitnofile)
        collector._collect(vitals)

    return collector


@pytest.mark.parametrize("limitnofile", ["800000", " 800000 "])
def test_ScyllaLimitNOFILECollector_numeric_value(limitnofile):
    collector = _run_limitnofile_collector(limitnofile)

    assert collector.status == CollectorStatus.PASSED, collector._message
    assert collector._data == {'limitnofile': "800000"}
    # Only the LimitNOFILE line is printed, not the Environment= holding a credential.
    printed = [entry.value for entry in collector._output if entry.name.startswith("LimitNOFILE")]
    assert printed == [f"LimitNOFILE={limitnofile}\n"]


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
    doctor = doctor_factory(collectors=[SysctlCollector])

    doctor.run()

    result = doctor.vitals['SysctlCollector']
    assert result.status == CollectorStatus.PASSED, result.message

    for value in ["fs.aio-max-nr", "fs.file-max", "fs.nr_open"]:
        assert value in result.data
    assert_output_gathered(result, OutputEntryType.STDOUT, "sysctl -a")


def test_ScyllaBinaryCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaBinaryCollector])

    doctor.run()

    result = doctor.vitals['ScyllaBinaryCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert 'scylla_bin' in result.data


def test_ScyllaLogsCollector(doctor_factory, provider_identify_shorten_timeout_options):
    doctor = doctor_factory(collectors=[NICsCollector,
                                        InfrastructureProviderCollector,
                                        CPUSpecificationsCollector,
                                        NodePlatformCollector,
                                        ScyllaLogsCollector],
                            config_options=provider_identify_shorten_timeout_options)

    doctor.run()

    result = doctor.vitals['ScyllaLogsCollector']
    if not running_in_container():
        assert result.status == CollectorStatus.PASSED, result.message
    else:
        assert result.status == CollectorStatus.SKIPPED, result.message
        assert "Not available" in result.message


def _make_manager_agent_logs_collector(doctor_factory) -> ScyllaManagerAgentLogsCollector:
    """Instantiate a ScyllaManagerAgentLogsCollector without running it (no Scylla required)."""
    doctor = doctor_factory(collectors=[ScyllaManagerAgentLogsCollector], analyzers={})
    return doctor.collectors['ScyllaManagerAgentLogsCollector']


def test_ScyllaManagerAgentLogsCollector_skips_when_service_missing(doctor_factory):
    collector = _make_manager_agent_logs_collector(doctor_factory)

    with patch.object(ServiceManager, 'service_exists', return_value=False):
        collector._collect({})

    assert collector.status == CollectorStatus.SKIPPED
    assert "not installed" in collector.result.message


def test_ScyllaManagerAgentLogsCollector_passes(doctor_factory):
    collector = _make_manager_agent_logs_collector(doctor_factory)

    with patch.object(ServiceManager, 'service_exists', return_value=True), \
            patch.object(Executor, 'generate_output_filename',
                         return_value="scylla_manager_agent_logs_test.txt"), \
            patch.object(Executor, 'run_command', return_value=Mock()) as mock_run:
        collector._collect({})

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
    doctor = doctor_factory(collectors=[ScyllaManagerAgentLogsCollector], analyzers={},
                            config_options=[('ScyllaManagerAgentLogsCollector', 'since_date', '2024-01-01')])
    collector = doctor.collectors['ScyllaManagerAgentLogsCollector']

    with patch.object(ServiceManager, 'service_exists', return_value=True), \
            patch.object(Executor, 'generate_output_filename', return_value="scylla_manager_agent_logs_test.txt"), \
            patch.object(Executor, 'run_command', return_value=Mock()) as mock_run:
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    command = mock_run.call_args.args[0]
    assert "--since=2024-01-01" in command


def test_ScyllaManagerAgentLogsCollector_fails_when_no_output(doctor_factory):
    collector = _make_manager_agent_logs_collector(doctor_factory)

    with patch.object(ServiceManager, 'service_exists', return_value=True), \
            patch.object(Executor, 'generate_output_filename', return_value="scylla_manager_agent_logs_test.txt"), \
            patch.object(Executor, 'run_command', return_value=None):
        collector._collect({})

    assert collector.status == CollectorStatus.FAILED
    assert "Cannot gather Scylla Manager Agent logs" in collector.result.message


def test_ScyllaServicesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaServicesCollector])

    doctor.run()

    result = doctor.vitals['ScyllaServicesCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data) > 0
    for service in result.data.values():
        for key in ['active', 'autostarts']:
            assert key in service
            assert isinstance(service[key], bool)


def test_ScyllaSeedsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaConfigurationFileCollector,
                                        ScyllaSeedsCollector])

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
    doctor = doctor_factory(collectors=[ScyllaSeedsCollector])
    collector = doctor.collectors['ScyllaSeedsCollector']

    fake_sock = Mock()
    fake_sock.__enter__ = Mock(return_value=fake_sock)
    fake_sock.__exit__ = Mock(return_value=False)

    with patch("socket.create_connection", return_value=fake_sock) as create_conn:
        collector._collect(_seeds_config_vitals(seed))

    assert collector.status == CollectorStatus.PASSED
    assert collector._data[seed] == 0
    create_conn.assert_called_once_with((resolved_host, 7000), timeout=2.0)


def test_ScyllaSeedsCollector_ipv6_connect_failure_errno(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaSeedsCollector])
    collector = doctor.collectors['ScyllaSeedsCollector']

    with patch("socket.create_connection",
               side_effect=ConnectionRefusedError(111, "Connection refused")):
        collector._collect(_seeds_config_vitals("2001:db8::1"))

    assert collector.status == CollectorStatus.PASSED
    assert collector._data["2001:db8::1"] == 111


def test_ScyllaSeedsCollector_gaierror_unreachable(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaSeedsCollector])
    collector = doctor.collectors['ScyllaSeedsCollector']

    with patch("socket.create_connection",
               side_effect=socket.gaierror(socket.EAI_NONAME, "unknown host")):
        collector._collect(_seeds_config_vitals("not-a-real-host.invalid"))

    assert collector.status == CollectorStatus.PASSED
    assert collector._data["not-a-real-host.invalid"] == -1


def test_ScyllaSeedsCollector_skips_empty_seed_entries(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaSeedsCollector])
    collector = doctor.collectors['ScyllaSeedsCollector']

    fake_sock = Mock()
    fake_sock.__enter__ = Mock(return_value=fake_sock)
    fake_sock.__exit__ = Mock(return_value=False)

    with patch("socket.create_connection", return_value=fake_sock):
        collector._collect(_seeds_config_vitals("2001:db8::1,"))

    assert collector.status == CollectorStatus.PASSED
    assert list(collector._data) == ["2001:db8::1"]
    assert collector._data["2001:db8::1"] == 0


def test_ScyllaSSTablesCollector(doctor_factory):
    doctor = doctor_factory(collectors=[ScyllaSSTablesCollector])

    doctor.run()

    result = doctor.vitals['ScyllaSSTablesCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert isinstance(result.data['sstables'], dict)
    assert all(isinstance(stems, dict) for stems in result.data['sstables'].values())
    assert isinstance(result.data['other_files'], dict)


def test_ScyllaSSTablesCollector_stores_nested_sstables():
    """
    Groups flat paths into data.sstables[directory][stem] = [suffix, ...] and files without '-' into
    data.other_files[directory] = [name, ...], sorted at every level; directories are dropped; every path is
    recoverable.
    """
    table_dir = '/var/lib/scylla/data/ks1/t1-0123456789abcdef0123456789abcdef'
    legacy_dir = '/var/lib/scylla/data/ks0/t0-abcdef0123456789abcdef0123456789'
    snapshot_dir = f'{table_dir}/snapshots/sm_20240101000000UTC'
    stem = 'me-3grk_0gqu_48tjk253tdghsvc1lj-big'
    paths = [
        f'{table_dir}/{stem}-TOC.txt',
        f'{table_dir}/{stem}-Data.db',
        f'{table_dir}/md-42-big-Data.db',
        f'{table_dir}/snapshots',  # a directory: dropped
        f'{snapshot_dir}/schema.cql',  # no '-': goes to other_files
        f'{snapshot_dir}/manifest.json',
        f'{snapshot_dir}/foo-Data.db',  # 'foo' (other_files), 'foo-' (suffix '') and 'foo-Data.db' stay distinct
        f'{snapshot_dir}/foo-',
        f'{snapshot_dir}/foo',
        f'{snapshot_dir}/{stem}-Data.db',  # snapshot hardlink of a live sstable
        f'{legacy_dir}/ks0-t0-ka-1-Data.db',  # legacy ka naming
    ]
    expected = {
        'sstables': {
            legacy_dir: {'ks0-t0-ka-1': ['Data.db']},
            table_dir: {'md-42-big': ['Data.db'], stem: ['Data.db', 'TOC.txt']},
            snapshot_dir: {'foo': ['', 'Data.db'], stem: ['Data.db']},
        },
        'other_files': {snapshot_dir: ['foo', 'manifest.json', 'schema.cql']},
    }

    collector = ScyllaSSTablesCollector({}, {'scylla_directory_var': '/var/lib/scylla'})
    with patch.object(glob, 'glob', return_value=paths), \
            patch('os.path.isdir', side_effect=lambda path: path == f'{table_dir}/snapshots'):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    # json.dumps keeps insertion order, so this also checks the sort at every level
    assert json.dumps(collector._data) == json.dumps(expected)
    # One line per directory: sstables first, then other_files
    expected_output = "\n".join([
        f"{legacy_dir}: {json.dumps(expected['sstables'][legacy_dir])}",
        f"{table_dir}: {json.dumps(expected['sstables'][table_dir])}",
        f"{snapshot_dir}: {json.dumps(expected['sstables'][snapshot_dir])}",
        f"{snapshot_dir}: {json.dumps(expected['other_files'][snapshot_dir])}",
    ])
    assert_output_gathered(collector.result, OutputEntryType.VALUE, "All 10 files in /var/lib/scylla/data/**/*",
                           value_content=expected_output)
    assert [entry.value for entry in collector.result.output] == [expected_output]


def test_ScyllaSSTablesCollector_empty_data_dir():
    collector = ScyllaSSTablesCollector({}, {'scylla_directory_var': '/var/lib/scylla'})
    with patch.object(glob, 'glob', return_value=[]):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED
    assert collector._data == {'sstables': {}, 'other_files': {}}


def test_SELinuxCollector(doctor_factory):
    doctor = doctor_factory(collectors=[SELinuxCollector])

    doctor.run()

    result = doctor.vitals['SELinuxCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert "/etc/selinux/config" in result.data['files']


def test_SwapCollector(doctor_factory):
    doctor = doctor_factory(collectors=[SwapCollector])

    doctor.run()

    result = doctor.vitals['SwapCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert isinstance(result.data['total'], int)
    assert_output_gathered(result, OutputEntryType.FILE, '/proc/swaps')


def test_TCPConnectionsCollector(doctor_factory):
    doctor = doctor_factory(collectors=[TCPConnectionsCollector])

    doctor.run()

    result = doctor.vitals['TCPConnectionsCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, 'ss --all --tcp')


def test_HypervisorTypeCollector(doctor_factory):
    doctor = doctor_factory(collectors=[HypervisorTypeCollector])

    doctor.run()

    result = doctor.vitals['HypervisorTypeCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, 'systemd-detect-virt')
    assert ('hypervisor' in result.data and isinstance(result.data['hypervisor'], str) and
            len(result.data['hypervisor']) > 0)


def test_NodetoolCFStatsCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[NodetoolCFStatsCollector])

    doctor.run()

    result = doctor.vitals['NodetoolCFStatsCollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, 'nodetool cfstats',
                           value_content="Keyspace : system_traces")


def test_RaftTopologyRPCStatusCollector(doctor_factory, await_scylla_start):
    doctor = doctor_factory(collectors=[RaftTopologyRPCStatusCollector,
                                        CqlshCollector,
                                        SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        ScyllaConfigurationFileCollector])

    doctor.run()

    result = doctor.vitals['RaftTopologyRPCStatusCollector']
    if result.status == CollectorStatus.SKIPPED:
        pytest.skip(f"{result.message}")

    assert result.status == CollectorStatus.PASSED, result.message
    # There should be no Raft Topology operations in the air during CI/CD execution
    assert result.data == "none"


def test_ScyllaTablesCompressionInfoCollector(doctor_factory, await_scylla_start, setup_views_cdc_keyspace):
    doctor = doctor_factory(collectors=[SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        ScyllaTablesCompressionInfoCollector,
                                        ScyllaClusterTablesDescriptionCollector])

    doctor.run()
    result = doctor.vitals['ScyllaTablesCompressionInfoCollector']

    assert result.status == CollectorStatus.PASSED, result.message
    assert len(result.data) > 0
    assert 'system_traces' in result.data and 'sessions' in result.data['system_traces'] and \
           result.data['system_traces']['sessions'] >= 0.0
    assert result.data['test_views_keyspace']['mv'] >= 0.0
    assert result.data['test_views_keyspace']['base_scylla_cdc_log'] >= 0.0


def test_ScyllaTablesUsedDiskCollector(doctor_factory, await_scylla_start, setup_views_cdc_keyspace):
    doctor = doctor_factory(collectors=[SystemConfigCollector,
                                        SystemPeersLocalCollector,
                                        ScyllaConfigurationFileCollector,
                                        CqlshCollector,
                                        ScyllaTablesUsedDiskCollector,
                                        ScyllaClusterTablesDescriptionCollector])

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

def _make_perftune_collector(doctor_factory) -> PerftuneSystemConfigurationCollector:
    """Instantiate a PerftuneSystemConfigurationCollector without running it."""
    doctor = doctor_factory(collectors=[PerftuneSystemConfigurationCollector], analyzers=())
    return doctor.collectors['PerftuneSystemConfigurationCollector']


_PERFTUNE_NO_DEV_NODE = "ERROR: [Errno 2] No such file or directory: '/dev/vda4'. Your system can't be tuned.\n"

_STORAGE_SYSTEM_CONFIG = {
    'workdir,W': {'value': ''},
    'data_file_directories': {'value': ['/var/lib/scylla/data']},
    'commitlog_directory': {'value': '/var/lib/scylla/commitlog'},
    'hints_directory': {'value': '/var/lib/scylla/hints'},
    'view_hints_directory': {'value': '/var/lib/scylla/view_hints'},
}


@pytest.mark.parametrize("in_container,stdout,stderr,expected_status,expected_message", [
    (True, "", _PERFTUNE_NO_DEV_NODE, CollectorStatus.SKIPPED,
     "Block device nodes behind the Scylla directories are not visible from this container"),
    # the same refusal, printed on stdout and without quotes
    (True, "ERROR: [Errno 2] No such file or directory: /dev/vda4\n", "", CollectorStatus.SKIPPED,
     "Block device nodes behind the Scylla directories are not visible from this container"),
    (True, "", "ERROR: Unsupported disk type\n", CollectorStatus.FAILED, "Failed to run"),
    (False, "", _PERFTUNE_NO_DEV_NODE, CollectorStatus.FAILED, "Failed to run"),
])
def test_StorageConfigurationCollector_perftune_refused(doctor_factory, monkeypatch, in_container, stdout, stderr,
                                                        expected_status, expected_message):
    """
    Only a container that cannot see the /dev node behind a directory may skip; any other perftune error, and any
    error on a host, stays FAILED.
    """
    doctor = doctor_factory(collectors=[StorageConfigurationCollector])
    collector = doctor.collectors['StorageConfigurationCollector']

    def fake_run_command(command, *args, **kwargs):
        if "perftune.py" in command:
            return subprocess.CompletedProcess(args=command, returncode=1, stdout=stdout, stderr=stderr)
        if command == "mount":
            return subprocess.CompletedProcess(args=command, returncode=0,
                                               stdout="/dev/vda4 on /var/lib/scylla type ext4 (rw,relatime)\n")
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(Executor, 'run_command', fake_run_command)
    monkeypatch.setattr('collectors.storage.running_in_container', lambda: in_container)

    collector._collect({'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, _STORAGE_SYSTEM_CONFIG,
                                                                 Output(), '')})

    result = collector.result
    assert result.status == expected_status, result.message
    assert expected_message in result.message
    assert (stderr + stdout).strip() in result.message
    assert result.data == {'data_file_directories': {}}


def test_StorageConfigurationCollector_keeps_collected_directories_on_failure(doctor_factory, monkeypatch):
    """
    When a later directory fails, the directories already collected stay in the data: the PS vitals summary reads
    the data directory's size from there regardless of the collector status.
    """
    doctor = doctor_factory(collectors=[StorageConfigurationCollector])
    collector = doctor.collectors['StorageConfigurationCollector']

    def fake_run_command(command, *args, **kwargs):
        if "perftune.py" in command and "/var/lib/scylla/data " in command:
            return subprocess.CompletedProcess(args=command, returncode=0, stdout="Setting non-NVMe disks: vdaXXX\n")
        if "perftune.py" in command:
            return subprocess.CompletedProcess(args=command, returncode=1, stdout="", stderr=_PERFTUNE_NO_DEV_NODE)
        if command == "mount":
            return subprocess.CompletedProcess(args=command, returncode=0,
                                               stdout="/dev/vda4 on /var/lib/scylla type xfs (rw,noatime)\n")
        if command.startswith("df -T"):
            return subprocess.CompletedProcess(args=command, returncode=0, stdout=(
                "Filesystem Type 1K-blocks Used Available Use% Mounted on\n"
                "/dev/vda4  xfs  100       10   90        10%  /var/lib/scylla\n"))
        raise AssertionError(f"unexpected command: {command}")

    monkeypatch.setattr(Executor, 'run_command', fake_run_command)
    monkeypatch.setattr(Executor, 'read_file_content', lambda path: (_ for _ in ()).throw(OSError(path)))
    fake_statvfs = os.statvfs_result((4096, 4096, 1000, 900, 900, 0, 0, 0, 0, 255))
    monkeypatch.setattr(os, 'statvfs', lambda path: fake_statvfs)
    monkeypatch.setattr('collectors.storage.running_in_container', lambda: True)

    collector._collect({'SystemConfigCollector': CollectorResult(CollectorStatus.PASSED, _STORAGE_SYSTEM_CONFIG,
                                                                 Output(), '')})

    result = collector.result
    assert result.status == CollectorStatus.SKIPPED, result.message
    assert result.data['data_file_directories']['/var/lib/scylla/data']['storage_size_kb'] == 4096 * 1000 / 1024
    assert result.data['commitlog_directories'] == {}


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


@pytest.mark.parametrize("in_container,expected_status,expected_message", [
    (False, CollectorStatus.FAILED, "perftune.yaml is not found"),
    (True, CollectorStatus.SKIPPED, "perftune.yaml is not available from this container"),
])
def test_PerftuneSystemConfigurationCollector_missing_perftune_yaml(doctor_factory, monkeypatch, in_container,
                                                                    expected_status, expected_message):
    """Collector must FAIL immediately when perftune.yaml is not found on a host, and skip in a container."""
    collector = _make_perftune_collector(doctor_factory)

    monkeypatch.setattr(os.path, 'isfile', lambda _: False)
    monkeypatch.setattr('collectors.tuning.running_in_container', lambda: in_container)
    collector._collect(_make_perftune_vitals())

    assert collector.status == expected_status, collector.result.message
    assert expected_message in collector.result.message


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
    doctor = doctor_factory(collectors=[ProcInterruptsCollector])

    doctor.run()

    result = doctor.vitals['ProcInterruptsCollector']
    # Container runtimes mask /proc/interrupts (empty when privileged, /dev/null when not).
    if running_in_container() and result.status == CollectorStatus.SKIPPED:
        assert "/proc/interrupts is not readable from this container" in result.message
        return
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.FILE, '/proc/interrupts')


_INTERRUPTS = ["           CPU0\n", "  0:         12   IO-APIC   2-edge      timer\n"]


@pytest.mark.parametrize("in_container,content,expected_status,expected_message", [
    (False, _INTERRUPTS, CollectorStatus.PASSED, ""),
    (True, _INTERRUPTS, CollectorStatus.PASSED, ""),
    (True, [], CollectorStatus.SKIPPED, "not readable from this container"),
    (True, FileNotFoundError("/proc/interrupts"), CollectorStatus.SKIPPED, "not readable from this container"),
    (False, [], CollectorStatus.FAILED, "Cannot read /proc/interrupts"),
])
def test_ProcInterruptsCollector_refused(in_container, content, expected_status, expected_message):
    collector = ProcInterruptsCollector({}, {})
    side_effect = content if isinstance(content, Exception) else [content]

    with patch('collectors.hardware.running_in_container', return_value=in_container), \
         patch.object(Executor, 'read_file_content', side_effect=side_effect):
        collector._collect({})

    result = collector.result
    assert result.status == expected_status, result.message
    assert expected_message in result.message
    if expected_status == CollectorStatus.PASSED:
        assert_output_gathered(result, OutputEntryType.FILE, '/proc/interrupts')


def test_LSPCICollector(doctor_factory, await_scylla_start):
    """
    Verifies that LSPCICollector collects the output of 'lspci -vvv' and it's not empty
    """
    doctor = doctor_factory(collectors=[LSPCICollector])

    doctor.run()

    result = doctor.vitals['LSPCICollector']
    assert result.status == CollectorStatus.PASSED, result.message
    assert_output_gathered(result, OutputEntryType.STDOUT, 'lspci -vvv')


def test_SeastarCPUMapCollector(doctor_factory, await_scylla_start):
    """
    Verifies that SeastarCPUMapCollector collects the output of 'seastar-cpu-map.sh -n scylla' and it's not empty
    """
    doctor = doctor_factory(collectors=[SeastarCPUMapCollector])

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
    collector = SeastarCPUMapCollector({}, {'scylla_directory_scripts': '/opt/scylladb/scripts'})
    with patch('collectors_base.shutil.which', return_value='/usr/bin/taskset'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout=cpu_map_output)):
        collector._collect({})

    assert collector.status == CollectorStatus.PASSED, collector.message
    assert collector._data['shard_cpu_map'] == {'0': '0', '1': '1,17'}
    assert_output_gathered(collector, OutputEntryType.VALUE, 'shard to CPU mapping', value_content='shard 1: CPU 1,17')


def test_SeastarCPUMapCollector_failed_without_shard_cpu_map():
    """
    Verifies that the collector fails when no shard to CPU mapping can be parsed, e.g. when Scylla is not running
    """
    collector = SeastarCPUMapCollector({}, {'scylla_directory_scripts': '/opt/scylladb/scripts'})
    with patch('collectors_base.shutil.which', return_value='/usr/bin/taskset'), \
         patch.object(Executor, 'run_command', return_value=Mock(returncode=0, stdout='no scylla process found\n')):
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


def _make_sd_version_collector(doctor_factory) -> SDVersionCollector:
    doctor = doctor_factory(collectors=[SDVersionCollector], analyzers=())
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
    doctor = doctor_factory(collectors=[SystemTabletsCollector], analyzers=(),
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


def _system_tablets_schema_cqlsh(column_names=None):
    """Return a mock Executor.cqlsh answering the system_schema.columns detection query."""
    cols = column_names if column_names is not None else _SYSTEM_TABLETS_COLUMNS

    def fake_cqlsh(query, scylla_config, *args, **kwargs):
        stdout = Mock()
        stdout.stdout = "column_name\n-----------\n" + "\n".join(cols) + "\n"
        return stdout

    return fake_cqlsh


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
    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table), \
            patch.object(Executor, 'cqlsh', side_effect=_system_tablets_schema_cqlsh()):
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
    with patch.object(Executor, 'read_cql_table', return_value=('COPY system.tablets ...', [])), \
            patch.object(Executor, 'cqlsh', side_effect=_system_tablets_schema_cqlsh()):
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

    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table), \
            patch.object(Executor, 'cqlsh', side_effect=_system_tablets_schema_cqlsh()):
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
    with patch.object(Executor, 'read_cql_table', side_effect=CqlFailedException("no tablets table")), \
            patch.object(Executor, 'cqlsh', side_effect=_system_tablets_schema_cqlsh()):
        collector._collect(_make_system_tablets_vitals())

    assert collector.status == CollectorStatus.FAILED
    assert "no tablets table" in collector.result.message


def test_SystemTabletsCollector_retries_without_base_table(doctor_factory):
    """
    Scylla versions without the system.tablets base_table column (e.g. 2025.1) expose fewer
    columns via system_schema.columns; the collector reads only the available ownership columns
    and still PASSES (DOCTOR-120).
    """
    rows = [
        {'table_id': 'aaaa', 'keyspace_name': 'ks_a', 'table_name': 't1', 'last_token': '100',
         'replicas': '[(aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 0)]'},
    ]
    seen = []

    def fake_read_cql_table(scylla_config, table_name, columns=None, max_rows=-1):
        seen.append(columns)
        assert 'base_table' not in columns
        return ('COPY system.tablets ...', rows)

    collector = _make_system_tablets_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table), \
            patch.object(Executor, 'cqlsh',
                         side_effect=_system_tablets_schema_cqlsh(
                             [c for c in _SYSTEM_TABLETS_COLUMNS if c != 'base_table'])):
        collector._collect(_make_system_tablets_vitals())

    assert seen == [[c for c in _SYSTEM_TABLETS_COLUMNS if c != 'base_table']]
    assert collector.status == CollectorStatus.PASSED
    assert collector._data['tables'][0]['base_table'] == ''


def test_SystemTabletsCollector_reads_all_available_columns(doctor_factory):
    """
    When base_table exists in system.tablets the full ownership column set is read.
    """
    rows = [
        {'table_id': 'aaaa', 'keyspace_name': 'ks_a', 'table_name': 't1', 'last_token': '100',
         'replicas': '[(aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, 0)]', 'base_table': 't0'},
    ]
    seen = []

    def fake_read_cql_table(scylla_config, table_name, columns=None, max_rows=-1):
        seen.append(columns)
        return ('COPY system.tablets ...', rows)

    collector = _make_system_tablets_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table', side_effect=fake_read_cql_table), \
            patch.object(Executor, 'cqlsh', side_effect=_system_tablets_schema_cqlsh()):
        collector._collect(_make_system_tablets_vitals())

    assert seen == [_SYSTEM_TABLETS_COLUMNS]
    assert collector.status == CollectorStatus.PASSED
    assert collector._data['tables'][0]['base_table'] == 't0'


def test_SystemTabletsCollector_unrelated_failure_does_not_retry(doctor_factory):
    """
    A read failure (timeout, connection error) must surface as FAILED with the original message;
    column detection only narrows the projected columns, it never retries a failed read.
    """
    from utils import CqlFailedException

    collector = _make_system_tablets_collector(doctor_factory)
    timeout_msg = "Command: /scylla/share/cassandra/bin/cqlsh localhost -e \"COPY system.tablets " \
        "(table_id,last_token,keyspace_name,table_name,replicas) TO STDOUT " \
        "WITH DELIMITER=';' AND HEADER=TRUE\", was attempted with 3 tries, and a timeout of 300 seconds."
    with patch.object(Executor, 'read_cql_table',
                      side_effect=CqlFailedException(timeout_msg)) as read, \
            patch.object(Executor, 'cqlsh',
                         side_effect=_system_tablets_schema_cqlsh(
                             [c for c in _SYSTEM_TABLETS_COLUMNS if c != 'base_table'])):
        collector._collect(_make_system_tablets_vitals())

    assert read.call_count == 1
    assert collector.status == CollectorStatus.FAILED
    assert "timeout of 300 seconds" in collector.result.message


def test_SystemTabletsCollector_schema_detection_failure_sets_failed_status(doctor_factory):
    """
    A failure of the system_schema.columns detection query (transient CQL failure) surfaces as
    FAILED rather than reading the table with an empty/incorrect column projection.
    """
    collector = _make_system_tablets_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table') as read, \
            patch.object(Executor, 'cqlsh', return_value=None):
        collector._collect(_make_system_tablets_vitals())

    read.assert_not_called()
    assert collector.status == CollectorStatus.FAILED
    assert "system_schema.columns" in collector.result.message


def test_SystemTabletsCollector_missing_table_sets_skipped_status(doctor_factory):
    """
    system.tablets not existing (pre-tablets Scylla) is SKIPPED, not FAILED.
    """
    from utils import CqlFailedException

    collector = _make_system_tablets_collector(doctor_factory)
    with patch.object(Executor, 'read_cql_table',
                      side_effect=CqlFailedException("unconfigured table tablets")), \
            patch.object(Executor, 'cqlsh', side_effect=_system_tablets_schema_cqlsh()):
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
    with patch.object(Executor, 'read_cql_table', return_value=('COPY system.tablets ...', rows)), \
            patch.object(Executor, 'cqlsh', side_effect=_system_tablets_schema_cqlsh()):
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
    doctor = doctor_factory(collectors=[LargePartitionsCellsRowsCollector], analyzers=(),
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
    doctor = doctor_factory(collectors=[RolePermissionsCollector], analyzers=())
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
    doctor = doctor_factory(collectors=[RolesCollector], analyzers=())
    return doctor.collectors['RolesCollector']


def _make_default_credentials_collector(doctor_factory):
    doctor = doctor_factory(collectors=[DefaultCredentialsCollector], analyzers=())
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
    doctor = doctor_factory(collectors=[ServiceLevelsCollector], analyzers=())
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
