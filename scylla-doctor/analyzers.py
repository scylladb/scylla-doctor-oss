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

import ast
import copy
import ipaddress
import itertools
import json
import operator
import os
import re
import socket
import ssl
import urllib
import zipfile

from typing import Any, Dict, List, Set, Tuple, Optional, Iterable

from analyzers_base import Analyzer, AnalyzerStatus
from common import GossipInfoInvariantValues, HumanBytesUnitFormat
from common import DictView, NodePlatform, AbortedException


###############################################################################
# Utils
###############################################################################
class InvalidVersionFormat(Exception):
    def __init__(self, raw_version: str):
        super().__init__(f"Unexpected version format: \"{raw_version}\"")


def compare_versions(raw_version_a: str, raw_version_b: str, comparison_operator: str) -> bool:
    """Compares 'version_a' against 'version_b' using 'comparison_operator'"""

    operators = {
        '>': operator.gt,
        '<': operator.lt,
        '>=': operator.ge,
        '<=': operator.le,
        '==': operator.eq
    }

    def sanitize_version(raw_version_string: str):
        """
         Convert raw_version to X.Y.Z format

         Return value: X,Y,Z
         """

        raw_version = raw_version_string.split(".")

        def try_parse_int(value):
            for part in value.split('-'):
                if part.isdigit():
                    return int(part)
            raise Exception()

        try:
            if len(raw_version) >= 3:
                return try_parse_int(raw_version[0]), try_parse_int(raw_version[1]), try_parse_int(raw_version[2])
            elif len(raw_version) == 2:
                return try_parse_int(raw_version[0]), try_parse_int(raw_version[1]), 0
            elif len(raw_version) == 1:
                return try_parse_int(raw_version[0]), 0, 0
            else:
                return 0, 0, 0
        except Exception:
            raise InvalidVersionFormat(raw_version_string)

    # Validate comparison operator
    if comparison_operator not in operators:
        raise TypeError('Invalid comparison operator')

    # 'Version A' and 'Version B' sanitization
    version_a = sanitize_version(raw_version_a)
    version_b = sanitize_version(raw_version_b)

    # Digit by digit comparison
    for index in range(0, 3):
        if version_a[index] == version_b[index]:
            continue
        if operators[comparison_operator](version_a[index], version_b[index]):
            return True
        else:
            return False

    if comparison_operator in ('==', '>=', '<='):
        return True

    return False


def get_url_content(url: str, headers=None,  data=None, timeout: int = 3) -> Optional[str]:
    """
    :param url: URL endpoint to make a post call to.
    :param data: Dictionary with post variables.
    :param headers: Dictionary with HTTP headers.
    :param timeout: Timeout in seconds.
    :return: Returns results from the post call or None in case of an error.
    """
    if data is not None:
        data = json.dumps(data).encode("utf-8")
    if headers is None:
        headers = {}

    context = ssl._create_unverified_context()
    sslHandler = urllib.request.HTTPSHandler(context=context)
    proxy_handler = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_handler,
                                         sslHandler)
    urllib.request.install_opener(opener)

    try:
        req = urllib.request.Request(url, data=data, headers=headers)
        output = opener.open(req, timeout=timeout)
    except (urllib.error.URLError, socket.error):
        return None

    return output.read().decode("UTF-8")


def has_loopback(ip_addr_list: List[str]) -> bool:
    """
    Checks in any of address in the given address list is a loopback address
    :param ip_addr_list: List of IP addresses (as strings)
    :return: True if any of the elements of ip_addr_list is a loopback address
    """
    for addr_str in ip_addr_list:
        addr = ipaddress.ip_address(addr_str)
        if addr.is_loopback:
            return True

    return False


def has_ipaddr_any(ip_addr_list: List[str]) -> bool:
    """
    Checks in any of address in the given address list is an INADDR_ANY address
    :param ip_addr_list: List of IP addresses (as strings)
    :return: True if any of the elements of ip_addr_list is a INADDR_ANY address
    """
    for addr_str in ip_addr_list:
        addr = ipaddress.ip_address(addr_str)
        if int(addr) == socket.INADDR_ANY:
            return True

    return False


###############################################################################
# Analyzers
###############################################################################
class ClockSourceAnalyzer(Analyzer):
    @property
    def __preferred_sources(self) -> Set[str]:
        return {"tsc", "kvm-clock", "hyperv_clocksource_tsc_page", "arch_sys_counter"}

    @property
    def name(self) -> str:
        return "Clock source setup analysis"

    @property
    def __collector(self):
        return "ClockSourceCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that clocksource is set up to a recommended value.
        """
        clocksource = vitals[self.__collector].data['clocksource']
        if clocksource:
            if clocksource in self.__preferred_sources:
                self.status = AnalyzerStatus.PASSED
                self.message = f"{clocksource} is used as clock source"
            else:
                self.status = AnalyzerStatus.WARNING
                self.message = f"{clocksource} is used as clock source, which is not recommended"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = "Clock source setup was not done"


class CPUInstructionSetAnalyzer(Analyzer):
    @property
    def __cpu_spec_collector(self) -> str:
        return "CPUSpecificationsCollector"

    @property
    def __comp_arch_collector(self) -> str:
        return "ComputerArchitectureCollector"

    @property
    def name(self) -> str:
        return "CPU instruction set"

    @property
    def __required_flags(self) -> Set[str]:
        return {"sse4_2"}

    @property
    def __archs_with_sse4_2(self) -> Set[str]:
        return {"x86_64", "i386", "i686"}

    @property
    def depends_on(self) -> Set[str]:
        return {self.__cpu_spec_collector, self.__comp_arch_collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check if CPU has required flags.
        """
        arch = vitals[self.__comp_arch_collector].data['architecture']
        if arch not in self.__archs_with_sse4_2:
            self.status = AnalyzerStatus.SKIPPED
            self.message = f"SSE4.2 CPU instruction set is not supported on {arch}"
            return

        missing_flags = {flag for flag in self.__required_flags
                         if flag not in vitals[self.__cpu_spec_collector].data['flags']}
        if len(missing_flags) == 0:
            self.status = AnalyzerStatus.PASSED
            self.message = "All required CPU flags are present"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Required CPU flags {', '.join(missing_flags)} are not present"


class CPUScalingAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "CPU scaling setup"

    @property
    def __collector(self) -> str:
        return "CPUScalingCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that CPU scaling is supported, and respective services are active.
        """
        scaling_governor = vitals[self.__collector].data['scaling_governor']
        if not scaling_governor:
            self.status = AnalyzerStatus.FAILED
            self.message = "CPU does not support scaling"
        else:
            active_services = [service for service in vitals[self.__collector].data['services']
                               if vitals[self.__collector].data['services'][service]['active']]
            if len(active_services) == 0:
                self.status = AnalyzerStatus.FAILED
                self.message = "CPU scaling setup was not done"
            else:
                self.status = AnalyzerStatus.PASSED
                self.message = f"{active_services} scaling services are active"


class CPUSetAnalyzer(Analyzer):

    @property
    def name(self) -> str:
        return "cpuset setup"

    @property
    def __collector(self) -> str:
        return "CPUSetCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Scylla CPU set defined on cpuset.conf should be a subset of the
        maximum CPU set allowed by the configuration in the peftune.yaml.
        """
        cpusetconf_mask = vitals[self.__collector].data['cpusetconf_mask']
        cpusetconf_intersect_perftune_mask = vitals[self.__collector].data['cpusetconf_intersect_perftune_mask']

        if cpusetconf_intersect_perftune_mask != cpusetconf_mask:
            self.status = AnalyzerStatus.FAILED
            self.message = "cpuset value in cpuset.conf is not a subset of cpu_mask in perftune.yaml"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "cpuset is configured properly"


class CoredumpAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Coredump setup"

    @property
    def __collector(self) -> str:
        return "CoredumpCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __coredump_service(self) -> str:
        return "var-lib-systemd-coredump.mount"

    @property
    def __user_generated_filename(self) -> str:
        return "/usr/lib/sysctl.d/50-coredump.conf"

    @property
    def __scylla_generated_filename(self) -> str:
        return "/etc/sysctl.d/99-scylla-coredump.conf"

    @property
    def __scylla_generated_file_content(self) -> str:
        return 'kernel.core_pattern=|/usr/lib/systemd/systemd-coredump %p %u %g %s %t %e"'

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that coredump setup is done for scylla.
        """
        if self.__coredump_service not in vitals[self.__collector].data['services'] \
                or not vitals[self.__collector].data['services'][self.__coredump_service]['active']:
            self.status = AnalyzerStatus.FAILED
            self.message = "Coredump setup was not done, please run scylla_coredump_setup.py"
            return

        if self.__user_generated_filename in vitals[self.__collector].data['files']:
            self.status = AnalyzerStatus.PASSED
            self.message = "Coredump optimized"
            return

        if self.__scylla_generated_filename in vitals[self.__collector].data['files']:
            self.status = AnalyzerStatus.PASSED
            self.message = "Coredump optimized"

            file_content = vitals[self.__collector].data['files'][self.__scylla_generated_filename]
            lineno = 0

            # Check that except for comments and empty lines the only meaningful content in the file
            # is the one generated by scylla_coredump_setup.py.
            for line in file_content:
                lineno += 1
                clean_line = line.strip()

                # Skip comments and empty lines
                if len(clean_line) == 0 or clean_line[0] == '#':
                    continue

                if clean_line != self.__scylla_generated_file_content:
                    self.status = AnalyzerStatus.FAILED
                    self.message = f"Unexpected content in {self.__scylla_generated_filename}: " \
                                   f"line: {lineno}: {line}, please run scylla_coredump_setup.py"
                    break

            return

        self.status = AnalyzerStatus.FAILED
        self.message = "Coredump setup was not done properly, please run scylla_coredump_setup.py"


class DeveloperModeAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Developer Mode setup"

    @property
    def __collector(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that dev-mode is disabled for Scylla.
        """
        devmode_content = vitals[self.__collector].data['files'].get("dev-mode.conf", {})
        if devmode_content:
            devmode_value = devmode_content.get('DEV_MODE', "")
            if "1" in devmode_value:
                self.status = AnalyzerStatus.WARNING
                self.message = "Developer mode is enabled"
                return

        self.status = AnalyzerStatus.PASSED
        self.message = "Developer mode is not enabled"


class RaftEnablementAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Raft is properly enabled"

    @property
    def __raft_group0_collector(self) -> str:
        return "RaftGroup0Collector"

    @property
    def __scylla_system_config_collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__raft_group0_collector, self.__scylla_system_config_collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check if Raft enablement was requested:
           - If 'no', return SKIPPED state.
           - If 'yes', verify that Raft enablement is complete: Raft is enabled and its upgrade state is
             'use_post_raft_procedures'.
        """
        # Changing 'consistent_cluster_management' configuration value from 'false' to 'true' on all nodes in the
        # cluster is going to initialize Raft enablement on all nodes which is going to lead to all cluster nodes join
        # Raft Group0 and Raft becoming operational.
        # After Raft enablement is complete all nodes are going to have 'group0_upgrade_state' value in
        # system.scylla_local set to 'use_post_raft_procedures'.
        # See more at https://opensource.docs.scylladb.com/stable/architecture/raft.html#verifying-that-raft-is-enabled
        raft_requested = (
            vitals[self.__scylla_system_config_collector].data.get('consistent_cluster_management'))
        if not (raft_requested and raft_requested['value']):
            self.status = AnalyzerStatus.SKIPPED
            self.message = "Raft is disabled"
            return

        raft_info = vitals[self.__raft_group0_collector].data
        raft_upgrade_state = raft_info['group0_upgrade_state']
        group0_id = raft_info['group0_id']
        if not (group0_id and raft_upgrade_state == 'use_post_raft_procedures'):
            self.status = AnalyzerStatus.FAILED
            self.message = f"Raft isn't properly enabled: group0 {group0_id}, upgrade_state {raft_upgrade_state}"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"Raft enabled: group0 ID: {group0_id}"


class RaftTopologyEnablementAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Consistent Topology is enabled"

    @property
    def __system_topology_collector(self) -> str:
        return "SystemTopologyCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__system_topology_collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check if Topology Over Raft is enabled: if 'upgrade_state' column in any row of 'system.topology' table is not
        'done', then Topology Over Raft is not enabled, and the Analyzer should return FAILED state.
        """
        # If Consistent Topology is not supported by Scylla - return SKIPPED state.
        if not vitals[self.__system_topology_collector].data['consistent_topology_supported']:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "Consistent Topology is not supported by Scylla"
            return

        bad_hosts = []
        system_topology_rows = vitals[self.__system_topology_collector].data['system_topology_rows']
        for topology_row in system_topology_rows:
            if topology_row['upgrade_state'] != 'done':
                bad_hosts.append(topology_row['host_id'])

        if not system_topology_rows:
            self.status = AnalyzerStatus.FAILED
            self.message = "Consistent Topology feature isn't enabled"
        elif bad_hosts:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Consistent Topology isn't properly enabled on the following hosts: {', '.join(bad_hosts)}"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "Consistent Topology is enabled on all hosts"


class GossipInfoConsistencyAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "TOKENS/CDC_GENERATION_ID in GossipInfo"

    @property
    def __gossip_info_collector(self) -> str:
        return "GossipInfoCollector"

    @property
    def __consistent_topology_feature_name(self) -> str:
        return "SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__gossip_info_collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        If Consistent Topology is not supported, check that TOKENS and CDC_GENERATION_ID fields are present in
        GossipInfo of the corresponding hosts.
        """
        gossip_info = vitals[self.__gossip_info_collector].data['gossip_info']
        bad_hosts: List[str] = []

        # Mandatory GossipInfo (application state) entries for every host that doesn't support Consistent Topology.
        # For those that do support Consistent Topology those entries are going to be in the system.topology table.
        no_consistent_topology_mandatory_field = [
            GossipInfoInvariantValues.TOKENS,
            GossipInfoInvariantValues.CDC_GENERATION_ID
        ]

        for host_id, host_gossip_info in gossip_info:
            if GossipInfoInvariantValues.SUPPORTED_FEATURES.name not in host_gossip_info:
                bad_hosts.append(f"{host_id}: {GossipInfoInvariantValues.SUPPORTED_FEATURES.name} is missing in the "
                                 f"GossipInfo")
                continue

            if self.__consistent_topology_feature_name not in host_gossip_info[GossipInfoInvariantValues.SUPPORTED_FEATURES.name]:  # noqa: E501
                for field in no_consistent_topology_mandatory_field:
                    if field.name not in host_gossip_info or not host_gossip_info[field.name]:
                        bad_hosts.append(f"{host_id}: {field.name} entry is missing or empty in the GossipInfo while "
                                         f"Consistent Topology is not supported")

        if bad_hosts:
            self.status = AnalyzerStatus.FAILED
            self.message = ', '.join(bad_hosts)
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "All hosts have TOKENS and CDC_GENERATION_ID entries in GossipInfo when needed"


class TopologyConsistencyAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Analyze Topology State Consistency"

    @property
    def __gossip_info_collector(self) -> str:
        return "GossipInfoCollector"

    @property
    def __token_metadata_hosts_mapping_collector(self) -> str:
        return "TokenMetadataHostsMappingCollector"

    @property
    def __raft_group0_collector(self) -> str:
        return "RaftGroup0Collector"

    @property
    def __system_peers_local_collector(self) -> str:
        return "SystemPeersLocalCollector"

    @property
    def __system_cluster_status_collector(self) -> str:
        return "SystemClusterStatusCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__gossip_info_collector,
                self.__token_metadata_hosts_mapping_collector,
                self.__raft_group0_collector,
                self.__system_peers_local_collector,
                self.__system_cluster_status_collector}

    def __compare_uuids_sets(self, s1_t: Tuple[str, Set[str]], s2_t: Tuple[str, Set[str]]) -> None:
        """
        Compare two sets of UUIDs and set a proper error message and error code if they are not equal
        :param s1_t: First UUIDs' set name and set itself
        :param s2_t: Second UUIDs' set name and set itself
        """
        if s1_t[1] == s2_t[1]:
            return

        s1_uniq_uuids = s1_t[1] - s2_t[1]
        s2_uniq_uuids = s2_t[1] - s1_t[1]

        error_messages = []

        if s1_uniq_uuids:
            s1_uniq_uuids_str = ", ".join(s1_uniq_uuids)
            error_messages.append(f"{s1_t[0]} items not present in {s2_t[0]}: {s1_uniq_uuids_str}")

        if s2_uniq_uuids:
            s2_uniq_uuids_str = ", ".join(s2_uniq_uuids)
            error_messages.append(f"{s2_t[0]} items not present in {s1_t[0]}: {s2_uniq_uuids_str}")

        self.status = AnalyzerStatus.FAILED
        self.message = ", ".join([self.message] + error_messages) if self.message else ", ".join(error_messages)

    def __compare_addr_uuids_maps(self, m1_t: Tuple[str, Dict[str, str]], m2_t: Tuple[str, Dict[str, str]]) -> None:
        """
        Compare two maps of addr -> UUIDs and set a proper error message and error code if they are not equal
        :param m1_t: First addr -> UUIDs' map name and a map itself
        :param m2_t: Second addr -> UUIDs' map name and a map itself
        """
        error_messages = []
        for addr, uuid in m1_t[1].items():
            if addr not in m2_t[1]:
                error_messages.append(f"{addr} is present in {m1_t[0]} but not in {m2_t[0]}")
                continue

            if m2_t[1][addr] != uuid:
                error_messages.append(f"{addr} has different host IDs in {m1_t[0]} ({uuid}) and "
                                      f"in {m2_t[0]} ({m2_t[1][addr]})")

        for addr, uuid in m2_t[1].items():
            if addr not in m1_t[1]:
                error_messages.append(f"{addr} is present in {m2_t[0]} but not in {m1_t[0]}")

        if error_messages:
            self.status = AnalyzerStatus.FAILED
            self.message = ", ".join([self.message] + error_messages) if self.message else ", ".join(error_messages)

    def __verify_gossip_info_consistency(self, gossip_info: List[Tuple[str, Dict]]) -> None:
        """
        Vewrify that Gossip application state doesn't have weird artifacts.
        :param gossip_info: data collected by GossipInfoCollector
        """
        # Verify that the same host address appears exactly once and that there are no None address entries
        seen_addrs = set()
        reported_addrs = set()
        none_addr_seen = False
        error_messages = []
        for addr, info in gossip_info:
            if addr in seen_addrs and addr not in reported_addrs:
                error_messages.append(f"Host with the address {addr} appears more than once in the Gossip state")
                reported_addrs.add(addr)

            if not none_addr_seen and addr is None:
                error_messages.append("Gossip state has an entry with a None address")
                # Report 'None' address just once
                none_addr_seen = True

            seen_addrs.add(addr)

        if error_messages:
            self.status = AnalyzerStatus.FAILED
            self.message = ", ".join([self.message] + error_messages) if self.message else ", ".join(error_messages)

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that host id sets in raft_group0, system.peers and local host, gossipinfo, system.cluster_status and
        token_metadata are identical
        """
        self.status = AnalyzerStatus.PASSED

        # Generate Sets of UUIDs from each Collector

        # GossipInfo
        gossip_info = vitals[self.__gossip_info_collector].data['gossip_info']
        gossip_uuids = {v.get(GossipInfoInvariantValues.HOST_ID.name) for k, v in gossip_info
                        if v.get(GossipInfoInvariantValues.HOST_ID.name) is not None}

        # Verify that the same broadcast_address doesn't appear more than once in the Gossip state, etc.
        self.__verify_gossip_info_consistency(gossip_info)

        # If Gossip state contains more than a single entry per-some address __verify_gossip_info_consistency()
        # have already reported it and the Analyzer would already be FAILED.
        # In such case let's use the first one such entry in order to possibly find additional issues.
        gossip_addr_uuids = {k: v.get(GossipInfoInvariantValues.HOST_ID.name) for k, v in gossip_info}

        # Token Metadata
        tm_info = vitals[self.__token_metadata_hosts_mapping_collector].data['hosts']
        tm_uuids = set(tm_info.values())
        tm_addr_uuids = tm_info

        # Raft Group0
        raft_group0_info = vitals[self.__raft_group0_collector].data
        raft_group0_uuids = set(raft_group0_info['hosts'])

        # system.peers + system.local
        system_peers_local_info = vitals[self.__system_peers_local_collector].data['hosts']
        system_peers_local_uuids = set([v['host_id'] for v in system_peers_local_info.values()])
        system_peers_local_addr_uuids = {k: v['host_id'] for k, v in system_peers_local_info.items()}

        # system.cluster_status
        system_cluster_status_info = vitals[self.__system_cluster_status_collector].data['hosts']
        system_cluster_status_uuids = set([v['host_id'] for v in system_cluster_status_info.values()])
        system_cluster_status_addr_uuids = {k: v['host_id'] for k, v in system_cluster_status_info.items()}

        uuids_sets_list = [
            ('GossipInfo', gossip_uuids),
            ('TokenMetadata', tm_uuids),
            ('SystemPeersLocal', system_peers_local_uuids),
            ('SystemClusterStatus', system_cluster_status_uuids),
        ]

        if raft_group0_info["group0_id"]:
            uuids_sets_list.append(('RaftGroup0', raft_group0_uuids))

        for i1 in range(len(uuids_sets_list) - 1):
            for i2 in range(i1 + 1, len(uuids_sets_list)):
                self.__compare_uuids_sets(uuids_sets_list[i1], uuids_sets_list[i2])

        # Compare (address, UUID) pairs
        addr_uuids_maps = [
            ('GossipInfo', gossip_addr_uuids),
            ('TokenMetadata', tm_addr_uuids),
            ('SystemPeersLocal', system_peers_local_addr_uuids),
            ('SystemClusterStatus', system_cluster_status_addr_uuids),
        ]

        for i1 in range(len(addr_uuids_maps) - 1):
            for i2 in range(i1 + 1, len(addr_uuids_maps)):
                self.__compare_addr_uuids_maps(addr_uuids_maps[i1], addr_uuids_maps[i2])

        if self.status == AnalyzerStatus.PASSED:
            self.message = "Topology is consistent"


class DriverVersionAnalyzer(Analyzer):

    @property
    def name(self) -> str:
        return "Driver version analyzer"

    @property
    def __collector_client_connections(self) -> str:
        return "ClientConnectionCollector"

    @property
    def __collector_scylla_version(self) -> str:
        return "ScyllaVersionCollector"

    @property
    def __key_minimum_version(self) -> str:
        return "minimum_version"

    @property
    def __key_latest_version(self) -> str:
        return "latest_version"

    @property
    def __api_endpoint(self) -> str:
        return self.config.get('driver_api_endpoint',
                               'https://cfqlgypqmoofu6wdoojklzdzhe0lqqso.lambda-url.us-east-2.on.aws/search')

    def __init_config_required_version(self, version_type: str) -> Dict[str, str]:
        """
        :param version_type: Either minimum or latest version.
        :return: Loads input minimum or latest driver version from the config and sanitizes the versions.
        """
        config_required_version = json.loads(self.config.get(version_type, "{}"))

        # Strip version 'v' prefix if it occurs in the driver version
        for driver, driver_version in config_required_version.items():
            config_required_version[driver] = re.sub(r'^v', '', driver_version)

        return config_required_version

    def __init__(self, configuration: DictView):
        super().__init__(configuration)

        self.__driver_names_config_mapping = {
            'DataStax Java Driver': 'Java',
            'Scylla Python Driver': 'Python',
            'ScyllaDB Python Driver': 'Python',
            'github.com/scylladb/gocql': 'Go',
            'github.com/gocql/gocql': 'Go',
            'scylla-rust-driver': 'Rust',
            'Scylla Shard-Aware C/C++ Driver': 'CPP',
            # DataStax Python Driver: It has been >5 years since the Scylla driver used that name (Jun 2020)
            # DataStax Java Driver for Apache Cassandra: This name was never used by Scylla drivers.
        }

        self.__config_required_minimum_version = self.__init_config_required_version(self.__key_minimum_version)
        self.__config_required_latest_version = self.__init_config_required_version(self.__key_latest_version)

    @property
    def __config_minimum_version(self) -> Dict[str, str]:
        return self.__config_required_minimum_version

    @property
    def __config_latest_version(self) -> Dict[str, str]:
        return self.__config_required_latest_version

    @property
    def __driver_names_to_config_mapping(self) -> Dict[str, str]:
        return self.__driver_names_config_mapping

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_client_connections, self.__collector_scylla_version}

    def _is_supported_driver_name(self, driver_name: str) -> bool:
        """
        :param driver_name: Driver name (e.g. Scylla Python Driver)
        :return: Checks if the client driver name is a supported one by the analyzer.
        """
        return driver_name in self.__driver_names_to_config_mapping.keys()

    def _get_minimum_driver_version(self, client_driver_name: str, scylla_version: str) -> Optional[str]:
        """
        :param client_driver_name: The client driver name (e.g. Scylla Python Driver)
        :param scylla_version: The scylla version (e.g. 2024.1)
        :return: The minimum driver version for the provided scylla_version and driver_name,
                 or None in case a driver version could not be fetched.
        """
        return self._get_required_driver_version(self.__key_minimum_version, self.__config_minimum_version,
                                                 client_driver_name, scylla_version)

    def _get_latest_driver_version(self, client_driver_name: str) -> Optional[str]:
        """
        :param client_driver_name: The client driver name (e.g. Scylla Python Driver)
        :return: The latest driver version for the provided driver_name,
                 or None in case a driver version could not be fetched.
        """
        return self._get_required_driver_version(self.__key_latest_version, self.__config_latest_version,
                                                 client_driver_name)

    def _get_required_driver_version(self, version_type, config_input_version, client_driver_name: str,
                                     scylla_version: str = '') -> Optional[str]:
        """
        :param version_type: Retrieve either the latest, or the minimum driver version
        :param config_input_version: Input (if provided) with a driver version per driver
        :param client_driver_name: The client driver name (e.g. Scylla Python Driver)
        :param scylla_version: The scylla version (e.g. 2022.1.14 or 2024.1.4-0.20240428.67dd10537f78)
        :return: The minimum driver version for the provided scylla_version, or the latest driver version,
                 or None in case a driver version could not be fetched.
        """
        # If a user did not provide any required driver versions, we fetch it via an API call.
        config_driver_name = self.__driver_names_to_config_mapping[client_driver_name]

        if config_driver_name not in config_input_version:
            headers = {'Content-Type': 'application/json'}
            data = {'driverName': client_driver_name, 'scyllaVersion': scylla_version}
            response = get_url_content(self.__api_endpoint, headers, data)

            if response is None or len(json.loads(response)) == 0:
                return None
            else:
                required_driver_response = json.loads(response)

            # Select the oldest returned driver version in case of minimum, otherwise the newest.
            required_driver = required_driver_response[-1 if version_type == self.__key_minimum_version else 0]
            required_driver_version = re.sub(r'^v', '', required_driver['version'])

            return required_driver_version
        else:
            return config_input_version[config_driver_name]

    @staticmethod
    def _get_driver_versions_from_client_connections(client_connections: Dict[str, List[Dict[str, str]]]) \
            -> Dict[str, Set[str]]:
        """
        :param client_connections: Data from the ClientConnectionCollector with connection info per IP.
        :result: A dictionary of driver_name and associated driver versions e.g. {'Python Driver': ('1.1', '2.0')}
        """
        driver_versions: Dict[str, Set[str]] = {}

        # For each client IP
        # For each client IP connection: Retrieve the used driver and driver version
        for client_ip, client_ip_connections in client_connections.items():
            for client_connection in client_ip_connections:
                driver_name = client_connection.get('driver_name')
                driver_version = client_connection.get('driver_version')

                if not driver_name or not driver_version:
                    continue

                # Sanitize and remove 'v' prefix if present
                driver_version = re.sub(r'^v', '', driver_version)

                driver_versions.setdefault(driver_name, set()).add(driver_version)

        return driver_versions

    def _analyze(self, vitals: DictView) -> None:
        """
        We check whether all used client driver version numbers are above the required driver version.
        min versions: {'Scylla Python Driver': '3.2.5' }
        """
        client_connections = vitals[self.__collector_client_connections].data
        client_driver_versions = self._get_driver_versions_from_client_connections(client_connections)
        scylla_version = vitals[self.__collector_scylla_version].data['version']

        # Carve out the short version of Scylla Version (e.g. 2022.2.15) because this is what API expects
        m = re.match(r'(\d+\.\d+\.\d+).*', scylla_version)
        if m:
            scylla_version = m.group(1)
        else:
            # Bad scylla version format
            self.status = AnalyzerStatus.FAILED
            self.message = f"Bad Scylla Version format: {scylla_version}"
            return

        error_messages = []
        warning_messages = []

        for client_driver_name in client_driver_versions:
            # Warning (i):  The driver name is not recognized
            if not self._is_supported_driver_name(client_driver_name):
                warning_messages.append(f"Unknown driver name: {client_driver_name}")
                continue

            for client_driver_version in client_driver_versions[client_driver_name]:
                minimum_driver_version = self._get_minimum_driver_version(client_driver_name, scylla_version)
                recommended_driver_version = self._get_latest_driver_version(client_driver_name)

                if minimum_driver_version is None or recommended_driver_version is None:
                    self.status = AnalyzerStatus.FAILED
                    self.message = (f"API call error occurred to retrieve the minimum or latest driver version for "
                                    f"'{client_driver_name}'")
                    return

                try:
                    # Error (i): The used driver name is proper and the version is below the minimum version.
                    if compare_versions(client_driver_version, minimum_driver_version, "<"):
                        message = (f"{client_driver_name} with version {client_driver_version} is below "
                                   f"the minimum driver version {minimum_driver_version}")
                        error_messages.append(message)

                    # Warning (ii): The used driver name is proper and the version is below the recommended version.
                    elif compare_versions(client_driver_version, recommended_driver_version, "<"):
                        message = (f"{client_driver_name} with version {client_driver_version} is below "
                                   f"the latest driver version {recommended_driver_version}")
                        warning_messages.append(message)

                # Warning (iii): Invalid driver version format by the client
                except InvalidVersionFormat:
                    warning_messages.append(f"Invalid driver version format by driver: {client_driver_name} " +
                                            f"with version: {client_driver_version}")

        if len(error_messages) > 0 or len(warning_messages) > 0:
            self.status = AnalyzerStatus.FAILED if len(error_messages) > 0 else AnalyzerStatus.WARNING
            self.message = ', '.join([f"ERROR: {e}" for e in error_messages] +
                                     [f"WARNING: {w}" for w in warning_messages])
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "Client driver versions are within bounds."


class IOSetupAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "I/O setup"

    @property
    def __collector_config(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def __collector_paths(self) -> str:
        return "PathsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_config, self.__collector_paths}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that I/O setup was done, and io.conf content matches io_properties.yaml content.
        """
        io_file = "io.conf"
        ioproperties_file = "io_properties.yaml"
        seastar_io_option = "SEASTAR_IO"
        scylla_config_dir = vitals[self.__collector_paths].data['scylla_directory_configs']
        seastar_io_recommended_value = f"--io-properties-file[= ]{os.path.join(scylla_config_dir, ioproperties_file)}"

        io_file_content = vitals[self.__collector_config].data['files'].get(io_file, {})
        if not io_file_content or not io_file_content.get(seastar_io_option):
            self.status = AnalyzerStatus.WARNING
            self.message = "I/O setup was not done"
            return

        seastar_io_value = io_file_content[seastar_io_option]
        ioproperties_file_content = vitals[self.__collector_config].data['files'].get(ioproperties_file, {})
        if re.search(seastar_io_recommended_value, seastar_io_value):
            if ioproperties_file_content:
                # TODO: Check if io_properties.yaml content is valid
                self.status = AnalyzerStatus.PASSED
                self.message = "I/O setup was done"
            else:
                self.status = AnalyzerStatus.WARNING
                self.message = "I/O setup has its configuration broken (io_properties.yaml is missing)"
        else:
            if ioproperties_file_content:
                self.status = AnalyzerStatus.WARNING
                self.message = "I/O setup has its configuration broken (io_properties.yaml isn't being used)"
            else:  # some customized confgiuration
                self.status = AnalyzerStatus.PASSED
                self.message = "I/O setup was done"


class KernelVersionAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Kernel version"

    @property
    def __collector(self) -> str:
        return "ComputerArchitectureCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __minimal_version(self) -> str:
        return "3.15"

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that kernel version is officially supported.
        """
        current_kernel_version = vitals[self.__collector].data['kernel_version']
        try:
            if compare_versions(current_kernel_version, self.__minimal_version, ">="):
                self.status = AnalyzerStatus.PASSED
                self.message = f"Kernel version {current_kernel_version} is supported"
            else:
                self.status = AnalyzerStatus.FAILED
                self.message = f"Kernel version is lower than {self.__minimal_version}"
        except InvalidVersionFormat as e:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Failed to analyze a kernel version: {e}"


class MemoryTuningAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Memory tuning configuration"

    @property
    def __collector(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that memory tweaking was done.
        """
        memory_file = vitals[self.__collector].data['files'].get("memory.conf", {})
        if not memory_file or not memory_file.get('MEM_CONF'):
            self.status = AnalyzerStatus.WARNING
            self.message = "Memory setup was not done, please check memory.conf"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "Memory setup was done"


class NICsAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Analyze NICs"

    @property
    def __collector_nics(self):
        return "NICsCollector"

    @property
    def __collector_provider(self):
        return "InfrastructureProviderCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_nics, self.__collector_provider}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that there is a NIC with a speed over recommended threshold.
        For AWS, check that VPC support and enhanced networking is enabled.
        """
        provider = vitals[self.__collector_provider].data['provider']
        skip_nic_speed_check = self.config.get('skip_nic_speed_check')
        # Let's not check NIC speed on AWS and GCP by default since they don't expose NIC's link speed via
        # 'ethtool <nic>'.
        if skip_nic_speed_check is None and provider in {"AWS", "GCP"}:
            skip_nic_speed_check = True

        warn = []
        messages = []
        if not skip_nic_speed_check:
            nics = vitals[self.__collector_nics].data['nics']

            suggested_speed = int(self.config.get('speed', 10000))  # 10 Gbps is the minimum speed suggested
            suggested_nic_count = len([nic for nic, nic_data in nics.items()
                                       if nic_data['speed'] and nic_data['speed'] >= suggested_speed])

            if suggested_nic_count == 0:
                warn.append(f"There is no NIC available that matches recommended speed threshold of {suggested_speed}.")
        else:
            messages.append("Skipped NIC speed check.")

        # provider-specific checks
        if provider == "AWS":
            if not vitals[self.__collector_provider].data['extra'].get('enhanced_networking_nic_type'):
                warn.append("EC2 instance class does not support enhanced networking.")
            elif not vitals[self.__collector_provider].data['extra'].get('vpc_enabled_from_nics'):
                warn.append("VPC is not enabled and it is required to have enhanced networking support.")
            elif not vitals[self.__collector_provider].data['extra'].get('enhanced_networking_driver_support'):
                warn.append("Enhanced networking is disabled.")

        if warn:
            self.status = AnalyzerStatus.WARNING
            self.message = " ".join(warn)
        else:
            self.status = AnalyzerStatus.PASSED
            messages.append("Networking setup is ok.")
            self.message = " ".join(messages)


class NodeInstanceTypeAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Node instance type"

    @property
    def __collector(self) -> str:
        return "InfrastructureProviderCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __recommended_instance_types(self) -> Dict[str, List[str]]:
        return {
            "AZURE": [
                "Standard_L8s_v2",
                "Standard_L16s_v2",
                "Standard_L32s_v2",
                "Standard_L48s_v2",
                "Standard_L64s_v2",
                "Standard_L80s_v2",
                "Standard_L8s_v3",
                "Standard_L16s_v3",
                "Standard_L32s_v3",
                "Standard_L48s_v3",
                "Standard_L64s_v3",
                "Standard_L80s_v3"
            ],
            "AWS": [
                "i3.large",
                "i3.xlarge",
                "i3.2xlarge",
                "i3.4xlarge",
                "i3.8xlarge",
                "i3.16xlarge",
                "i3.metal",
                "i3en.large",
                "i3en.xlarge",
                "i3en.2xlarge",
                "i3en.3xlarge",
                "i3en.6xlarge",
                "i3en.12xlarge",
                "i3en.24xlarge",
                "i4i.large",
                "i4i.xlarge",
                "i4i.2xlarge",
                "i4i.4xlarge",
                "i4i.8xlarge",
                "i4i.12xlarge",
                "i4i.16xlarge",
                "i4i.24xlarge",
                "i4i.32xlarge",
                "i4i.metal",
                "i7i.large",
                "i7i.xlarge",
                "i7i.2xlarge",
                "i7ie.large",
                "i7ie.xlarge",
                "i7ie.2xlarge",
                "i7ie.3xlarge",
                "i7ie.6xlarge",
                "i7ie.12xlarge",
                "i7ie.18xlarge",
                "i7ie.24xlarge",
                "i7ie.48xlarge",
                "i8g.large",
                "i8g.xlarge",
                "i8g.2xlarge",
                "i8g.4xlarge",
                "i8g.8xlarge",
                "i8g.12xlarge",
                "i8g.16xlarge",
                "i8g.24xlarge",
                "i8g.48xlarge",
                "i8g.metal-24xl",
                "i8g.metal-48xl",
                "i8ge.large",
                "i8ge.xlarge",
                "i8ge.2xlarge",
                "i8ge.3xlarge",
                "i8ge.6xlarge",
                "i8ge.12xlarge",
                "i8ge.18xlarge",
                "i8ge.24xlarge",
                "i8ge.48xlarge",
                "i8ge.metal-24xl",
                "i8ge.metal-48xl",
            ],
            "GCP": [
                "n2-highmem-2",
                "n2-highmem-4",
                "n2-highmem-8",
                "n2-highmem-16",
                "n2-highmem-32",
                "n2-highmem-48",
                "n2-highmem-64",
                "n2-highmem-80",
                "n2-highmem-96",
                "n2d-highmem-2",
                "n2d-highmem-4",
                "n2d-highmem-8",
                "n2d-highmem-16",
                "n2d-highmem-32",
                "n2d-highmem-48",
                "n2d-highmem-64",
                "n2d-highmem-80",
                "n2d-highmem-96",
                "z3-highmem-8-highlssd",
                "z3-highmem-16-highlssd",
                "z3-highmem-22-highlssd"
                "z3-highmem-32-highlssd",
                "z3-highmem-44-highlssd",
                "z3-highmem-88-highlssd",
                "z3-highmem-14-standardlssd",
                "z3-highmem-22-standardlssd"
                "z3-highmem-44-standardlssd",
                "z3-highmem-88-standardlssd",
                "z3-highmem-176-standardlssd"
            ]
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that for cloud installations, recommended instance types are used.
        """
        provider = vitals[self.__collector].data['provider']
        if not provider:
            self.status = AnalyzerStatus.PASSED
            self.message = "Not a cloud instance"
            return

        instance_type = vitals[self.__collector].data['instance_type']
        if not instance_type:
            self.status = AnalyzerStatus.WARNING
            self.message = "Cannot determine node instance type"
            return

        self.message = f"'{instance_type}' instance type"
        if instance_type in self.__recommended_instance_types.get(provider, []):
            self.status = AnalyzerStatus.PASSED
            self.message += " is listed as recommended"
        else:
            self.status = AnalyzerStatus.WARNING
            self.message += " is not listed as recommended"


class NTPStatusAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "NTP Status Analyzer"

    @property
    def __collector(self) -> str:
        return "NTPStatusCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that NTP is enabled, and the system clock is synchronized.
        """
        ntp_enabled = vitals[self.__collector].data.get('ntp_enabled', False)
        ntp_synchronized = vitals[self.__collector].data.get('ntp_synchronized', False)

        if not ntp_enabled:
            self.status = AnalyzerStatus.FAILED
            self.message = "NTP is not enabled."
            return

        if not ntp_synchronized:
            self.status = AnalyzerStatus.FAILED
            self.message = "The system clock is not NTP synchronized."
            return

        self.status = AnalyzerStatus.PASSED
        self.message = "NTP is enabled and the system clock is synchronized."


class NTPServicesAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "NTP Services Setup"

    @property
    def __collector(self) -> str:
        return "NTPServicesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that at least one NTP-related service is enabled.
        """
        ntp_services = vitals[self.__collector].data['services']
        active_services = [service for service in ntp_services if ntp_services[service]['active'] is True]
        if len(active_services) > 0:
            self.status = AnalyzerStatus.PASSED
            self.message = "NTP setup was done"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = "NTP setup was not done"


class ComputerArchitectureAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Computer architecture"

    @property
    def __collector(self) -> str:
        return "ComputerArchitectureCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __supported_arch(self) -> Set[str]:
        return {"x86_64", "arm64", "ppc64", "aarch64"}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check whether architecture is officially supported.
        """
        arch = vitals[self.__collector].data['architecture']
        if arch in self.__supported_arch:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{arch} is officially supported"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"{arch} is not officially supported"


class OSSupportAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Operating system"

    @property
    def __collector(self) -> str:
        return "OSCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __supported_distros(self) -> Dict[str, Any]:
        return {
            'ubuntu': {
                'versions': ["24.04", "22.04", "20.04", "18.04", "16.04"],
            },
            'debian': {
                'versions': ["12", "11", "10", "9"],
            },
            'centos': {
                'versions': ["10", "9", "8", "7"],
                'minimum_version': "7.2"
            },
            'rhel': {
                'versions': ["10", "9", "8"],
            },
            'rocky': {
                'versions': ["10", "9", "8"],
            },
            'amzn': {
                'versions': ["2023"]
            }
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that OS is officially supported.
        """
        distro = vitals[self.__collector].data['name']
        version = vitals[self.__collector].data['version']
        full_version_minor = vitals[self.__collector].data['version_minor']
        split_version_minor = full_version_minor.split()
        if len(split_version_minor) > 0:
            version_minor = split_version_minor[0]
        else:
            version_minor = ""

        if not (distro in self.__supported_distros and
                (version_minor in self.__supported_distros[distro]['versions'] or
                 version in self.__supported_distros[distro]['versions'])):
            self.status = AnalyzerStatus.FAILED
            self.message = f"'{distro} {version_minor}'" \
                           " is not officially supported"
            return

        if self.__supported_distros[distro].get('minimum_version'):
            minimum_version = self.__supported_distros[distro]['minimum_version']
            try:
                if not compare_versions(version_minor, minimum_version, ">="):
                    self.status = AnalyzerStatus.FAILED
                    self.message = f"{distro} {version} is officially supported starting from version {minimum_version}"
                    return
            except InvalidVersionFormat as e:
                self.status = AnalyzerStatus.FAILED
                self.message = f"Failed to analyze a OS version: {e}"
                return

        self.status = AnalyzerStatus.PASSED
        self.message = f"'{distro} {full_version_minor}' is officially supported"


class PerftuneAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Perftune.py"

    @property
    def __collector(self) -> str:
        return "PerftuneSystemConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def __compare_str_or_int16_list(self, a: str, b: str) -> bool:
        """
        Compare two strings, which can be either plain strings or lists of hex values (e.g. "ff", "0a,ff,00").
        :param a: First string to compare
        :param b: Second string to compare
        :return: True if strings contain values that compare as equal.

        Two string values are considered equal if:
          - They are equal lexicographically.
          - Strings contain comma-separated list of hex values. In such a case corresponding integer lists are aligned
            to have the same length by prepending a required number of zero values to the shorter list. After that
            lists are compared following tuples comparison rule.
          - Strings contain space-separated lists of hex values. In this case lists are compared as tuples without
            aligning.
        """
        def compare_int16_lists(aa: str, bb: str, separator: None | str, pad_with_zeros: bool) -> bool:
            def parse_hex_list(s: str) -> List[int]:
                return [int(p.strip(), 16) for p in s.split(separator)]

            try:
                # Compare lists of hex values or plain hex values.
                # Note: split(',') on a string without commas returns a single-element list,
                # so this handles both hex lists and plain hex cases uniformly.
                # When lists differ in length, the shorter one is prepended with zeros if pad_with_zeros == True
                a_ints = parse_hex_list(aa)
                b_ints = parse_hex_list(bb)
                if pad_with_zeros:
                    pad = len(a_ints) - len(b_ints)
                    if pad > 0:
                        b_ints = [0] * pad + b_ints
                    elif pad < 0:
                        a_ints = [0] * (-pad) + a_ints
                return a_ints == b_ints
            except (ValueError, TypeError):
                return False

        # String comparison
        if a == b:
            return True
        elif not a or not b:
            # If only one of the values is an empty string - return False
            # At this point we already established that a != b thanks to a previous condition
            return False

        # Integers lists comparison
        for separator, pad_with_zeros in [(None, False), (",", True)]:
            if compare_int16_lists(a, b, separator, pad_with_zeros):
                return True

        return False

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all tweakings suggested by perftune (based on perftune.yaml content) are actually applied.
        """
        def inconsistent_message(kind: str, where: str, read_value: str, should_be_value: str) -> str:
            """
            :param kind: "file" or "sysctl"
            :param where: a file or a sysctl name
            :param read_value: actual value
            :param should_be_value: expected value
            :return: Resulting message
            """
            return f"Inconsistent value found for {kind} {where}: {read_value} instead of {should_be_value}"

        def append_new_status(
                status_list: List[Tuple[str, AnalyzerStatus]], message: str, status: AnalyzerStatus) -> None:
            """
            Append a given message and an Analyzer status to the list.
            If the list is not empty - make sure the first word of the message uses lower case characters.
            :param status_list: List of status tuples to append new info to
            :param message: message to append
            :param status: Analyzer status
            """
            if not status_list:
                status_list.append((message, status))
            else:
                split_message = message.split()

                # Sanity
                if not split_message:
                    status_list.append((message, status))
                    return

                # lowercase the first word
                status_list.append((" ".join([split_message[0].lower()] + split_message[1:]), status))

        skip_files: Set[str] = self._parse_comma_separated_config('skip_files')
        skip_sysctls: Set[str] = self._parse_comma_separated_config('skip_sysctls')

        inconsistency_status: List[Tuple[str, AnalyzerStatus]] = []

        files = vitals[self.__collector].data['perftune'].get('files')
        if files:
            for file, content in files.items():
                if file in skip_files:
                    continue
                # Special case 'scheduler' files: their content goes as follows:
                # <val1> [<val2>] val3 val4 ...
                # Where the value in [] is the actually configured value (val2 in the example above)
                if os.path.basename(file) == 'scheduler':
                    res = re.match(r".*\[(.*)].*", vitals[self.__collector].data['files'][file])
                    if res:
                        file_content = res.group(1)
                    else:
                        append_new_status(inconsistency_status, f"Unexpected format in {file}",
                                          AnalyzerStatus.FAILED)
                        continue
                else:
                    file_content = vitals[self.__collector].data['files'][file]
                if not self.__compare_str_or_int16_list(content, file_content):
                    append_new_status(inconsistency_status,
                                      inconsistent_message(
                                          "file", file, file_content, content), AnalyzerStatus.WARNING)

        sysctls = vitals[self.__collector].data['perftune'].get('sysctl')
        if sysctls:
            for param, value in sysctls.items():
                if param in skip_sysctls:
                    continue
                sysctl_value = vitals[self.__collector].data['sysctl'][param]
                if value != sysctl_value:
                    append_new_status(inconsistency_status,
                                      inconsistent_message(
                                          "sysctl", param, sysctl_value, value), AnalyzerStatus.WARNING)

        if not inconsistency_status:
            self.status = AnalyzerStatus.PASSED
            message = "Verified perftune.py modifications are intact"
            if skip_files:
                message += f" (not checked files: {skip_files})"
            if skip_sysctls:
                message += f" (not checked sysctls: {skip_sysctls})"
            self.message = message

        else:
            self.status = AnalyzerStatus.combine([s[1] for s in inconsistency_status])
            self.message = ", ".join([s[0] for s in inconsistency_status])


class PerftuneCpuMaskAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Check CPU mask against defaults"

    @property
    def __collector_cpuset(self) -> str:
        return "CPUSetCollector"

    @property
    def __collector_default(self) -> str:
        return "PerftuneYamlDefaultCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cpuset, self.__collector_default}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that cpu_mask generated using mode specified in perftune.yaml,
        matches the one generated by perftune.py with default settings (as in scylla_setup)
        """
        cpu_mask_actual = vitals[self.__collector_cpuset].data.get('perftune_mask', '').strip()
        cpu_mask_default = vitals[self.__collector_default].data.get('cpu_mask', '').strip()

        if cpu_mask_actual == cpu_mask_default:
            self.status = AnalyzerStatus.PASSED
            self.message = f"Actual cpu mask ({cpu_mask_actual}) matches default"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Actual cpu mask content ({cpu_mask_actual}) differs from default ({cpu_mask_default})"


class PerftuneYamlAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Check perftune.yaml content against defaults"

    @property
    def __collector_actual(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def __collector_default(self) -> str:
        return "PerftuneYamlDefaultCollector"

    @property
    def __ignore_keys(self) -> Set:
        return {'mode', 'irq_cpu_mask'}

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_actual, self.__collector_default}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that perftune.yaml on disk has the content that would have been generated by `scylla_sysconfig_setup`.
        """
        perftune_actual_content = vitals[self.__collector_actual].data['files'].get('perftune.yaml', {})
        perftune_default_content = vitals[self.__collector_default].data.get('perftune.yaml', {})

        if {k: v for k, v in perftune_actual_content.items() if k not in self.__ignore_keys} == \
                {k: v for k, v in perftune_default_content.items() if k not in self.__ignore_keys}:
            self.status = AnalyzerStatus.PASSED
            self.message = "Actual perftune.yaml content matches default"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = "Actual perftune.yaml content differs from default"


class RAIDSetupAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "RAID Setup"

    @property
    def __collector_raid(self) -> str:
        return "RAIDSetupCollector"

    @property
    def __collector_storage(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_raid, self.__collector_storage}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that if any data-related directory is mounted on an SW RAID assembly it is of a RAID0 kind.
        """
        mdstat_content = vitals[self.__collector_raid].data['/proc/mdstat']

        messages = []
        for dir, dir_stats in vitals[self.__collector_storage].data.items():
            for dir_stat in dir_stats.values():
                # union nvme and non-nvme devices
                devices = set(itertools.chain.from_iterable(dir_stat['devices'].values()))

                raid_device = None
                raid_mode = None

                for device in devices:
                    output = [line for line in mdstat_content if device in line]

                    if output:
                        if len(output) > 1:
                            self.status = AnalyzerStatus.WARNING
                            self.message = f"Funny RAID configuration detected for {dir}"
                            return
                        else:
                            raid_device = output[0].split(" : ")[0]
                            raid_mode = output[0].split(" : ")[1].split()[1].upper()

                if raid_mode not in [None, "RAID0"]:
                    self.status = AnalyzerStatus.WARNING
                    self.message = f"RAID mode {raid_mode} detected for {dir}, it is not recommended"
                    return

                if not raid_device or not raid_mode:
                    messages.append(f"{dir}: No RAID")
                else:
                    messages.append(f"{dir}: {raid_mode}")

        self.message = ",".join(messages)
        self.status = AnalyzerStatus.PASSED


class RAMAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "RAM availablity"

    @property
    def __collector_ram(self) -> str:
        return "RAMCollector"

    @property
    def __collector_cpu(self) -> str:
        return "CPUSpecificationsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_ram, self.__collector_cpu}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that available RAM is greater than recommended (or at least, minimal required),
        both total and per logical core.
        """
        ram_minimum_total = int(self.config.get('ram_minimum_total', 4194304))  # 4 gb
        ram_minimum_per_lcore = int(self.config.get('ram_minimum_per_lcore', 524288))  # 0.5 gb
        ram_recommended_total = int(self.config.get('ram_recommended_total', 16777216))  # 16 gb
        ram_recommended_per_lcore = int(self.config.get('ram_recommended_per_lcore', 4194304))  # 4 gb

        if any([ram_minimum_total > ram_recommended_total,
                ram_minimum_per_lcore > ram_recommended_per_lcore]):
            raise AbortedException(f"Sanity check failed for {self.id}: please check configuration parameters: "
                                   f"ram_minimum_total, ram_minimum_per_lcore, "
                                   f"ram_recommended_total, ram_recommended_per_lcore")

        detected_available_ram = vitals[self.__collector_ram].data['total']
        logical_cores = vitals[self.__collector_cpu].data['logical_cores']

        suggested_minimum_ram = max(ram_minimum_total, ram_minimum_per_lcore * logical_cores)
        suggested_recommended_ram = max(ram_recommended_total, ram_recommended_per_lcore * logical_cores)

        if detected_available_ram < suggested_minimum_ram:
            memory_unit = HumanBytesUnitFormat.get_differentiating_format_for_kib(detected_available_ram,
                                                                                  suggested_minimum_ram)
            detected_human = f"{self.format_float(memory_unit.translate_kib(detected_available_ram))} {memory_unit}"
            minimum_human = f"{self.format_float(memory_unit.translate_kib(suggested_minimum_ram))} {memory_unit}"

            self.status = AnalyzerStatus.FAILED
            self.message = f"{detected_human} were detected but it is less than {minimum_human} (minimum required)"
        elif detected_available_ram < suggested_recommended_ram:
            memory_unit = HumanBytesUnitFormat.get_differentiating_format_for_kib(detected_available_ram,
                                                                                  suggested_recommended_ram)
            detected_human = f"{self.format_float(memory_unit.translate_kib(detected_available_ram))} {memory_unit}"
            recommended_human = (f"{self.format_float(memory_unit.translate_kib(suggested_recommended_ram))} "
                                 f"{memory_unit}")

            self.status = AnalyzerStatus.WARNING
            self.message = f"{detected_human} were detected but it is less than {recommended_human} (recommended)"
        else:
            memory_unit = HumanBytesUnitFormat.get_format_for_kib(detected_available_ram)
            detected_human = f"{self.format_float(memory_unit.translate_kib(detected_available_ram))} {memory_unit}"

            self.status = AnalyzerStatus.PASSED
            self.message = f"{detected_human} were detected"


class RsyslogAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Rsyslog setup"

    @property
    def __collector(self) -> str:
        return "RsyslogCollector"

    @property
    def __collector_platform(self) -> str:
        return "NodePlatformCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector, self.__collector_platform}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that rsyslog collection is set up for Scylla.
        """
        if vitals[self.__collector_platform].data['platform'] == NodePlatform.CONTAINER:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "Not available for containers"
            return

        if vitals[self.__collector].data['files']['/etc/rsyslog.d/scylla.conf']:
            self.status = AnalyzerStatus.PASSED
            self.message = "Rsyslog setup was done"
        else:
            self.status = AnalyzerStatus.WARNING
            self.message = "Rsyslog setup was not done"


class AIOMAXNRAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "aio-max-nr parameter"

    @property
    def __collector_sysctl(self) -> str:
        return "SysctlCollector"

    @property
    def __collector_cpu(self) -> str:
        return "CPUSpecificationsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_sysctl, self.__collector_cpu}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that fs.aio-max-nr sysctl value is greater than recommended value (per shard/CPU).
        """
        aiomaxnr = vitals[self.__collector_sysctl].data['fs.aio-max-nr']
        shards = vitals[self.__collector_cpu].data['logical_cores']

        # Defined based on expert knowledge (aka 'black magic')
        black_magic_number = shards * 11026 + 65536

        if aiomaxnr >= black_magic_number:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{aiomaxnr} is equal or greater than {black_magic_number} (recommended value)"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"{aiomaxnr} is less than {black_magic_number} (recommended value)"


class AssignedNICsAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "NICs assigned to Scylla"

    @property
    def __collector_nics(self) -> str:
        return "NICsCollector"

    @property
    def __collector_iproutes(self) -> str:
        return "IPRoutesCollector"

    @property
    def __collector_extra(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def __collector_system(self) -> str:
        return "ScyllaSystemConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_nics, self.__collector_iproutes, self.__collector_system, self.__collector_extra}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all NICs that Scylla adresses route thorugh, are tuned by perftune.
        """
        scylla_server = vitals[self.__collector_system].data['files'].get('scylla-server')
        if scylla_server is not None:
            set_nic_and_disks = scylla_server.get('SET_NIC_AND_DISKS', '')
            if set_nic_and_disks.lower() != "yes":
                self.status = AnalyzerStatus.SKIPPED
                self.message = "SET_NIC_AND_DISKS is not set"
                return
        else:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "scylla-server is not part of vitals!"
            return

        perftune_yaml = vitals[self.__collector_extra].data['files'].get('perftune.yaml')
        if not perftune_yaml:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "perftune.yaml is not found"
            return

        perftune_nics = perftune_yaml.get('nic')
        if isinstance(perftune_nics, str):
            perftune_nics = [perftune_nics]

        iproutes = [route for (addr, route) in vitals[self.__collector_iproutes].data.items()
                    if addr == "localhost" or int(ipaddress.ip_address(addr) != socket.INADDR_ANY)]
        all_nics = vitals[self.__collector_nics].data['nics'].keys()

        assigned_nics = set([nic for nic in all_nics
                             if any(nic in iproute for iproute in iproutes)])

        if not assigned_nics or not assigned_nics.issubset(perftune_nics):
            self.status = AnalyzerStatus.WARNING
            self.message = f"NICs assigned to scylla ({assigned_nics}) are not set up according to perftune.yaml ({perftune_nics})"  # noqa: E501
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{len(assigned_nics)} NIC(s) are assigned to Scylla"


class ScheduledMaintenanceEventAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scheduled Maintenance Event Analyzer"

    @property
    def __collector(self) -> str:
        return "MaintenanceEventsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that for cloud installations that support retrieving scheduled events,
        that there are no pending maintenance events.
        """
        events = vitals[self.__collector].data.get('scheduled_maintenance_events')

        if events is None:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "Pending maintenance events cannot be detected for the instance type and/or platform."
            return

        if not events:
            self.status = AnalyzerStatus.PASSED
            self.message = "No pending maintenance events detected."
            return

        self.status = AnalyzerStatus.FAILED
        self.message = f"The instance has a number of {len(events)} pending maintenance events."


class ScyllaBroadcastAddressAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Broadcast address"

    @property
    def __collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that Scylla broadcast address is not set to localhost or 0.0.0.0.
        """
        # broadcast address defaults to listen address, when not set:
        # https://docs.scylladb.com/stable/operating-scylla/admin.html#address-configuration-in-scylla
        broadcast_addr_key = "listen_address"
        if "broadcast_address" in vitals[self.__collector].data:
            broadcast_addr_key = "broadcast_address"

        if broadcast_addr_key not in vitals[self.__collector].data:
            self.status = AnalyzerStatus.FAILED
            self.message = "neither broadcast_address nor listen_address were set"
            return

        broadcast_addr_str = vitals[self.__collector].data[broadcast_addr_key]
        broadcast_addr_resolved = vitals[self.__collector].data["resolved"][broadcast_addr_key]

        ipv4_ipv6_resolved_addresses = broadcast_addr_resolved[0] + broadcast_addr_resolved[1]
        if has_ipaddr_any(ipv4_ipv6_resolved_addresses):
            self.status = AnalyzerStatus.FAILED
            self.message = f"{broadcast_addr_str} can't be used - resolves to INADDR_ANY"
        elif has_loopback(ipv4_ipv6_resolved_addresses):
            self.status = AnalyzerStatus.WARNING
            self.message = (f"{broadcast_addr_str} usage is not recommended for production environment - "
                            f"resolves to loopback")
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{broadcast_addr_str} is being used"


class ScyllaClusterSchemaAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Cluster schema"

    @property
    def __collector(self) -> str:
        return "ScyllaClusterSchemaCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that schema version is the same on all cluster nodes.
        """
        if len(vitals[self.__collector].data) > 1:
            self.status = AnalyzerStatus.WARNING
            self.message = "Schema mismatch"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "Schema synchronized"


class ScyllaClusterSystemKeyspacesReplicationAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "System keyspaces replication strategy"

    @property
    def __collector_keyspaces(self) -> str:
        return "ScyllaClusterSystemKeyspacesCollector"

    @property
    def __collector_nodes(self) -> str:
        return "ScyllaClusterStatusCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_keyspaces, self.__collector_nodes}

    @property
    def __keyspaces(self) -> Dict[str, Dict]:
        """
        Map of {keyspace_name: settings}. Available settings:
         - optional (defaults to False) - don't raise an error if keyspace is not present.
         - check_replication_factor (defaults to True) - raise an error if replication factor is insufficient
        """
        return {
            "system_auth": {},
            "system_distributed": {},
            "system_traces": {
                "check_replication_factor": False
            },
            "audit": {
                "optional": True
            }
        }

    @property
    def __strategy(self) -> str:
        return "NetworkTopologyStrategy"

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that system keyspaces use NetworkTopologyStrategy and have sufficient replication factor
        """
        node_count = len(vitals[self.__collector_nodes].data['up']) + len(vitals[self.__collector_nodes].data['down'])
        errors = []
        for keyspace, settings in self.__keyspaces.items():
            if keyspace not in vitals[self.__collector_keyspaces].data:
                if not settings.get("optional"):
                    errors.append(f"Keyspace '{keyspace}' is missing")
                continue

            replication = ast.literal_eval(vitals[self.__collector_keyspaces].data[keyspace]['replication'])
            if self.__strategy not in replication['class']:
                errors.append(f"{keyspace} keyspace is not using '{self.__strategy}' strategy")

            if settings.get("check_replication_factor", True):
                for dc in replication.keys():
                    if dc != "class" and int(replication[dc]) < min(3, node_count):
                        errors.append(f"{keyspace} keyspace has replication factor {replication[dc]} in {dc}")

        if errors:
            self.status = AnalyzerStatus.FAILED
            self.message = ";".join(errors)
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "All system keyspaces are ok"


class ScyllaKeyspacesReplicationAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Verify keyspaces replication strategy"

    @property
    def __collector_keyspaces(self) -> str:
        return "ScyllaClusterSystemKeyspacesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_keyspaces}

    @property
    def __system_keyspaces_replication(self) -> Dict[str, str]:
        """
        Map of {keyspace_name: replication strategy}.
        The rest of keyspaces are expected to use NetworkTopologyStrategy.
        """
        return {
            "system_replicated_keys": "EverywhereStrategy",
            "system_schema": "LocalStrategy",
            "system": "LocalStrategy",
            "system_distributed_everywhere": "EverywhereStrategy",
        }

    @property
    def __network_topology_strategy(self) -> str:
        return "NetworkTopologyStrategy"

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all keyspaces except for a few known ones use NetworkTopologyStrategy
        """
        errors = []
        keyspaces_schema = vitals[self.__collector_keyspaces].data
        for keyspace, schema in keyspaces_schema.items():
            replication_config = ast.literal_eval(schema.get("replication", "{}"))
            replication = replication_config.get("class", "")
            expected_replication = self.__system_keyspaces_replication.get(keyspace, self.__network_topology_strategy)

            if expected_replication not in replication:
                errors.append(f"'{keyspace}' is using '{replication}', expected '{expected_replication}'")

        if errors:
            self.status = AnalyzerStatus.FAILED
            self.message = ";".join(errors)
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "All keyspaces are ok"


class ScyllaDeprecatedArgumentsAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Deprecated arguments"

    @property
    def __deprecated_arguments(self) -> Set[str]:
        return {
            "--background-writer-scheduling-quota",
            "--auto-adjust-flush-quota",
            "--load-balance",
            "--join-ring",
            "--no-handle-interrupt"
        }

    @property
    def __collector(self) -> str:
        return "ScyllaSystemConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that no deprecated arguments are used to start Scylla.
        """
        filename = "scylla-server"
        content = vitals[self.__collector].data['files'].get(filename)
        if not content:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Config file '{filename}' was not found"
            return

        current_arguments = content.get("SCYLLA_ARGS", "").split()
        detected_deprecated_arguments = [argument for argument in current_arguments[::2]
                                         if argument in self.__deprecated_arguments]

        if len(detected_deprecated_arguments) == 0:
            self.status = AnalyzerStatus.PASSED
            self.message = "No deprecated arguments are currently in use"
        else:
            self.status = AnalyzerStatus.WARNING
            self.message = f"{', '.join(detected_deprecated_arguments)} deprecated argument(s) are in use"


class FSFILEMAXAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "'fs.file-max' value"

    @property
    def __collector_sysctl(self) -> str:
        return "SysctlCollector"

    @property
    def __collector_limitnofile(self) -> str:
        return "ScyllaLimitNOFILECollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_sysctl, self.__collector_limitnofile}

    @property
    def __recommended_value(self) -> int:
        """
        Black magic recommended value
        """
        return 9223372036854775807

    def _analyze(self, vitals: DictView) -> None:
        """
        Check fs.file-max limit is huge enough.
        """
        limitnofiles_value = vitals[self.__collector_limitnofile].data['limitnofile']
        filemax_value = vitals[self.__collector_sysctl].data['fs.file-max']

        if filemax_value < limitnofiles_value:
            self.status = AnalyzerStatus.FAILED
            self.message = f"fs.file-max value {filemax_value} is less than LimitNOFILE value {limitnofiles_value}"
        elif filemax_value < self.__recommended_value:
            self.status = AnalyzerStatus.WARNING
            self.message = f"fs.file-max value {filemax_value} is less than recommended value {self.__recommended_value}"  # noqa: E501
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"fs.file-max value {filemax_value} is greater than recommended value"


class FSNROPENAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "'fs.nr_open' value"

    @property
    def __collector_sysctl(self) -> str:
        return "SysctlCollector"

    @property
    def __collector_limitnofile(self) -> str:
        return "ScyllaLimitNOFILECollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_sysctl, self.__collector_limitnofile}

    @property
    def __recommended_value(self) -> int:
        """
        Black magic recommended value
        """
        return 1073741816

    def _analyze(self, vitals: DictView) -> None:
        """
        Check fs.nr_open limit is huge enough.
        """
        limitnofiles_value = vitals[self.__collector_limitnofile].data['limitnofile']
        nropen_value = vitals[self.__collector_sysctl].data['fs.nr_open']

        if nropen_value < limitnofiles_value:
            self.status = AnalyzerStatus.FAILED
            self.message = f"fs.nr_open value {nropen_value} is less than LimitNOFILE value {limitnofiles_value}"
        elif nropen_value < self.__recommended_value:
            self.status = AnalyzerStatus.WARNING
            self.message = f"fs.nr_open value {nropen_value} is less than recommended value {self.__recommended_value}"  # noqa: E501
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"fs.nr_open value {nropen_value} is greater than recommended value"


class ScyllaInternodeCompressionAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla internode compression"

    @property
    def __collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that internode compression is fully enabled.
        """

        recommended_compression = self.config.get("recommended_compression", "all")

        compression = vitals[self.__collector].data.get("internode_compression", "none")
        if compression != recommended_compression:
            self.status = AnalyzerStatus.WARNING
            self.message = f"Internode compression is set to '{compression}', " \
                           f"but it should be '{recommended_compression}'"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"Internode compression is set to '{compression}'"


class ScyllaLimitNOFILEAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "LimitNOFILE"

    @property
    def __collector(self) -> str:
        return "ScyllaLimitNOFILECollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __limitnofile_minimum(self) -> int:
        return 10000

    @property
    def __limitnofile_recommended(self) -> int:
        return 500000

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that LimitNOFILE value is big enough for scylla service.
        """
        limitnofile = vitals[self.__collector].data['limitnofile']

        if limitnofile < self.__limitnofile_minimum:
            self.status = AnalyzerStatus.FAILED
            self.message = f"{limitnofile} is less than {self.__limitnofile_minimum} (minimum value)"
        elif limitnofile < self.__limitnofile_recommended:
            self.status = AnalyzerStatus.WARNING
            self.message = f"{limitnofile} is less than {self.__limitnofile_recommended} (recommended value)"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{limitnofile} is greater than {self.__limitnofile_recommended} (recommended value)"


class ScyllaListenAddressAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla listen address"

    @property
    def __collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that listen address is not set to 0.0.0.0 or localhost.
        """
        listen_address_str = vitals[self.__collector].data.get("listen_address")
        if not listen_address_str:
            self.status = AnalyzerStatus.FAILED
            self.message = "Listen address is not set"
            return

        listen_address_resolved = vitals[self.__collector].data["resolved"]["listen_address"]

        ipv4_ipv6_resolved_addresses = listen_address_resolved[0] + listen_address_resolved[1]
        if has_loopback(ipv4_ipv6_resolved_addresses) or has_ipaddr_any(ipv4_ipv6_resolved_addresses):
            self.status = AnalyzerStatus.WARNING
            self.message = f"{listen_address_str} usage is not recommended for production environment"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{listen_address_str} is being used"


class ScyllaNICsDisksSetupAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla NICs and disks setup"

    @property
    def __collector(self) -> str:
        return "ScyllaSystemConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that SET_NIC_AND_DISKS option is enabled
        (responsible for NIC's and disks' interrupts, RPS, XPS, nomerges and I/O scheduler)
        """
        server_config = vitals[self.__collector].data['files'].get('scylla-server')
        if not server_config:
            self.status = AnalyzerStatus.FAILED
            self.message = "Scylla server config not found"
            return

        if server_config.get('SET_NIC_AND_DISKS', '').lower() != "yes":
            self.status = AnalyzerStatus.WARNING
            self.message = "SET_NIC_AND_DISKS should be set to 'yes'"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "SET_NIC_AND_DISKS is enabled"


class ScyllaRPCAddressAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla RPC address"

    @property
    def __collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that rpc_address is not set to "any" or localhost.
        """
        # rpc address must be set:
        # https://docs.scylladb.com/stable/operating-scylla/admin.html#address-configuration-in-scylla
        if "rpc_address" not in vitals[self.__collector].data:
            self.status = AnalyzerStatus.FAILED
            self.message = "rpc_address is not set"
            return

        rpc_address_str = vitals[self.__collector].data["rpc_address"]
        rpc_address_resolved = vitals[self.__collector].data["resolved"]["rpc_address"]

        ipv4_ipv6_resolved_addresses = rpc_address_resolved[0] + rpc_address_resolved[1]
        if has_loopback(ipv4_ipv6_resolved_addresses) or has_ipaddr_any(ipv4_ipv6_resolved_addresses):
            self.status = AnalyzerStatus.WARNING
            self.message = f"{rpc_address_str} usage is not recommended for production environment"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{rpc_address_str} is being used"


class ScyllaBroadcastRPCAddressAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla RPC broadcast address"

    @property
    def __collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that broadcast_rpc_address is effectively not to 0.0.0.0 (forbidden) or localhost (discouraged).
        """
        # broadcast_rpc_address defaults to rpc_address, when not set:
        # https://docs.scylladb.com/stable/operating-scylla/admin.html#address-configuration-in-scylla
        broadcast_rpc_address_key = "rpc_address"
        if "broadcast_rpc_address" in vitals[self.__collector].data:
            broadcast_rpc_address_key = "broadcast_rpc_address"

        if broadcast_rpc_address_key not in vitals[self.__collector].data:
            self.status = AnalyzerStatus.FAILED
            self.message = "neither broadcast_rpc_address nor rpc_address are set"
            return

        broadcast_rpc_address_str = vitals[self.__collector].data[broadcast_rpc_address_key]
        broadcast_rpc_address_resolved = vitals[self.__collector].data["resolved"][broadcast_rpc_address_key]
        ipv4_ipv6_resolved_addresses = broadcast_rpc_address_resolved[0] + broadcast_rpc_address_resolved[1]

        if has_ipaddr_any(ipv4_ipv6_resolved_addresses):
            self.status = AnalyzerStatus.FAILED
            self.message = f"{broadcast_rpc_address_str} can't be used as broadcast address - resolved to IPADDR_ANY"
        elif has_loopback(ipv4_ipv6_resolved_addresses):
            self.status = AnalyzerStatus.WARNING
            self.message = (f"{broadcast_rpc_address_str} usage is not recommended for production environment - "
                            f"resolves to loopback")
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{broadcast_rpc_address_str} is being used"


class ScyllaServicesAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla services"

    @property
    def __collector_services(self) -> str:
        return "ScyllaServicesCollector"

    @property
    def __discard_mount_option_name(self) -> str:
        return "discard"

    @property
    def __collector_storage_configuration(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def __scylla_version_collector(self) -> str:
        return "ScyllaVersionCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_services, self.__collector_storage_configuration, self.__scylla_version_collector}

    def __all_dirs_have_discard_opt(self, vitals: DictView) -> bool:
        """
        Check if all Scylla directories are mounted with a 'discard' option
        :param vitals: Vitals map
        :return: True if all Scylla directories are mounted with a 'discard' option, False otherwise.
        """
        for dir_group_name, dir_group in vitals[self.__collector_storage_configuration].data.items():
            for dir_info in dir_group.values():
                if self.__discard_mount_option_name not in dir_info['mount_options']:
                    return False

        return True

    def __services(self, vitals: DictView) -> List[Set[str]]:
        """Some services may have aliases"""
        services = [
            {"scylla-server", "scylla"},
            {"node-exporter", "scylla-node-exporter"},
            {"scylla-housekeeping-daily", "scylla-housekeeping"},
            {"scylla-manager-agent"}
        ]

        # scylla-jmx has been removed in 2025.1.0.
        # Ref https://forum.scylladb.com/t/release-scylladb-2025-1-part-2/4693
        scylla_version = vitals[self.__scylla_version_collector].data['version']
        if compare_versions(scylla_version, "2025.1.0", "<"):
            services.append({"scylla-jmx"})

        # scylla-fstrim service is special.
        # If scylla directories are all mounted with a 'dicard' option then it doesn't need to
        # be active and enabled. Otherwise, it must.
        if not self.__all_dirs_have_discard_opt(vitals):
            services.append({"scylla-fstrim.timer"})

        return services

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all scylla-related services are active and enabled.
        """
        skip_autostart_check = self._parse_comma_separated_config("skip_autostarts_check")
        autostart_disabled_services = self._parse_comma_separated_config("disable_autostarts")
        skip_active_check = self._parse_comma_separated_config("skip_active_check")
        disabled_services = self._parse_comma_separated_config("disable_active")
        services_info = vitals[self.__collector_services].data

        fails = []
        for service in self.__services(vitals):
            service_name = next((name for name in service if name in services_info), None)
            if not service_name:
                fails.append(f"{' or '.join(service)} (not found)")
            else:
                active = services_info[service_name]['active']
                must_be_autostart = service_name not in autostart_disabled_services
                must_be_active = service_name not in disabled_services
                autostarts = services_info[service_name]['autostarts']
                if not all([active == must_be_active or (service_name in skip_active_check),
                            autostarts == must_be_autostart or (service_name in skip_autostart_check)
                            ]):
                    fails.append(f"{service_name} (active - {active}, autostarts - {autostarts})")

        if not fails:
            self.status = AnalyzerStatus.PASSED
            self.message = "All services are ok"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Services not ok: {', '.join(fails)}"


class ScyllaSeedsAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla seeds availability"

    @property
    def __collector(self) -> str:
        return "ScyllaSeedsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all scylla seed nodes are reachable.
        """
        seeds = vitals[self.__collector].data
        if len(seeds) == 0:
            self.status = AnalyzerStatus.FAILED
            self.message = "No seeds detected"
            return

        unavailable_seeds = [seed for seed in seeds if seeds[seed] != 0]
        if len(unavailable_seeds) > 0:
            self.status = AnalyzerStatus.WARNING
            self.message = f"Some seeds are unreachable: {', '.join(unavailable_seeds)}"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "All seeds are reachable"


class ScyllaSnitchAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla snitch"

    @property
    def __collector_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def __collector_provider(self) -> str:
        return "InfrastructureProviderCollector"

    @property
    def __default_recommended_snitch(self) -> str:
        return "GossipingPropertyFileSnitch"

    @property
    def __provider_snitch(self) -> Dict[str, str]:
        return {
            "AWS": "Ec2MultiRegionSnitch",
            "GCP": "GoogleCloudSnitch"
        }

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_config, self.__collector_provider}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that scylla snitch is set to recommended value (gcp or aws specific ones, if applicable).
         """
        snitch = vitals[self.__collector_config].data.get('endpoint_snitch')
        if not snitch:
            self.status = AnalyzerStatus.FAILED
            self.message = "'endpoint_snitch' is not set"
            return

        provider = vitals[self.__collector_provider].data['provider']
        skip_check_provider = self.config.get('check_provider_snitch', '').lower() in self.config_run_skip_values
        if not provider or skip_check_provider:
            if snitch != self.__default_recommended_snitch:
                self.status = AnalyzerStatus.WARNING
                self.message = f"'{snitch}' is not recommended for production environment"
            else:
                self.status = AnalyzerStatus.PASSED
                self.message = f"'{snitch}' is used"
            return

        provider_snitch = self.__provider_snitch.get(provider, self.__default_recommended_snitch)
        if snitch != provider_snitch:
            if snitch == self.__default_recommended_snitch:
                self.status = AnalyzerStatus.WARNING
                self.message = f"'{snitch}' is used but it should be '{provider_snitch}' (recommended)"
            else:
                self.status = AnalyzerStatus.WARNING
                self.message = f"'{snitch}' is not recommended for production environment"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"'{snitch}' is used"


class ScyllaSSTablesAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla SSTables"

    @property
    def __sstables_collector(self) -> str:
        return "ScyllaSSTablesCollector"

    @property
    def __system_config_collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__sstables_collector, self.__system_config_collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that sstables are stored in recommended format
        """
        scylla_config = vitals[self.__system_config_collector].data
        sstable_format = (
            self.config.get("recommended_format", scylla_config.get('sstable_format', {}).get('value', 'me')))
        sstables = list(self.__sstables_files(vitals))
        if len(sstables) == 0:
            self.status = AnalyzerStatus.PASSED
            self.message = "No SSTables found"
        elif next((sstable for sstable in sstables if not re.search(f"^({sstable_format})",
                                                                    os.path.basename(sstable))), None):
            self.status = AnalyzerStatus.WARNING
            self.message = f"SSTable format is not '{sstable_format}' (recommended)"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"SSTable format is '{sstable_format}'"

    def __sstables_files(self, vitals: DictView) -> Iterable[str]:
        # Ref https://github.com/scylladb/scylladb/blob/master/docs/dev/sstables-directory-structure.md
        sstables_re = re.compile(r".*(((Data|Index|Filter|CompressionInfo|Summary|Statistics|CRC|Scylla)\.db)|"
                                 r"(Digest\.(crc32|adler32|sha1))|"
                                 r"TOC\.txt)$")

        return filter(lambda file_name: sstables_re.match(os.path.basename(file_name.strip())),
                      vitals[self.__sstables_collector].data['files'])


class CloudCPUPlatformAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Cloud VM CPU Platform"

    @property
    def __infrastructure_provider_collector(self) -> str:
        return "InfrastructureProviderCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__infrastructure_provider_collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check the VM has the requested CPU Platform.
        In case the host is not the VM or is a VM on a platform that doesn't support
        dynamic CPU Platform (currently only GCP supports it) the result is going to be
        'SKIPPED'.
        """
        expected_cpu_platform = self.config.get("expected_cpu_platform")
        current_cpu_platform = None
        infra_provider_info = vitals[self.__infrastructure_provider_collector].data
        if infra_provider_info['provider']:
            current_cpu_platform = infra_provider_info['cpu_platform']

        if not (expected_cpu_platform and current_cpu_platform):
            self.status = AnalyzerStatus.SKIPPED
            self.message = "'expected_cpu_platform' is not specified or CPU Platform is not dynamic"
        elif current_cpu_platform != expected_cpu_platform:
            self.status = AnalyzerStatus.FAILED
            self.message = f"CPU platform is '{current_cpu_platform}' while expecting '{expected_cpu_platform}'"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"CPU platform is '{current_cpu_platform}'"


class ScyllaSupportAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla version support"

    @property
    def __collector(self) -> str:
        return "ScyllaVersionCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that Scylla version has not reached EOL yet.
        """
        minimum_version = {
            'oss': self.config.get('oss_minimum_version', '6.1'),
            'enterprise': self.config.get('enterprise_minimum_version', '2024.1')
        }
        current_edition = vitals[self.__collector].data['edition']
        current_version = vitals[self.__collector].data['version']

        if current_edition == "development":
            self.status = AnalyzerStatus.SKIPPED
            self.message = "'Development' versions are not checked"
            return

        try:
            if compare_versions(current_version, minimum_version[current_edition], ">="):
                self.status = AnalyzerStatus.PASSED
                self.message = "Currently supported"
            else:
                self.status = AnalyzerStatus.WARNING
                self.message = "Currently unsupported since this version has reached its end of life"
        except InvalidVersionFormat as e:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Failed to analyze a Scylla version: {e}"


class ScyllaSystemConfigurationFilesAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla system-wide config files"

    @property
    def __scylla_system_config_file_collector(self) -> str:
        return "ScyllaSystemConfigurationFilesCollector"

    @property
    def __scylla_version_collector(self) -> str:
        return "ScyllaVersionCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__scylla_system_config_file_collector, self.__scylla_version_collector}

    def __required_files(self, vitals) -> Set[str]:
        required_files = {"scylla-housekeeping", "scylla-server"}

        # scylla-jmx has been removed in 2025.1.0.
        # Ref https://forum.scylladb.com/t/release-scylladb-2025-1-part-2/4693
        scylla_version = vitals[self.__scylla_version_collector].data['version']
        if compare_versions(scylla_version, "2025.1.0", "<"):
            required_files.add("scylla-jmx")

        return required_files

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all scylla-related services are configured.
        """
        for file in self.__required_files(vitals):
            if file not in vitals[self.__scylla_system_config_file_collector].data['files']:
                self.status = AnalyzerStatus.FAILED
                self.message = (f"Required config file {file} not found in "
                                f"{vitals[self.__scylla_system_config_file_collector].data['directory']}")
                return

        self.status = AnalyzerStatus.PASSED
        self.message = "All required config files are present"


class ScyllaUpdateAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla version up-to-dateness"

    @property
    def __collector(self) -> str:
        return "ScyllaVersionCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that scylla is upgraded to latest version, that' known to be stable.
        """
        current_version = vitals[self.__collector].data['version']
        current_edition = vitals[self.__collector].data['edition']
        if current_edition == "enterprise":
            latest_version = self.config.get('enterprise_latest_version')
        else:
            latest_version = self.config.get('oss_latest_version')

        if not latest_version:
            scylla_url_version = "https://repositories.scylladb.com/scylla/check_version"
            if current_edition == "enterprise":
                scylla_url_version += "?system=enterprise"

            latest_version_response = get_url_content(scylla_url_version)

            if latest_version_response is None:
                self.status = AnalyzerStatus.FAILED
                self.message = f"Cannot retrieve scylla latest version from {scylla_url_version}"
                return
            else:
                latest_version = json.loads(latest_version_response)['version']

        try:
            if compare_versions(current_version, latest_version, "<"):
                self.status = AnalyzerStatus.WARNING
                self.message = f"Current version {current_version} can be upgraded to {latest_version}"
            elif compare_versions(current_version, latest_version, ">"):
                self.status = AnalyzerStatus.FAILED
                self.message = f"Current version {current_version} is greater than {latest_version} (latest available version) - check your configuration."  # noqa: E501
            else:
                self.status = AnalyzerStatus.PASSED
                self.message = f"Current version {current_version} is the latest available version"
        except InvalidVersionFormat as e:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Failed to analyze a Scylla version: {e}"


class SELinuxAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "SELinux setup"

    @property
    def __collector(self) -> str:
        return "SELinuxCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that SELinux is disabled (due to performance penalty).
        """
        content = vitals[self.__collector].data['files']['/etc/selinux/config']
        if not content:
            self.status = AnalyzerStatus.PASSED
            self.message = "SELinux is not present"
            return

        selinux_config = [s for s in content if re.search("^SELINUX=", s)]
        selinux_mode = selinux_config[0].split('=')[1].strip() if selinux_config else None
        if not selinux_mode:
            self.status = AnalyzerStatus.WARNING
            self.message = "SELinux status cannot be determined"
        elif selinux_mode == "disabled":
            self.status = AnalyzerStatus.PASSED
            self.message = "SELinux is disabled"
        else:
            self.status = AnalyzerStatus.WARNING
            self.message = "SELinux is working in {} mode".format(selinux_mode)


class StorageTypeAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Storage configuration"

    @property
    def __collector(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all data-related directories settle on NVME disks.
        """
        nvme_devices_count = sum([len(dir_stats['devices']['nvme'])
                                  for dir_stats in vitals[self.__collector].data['data_file_directories'].values()])
        non_nvme_devices_count = sum([len(dir_stats['devices']['non_nvme'])
                                      for dir_stats in vitals[self.__collector].data['data_file_directories'].values()])

        if not nvme_devices_count and not non_nvme_devices_count:
            self.status = AnalyzerStatus.FAILED
            self.message = "Storage type cannot be determined"
            return

        if nvme_devices_count and non_nvme_devices_count:
            self.status = AnalyzerStatus.WARNING
            disk_type = "NVME + non-NVME"
        elif non_nvme_devices_count:
            self.status = AnalyzerStatus.WARNING
            disk_type = "non-NVME"
        else:
            self.status = AnalyzerStatus.PASSED
            disk_type = "NVME"

        storage_size = sum([dir_stats['storage_size_kb'] for dir_stats
                            in vitals[self.__collector].data['data_file_directories'].values()])
        storage_unit = HumanBytesUnitFormat.get_format_for_kib(storage_size)
        self.message = (f"{self.format_float(storage_unit.translate_kib(storage_size))} {storage_unit} "
                        f"detected ({disk_type})")


class StorageRAMRatioAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Storage/RAM ratio"

    @property
    def __collector_ram(self) -> str:
        return "RAMCollector"

    @property
    def __collector_storage(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_ram, self.__collector_storage}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that Storage/RAM ratio is lower than recommended value.
        """
        recommended_ratio = int(self.config.get('ratio', 105))
        total_storage = sum([dir_stats['storage_size_kb'] for dir_stats
                             in vitals[self.__collector_storage].data['data_file_directories'].values()])
        total_ram = vitals[self.__collector_ram].data['total']

        if not total_storage:
            self.status = AnalyzerStatus.FAILED
            self.message = "Cannot determine the ratio between storage/RAM"
            return

        detected_ratio = int(total_storage / total_ram)
        if detected_ratio <= recommended_ratio:
            self.status = AnalyzerStatus.PASSED
            self.message = f"Storage/RAM ratio ({str(detected_ratio)}:1) is lower than recommended ({str(recommended_ratio)}:1)"  # noqa: E501
        else:
            self.status = AnalyzerStatus.WARNING
            self.message = f"Storage/RAM ratio ({str(detected_ratio)}:1) is higher than recommended ({str(recommended_ratio)}:1)"  # noqa: E501


class SwapAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Swap configuration"

    @property
    def __collector_swap(self) -> str:
        return "SwapCollector"

    @property
    def __collector_ram(self) -> str:
        return "RAMCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_swap, self.__collector_ram}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that sufficient amount of swap is configured.
        """
        swap_minimum = int(self.config.get('swap_minimum_total', 16777216))
        recommended_ratio = float(self.config.get('ram_swap_ratio', 3))
        suggested_swap = min(swap_minimum, vitals[self.__collector_ram].data['total'] / recommended_ratio)
        detected_swap = vitals[self.__collector_swap].data['total']

        if detected_swap == 0:
            self.status = AnalyzerStatus.FAILED
            self.message = "No swap configuration detected"
            return

        if detected_swap >= suggested_swap:
            unit_human = HumanBytesUnitFormat.get_format_for_kib(detected_swap)
            self.status = AnalyzerStatus.PASSED
            self.message = f"{self.format_float(unit_human.translate_kib(detected_swap))} {unit_human} were detected"
        else:
            unit_human = HumanBytesUnitFormat.get_differentiating_format_for_kib(detected_swap, suggested_swap)
            self.status = AnalyzerStatus.WARNING
            self.message = \
                (f"{self.format_float(unit_human.translate_kib(detected_swap))} {unit_human} were "
                 f"detected but it is less than "
                 f"{self.format_float(unit_human.translate_kib(suggested_swap))} (recommended)")


class XFSAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "XFS setup"

    @property
    def _collector(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self._collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that data-related directories reside on XFS.
        """
        for dirs in vitals[self._collector].data.values():
            for dir_stats in dirs.values():
                if dir_stats['filesystem'] != "xfs":
                    self.status = AnalyzerStatus.WARNING
                    self.message = "XFS setup was not done"
                    return
        self.status = AnalyzerStatus.PASSED
        self.message = "XFS setup was done"


class SDVersionAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "SD version"

    @property
    def __collector_sdversion(self) -> str:
        return "SDVersionCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_sdversion}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that versions of collected data and this analyzer match.
        """
        script_path = os.path.dirname(__file__)
        verfile = 'version'
        buildversion = os.path.join(script_path, verfile)
        if zipfile.is_zipfile(script_path):
            with zipfile.ZipFile(script_path, 'r') as archive:
                gitversion = archive.read(verfile).decode().strip()
        elif os.path.isfile(buildversion):
            with open(buildversion) as f:
                gitversion = f.readline().strip()
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = "Cannot find version file, did you run 'make version' ?"
            return

        collected_version = vitals[self.__collector_sdversion].data['version']

        if gitversion is not None and collected_version == gitversion:
            self.status = AnalyzerStatus.PASSED
            self.message = "Versions of collected data and analyzer match."
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Version mismatch: collected: {collected_version} analyzer: {gitversion}"


class ScyllaConfigurationFileFormatAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Special scylla.yaml fields format"

    @property
    def __raw_scylla_yaml_collector(self) -> str:
        return "ScyllaConfigurationFileNoParsingCollector"

    @property
    def __scylla_config_collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__raw_scylla_yaml_collector, self.__scylla_config_collector}

    def __validate_restriction_mode_fields(self, vitals: DictView) -> Tuple[AnalyzerStatus, str]:
        """
        Checks the format of so-called "tri-state" values.

        Ref https://github.com/scylladb/scylladb/issues/22785
        tri_mode_restriction configuration parameters are allowed to be configured to case-sensitive strings
        'true', 'false', 'warn', '0', '1' or an integer 0 or 1, or boolean values (only lower-case) true or false.
        The 'type' of these values in system.config is 'restriction mode'.

        Let's verify that the value of each such parameter present in the scylla.yaml is one of the supported ones.

        :param vitals: Vitals of the required collectors
        :return: A tuple of a corresponding AnalyzerStatus and an error message.
        """
        raw_scylla_yaml = vitals[self.__raw_scylla_yaml_collector].data
        scylla_config = vitals[self.__scylla_config_collector].data
        allowed_values = ['true', 'false', '0', '1', 'warn']

        # Let's build a list of all allowed YAML ways to set values in unquoted, quoted and double-quoted ways.
        allowed_config_values = []
        for value in allowed_values:
            allowed_config_values += [value, f"'{value}'", f'"{value}"']

        bad_fields = []
        for field, _ in filter(lambda config_record: config_record[1]['type'] == 'restriction mode',
                               scylla_config.items()):
            if field in raw_scylla_yaml and raw_scylla_yaml[field] not in allowed_config_values:
                bad_fields.append(field)

        if bad_fields:
            error_message = ", ".join([f"{field} has an invalid value: [{raw_scylla_yaml[field]}]"
                                       for field in bad_fields])
            error_message += f", while allowed values are {allowed_config_values}."
            return AnalyzerStatus.FAILED, error_message

        return AnalyzerStatus.PASSED, ""

    def _analyze(self, vitals: DictView) -> None:
        """
        Analyzer fields that have format that is beyond regular YAML syntax
        """
        error_messages = []

        # Validate 'restriction mode' values format
        status, message = self.__validate_restriction_mode_fields(vitals)
        if status != AnalyzerStatus.PASSED:
            error_messages.append(message)

        if error_messages:
            self.message = " ".join(error_messages)
            self.status = AnalyzerStatus.FAILED
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "Scylla Configuration is well-formed"


class ScyllaConfigurationConsistencyAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla configuration consistency"

    @property
    def __scylla_yaml_collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def __scylla_config_collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__scylla_yaml_collector, self.__scylla_config_collector}

    def __validate_config_source(self, vitals: DictView) -> Tuple[List[str], Set[str]]:
        """
        Check that every key that is not present in scylla.yaml has a 'default' or 'internal' as a source and every one
        that is present has a 'config' as a source.
        :param vitals: Vitals collected by required Collectors
        :return: Tuple of (sorted list of keys with an incorrect source, user-configured skip keys).
        """

        user_skip_keys: Set[str] = self._parse_comma_separated_config("skip_source_validation_keys")

        scylla_yaml_dict = vitals[self.__scylla_yaml_collector].data['pure_scylla_yaml']
        scylla_config_sources_dict = {key: value['source'] for
                                      key, value in vitals[self.__scylla_config_collector].data.items()}

        skip_keys = user_skip_keys | {
            # These have to be removed from the scylla.yaml after usage, but they would still remain in memory
            'initial_token',
            'replace_node',
            'replace_node_first_boot',
            'replace_address',
            'replace_address_first_boot',
            'ignore_dead_nodes_for_replace'
        }

        divergent_keys = []
        for k, v in scylla_config_sources_dict.items():
            key_in_scylla_yaml = k in scylla_yaml_dict

            # max_memory_for_unlimited_query is a shortcut for max_memory_for_unlimited_query_hard_limit
            if not key_in_scylla_yaml:
                if k == 'max_memory_for_unlimited_query_hard_limit':
                    key_in_scylla_yaml = 'max_memory_for_unlimited_query' in scylla_yaml_dict

            # Skip these keys
            if k in skip_keys:
                continue

            if not key_in_scylla_yaml:
                if v not in ['default', 'internal']:
                    divergent_keys.append(k)
            else:
                if v != 'config':
                    divergent_keys.append(k)

        return sorted(divergent_keys), user_skip_keys

    def __validate_persisted_config_values(self, vitals: DictView) -> Tuple[List[str], Set[str]]:
        """
        Check that all configuration keys that are present in scylla.yaml have the same value in-memory

        :param vitals: Vitals collected by required Collectors
        :return: Tuple of (sorted list of keys with differing values, user-configured skip keys).
        """

        user_skip_keys: Set[str] = self._parse_comma_separated_config("skip_persisted_validation_keys")

        scylla_yaml_dict = copy.deepcopy(vitals[self.__scylla_yaml_collector].data['pure_scylla_yaml'])
        scylla_config_values_dict = {key: copy.deepcopy(value['value']) for
                                     key, value in vitals[self.__scylla_config_collector].data.items()}

        # Special cases: ###########################################

        # Tri-state fields
        # Ref https://github.com/scylladb/scylladb/issues/22785
        # tri_mode_restriction configuration parameters are allowed to be configured to (case-sensitive):
        # 'true', 'false', 'warn', '0', '1', integer 0 or 1, boolean True or False.
        # However, the corresponding value in system.config is going to be one of the following strings '1', '0',
        # 'warn'.
        #
        # Let's bring both the scylla.yaml and the system.config value to a common denominator
        for tri_state_key, _ in filter(lambda config_record: config_record[1]['type'] == 'restriction mode',
                                       vitals[self.__scylla_config_collector].data.items()):
            if scylla_yaml_dict.get(tri_state_key) in [False, 0, 'false', '0']:
                scylla_yaml_dict[tri_state_key] = '0'
            elif scylla_yaml_dict.get(tri_state_key) in [True, 1, 'true', '1']:
                scylla_yaml_dict[tri_state_key] = '1'

            if scylla_config_values_dict[tri_state_key] in [False, 0, 'false', '0']:
                scylla_config_values_dict[tri_state_key] = '0'
            elif scylla_config_values_dict[tri_state_key] in [True, 1, 'true', '1']:
                scylla_config_values_dict[tri_state_key] = '1'

        # hinted_handoff_enabled can get a string or a boolean value
        if scylla_config_values_dict.get('hinted_handoff_enabled') == 'false':
            scylla_config_values_dict['hinted_handoff_enabled'] = False

        # max_memory_for_unlimited_query is an alias for max_memory_for_unlimited_query_hard_limit
        if 'max_memory_for_unlimited_query' in scylla_yaml_dict:
            scylla_yaml_dict['max_memory_for_unlimited_query_hard_limit'] = (
                scylla_yaml_dict)['max_memory_for_unlimited_query']
            del scylla_yaml_dict['max_memory_for_unlimited_query']

        # Keys to skip
        skip_keys = user_skip_keys | {
            "seed_provider",  # https://github.com/scylladb/scylladb/issues/21269
            "object_storage_endpoints",  # https://scylladb.atlassian.net/browse/SCYLLADB-1658
        }

        def to_bool(val: Any) -> bool:
            """
            Convert a value from system.config to bool, handling string representations.
            """
            if isinstance(val, str):
                return val.lower() in ('1', 'true', 'yes')
            return bool(val)

        divergent_keys = []
        for k, v in scylla_yaml_dict.items():
            # Special cases: https://github.com/scylladb/scylladb/issues/21355,
            #                https://scylladb.atlassian.net/browse/SCT-253
            if (k in {"client_encryption_options", "system_info_encryption", "user_info_encryption"} and
                    k in scylla_config_values_dict and 'enabled' in scylla_config_values_dict[k]):
                scylla_config_values_dict[k]['enabled'] = to_bool(scylla_config_values_dict[k]['enabled'])

            if k == "kms_hosts" and k in scylla_config_values_dict:
                for sub_key in ["aws_use_ec2_credentials", "aws_use_ec2_region"]:
                    if sub_key in scylla_config_values_dict[k]:
                        scylla_config_values_dict[k][sub_key] = to_bool(scylla_config_values_dict[k][sub_key])

            # Skip keys that are not in system.config table - these are not supported by the current Scylla
            # version.
            # Also skip keys from the skip_keys set which includes keys with known issues.
            if k not in scylla_config_values_dict or k in skip_keys:
                continue

            if scylla_config_values_dict[k] != v:
                divergent_keys.append(k)

        return sorted(divergent_keys), user_skip_keys

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that scylla.yaml configuration and in-memory configuration are the same.
        All values present in scylla.yaml must be exactly the same in the in-memory configuration.

        And then also check that all in-memory configuration values that are not present in scylla.yaml
        have a default value.

        :param vitals: Vitals collected by required Collectors
        """
        # Validate in-memory values of keys present in scylla.yaml
        persisted_divergent_keys, skipped_persisted_keys = self.__validate_persisted_config_values(vitals)

        # Validate in-memory keys' sources consistency
        bad_source_keys, skipped_source_keys = self.__validate_config_source(vitals)

        self.status = AnalyzerStatus.PASSED

        skipped_notes = []
        if skipped_persisted_keys:
            skipped_notes.append(f"Keys excluded from a validation against scylla.yaml: "
                                 f"{sorted(skipped_persisted_keys)}")

        if skipped_source_keys:
            skipped_notes.append(f"Keys excluded from a source check validation: {sorted(skipped_source_keys)}")

        self.message = ". ".join(["Scylla configuration is consistent"] + skipped_notes)
        error_messages = []

        if persisted_divergent_keys:
            error_messages.append(f"Scylla configuration differs from the one present in scylla.yaml for "
                                  f"keys: {persisted_divergent_keys}.")

        if bad_source_keys:
            error_messages.append(f"Keys with the inconsistent configuration source: {bad_source_keys}")

        if error_messages:
            self.status = AnalyzerStatus.FAILED
            self.message = ". ".join(error_messages + skipped_notes)


class RaftTopologyRPCStatusAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Verify no ongoing Raft Topology RPCs"

    @property
    def __collector_raft_topology_rpc_status(self) -> str:
        return "RaftTopologyRPCStatusCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_raft_topology_rpc_status}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that there are no hang Raft Topology RPC commands.
        """
        topology_rpc_status = vitals[self.__collector_raft_topology_rpc_status].data

        if topology_rpc_status == "none":
            self.status = AnalyzerStatus.PASSED
            self.message = "No ongoing Raft Topology RPCs."
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"There is an ongoing Raft Topology RPC: {topology_rpc_status}."


class DisabledCompactionAnalyzer(Analyzer):
    """
    Verify that not-Null compaction strategy is defined and enabled for every table.
    """
    @property
    def name(self) -> str:
        return "Verify compactions are enabled"

    @property
    def __tables_schema_collector(self) -> str:
        return "ScyllaClusterTablesDescriptionCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__tables_schema_collector}

    def _analyze(self, vitals: DictView) -> None:
        # Example entry in the ScyllaClusterTablesDescriptionCollector data:
        #
        # "system_replicated_keys": {
        #         "encrypted_keys": {
        #           "keyspace_name": "system_replicated_keys",
        #           "table_name": "encrypted_keys",
        #           "bloom_filter_fp_chance": "0.01",
        #           "caching": "{'keys': 'ALL', 'rows_per_partition': 'ALL'}",
        #           "comment": "",
        #           "compaction": "{'class': 'IncrementalCompactionStrategy', 'enabled': 'false'}",
        #           "compression": "{'sstable_compression': 'org.apache.cassandra.io.compress.LZ4Compressor'}",
        #           "crc_check_chance": "1",
        #           "dclocal_read_repair_chance": "0",
        #           "default_time_to_live": "0",
        #           "extensions": "{}",
        #           "flags": "{'compound'}",
        #           "gc_grace_seconds": "864000",
        #           "id": "f705e6dd-8cc5-378b-a7e9-aec38e033747",
        #           "max_index_interval": "2048",
        #           "memtable_flush_period_in_ms": "0",
        #           "min_index_interval": "128",
        #           "read_repair_chance": "0",
        #           "speculative_retry": "99.0PERCENTILE"
        #         }
        #       },
        # ...
        #
        # We only want to check the data[<ks>][<table>]['compaction'] content: if compaction class is specified it's
        # enabled by default.
        #
        schema = vitals[self.__tables_schema_collector].data
        ignored_tables = self._parse_comma_separated_config("ignored_tables")

        # Workaround for https://scylladb.atlassian.net/browse/SCYLLADB-1372
        ignored_tables.add("system.hints")

        null_compaction_strategy_tables = []
        for ks, ks_info in schema.items():
            for table, table_schema in ks_info.items():
                if f"{ks}.{table}" in ignored_tables:
                    continue
                compaction_config = json.loads(table_schema.get("compaction", "{}").replace("'", '"'))
                if (not compaction_config or
                        compaction_config.get("class", "").lower() in ["nullcompactionstrategy", ""] or
                        compaction_config.get("enabled", "").lower() == "false"):
                    null_compaction_strategy_tables.append(f"{ks}:{table}")

        if null_compaction_strategy_tables:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Tables {', '.join(null_compaction_strategy_tables)} have compactions disabled."
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "All tables have compactions enabled."
            if ignored_tables:
                self.message += f" Ignored tables: {', '.join(sorted(ignored_tables))}"


class BrokenRolePermissionsAnalyzer(Analyzer):
    """
    Verify that there are no 'null' permissions in the 'roles' table..
    """
    @property
    def name(self) -> str:
        return "Verify non-null permissions in the 'roles' table"

    @property
    def __roles_permissions_collector(self) -> str:
        return "RolePermissionsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__roles_permissions_collector}

    def _analyze(self, vitals: DictView) -> None:
        permissions = vitals[self.__roles_permissions_collector].data
        errors = []
        for permission in permissions:
            # If permissions have a null value, it will be presented as an empty string in the Collector's data
            if permission.get('permissions', '') == '':
                self.status = AnalyzerStatus.FAILED
                errors.append(f"Role '{permission.get('role')}' has a null permission for "
                              f"resource '{permission.get('resource')}'")

        if errors:
            self.status = AnalyzerStatus.FAILED
            self.message = " ; ".join(errors)
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "No null permissions in the 'roles' table."


class STCSInSchemaAnalyzer(Analyzer):
    """
    Verify that tables don't use STCS
    """
    @property
    def name(self) -> str:
        return "Verify that tables don't use STCS"

    @property
    def __tables_schema_description_collector(self) -> str:
        return "ScyllaClusterTablesDescriptionCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__tables_schema_description_collector}

    def _analyze(self, vitals: DictView) -> None:
        tables_schema = vitals[self.__tables_schema_description_collector].data
        errors = []
        for ks, tables_data in tables_schema.items():
            for table, table_schema in tables_data.items():
                compaction_config = ast.literal_eval(table_schema.get("compaction", "{}"))
                if "SizeTieredCompactionStrategy" in compaction_config.get("class", ""):
                    errors.append(f"{ks}.{table}")

        if errors:
            self.status = AnalyzerStatus.FAILED
            self.message = "Tables that use STCS: " + ", ".join(errors)
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "There are no tables that use STCS."
