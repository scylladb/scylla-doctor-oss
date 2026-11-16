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

from typing import Dict, List, Set, Tuple

from analyzers_base import Analyzer, AnalyzerStatus
from common import GossipInfoInvariantValues, DictView


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
