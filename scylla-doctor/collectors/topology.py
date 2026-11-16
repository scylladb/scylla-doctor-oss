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

from typing import Dict, Optional, Set, List, Iterable, Union, Sequence, Tuple

from common import DictView, Paths, ConfigParameter, GossipInfoInvariantValues
from collectors_base import CollectorStatus, Collector, ScyllaRestApiAwareCollector
from models.output_entry import OutputEntryType, Level

from utils import Executor, CqlFailedException, ServiceManager


class InvalidGossipInfo(Exception):
    pass


class GossipInfoCollector(ScyllaRestApiAwareCollector):
    @property
    def name(self) -> str:
        return "Collect gossipinfo data"

    @property
    def __collector_scylla_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_scylla_config}

    def __parse_one_gossipinfo_entry(self, entry: DictView) -> Tuple[str | None, Dict]:
        """
        Parse a single host gossipinfo entry creating an ordered dictionary with fields that are supposed to be the same
        on all nodes.

        :param entry: raw gossipinfo single host entry returned by the REST API
        :return: Host address and a dictionary with parsed gossipinfo entry values that we want to compare between
                 different nodes.
        """
        # Gossipinfo has the following structure:
        #  [ {
        #      "addrs": <Host0 broadcast address>,
        #      "generation": <gossip generation>,
        #      "version": <gossip version>,
        #      "update_time": <timestamp>,
        #      "is_alive": <host0 alive state: 'true' or 'false'>,
        #      "application_state": [
        #            {
        #               "application_state": <state code>,
        #               "value": <state value>,
        #               "version": <state version"
        #            },
        #            ...
        #       ],
        #     },
        #     ...
        #  ]
        # Application state items have following codes
        # enum class application_state {
        #     STATUS = 0,
        #     LOAD,
        #     SCHEMA,
        #     DC,
        #     RACK,
        #     RELEASE_VERSION,
        #     REMOVAL_COORDINATOR,
        #     INTERNAL_IP,
        #     RPC_ADDRESS,
        #     X_11_PADDING, // padding specifically for 1.1
        #     SEVERITY,
        #     NET_VERSION,
        #     HOST_ID,
        #     TOKENS,
        #     SUPPORTED_FEATURES,
        #     CACHE_HITRATES,
        #     SCHEMA_TABLES_VERSION,
        #     RPC_READY,
        #     VIEW_BACKLOG,
        #     SHARD_COUNT,
        #     IGNORE_MSB_BITS,
        #     CDC_GENERATION_ID,
        #     SNITCH_NAME,
        # }

        result = {}
        host_address = entry.get('addrs')

        # Transform an application state list into a map by the app-state value
        app_state_dict = {int(app_entry['application_state']): app_entry for app_entry in entry['application_state']}

        # Fetch cross-nodes comparable entries
        for state_code in GossipInfoInvariantValues:
            if state_code in app_state_dict:
                result[state_code.name] = app_state_dict[state_code]['value']

        # Parse 'SUPPORTED_FEATURES' value into a sorted Python List
        if GossipInfoInvariantValues.SUPPORTED_FEATURES.name in result:
            supported_features_str = result[GossipInfoInvariantValues.SUPPORTED_FEATURES.name]
            result[GossipInfoInvariantValues.SUPPORTED_FEATURES.name] = sorted(supported_features_str.split(','))

        if GossipInfoInvariantValues.TOKENS.name in result:
            # Parse 'TOKENS' value into a sorted Python List
            tokens_str = result[GossipInfoInvariantValues.TOKENS.name]
            result[GossipInfoInvariantValues.TOKENS.name] = sorted(tokens_str.split(';'))

        # STATUS value has the following format: <STATUS, e.g. NORMAL>[,<Numeric value X>]*
        # Let's strip away numeric values and leave only the status value.
        if GossipInfoInvariantValues.STATUS.name in result:
            full_status_str = result[GossipInfoInvariantValues.STATUS.name]
            result[GossipInfoInvariantValues.STATUS.name] = full_status_str.split(',')[0]

        return host_address, result

    def _collect(self, vitals: DictView) -> None:
        """
        Collect gossipinfo data

        :param vitals: vitals collected by dependencies
        """
        if not ServiceManager().scylla_server_service_active:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrieve nodes information because 'scylla' service is down"
            return

        api_address = vitals[self.__collector_scylla_config].data['api_address']['value']
        api_port = int(vitals[self.__collector_scylla_config].data['api_port']['value'])

        response_json = self._read_scylla_rest_api(endpoint="/failure_detector/endpoints/",
                                                   api_address=api_address, api_port=api_port)

        # The _data['gossip_info'] structure is a Dict with a host address as a key and Dict of
        # parsed GossipInfoComparableValues values as a value with a GossipInfoComparableValues names as keys:
        #
        # "data": {
        #       "gossip_info": {
        #         "172.17.144.64": {
        #           "SCHEMA": "fae808bd-d947-31cf-9516-f0e12a8410ab",
        #           "DC": "asia-south1",
        #           "RACK": "a",
        #           ....
        try:
            hosts_info: List[Tuple[str | None, Dict[str, Union[str, List[str]]]]] = []
            for host_info in response_json:
                addr, parsed_info = self.__parse_one_gossipinfo_entry(host_info)

                # Skip decommissioned nodes: decommissioned nodes are intentionally kept for additional 3 days in the
                # GossipInfo/ClusterStatus while they are removed from Raft state and from system.peers.
                # Ref: https://github.com/scylladb/scylla-doctor/issues/8
                if parsed_info.get(GossipInfoInvariantValues.STATUS.name) == "LEFT":
                    continue

                hosts_info.append((addr, parsed_info))

            self._data = {
                'gossip_info': sorted(hosts_info, key=lambda x: x[0])
            }
            self.status = CollectorStatus.PASSED
        except InvalidGossipInfo as e:
            self._message = f"{e}"
            self.status = CollectorStatus.FAILED


class RaftGroup0Collector(Collector):
    def __init__(self, configuration: DictView, paths: Paths):
        super().__init__(configuration, paths)

        self.__system_scylla_local_rows: Optional[List[Dict[str, str]]] = None

    @property
    def name(self) -> str:
        return "Collects Raft Group0 state and members"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_scylla_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_scylla_config}

    def __read_system_scylla_local_rows(self, vitals: DictView) -> List[Dict[str, str]]:
        """
        :param vitals: vitals collected by dependencies
        :return: parsed rows of system.scylla_local table
        """
        if self.__system_scylla_local_rows is None:
            table_name = 'system.scylla_local'
            query, self.__system_scylla_local_rows = (
                Executor.read_cql_table(vitals[self.__collector_scylla_config].data, table_name))
            self._output.put(OutputEntryType.CQL, query, self.__system_scylla_local_rows, Level.VERBOSE)

        return self.__system_scylla_local_rows

    def __get_system_scylla_local_value(self, key: str, vitals: DictView) -> Optional[str]:
        rows = self.__read_system_scylla_local_rows(vitals)
        key_rows = list(filter(lambda row: row and row['key'] == key, rows))

        if not key_rows:
            return None

        return key_rows[0]['value']

    def __collect_group0_hosts_ids(self, vitals: DictView, group0_id: str) -> List[str]:
        """
        Collect IDs of all members of Group0 from system.raft_state.

        :param vitals: vitals collected by dependencies
        :param group0_id: ID of Raft Group0
        :return: Sorted list of IDs of hosts belonging to Raft Group0 with the given ID
        """
        table_name = 'system.raft_state'
        query, rows = (
            Executor.read_cql_table(vitals[self.__collector_scylla_config].data, table_name))
        self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

        return sorted([row['server_id'] for row in filter(lambda row: row and row['group_id'] == group0_id, rows)])

    def _collect(self, vitals: DictView) -> None:
        """
        - Checks whether raft is enabled or not.
        - If raft is enabled collect Raft Group0 and IDs of all members of Raft Group0.

        :param vitals: vitals collected by dependencies
        """
        try:
            group0_upgrade_state = self.__get_system_scylla_local_value('group0_upgrade_state', vitals)
            self._data = {
                'group0_upgrade_state': group0_upgrade_state
            }

            group0_id = self.__get_system_scylla_local_value('raft_group0_id', vitals)
            if group0_id:
                self._data.update({
                    'group0_id': group0_id,
                    'hosts': self.__collect_group0_hosts_ids(vitals, group0_id)
                })
            else:
                self._data.update({
                    'group0_id': None,
                    'hosts': []
                })

            self.status = CollectorStatus.PASSED
        except Exception as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"


class RaftTopologyRPCStatusCollector(ScyllaRestApiAwareCollector):
    @property
    def name(self) -> str:
        return "Ongoing Raft topology RPC status"

    @property
    def __collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        api_address = vitals[self.__collector].data['api_address']['value']
        api_port = int(vitals[self.__collector].data['api_port']['value'])

        if not ServiceManager().scylla_server_service_active:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrieve nodes information because 'scylla' service is down"
            return

        # The REST API above returns a '"none"' string if there is no ongoing Raft topology RPC or a following string if
        # there is:
        # '"<RPC name>[<some index>]: <coma separated list of IPs of nodes with pending responses>"'
        #
        # For example: '"move_raft_membership[17]: 1.2.3.4,2.3.4.5,3.4.5.6"'
        #
        # Ref: https://github.com/scylladb/scylladb/issues/25736
        self._data = self._read_scylla_rest_api(endpoint="/storage_service/raft_topology/cmd_rpc_status",
                                                api_address=api_address, api_port=api_port)
        self.status = CollectorStatus.PASSED


class ScyllaClusterStatusCollector(ScyllaRestApiAwareCollector):
    @property
    def name(self) -> str:
        return "Nodes status"

    @property
    def __collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        if not ServiceManager().scylla_server_service_active:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrieve nodes information because 'scylla' service is down"
            return

        api_address = vitals[self.__collector].data['api_address']['value']
        api_port = int(vitals[self.__collector].data['api_port']['value'])

        # status: endpoint
        endpoints = {
            'up': "/gossiper/endpoint/live/",
            'down': "/gossiper/endpoint/down/",
            'joining': "/storage_service/nodes/joining",
            'leaving': "/storage_service/nodes/leaving",
            'moving': "/storage_service/nodes/moving"
        }

        responses = {}
        for s, e in endpoints.items():
            responses[s] = self._read_scylla_rest_api(endpoint=e, api_address=api_address, api_port=api_port)

        self._data = {status: response for status, response in responses.items()}
        self.status = CollectorStatus.PASSED


class SystemClusterStatusCollector(Collector):
    @property
    def name(self) -> str:
        return "Collects system.cluster_status content"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_scylla_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_scylla_config}

    def _collect(self, vitals: DictView) -> None:
        """
        Collect a mapping of hosts broadcast address to host info as they appear in system.cluster_status content.
        :param vitals: vitals collected by dependencies
        """
        hosts_key = 'hosts'
        try:
            # A virtual table rebuilt per request can exceed a short server-side timeout; SELECT (not COPY) carries
            # USING TIMEOUT, and no column holds free text (DOCTOR-153).
            query, rows = Executor.read_cql_query(vitals[self.__collector_scylla_config].data,
                                                  "SELECT * FROM system.cluster_status")
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

            addr_to_info = {}
            for row in rows:
                # cqlsh prints a null cell as 'null' where COPY printed ''; keep the COPY shape so the vitals and
                # TopologyStateConsistencyAnalyzer's comparison with SystemPeersLocalCollector (still COPY) match.
                row = {k: ('' if v == 'null' else v) for k, v in row.items()}
                # 'load' value can have a slightly different value for the same host when read on different nodes due to
                # a delay in the gossip data propagation. Therefore, let's not include it in the _data for SDC purposes.
                row.pop('load')
                addr_to_info[row.pop('peer')] = row

            # Skip decommissioned nodes: decommissioned nodes are intentionally kept for additional 3 days in the
            # GossipInfo/ClusterStatus while they are removed from Raft state and from system.peers.
            # Ref: https://github.com/scylladb/scylla-doctor/issues/8
            addr_to_info_clean = dict(filter(lambda it: it[1]['status'] != 'LEFT', addr_to_info.items()))

            self._data = {hosts_key: addr_to_info_clean}
            self.status = CollectorStatus.PASSED
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"
            return


class SystemPeersLocalCollector(Collector):
    @property
    def name(self) -> str:
        return "Collects system.peers and system.local content"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_scylla_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_scylla_config}

    def __get_peers_info(self, vitals: DictView, table_name: str, address_column: str) \
            -> Dict[str, Dict[str, Union[str, List[str]]]]:
        """
        Read content of a given table using given column names and generate a map of peer broadcast address to peer's
        info.
        :param vitals: vitals collected by dependencies
        :param table_name: Name of the table to read
        :param address_column: Name of the column which contains the IP address.
        :return: map of a peer address to peer's info defined by the "peer's info" subset of columns
        """
        query, rows = Executor.read_cql_table(vitals[self.__collector_scylla_config].data, table_name)
        self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

        # Since peers are inherently different between nodes, we can't store all data from system.peers and
        # system.local. This would show up as a reported inconsistency. Instead we only store the common columns
        # between the two tables. The superset of data from the two tables is identical for use and comparison.
        common_columns = ['host_id', 'data_center', 'rack', 'release_version', 'rpc_address', 'schema_version',
                          'supported_features', 'tokens']

        result: Dict[str, Dict[str, Union[str, List[str]]]] = {}

        for row in rows:
            new_row: Dict[str, Union[str, List[str]]] = {key: row[key] for key in common_columns}
            new_row['supported_features'] = sorted(str(new_row['supported_features']).split(","))
            result[row[address_column]] = new_row

        return result

    def _collect(self, vitals: DictView) -> None:
        """
        Collect a mapping of hosts broadcast address to host info as they appear in system.peers and system.local
        content.
        :param vitals: vitals collected by dependencies
        """
        peers_to_info = {}
        system_local_rows = None
        try:
            # Read common columns from system.peers
            table_name = 'system.peers'
            peers_to_info.update(self.__get_peers_info(vitals, table_name, 'peer'))

            # Read common columns from system.local
            table_name = 'system.local'
            peers_to_info.update(self.__get_peers_info(vitals, table_name, 'broadcast_address'))

            # Read the whole contents of system.local
            _, system_local_rows = Executor.read_cql_table(vitals[self.__collector_scylla_config].data, table_name)
            if not system_local_rows:
                self.status = CollectorStatus.FAILED
                self._message = "system.local table is empty"
                return
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"
            return

        self._data = {
            'hosts': peers_to_info,
            # System.local contains only one row
            'local': system_local_rows[0]
        }

        # Substitute default values for possibly missing entries in system.local.
        # (this should never happen, but just in case).
        for key, value_callable in {
            'rpc_address': lambda: '127.0.0.1',
            'listen_address': lambda: '127.0.0.1',
            'broadcast_address': lambda: self._data['local']['listen_address']
        }.items():
            if not self._data['local'].get(key):
                self._data['local'][key] = value_callable()
                self._message = ",".join([self._message,
                                          f"'{key}' entry is missing in system.local, substituted "
                                          f"with '{value_callable()}'"])

        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        return ['local']  # system.local is different on each node


class SystemTabletsCollector(Collector):
    """
    Collects tablet ownership from system.tablets.

    Projects ownership-relevant columns only (not every system.tablets column):
    table_id, last_token, keyspace_name, table_name, replicas, base_table.

    Stored nested under data.tables so keyspace_name, table_name, table_id, and
    base_table are not repeated on every tablet entry. Each table entry holds
    those shared fields once; tablets lists only last_token and replicas.

    replicas is the tablet's replica list in CQL return order - index 0 is *not*
    guaranteed to be Scylla's current primary replica (primary selection can reshuffle it).
    base_table is set for co-located tables, whose own tablet map is empty; ownership for
    those must be resolved via the base table's map instead.
    """

    @property
    def name(self) -> str:
        return "Collects system.tablets content"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_scylla_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_scylla_config}

    @property
    def __columns(self) -> List[str]:
        # Ownership columns only — omits repair/session metadata and similar.
        return ['table_id', 'last_token', 'keyspace_name', 'table_name', 'replicas', 'base_table']

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude from cluster drift comparison. Tablet maps change under size-based
        balancing (split/merge/migration); concurrent collection across nodes can
        also capture different snapshots, so diffs are noisy and not meaningful.
        """
        return ['*']

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'max_rows': ConfigParameter(
                default='-1',
                param_type=int,
                description='Maximum rows to collect from system.tablets. -1 means no limit. '
                            'The tablet map scales with #tables x tablet_count and can be large '
                            'on busy clusters; set a cap if vitals size/runtime is a concern.',
            ),
        }

    @staticmethod
    def __group_rows_by_table(rows: List[Dict]) -> List[Dict]:
        """
        Collapse flat CQL rows into per-table entries with shared characteristics once.
        """
        grouped: Dict[Tuple[str, str], Dict] = {}
        for row in rows:
            key = (row.get('keyspace_name', ''), row.get('table_name', ''))
            entry = grouped.get(key)
            if entry is None:
                entry = {
                    'keyspace_name': key[0],
                    'table_name': key[1],
                    'table_id': row.get('table_id', ''),
                    'base_table': row.get('base_table', ''),
                    'tablets': [],
                }
                grouped[key] = entry
            entry['tablets'].append({
                'last_token': row.get('last_token', ''),
                'replicas': row.get('replicas', ''),
            })

        tables = []
        for key in sorted(grouped):
            entry = grouped[key]
            entry['tablets'].sort(key=lambda t: t.get('last_token', ''))
            tables.append(entry)
        return tables

    def __read_rows(self, scylla_config, table_name: str, max_rows: int) -> Tuple[str, List[Dict[str, str]]]:
        """
        Read ownership columns from system.tablets. base_table was added in later Scylla versions
        (co-located tables) and is absent on older ones, so read the table's actual columns and
        project the intersection with the ownership columns, instead of retrying the read on an
        error that might be unrelated. Any failure (timeout, connection, pre-tablets system.tablets
        missing, ...) propagates unchanged.
        """
        available = Executor.read_cql_table_columns(scylla_config, table_name)
        columns = [c for c in self.__columns if c in available]
        return Executor.read_cql_table(scylla_config, table_name, columns=columns, max_rows=max_rows)

    def _collect(self, vitals: DictView) -> None:
        """
        Collect tablet map from system.tablets into data.tables (nested by keyspace/table).
        """
        max_rows = self._get_config_value('max_rows')
        table_name = 'system.tablets'
        try:
            query, rows = self.__read_rows(vitals[self.__collector_scylla_config].data, table_name, max_rows)
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

            self._data = {'tables': self.__group_rows_by_table(rows)}
            self.status = CollectorStatus.PASSED
            self._message = f"Collected {len(rows)} rows"
        except CqlFailedException as e:
            # system.tablets doesn't exist on Scylla versions predating tablets - that's not a
            # failure, tablets simply aren't applicable to this node.
            if "unconfigured table" in str(e):
                self.status = CollectorStatus.SKIPPED
                self._message = "system.tablets does not exist - tablets are not supported on this node"
            else:
                self.status = CollectorStatus.FAILED
                self._message = f"{e}"


class SystemTopologyCollector(Collector):
    @property
    def name(self) -> str:
        return "Collects system.topology content"

    @property
    def __cqlsh_collector(self) -> str:
        return "CqlshCollector"

    @property
    def __gossip_info_collector(self) -> str:
        return "GossipInfoCollector"

    @property
    def __scylla_config_collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def __system_peers_local_collector(self) -> str:
        return "SystemPeersLocalCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__cqlsh_collector, self.__gossip_info_collector, self.__scylla_config_collector,
                self.__system_peers_local_collector}

    @property
    def __consistent_topology_feature_name(self) -> str:
        return "SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES"

    @property
    def __system_topology_rows_data_key(self) -> str:
        return "system_topology_rows"

    @property
    def __consistent_topology_supported_data_key(self) -> str:
        return "consistent_topology_supported"

    def _collect(self, vitals: DictView) -> None:
        """
        Collect the content of system.topology table.
        :param vitals: vitals collected by dependencies
        """
        messages = []
        collector_data: Dict[str, List | bool | None] = {
            self.__system_topology_rows_data_key: [],
            # If this remains None this means that we couldn't identify if Consistent Topology is supported
            self.__consistent_topology_supported_data_key: None
        }

        # Check if Consistent Topology is supported by the installed Scylla version:
        # SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES must be in the SUPPORTED_FEATURES list of the node.
        try:
            broadcast_address = vitals[self.__system_peers_local_collector].data['local']['broadcast_address']
            gossip_info = vitals[self.__gossip_info_collector].data['gossip_info']
            broadcast_address_gossip_entries = list(filter(lambda item: item[0] == broadcast_address, gossip_info))

            # Find the Gossip Info entry for the local host according to its broadcast_address
            if not broadcast_address_gossip_entries:
                messages.append(f"Own broadcast address {broadcast_address} not found in gossip_info")
                broadcast_address_gossip_info = None
            else:
                if len(broadcast_address_gossip_entries) > 1:
                    messages.append(f"Multiple broadcast address {broadcast_address} entries found in gossip_info. "
                                    f"Using the first one.")
                _, broadcast_address_gossip_info = broadcast_address_gossip_entries[0]

            # Check of Consistent Topology feature is supported.
            if broadcast_address_gossip_info:
                if (self.__consistent_topology_feature_name not in
                        broadcast_address_gossip_info.get(GossipInfoInvariantValues.SUPPORTED_FEATURES.name, [])):
                    messages.append(f"Scylla version does not support "
                                    f"{self.__consistent_topology_feature_name} feature")
                    collector_data[self.__consistent_topology_supported_data_key] = False
                else:
                    collector_data[self.__consistent_topology_supported_data_key] = True

            # Try to read 'system.topology' table
            query, rows = Executor.read_cql_table(vitals[self.__scylla_config_collector].data, 'system.topology')
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

            # If tokens are present - sort them so that this collector's data is comparable to the corresponding
            # data collected on different nodes of the same cluster.
            for row in rows:
                if "tokens" in row:
                    tokens = row.pop("tokens")
                    # 'token' key's value is of this format: "{'token1', 'token2', ..., 'tokenN'}"
                    row["tokens"] = f"{{{', '.join(sorted(tokens.strip('{}').split(', ')))}}}"

            collector_data[self.__system_topology_rows_data_key] = rows
            self.status = CollectorStatus.PASSED
        except Exception as e:
            messages.append(f"{e}")
            self.status = CollectorStatus.FAILED

        self._data = collector_data
        self._message = ". ".join(messages)


class TokenMetadataHostsMappingCollector(ScyllaRestApiAwareCollector):
    @property
    def name(self) -> str:
        return "Collect token_metadata hosts IP to UUID mapping"

    @property
    def __collector_scylla_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_scylla_config}

    def _collect(self, vitals: DictView) -> None:
        """
        Collect token_metadata hosts IP to UUID mapping

        :param vitals: vitals collected by dependencies
        """
        if not ServiceManager().scylla_server_service_active:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrieve nodes information because 'scylla' service is down"
            return

        api_address = vitals[self.__collector_scylla_config].data['api_address']['value']
        api_port = int(vitals[self.__collector_scylla_config].data['api_port']['value'])
        response_json = self._read_scylla_rest_api(endpoint="/storage_service/host_id", api_address=api_address,
                                                   api_port=api_port)

        ip_to_uuid: Dict[str, str] = {}
        errors = []
        for tm_item in response_json:
            addr = tm_item['key']
            if addr in ip_to_uuid:
                errors.append(f"Multiple Token Metadata entries for {addr}")
                continue

            ip_to_uuid[addr] = tm_item['value']

        if errors:
            self._message = ", ".join(errors)
            self.status = CollectorStatus.FAILED
            return

        # _data['hosts'] is a map from a host broadcast address to its UUID
        self._data = {
            'hosts': ip_to_uuid
        }
        self.status = CollectorStatus.PASSED
