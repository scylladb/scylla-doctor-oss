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
import json

from typing import Any, Dict, List, Mapping, Set, Optional

from analyzers_base import Analyzer, AnalyzerStatus
from common import ConfigParameter, DictView


def system_auth_managed_by_raft(keyspaces: Mapping, topology_data: Mapping) -> bool:
    """
    System-auth-2 stores auth in Raft. Pre-GA used a system_auth_v2 keyspace; GA OSS 6.0 /
    Enterprise 2024.2 folded those tables into system (scylladb/scylladb#18769). Leftover
    system_auth is created as SimpleStrategy RF=1 for cqlsh and must not be NTS/RF-checked.

    Completed Consistent Topology (system.topology upgrade_state == 'done' on every host) is the
    only signal used: auth-v2/Raft is guaranteed only once that upgrade procedure has finished, so
    a cluster on a GA version that skipped it still uses legacy system_auth and still needs the
    NTS/RF checks (scylladb/scylladb#17951). Version is deliberately not used as a fallback.
    """
    if "system_auth_v2" in keyspaces:
        return True
    if not topology_data.get("consistent_topology_supported"):
        return False
    rows = topology_data.get("system_topology_rows") or []
    return bool(rows) and all(row['upgrade_state'] == 'done' for row in rows)


class DisabledCompactionAnalyzer(Analyzer):
    """
    Verify that not-Null compaction strategy is defined and enabled for every table or view.
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

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'ignored_tables': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated keyspace.table (or view) names to ignore.',
            ),
        }

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
        ignored_tables = self._get_config_value("ignored_tables")

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
            self.message = f"Tables/views {', '.join(null_compaction_strategy_tables)} have compactions disabled."
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "All tables and views have compactions enabled."
            if ignored_tables:
                self.message += f" Ignored tables: {', '.join(sorted(ignored_tables))}"


class STCSInSchemaAnalyzer(Analyzer):
    """
    Verify that tables and views don't use STCS
    """
    @property
    def name(self) -> str:
        return "Verify that tables and views don't use STCS"

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
            self.message = "Tables/views that use STCS: " + ", ".join(errors)
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "There are no tables or views that use STCS."


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
    def __collector_topology(self) -> str:
        return "SystemTopologyCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_keyspaces, self.__collector_nodes, self.__collector_topology}

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
        Check that system keyspaces use NetworkTopologyStrategy and have sufficient replication factor.
        system_auth is skipped for System-auth-2 (Consistent Topology done, or system_auth_v2 present).
        Replication factor 0 in a DC only warns; the DC should be removed from the keyspace instead.
        """
        node_count = len(vitals[self.__collector_nodes].data['up']) + len(vitals[self.__collector_nodes].data['down'])
        errors = []
        warnings = []
        keyspaces = dict(self.__keyspaces)
        if system_auth_managed_by_raft(vitals[self.__collector_keyspaces].data,
                                       vitals[self.__collector_topology].data):
            keyspaces.pop("system_auth", None)

        for keyspace, settings in keyspaces.items():
            if keyspace not in vitals[self.__collector_keyspaces].data:
                if not settings.get("optional"):
                    errors.append(f"Keyspace '{keyspace}' is missing")
                continue

            replication = ast.literal_eval(vitals[self.__collector_keyspaces].data[keyspace]['replication'])
            if self.__strategy not in replication['class']:
                errors.append(f"{keyspace} keyspace is not using '{self.__strategy}' strategy")

            for dc in replication.keys():
                if dc == "class":
                    continue
                rf = int(replication[dc])
                if rf == 0:
                    warnings.append(
                        f"{keyspace} keyspace has replication factor 0 in {dc}; "
                        "remove the DC from the replication settings"
                    )
                elif settings.get("check_replication_factor", True) and rf < min(3, node_count):
                    errors.append(f"{keyspace} keyspace has replication factor {replication[dc]} in {dc}")

        if errors:
            self.status = AnalyzerStatus.FAILED
            self.message = ";".join(errors + warnings)
        elif warnings:
            self.status = AnalyzerStatus.WARNING
            self.message = ";".join(warnings)
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
    def __collector_topology(self) -> str:
        return "SystemTopologyCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_keyspaces, self.__collector_topology}

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
            # Pre-GA System-auth-2 keyspace; GA folded auth tables into system.
            "system_auth_v2": "LocalStrategy",
        }

    @property
    def __network_topology_strategy(self) -> str:
        return "NetworkTopologyStrategy"

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all keyspaces except for a few known ones use NetworkTopologyStrategy.
        Leftover system_auth is skipped for System-auth-2 (Consistent Topology done, or system_auth_v2 present).
        Warns if a NetworkTopologyStrategy DC has replication factor 0.
        """
        errors = []
        warnings = []
        keyspaces_schema = vitals[self.__collector_keyspaces].data
        skip_legacy_auth = system_auth_managed_by_raft(keyspaces_schema,
                                                       vitals[self.__collector_topology].data)
        for keyspace, schema in keyspaces_schema.items():
            if keyspace == "system_auth" and skip_legacy_auth:
                continue
            replication_config = ast.literal_eval(schema.get("replication", "{}"))
            replication = replication_config.get("class", "")
            expected_replication = self.__system_keyspaces_replication.get(keyspace, self.__network_topology_strategy)

            if expected_replication not in replication:
                errors.append(f"'{keyspace}' is using '{replication}', expected '{expected_replication}'")
                continue

            if self.__network_topology_strategy in replication:
                for dc, rf in replication_config.items():
                    if dc == "class":
                        continue
                    if int(rf) == 0:
                        warnings.append(
                            f"{keyspace} keyspace has replication factor 0 in {dc}; "
                            "remove the DC from the replication settings"
                        )

        if errors:
            self.status = AnalyzerStatus.FAILED
            self.message = ";".join(errors + warnings)
        elif warnings:
            self.status = AnalyzerStatus.WARNING
            self.message = ";".join(warnings)
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "All keyspaces are ok"


class ZstdCompressionLevelAnalyzer(Analyzer):
    """
    Verify that ZSTD compression levels are not higher than recommended.

    Inspects per-table and per-view compression in ``system_schema.tables``/
    ``system_schema.views`` and the in-memory server default from ``SystemConfigCollector``
    (``sstable_compression_user_table_options``). Only ``ZstdCompressor`` and
    ``ZstdWithDictsCompressor`` are considered; other compressors and
    non-numeric levels are skipped. Emits ``WARNING`` when any parseable ZSTD
    level exceeds ``max_recommended_level`` (higher levels may use more CPU),
    otherwise ``PASSED``.
    """
    __ZSTD_DEFAULT_LEVEL = 3
    __ZSTD_COMPRESSORS = frozenset({'ZstdCompressor', 'ZstdWithDictsCompressor'})

    @property
    def name(self) -> str:
        return "ZSTD compression level analysis"

    @property
    def __tables_schema_collector(self) -> str:
        return "ScyllaClusterTablesDescriptionCollector"

    @property
    def __system_config_collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__tables_schema_collector, self.__system_config_collector}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'max_recommended_level': ConfigParameter(
                default='4',
                param_type=int,
                description='Maximum recommended ZSTD compression level (levels above may use more CPU).',
            ),
            'ignored_tables': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated keyspace.table (or view) names to ignore in schema checks.',
            ),
        }

    @classmethod
    def __is_zstd_compressor(cls, compressor: str) -> bool:
        """
        Return True when ``compressor`` is a ZSTD compressor.

        Matches both short names and FQCNs (e.g.
        ``org.apache.cassandra.io.compress.ZstdCompressor``). Only
        ``ZstdCompressor`` and ``ZstdWithDictsCompressor`` qualify.
        """
        return compressor.rsplit('.', 1)[-1] in cls.__ZSTD_COMPRESSORS

    @classmethod
    def __parse_compression_level(cls, compression_config: Dict[str, Any]) -> Optional[int]:
        """
        Extract the ZSTD ``compression_level`` from a compression config.

        Falls back to :data:`__ZSTD_DEFAULT_LEVEL` when the key is absent.

        :returns: the level as an ``int``, or ``None`` when the value is not
            parseable as an integer (non-numeric levels are skipped, not
            flagged).
        """
        level = compression_config.get('compression_level', cls.__ZSTD_DEFAULT_LEVEL)
        try:
            return int(level)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def __parse_table_compression(raw_compression: str) -> Dict[str, Any]:
        """
        Parse a table ``compression`` value from CQL ``system_schema.tables``.

        The schema column stores a Python-literal dict string, e.g.
        ``"{'sstable_compression': 'org.apache.cassandra.io.compress.ZstdCompressor',
        'chunk_length_in_kb': '4', 'compression_level': '3'}"``, so
        :func:`ast.literal_eval` is used (not JSON).

        :returns: the parsed dict, or an empty dict when the value is empty or
            cannot be parsed. Never raises: ``ValueError`` / ``SyntaxError``
            from :func:`ast.literal_eval` are swallowed and treated as "no
            compression config".
        """
        if not raw_compression:
            return {}
        try:
            parsed = ast.literal_eval(raw_compression)
        except (ValueError, SyntaxError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    def __check_schema_tables(self, vitals: DictView, max_level: int,
                              ignored_tables: Set[str]) -> List[str]:
        """
        Scan per-table schema for ZSTD tables above ``max_level``.

        :param vitals: collected vitals; reads the tables-description collector.
        :param max_level: recommended maximum ZSTD compression level.
        :param ignored_tables: ``keyspace.table`` names to skip.
        :returns: list of ``"ks.table (level N)"`` strings for tables whose
            parseable ZSTD level exceeds ``max_level`` (empty when none).
        """
        high_level_tables: List[str] = []
        schema = vitals[self.__tables_schema_collector].data
        for ks, tables_data in schema.items():
            for table, table_schema in tables_data.items():
                if f"{ks}.{table}" in ignored_tables:
                    continue
                compression_config = self.__parse_table_compression(table_schema.get("compression", ""))
                compressor = compression_config.get("sstable_compression", "")
                if not self.__is_zstd_compressor(str(compressor)):
                    continue
                level = self.__parse_compression_level(compression_config)
                if level is not None and level > max_level:
                    high_level_tables.append(f"{ks}.{table} (level {level})")
        return high_level_tables

    def __check_system_config(self, vitals: DictView, max_level: int) -> Optional[str]:
        """
        Check the in-memory server-global ZSTD default from ``system.config``.

        Reads ``sstable_compression_user_table_options`` via
        ``SystemConfigCollector`` (effective runtime config, not on-disk yaml).

        :param vitals: collected vitals.
        :param max_level: recommended maximum ZSTD compression level.
        :returns: a warning string when the parseable global ZSTD level exceeds
            ``max_level``; ``None`` when the option is absent, not a dict, not a
            ZSTD compressor, non-numeric, or at/below ``max_level``.
        """
        config_entry = vitals[self.__system_config_collector].data.get(
            "sstable_compression_user_table_options")
        compression_options = config_entry.get("value") if config_entry else None
        if not compression_options or not isinstance(compression_options, dict):
            return None

        compressor = compression_options.get("sstable_compression", "")
        if not self.__is_zstd_compressor(str(compressor)):
            return None

        level = self.__parse_compression_level(compression_options)
        if level is not None and level > max_level:
            return (f"system.config sstable_compression_user_table_options compression level is {level} "
                    f"(above {max_level}; may use more CPU)")
        return None

    def _analyze(self, vitals: DictView) -> None:
        """
        Warn when ZSTD compression levels exceed the recommended maximum.

        Sets ``status`` to ``WARNING`` (with the offending tables and/or the
        in-memory ``system.config`` default listed in ``message``) when any
        parseable ZSTD level is above ``max_recommended_level``; otherwise
        ``PASSED``. Tables in ``ignored_tables`` are excluded and reported in
        the message.
        """
        max_level = self._get_config_value("max_recommended_level")
        ignored_tables = self._get_config_value("ignored_tables")

        high_level_tables = self.__check_schema_tables(vitals, max_level, ignored_tables)
        system_config_warning = self.__check_system_config(vitals, max_level)

        message_parts: List[str] = []
        if high_level_tables:
            message_parts.append(
                f"Tables with ZSTD compression level above {max_level} "
                f"(may use more CPU; confirm this is intended): {', '.join(high_level_tables)}")
        if system_config_warning:
            message_parts.append(system_config_warning)

        if message_parts:
            self.status = AnalyzerStatus.WARNING
            self.message = '. '.join(message_parts) + '.'
            if ignored_tables and high_level_tables:
                self.message += f" Ignored tables: {', '.join(sorted(ignored_tables))}."
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"All ZSTD compression levels are at or below {max_level}."
            if ignored_tables:
                self.message += f" Ignored tables: {', '.join(sorted(ignored_tables))}."
