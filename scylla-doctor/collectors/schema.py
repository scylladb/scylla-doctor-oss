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

import os

from typing import Dict, Set, Iterable, Union, Sequence

from common import DictView, ConfigParameter
from collectors_base import (
    CollectorStatus,
    Collector,
    ScyllaRestApiAwareCollector,
    ScyllaSimplePerTableRestApiCollector,
)
from models.output_entry import OutputEntryType, Level

from utils import Executor, CqlFailedException, ServiceManager


class LargePartitionsCellsRowsCollector(Collector):
    """
    Collects the content of system.large_partitions, system.large_cells and system.large_rows tables.
    These tables are populated by Scylla when it detects unusually large data and are useful for
    identifying data modeling issues.
    """

    @property
    def name(self) -> str:
        return "Collects system.large_xxx content"

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
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Let's exclude this collector from comparison - large partitions/cells/rows are workload- and
        compaction-dependent, so they naturally differ between nodes of the same cluster and would only
        add noise to drift checking.
        """
        return ['*']

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'max_rows': ConfigParameter(
                default='-1',
                param_type=int,
                description='Maximum rows to collect from each large_* table. -1 means no limit.',
            ),
        }

    def _collect(self, vitals: DictView) -> None:
        max_rows = self._get_config_value('max_rows')
        self._data = {}
        for table_name in ('system.large_partitions', 'system.large_cells', 'system.large_rows'):
            query, rows = Executor.read_cql_table(
                vitals[self.__collector_scylla_config].data, table_name, max_rows=max_rows)
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)
            self._data[table_name] = rows

        self.status = CollectorStatus.PASSED
        if max_rows >= 0:
            self._message = f"Collected {max_rows} rows per table (user configuration)"


class NodetoolCFStatsCollector(Collector):
    @property
    def include_output_default(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "nodetool cfstats"

    def _collect(self, vitals: DictView) -> None:
        # In Scylla 2025.1 the location of the nodetool executable has changed. Let's try both old and new locations.
        nodetool_path = [
            f"{self._paths['scylla_directory']}/bin/nodetool",
            f"{self._paths['scylla_directory']}/share/cassandra/bin/nodetool"
        ]
        nodetool_command = None
        for path in nodetool_path:
            if os.path.isfile(path):
                nodetool_command = path
                break

        if not nodetool_command:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot find nodetool executable"
            return

        command = f"{nodetool_command} cfstats"
        output = Executor.run_command(command)
        if not output or not output.stdout:
            self.status = CollectorStatus.FAILED
            self._message = "'nodetool cfstats' command failed"
        else:
            self._output.put(OutputEntryType.STDOUT, "nodetool cfstats", output.stdout, level=Level.VERBOSE)
            self.status = CollectorStatus.PASSED


class ScyllaClusterSchemaCollector(ScyllaRestApiAwareCollector):
    @property
    def name(self) -> str:
        return "Cluster schema"

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

        self._data = self._read_scylla_rest_api(endpoint="/storage_proxy/schema_versions",
                                                api_address=api_address, api_port=api_port)

        # The REST API above returns an array of following maps:
        # {
        #   'key'   : <schema version>,
        #   'value' : <array of IPs with the schema version from 'key'
        # }
        # To make such values comparable we want to sort the array from the 'value'
        for m in self._data:
            m['value'] = sorted(m.get('value', []))
        self.status = CollectorStatus.PASSED


class ScyllaClusterSchemaDescriptionCollector(Collector):
    @property
    def include_output_default(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "Cluster schema description"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_config}

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        # `DESC SCHEMA` emits statements in a non-deterministic per-node order, so a raw-text diff flags identical
        # schemas as inconsistent; exclude it from the cluster diff (agreement is checked by
        # ScyllaClusterSchemaAnalyzer).
        return ['schema']

    def _collect(self, vitals: DictView) -> None:
        command = "DESC SCHEMA"
        output = Executor.cqlsh(command, vitals[self.__collector_config].data)

        if not output:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrieve schema description"
            return

        # Raw `DESC SCHEMA` text is consumed programmatically (e.g. to recreate a schema), so it lives in `data`
        # as well as in the diagnostic output.
        self._data['schema'] = output.stdout
        self._output.put(OutputEntryType.CQL, command, output.stdout, level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class ScyllaClusterSystemKeyspacesCollector(Collector):
    @property
    def name(self) -> str:
        return "Get keyspaces description"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_config}

    def _collect(self, vitals: DictView) -> None:
        try:
            table_name = 'system_schema.keyspaces'
            query, rows = Executor.read_cql_table(vitals[self.__collector_config].data, table_name)
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

            for row in rows:
                keyspace = row['keyspace_name'].strip()
                self._data[keyspace] = row
            self.status = CollectorStatus.PASSED
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"


class ScyllaClusterTablesDescriptionCollector(Collector):
    @property
    def name(self) -> str:
        return "Tables description"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_config}

    def _collect(self, vitals: DictView) -> None:
        try:
            # Views (incl. secondary indexes) are column families too: their schema rows carry real
            # compression/compaction config and the per-table REST endpoints serve them.
            for table_name, name_column, kind in (('system_schema.tables', 'table_name', 'table'),
                                                  ('system_schema.views', 'view_name', 'view')):
                query, rows = Executor.read_cql_table(vitals[self.__collector_config].data, table_name)
                self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

                for row in rows:
                    keyspace = row['keyspace_name'].strip()
                    # Copy so the VERBOSE CQL dump above stays a faithful query result
                    entry = dict(row)
                    entry['table_kind'] = kind
                    self._data.setdefault(keyspace, {})[row[name_column].strip()] = entry
            self.status = CollectorStatus.PASSED
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"


class ScyllaTablesCompressionInfoCollector(ScyllaSimplePerTableRestApiCollector[float]):
    @property
    def name(self) -> str:
        return "Tables compression ratio info"

    @property
    def _endpoint(self) -> str:
        return "/column_family/metrics/compression_ratio"

    def _endpoint_value_converter(self, value: str) -> float:
        return float(value)

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Let's exclude this collector from comparison - compression ratio can be different on different nodes of the
        same cluster due to compaction and other factors.
        """
        return ['*']


class ScyllaTablesUsedDiskCollector(ScyllaSimplePerTableRestApiCollector[int]):
    @property
    def name(self) -> str:
        return "Tables used disk space size info"

    @property
    def _endpoint(self) -> str:
        return "/column_family/metrics/total_disk_space_used"

    def _endpoint_value_converter(self, value: str) -> int:
        return int(value)

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Let's exclude this collector from comparison - disk space can be different on different nodes.
        """
        return ['*']
