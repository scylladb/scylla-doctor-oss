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

import re

from typing import Set, Iterable, Union, Sequence

from common import DictView
from collectors_base import CollectorStatus, Collector
from models.output_entry import OutputEntryType, Level

from utils import Executor, CqlFailedException


class ClientConnectionCollector(Collector):
    @property
    def name(self) -> str:
        return "Collects all client connection information (e.g. driver, ports)"

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
        """
        Let's exclude this collector from comparison - port numbers and possible differences coming from connections
        that are being currently established makes this collector's data not the best candidate for comparison between
        nodes.
        """
        return ['*']

    def _collect(self, vitals: DictView) -> None:
        try:
            table_name = 'system.clients'
            query, rows = Executor.read_cql_table(vitals[self.__collector_config].data, table_name)
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"
            return

        self._data = {}
        for row in rows:
            # Sanitize the driver version (remove 'v' prefix if present)
            row['driver_version'] = re.sub(r'^v', '', row['driver_version'])

            self._data.setdefault(row['address'].strip(), []).append(row)

        self.status = CollectorStatus.PASSED


class ServiceLevelsCollector(Collector):
    """
    Collects service levels from system.service_levels_v2.

    Stored as a map keyed by service_level name so cluster diffs show added, removed, or
    changed levels (shares, timeout, workload_type) by name. Pre-2024.2 storage is ignored
    because those Scylla versions are no longer supported.
    """

    @property
    def name(self) -> str:
        return "Collects cluster service levels"

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
        table_name = 'system.service_levels_v2'
        try:
            query, rows = Executor.read_cql_table(
                vitals[self.__collector_scylla_config].data, table_name)
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

            self._data = {}
            for row in rows:
                name = row.get('service_level', '').strip()
                if name:
                    self._data[name] = row
            self.status = CollectorStatus.PASSED
        except CqlFailedException as e:
            if "unconfigured table" in str(e):
                self.status = CollectorStatus.SKIPPED
                self._message = (
                    "system.service_levels_v2 does not exist - service levels are not supported on this node"
                )
            else:
                self.status = CollectorStatus.FAILED
                self._message = f"{e}"
