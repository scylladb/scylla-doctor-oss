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

from typing import Set

from common import DictView, Authenticator
from collectors_base import CollectorStatus, Collector
from models.output_entry import OutputEntryType, Level

from utils import Executor


class CqlshCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla authentication"

    @property
    def __collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        output = Executor.cqlsh("HELP", vitals[self.__collector].data)

        if not output:
            self.status = CollectorStatus.FAILED
            self._message = "calling cqlsh failed, please check cql authentication configuration"
        else:
            self.status = CollectorStatus.PASSED


class DefaultCredentialsCollector(Collector):
    """
    Probes whether the default cassandra/cassandra user can log in.

    Always completes with PASSED. ``default_user_login`` is one of:
    - ``not_verified`` — authentication is off / probe unsafe (e.g. TransitionalAuthenticator)
    - ``denied`` — default user cannot log in
    - ``allowed`` — default user can log in
    """

    __DEFAULT_USER = "cassandra"
    __DEFAULT_PASSWORD = "cassandra"

    @property
    def name(self) -> str:
        return "Probe default CQL credentials"

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
        scylla_config = vitals[self.__collector_scylla_config].data
        authenticator = scylla_config.get('authenticator')

        # Only password-capable authenticators that reject bad passwords outright. See
        # Authenticator.password_login_probe_safe (TransitionalAuthenticator is not safe to probe).
        if not Authenticator.parse(authenticator).password_login_probe_safe:
            self._data = {'default_user_login': 'not_verified'}
            self._message = (
                f"Default user login was not verified (authenticator is '{authenticator or 'unset'}')"
            )
            self.status = CollectorStatus.PASSED
            return

        # Trivial authenticated query — success means the default user can still log in.
        query = "SELECT now() FROM system.local"
        output = Executor.cqlsh(query, scylla_config, user=self.__DEFAULT_USER, password=self.__DEFAULT_PASSWORD)
        default_user_login = 'allowed' if output is not None else 'denied'
        self._data = {'default_user_login': default_user_login}
        self._output.put(
            OutputEntryType.VALUE,
            "default_user_login",
            default_user_login,
            level=Level.VERBOSE,
        )
        self.status = CollectorStatus.PASSED


class RolePermissionsCollector(Collector):
    """
    Collects the content of the system.role_permissions table.
    """

    @property
    def name(self) -> str:
        return "Collects system.role_permissions content"

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
        query, rows = Executor.read_cql_table(
            vitals[self.__collector_scylla_config].data, 'system.role_permissions')
        self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

        # Sort by the 'role' column to make this data comparable between nodes
        self._data = sorted(rows, key=lambda row: row.get('role'))
        self.status = CollectorStatus.PASSED


class RolesCollector(Collector):
    """
    Collects role metadata from system.roles.

    salted_hash is intentionally omitted from collected data — it is sensitive and not needed
    for authentication best-practice analysis.
    """

    # Columns that are safe / useful for analysis and cluster comparison.
    __COLUMNS = ['role', 'is_superuser', 'can_login', 'member_of']

    @property
    def name(self) -> str:
        return "Collects system.roles content"

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
        query, rows = Executor.read_cql_table(
            vitals[self.__collector_scylla_config].data, 'system.roles', columns=self.__COLUMNS)
        self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

        # Sort by the 'role' column to make this data comparable between nodes
        self._data = sorted(rows, key=lambda row: row.get('role', ''))
        self.status = CollectorStatus.PASSED
