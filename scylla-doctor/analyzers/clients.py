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
import re
import urllib.parse

from dataclasses import dataclass
from typing import Any, Dict, List, Set, Tuple, Optional

from analyzers_base import Analyzer, AnalyzerStatus
from analyzers.helpers import InvalidVersionFormat, sanitize_version, compare_versions, get_url_content
from common import ConfigParameter, DictView


@dataclass(frozen=True, order=True)
class CqlClientTimeout:
    """One client application in system.clients: its user, driver and request timeout, whatever the number of hosts."""
    username: str
    driver_name: str
    driver_version: str
    timeout_ms: int

    def __str__(self) -> str:
        return f"{self.username} {self.driver_name} {self.driver_version}: {self.timeout_ms} ms"


class ClientCQLTimeoutAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Client CQL request timeout analysis"

    @property
    def __collector_client_connections(self) -> str:
        return "ClientConnectionCollector"

    @property
    def __collector_system_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_client_connections, self.__collector_system_config}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'server_timeouts': ConfigParameter(
                default='read_request_timeout_in_ms,write_request_timeout_in_ms,range_request_timeout_in_ms,'
                        'counter_write_request_timeout_in_ms,cas_contention_timeout_in_ms,request_timeout_in_ms',
                comma_separated=True,
                description='Comma-separated system.config timeout options (ms) the client request timeout must '
                            'exceed; truncate_request_timeout_in_ms (60 s) is left out by default.',
            ),
        }

    @staticmethod
    def __client_timeout_ms(client_options: Any) -> Optional[int]:
        """
        query.defaults.request.timeout-ms from the DRIVER_CONFIG STARTUP option inside a system.clients
        client_options value: cqlsh renders the map<text, text> as a Python literal, DRIVER_CONFIG itself is JSON.
        None when the column, the option or the timeout is absent or does not parse (timeout disabled or unknown).
        """
        if not isinstance(client_options, str) or 'DRIVER_CONFIG' not in client_options:
            return None  # cheap pre-check: most rows (non-control connections, older drivers) carry no config
        try:
            driver_config = json.loads(ast.literal_eval(client_options)['DRIVER_CONFIG'])
            timeout_ms = driver_config['query']['defaults']['request']['timeout-ms']  # absent when disabled
            return int(timeout_ms)
        except (KeyError, TypeError, ValueError, SyntaxError):
            return None

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that every connected CQL client reporting its driver configuration uses a request timeout strictly
        greater than the server-side request timeouts in system.config.
        """
        system_config = vitals[self.__collector_system_config].data
        server_timeouts: Set[str] = self._get_config_value('server_timeouts')
        server_values = {option: int(system_config[option]['value'])
                         for option in server_timeouts if option in system_config}
        missing = sorted(server_timeouts - set(server_values))
        if not server_values:
            self.status = AnalyzerStatus.FAILED
            self.message = f"None of the server_timeouts options exist in system.config: {', '.join(missing)}"
            return
        server_max_ms = max(server_values.values())
        # Scylla defaults tie range and request timeouts at 10000 ms: name every option at the max
        limiting = ', '.join(sorted(option for option, value in server_values.items() if value == server_max_ms))

        # One entry per application rather than per host or connection: DRIVER_CONFIG travels on a session's control
        # connection only, and a fleet of hosts running the same application shares one configuration.
        clients: Dict[CqlClientTimeout, Set[str]] = {}
        for client_ip, rows in vitals[self.__collector_client_connections].data.items():
            for row in rows:
                if row.get('client_type') != 'cql' or row.get('connection_stage') != 'READY':
                    continue
                timeout_ms = self.__client_timeout_ms(row.get('client_options'))
                if timeout_ms is not None:
                    client = CqlClientTimeout(row.get('username', ''), row.get('driver_name', ''),
                                              row.get('driver_version', ''), timeout_ms)
                    clients.setdefault(client, set()).add(client_ip)

        offenders = [client for client in sorted(clients) if client.timeout_ms <= server_max_ms]
        if not clients:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "No connected CQL client reported its driver configuration (DRIVER_CONFIG)"
        elif offenders:
            self.status = AnalyzerStatus.FAILED
            self.message = (f"Client request timeout must be greater than the server-side {server_max_ms} ms "
                            f"({limiting}): " + "; ".join(
                                f"{client} ({len(clients[client])} host{'s' if len(clients[client]) != 1 else ''})"
                                for client in offenders))
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = (f"{len(clients)} client driver configuration{'s' if len(clients) != 1 else ''} with a "
                            f"request timeout above the server-side {server_max_ms} ms ({limiting})")
        # Only a non-default list can hold a typo; with the default list an absent option is a Scylla version
        # difference, not a configuration error, so the remaining options are used without a warning.
        if missing and server_timeouts != self._get_config_default('server_timeouts'):
            self.status = AnalyzerStatus.combine([self.status, AnalyzerStatus.WARNING])
            self.message += f"; WARNING: server_timeouts options not found in system.config: {', '.join(missing)}"


class DriverVersionNotIndexed(Exception):
    """
    Raised when the driver version API responded successfully but returned no versions for the requested driver,
    i.e. a driver name Scylla Doctor recognizes that the API backend does not index (yet).

    Distinct from a failed API call: a recognized-but-unindexed driver is reported as a warning, not an error.
    """


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

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'minimum_version': ConfigParameter(
                default='{}',
                description='JSON map of driver type to minimum allowed version (e.g. {"Java": "3.14.0"}).',
            ),
            'latest_version': ConfigParameter(
                default='{}',
                description='JSON map of driver type to latest available version.',
            ),
            'driver_api_endpoint': ConfigParameter(
                default='https://version-api.ops.scylladb.com/driverInfo',
                description='URL used to look up driver versions when minimum_version/latest_version are unset.',
            ),
        }

    @property
    def __api_endpoint(self) -> str:
        return self._get_config_value('driver_api_endpoint')

    def __init_config_required_version(self, version_type: str) -> Dict[str, str]:
        """
        :param version_type: Either minimum or latest version.
        :return: Loads input minimum or latest driver version from the config and sanitizes the versions.
        """
        config_required_version = json.loads(self._get_config_value(version_type))

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
            # scylla-rust-driver renamed to ScyllaDB Rust Driver in 0.14.0
            'scylla-rust-driver': 'Rust',
            'ScyllaDB Rust Driver': 'Rust',
            'Scylla Shard-Aware C/C++ Driver': 'CPP',
            # cpp-rs-driver STARTUP DRIVER_NAME: "ScyllaDB Cpp-Rust Driver" until the
            # cpp-rust-driver rename, then "ScyllaDB CPP RS Driver". Version line is 0.x/1.x,
            # not legacy cpp-driver 2.x — keep a separate config key from CPP.
            'ScyllaDB Cpp-Rust Driver': 'CppRust',
            'ScyllaDB CPP RS Driver': 'CppRust',
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

    @staticmethod
    def _versions_only(drivers: List[Dict[str, str]]) -> List[Tuple[Tuple[int, int, int], str]]:
        """
        :param drivers: Driver entries from the version API.
        :return: (X.Y.Z, version without the 'v' prefix) for the entries whose version compare_versions can parse,
                 i.e. without tags such as 'stable' or versions such as '2.16.2b'. Picking one of those would make
                 every client comparison fail. The X.Y.Z orders versions exactly as compare_versions does.
        """
        versions = []
        for driver in drivers:
            version = re.sub(r'^v', '', driver['version'])
            # compare_versions alone would accept tags with digits, e.g. 'cassandra-driver-parent-2.0.9'.
            if not re.match(r'\d', version):
                continue
            try:
                versions.append((sanitize_version(version), version))
            except InvalidVersionFormat:
                continue
        return versions

    def _get_minimum_driver_version(self, client_driver_name: str, scylla_version: str) -> Optional[str]:
        """
        :param client_driver_name: The client driver name (e.g. Scylla Python Driver)
        :param scylla_version: The scylla version (e.g. 2024.1)
        :return: The minimum driver version for the provided scylla_version and driver_name,
                 or None in case the driver version API call failed.
        :raise DriverVersionNotIndexed: if the driver version API responded successfully but returned no versions
                                        for the requested driver name.
        """
        return self._get_required_driver_version(self.__key_minimum_version, self.__config_minimum_version,
                                                 client_driver_name, scylla_version)

    def _get_latest_driver_version(self, client_driver_name: str) -> Optional[str]:
        """
        :param client_driver_name: The client driver name (e.g. Scylla Python Driver)
        :return: The latest driver version for the provided driver_name,
                 or None in case the driver version API call failed.
        :raise DriverVersionNotIndexed: if the driver version API responded successfully but returned no versions
                                        for the requested driver name.
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
                 or None in case the driver version API call failed.
        :raise DriverVersionNotIndexed: if the driver version API responded successfully but returned no versions
                                        for the requested driver name.
        :raise ValueError: if the minimum is looked up without a Scylla version. The API only returns the tested-with
                           versions for a given Scylla version, so the driver would be misreported as not indexed.
        """
        # If a user did not provide any required driver versions, we fetch it via an API call.
        config_driver_name = self.__driver_names_to_config_mapping[client_driver_name]

        if config_driver_name not in config_input_version:
            if version_type == self.__key_minimum_version and not scylla_version:
                raise ValueError(f"A Scylla version is required to look up the minimum version of {client_driver_name}")

            query = {'driverName': client_driver_name}
            if scylla_version:
                query['scyllaVersion'] = scylla_version
            # A driver_api_endpoint override may already carry a query string (e.g. '?env=staging').
            separator = '&' if '?' in self.__api_endpoint else '?'
            # The version API can take a few seconds to answer its first request (cold start).
            response = get_url_content(f"{self.__api_endpoint}{separator}{urllib.parse.urlencode(query)}", timeout=10)

            if response is None:
                return None

            driver_info = json.loads(response)
            if version_type == self.__key_minimum_version:
                # Workaround for the version API not following its documented contract, where `recommended` is
                # [latest, minimum]: it can mix release lines (e.g. Java 3.x and 4.x) ordered by release date, so
                # recommended[1] can be above recommended[0], and it can contain tags that are not versions (e.g.
                # 'stable'). Take the lowest X.Y.Z (what compare_versions compares), on a tie the oldest release,
                # skipping non-version tags. Once the API is fixed, this can go back to recommended[1].
                required_driver = min(reversed(self._versions_only(driver_info.get('recommended', []))),
                                      default=None, key=lambda pair: pair[0])
            else:
                # The API's `latest` is the newest release, not the highest version: with several release lines
                # (e.g. Java 3.x and 4.x) it switches between them with each release. Take the highest X.Y.Z of all
                # releases instead, on a tie the newest release (listed first), skipping non-version tags.
                required_driver = max(self._versions_only(driver_info.get('driverInfo', [])),
                                      default=None, key=lambda pair: pair[0])

            if required_driver is None:
                # The API is reachable but has no version data for this driver name
                # (e.g. a supported driver name the backend hasn't indexed yet).
                raise DriverVersionNotIndexed(client_driver_name)

            return required_driver[1]
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

            try:
                minimum_driver_version = self._get_minimum_driver_version(client_driver_name, scylla_version)
                recommended_driver_version = self._get_latest_driver_version(client_driver_name)
            except DriverVersionNotIndexed:
                # Warning (iv): The driver name is recognized, but the version API has no data for it yet.
                warning_messages.append(f"No version data available for driver: {client_driver_name}")
                continue

            if minimum_driver_version is None or recommended_driver_version is None:
                self.status = AnalyzerStatus.FAILED
                self.message = (f"API call error occurred to retrieve the minimum or latest driver "
                                f"version for '{client_driver_name}'")
                return

            for client_driver_version in client_driver_versions[client_driver_name]:
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
