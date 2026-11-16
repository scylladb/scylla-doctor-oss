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

import json
import os
import socket

from typing import Dict, Set, List, Iterable, Union, Sequence, Tuple

from common import DictView, ConfigParameter, InvalidConfigurationException
from collectors_base import CollectorStatus, ScyllaConfigurationCollector
from models.output_entry import OutputEntryType, Level

from utils import Executor, CqlFailedException


class ScyllaConfigurationFileCollector(ScyllaConfigurationCollector):
    @property
    def name(self) -> str:
        return "scylla.yaml"

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        # We want to skip a Cartesian Product of these keys + addresses
        encryption_sections = ["client_encryption_options", "server_encryption_options",
                               "alternator_encryption_options"]
        encryption_keys = ["certificate", "keyfile", "truststore"]

        addresses_mask: List[Union[str, Iterable]] = \
            ["broadcast_address", "listen_address", "rpc_address", "broadcast_rpc_address", "resolved"]
        return ["pure_scylla_yaml"] + addresses_mask + [(a, b) for a in encryption_sections for b in encryption_keys]

    @staticmethod
    def __dns_resolve(hostname: str) -> Tuple[List[str], List[str]]:
        results = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
        ipv4_addresses = set()
        ipv6_addresses = set()

        for result in results:
            family, _, _, _, sockaddr = result
            address = sockaddr[0]

            if family == socket.AF_INET:
                ipv4_addresses.add(str(address))
            elif family == socket.AF_INET6:
                ipv6_addresses.add(str(address))

        return list(ipv4_addresses), list(ipv6_addresses)

    def _collect(self, vitals: DictView) -> None:
        scylla_config_path = os.path.join(self._paths['scylla_directory_config'], "scylla.yaml")
        if not os.path.isfile(scylla_config_path):
            self.status = CollectorStatus.FAILED
            self._message = f"'{scylla_config_path}' does not exist"
            return

        scylla_config = self._redact_credentials(Executor.parse_config_file_to_dict(
            scylla_config_path, "yaml", deep_sort=False))
        if not scylla_config:
            self.status = CollectorStatus.FAILED
            self._message = f"'{scylla_config_path}' exists, but it cannot be opened or parsed"
            return

        # Store a raw content of scylla.yaml as a special value. We will need it for a
        # ScyllaConfigurationConsistencyAnalyzer.
        scylla_config['pure_scylla_yaml'] = dict(scylla_config)

        # The parsed file rather than its text: a credential may span lines in YAML, and parsing finds it whole.
        self._output.put(OutputEntryType.PARSED_FILE, scylla_config_path, scylla_config['pure_scylla_yaml'],
                         level=Level.VERBOSE)

        # substitute default values
        for key, value_callable in {
            'storage_port': lambda: 7000,
            'ssl_storage_port': lambda: 7001,
            'rpc_address': lambda: 'localhost',
            'listen_address': lambda: 'localhost',
            'broadcast_address': lambda: scylla_config['listen_address'],
            'broadcast_rpc_address': lambda: scylla_config['rpc_address']
        }.items():
            if key not in scylla_config:
                scylla_config[key] = value_callable()

        # address keys we want to resolve:
        addr_keys = ["broadcast_address", "broadcast_rpc_address", "listen_address", "rpc_address"]
        resolved_ips = {}

        # Resolve DNS names for addresses keys and store the map with corresponding resolved addresses in
        # scylla_config["resolved"].
        for key in addr_keys:
            if key in scylla_config:
                try:
                    resolved_ips[key] = ScyllaConfigurationFileCollector.__dns_resolve(scylla_config[key])
                except socket.gaierror as e:
                    self.status = CollectorStatus.FAILED
                    self._message = f"Unable to resolve {key}: {scylla_config[key]}: {e}"
                    return

        scylla_config["resolved"] = resolved_ips
        self._output.put(OutputEntryType.VALUE, "Resolved DNS Addresses", f"{json.dumps(resolved_ips, indent=4)}",
                         level=Level.VERBOSE)

        self._data = scylla_config
        self.status = CollectorStatus.PASSED


class ScyllaConfigurationFileNoParsingCollector(ScyllaConfigurationCollector):
    @property
    def name(self) -> str:
        return "scylla.yaml raw content"

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        # We want to skip a Cartesian Product of these keys + addresses
        encryption_sections = ["client_encryption_options", "server_encryption_options",
                               "alternator_encryption_options"]
        encryption_keys = ["certificate", "keyfile", "truststore"]

        addresses_mask: List[Union[str, Iterable]] = \
            ["broadcast_address", "listen_address", "rpc_address", "broadcast_rpc_address", "resolved"]
        return ["pure_scylla_yaml"] + addresses_mask + [(a, b) for a in encryption_sections for b in encryption_keys]

    def _collect(self, vitals: DictView) -> None:
        scylla_config_path = os.path.join(self._paths['scylla_directory_config'], "scylla.yaml")
        if not os.path.isfile(scylla_config_path):
            self.status = CollectorStatus.FAILED
            self._message = f"'{scylla_config_path}' does not exist"
            return

        scylla_config = self._redact_credentials(Executor.parse_config_file_to_dict(
            scylla_config_path, "yaml", deep_sort=False, no_yaml_values_parsing=True))
        if not scylla_config:
            self.status = CollectorStatus.FAILED
            self._message = f"'{scylla_config_path}' exists, but it cannot be opened or parsed"
            return

        self._data = scylla_config
        self.status = CollectorStatus.PASSED


class ScyllaSystemConfigurationFilesCollector(ScyllaConfigurationCollector):
    @property
    def name(self) -> str:
        return "System-wide configuration files"

    def _collect(self, vitals: DictView) -> None:
        # Check a few candidate directories for configuration files: both when the service is installed in a system
        # and in a per-user modes.
        config_directories_candidates = [
            "/etc/sysconfig",
            "/etc/default",
            f"{self._paths['scylla_directory']}/etc/sysconfig",
            f"{self._paths['scylla_directory']}/etc/default"
        ]
        config_directories_candidates = [dir for dir in config_directories_candidates if os.path.isdir(dir)]

        if not config_directories_candidates:
            self.status = CollectorStatus.FAILED
            self._message = "No base directory found"
            return

        # Find the config directory containing scylla-server - this will be the one where other files are supposed
        # to be.
        # It should appear in exactly one location.
        current_directory = None
        for d in config_directories_candidates:
            if os.path.isfile(os.path.join(d, 'scylla-server')):
                if current_directory:
                    raise InvalidConfigurationException(f"'scylla-server' appears in more than a single "
                                                        f"configuration directory {config_directories_candidates}")
                current_directory = d

        if not current_directory:
            self.status = CollectorStatus.FAILED
            self._message = "scylla-server configuration file not found: is scylla installed?"
            return

        self._data = {
            'directory': current_directory,
            'files': {}
        }

        # Check each configuration file
        for filename in ["scylla-housekeeping", "scylla-jmx", "scylla-server"]:
            file = os.path.join(current_directory, filename)
            if os.path.isfile(file):
                content = self._redact_credentials(Executor.parse_config_file_to_dict(file))
                self._data['files'][filename] = content
                self._output.put(OutputEntryType.VALUE, "Directory", current_directory, level=Level.VERBOSE)
                self._output.put(OutputEntryType.PARSED_FILE, filename, content, level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED


class SystemConfigCollector(ScyllaConfigurationCollector):
    @property
    def name(self) -> str:
        return "Collects system.config content"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def __collector_system_peers_local(self) -> str:
        return "SystemPeersLocalCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_config, self.__collector_system_peers_local}

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        # These parameters are allowed to be unique per node.
        # We want to skip a Cartesian Product of these keys + addresses + other unique parameters
        encryption_sections = ["client_encryption_options", "server_encryption_options",
                               "alternator_encryption_options"]
        encryption_keys = ["certificate", "keyfile", "truststore"]

        addresses_parameters: List[Union[str, Iterable]] = \
            ["broadcast_address", "api_address",
             "listen_address", "alternator_address",
             "rpc_address", "broadcast_rpc_address"]

        other_unique_parameters: List[Union[str, Iterable]] = \
            ["initial_token", "replace_node_first_boot", "replace_address",
             "replace_address_first_boot", "ignore_dead_nodes_for_replace"]

        encryption_mask: List[Union[Tuple[str, str, str], Tuple[str, str], Iterable]] = \
            [(a, "*", b) for a in encryption_sections for b in encryption_keys]
        addresses_mask: List[Union[Tuple[str, str, str], Tuple[str, str], Iterable]] = \
            [(address_param, "*") for address_param in addresses_parameters]
        other_unique_parameters_mask: List[Union[Tuple[str, str, str], Tuple[str, str], Iterable]] = \
            [(param, "*") for param in other_unique_parameters]

        # Exclude encryption, addresses, and other unique parameters.
        return encryption_mask + addresses_mask + other_unique_parameters_mask

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'string_value_keys': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated list of system.config keys stored as plain strings (non-JSON).',
            ),
        }

    def _collect(self, vitals: DictView) -> None:
        """
        - Collects system.config parameters their values and appropriately casts them (e.g. bool, int, list).
        - Collects the source of values set for system.config parameters (e.g. default, API, etc.)
        - Collects types of values set for system.config parameters (e.g. 'string', 'int', 'restriction mode')
        """
        string_value_keys = self._get_config_value('string_value_keys')

        # Set 'object_storage_endpoints' has a non-JSON value.
        # Ref https://scylladb.atlassian.net/browse/SCYLLADB-1658
        string_value_keys.add("object_storage_endpoints")

        try:
            table_name = 'system.config'
            query, rows = Executor.read_cql_table(vitals[self.__collector_config].data, table_name)
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"
            return

        self._data = {}
        for row in rows:
            parameter_name = row.pop('name')
            if parameter_name not in string_value_keys:
                # The value is a JSON value. Its text is not in the message: it may be a credential.
                try:
                    row["value"] = json.loads(row["value"])
                except json.JSONDecodeError as e:
                    self.status = CollectorStatus.FAILED
                    self._message = f"Cannot parse the value of '{parameter_name}' in {table_name} as JSON: {e.msg}"
                    return

            row["value"] = self._redact_credentials_in_entry(parameter_name, row["value"])
            self._data[parameter_name] = row

        # Printed after the redaction, hence with the parsed values.
        self._output.put(OutputEntryType.CQL, query, [{'name': name, **row} for name, row in self._data.items()],
                         Level.VERBOSE)

        # substitute default values. system.config may have empty strings if values are unset.
        for key, value_callable in {
            'rpc_address': lambda: 'localhost',
            'listen_address': lambda: vitals[self.__collector_system_peers_local].data['local']['listen_address'],
            'api_address': lambda: 'localhost',
            'api_port': lambda: 10000,
            'broadcast_address': lambda: self._data['listen_address']['value'],
            'broadcast_rpc_address': lambda: vitals[self.__collector_system_peers_local].data['local']['rpc_address'],
            'workdir,W': lambda: "/var/lib/scylla",
            'data_file_directories': lambda: [os.path.join(self._data['workdir,W']['value'], 'data')],
            'commitlog_directory': lambda: os.path.join(self._data['workdir,W']['value'], 'commitlog'),
            'hints_directory': lambda: os.path.join(self._data['workdir,W']['value'], 'hints'),
            'view_hints_directory': lambda: os.path.join(self._data['workdir,W']['value'], 'view_hints')
        }.items():
            if not self._data.get(key, {}).get('value'):
                self._data[key]['value'] = value_callable()

        self.status = CollectorStatus.PASSED
