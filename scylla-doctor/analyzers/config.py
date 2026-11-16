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
import ipaddress
import socket

from typing import Any, Dict, List, Set, Tuple, Optional

from analyzers_base import Analyzer, AnalyzerStatus
from analyzers.helpers import compare_versions
from common import ConfigParameter, DictView


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

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'skip_source_validation_keys': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated system.config keys excluded from source consistency checks.',
            ),
            'skip_persisted_validation_keys': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated system.config keys excluded from value consistency checks.',
            ),
        }

    @staticmethod
    def __coerce_yaml_type(config_type: Optional[str], value: Any) -> Any:
        """
        Scylla (yaml-cpp) converts a scalar to the option's type, so `auto_bootstrap: "true"` or
        `native_transport_port_ssl: "9142"` are valid. PyYAML keeps quoted scalars as strings, and so is an unquoted
        `1e-05` (YAML 1.1 floats require a dot). Convert such strings to the type reported by system.config and leave
        the value unchanged when it doesn't parse, so a real mismatch is still reported.
        """
        if not isinstance(value, str):
            return value
        try:
            if config_type == 'bool':
                return {'true': True, 'false': False}[value.lower()]
            if config_type == 'integer':
                return int(value)
            if config_type in ('float', 'double'):
                return float(value)
        except (KeyError, ValueError):
            pass  # not a literal of that type: keep the string so the value check reports the mismatch
        return value

    def __validate_config_source(self, vitals: DictView) -> Tuple[List[str], Set[str]]:
        """
        Check that every key that is not present in scylla.yaml has a 'default' or 'internal' as a source and every one
        that is present has a 'config' as a source.
        :param vitals: Vitals collected by required Collectors
        :return: Tuple of (sorted list of keys with an incorrect source, user-configured skip keys).
        """

        user_skip_keys: Set[str] = self._get_config_value("skip_source_validation_keys")

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

        user_skip_keys: Set[str] = self._get_config_value("skip_persisted_validation_keys")

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

        # hinted_handoff_enabled can get a string or a boolean value, in scylla.yaml as well as in system.config
        for config_dict in (scylla_yaml_dict, scylla_config_values_dict):
            hinted_handoff = config_dict.get('hinted_handoff_enabled')
            if isinstance(hinted_handoff, str) and hinted_handoff.lower() in ('true', 'false'):
                config_dict['hinted_handoff_enabled'] = hinted_handoff.lower() == 'true'

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
            Convert a scylla.yaml or system.config value to bool, handling string representations.
            """
            if isinstance(val, str):
                return val.lower() in ('1', 'true', 'yes')
            return bool(val)

        config_types = {key: value.get('type') for key, value in vitals[self.__scylla_config_collector].data.items()}

        divergent_keys = []
        for k, v in scylla_yaml_dict.items():
            # Special cases: https://github.com/scylladb/scylladb/issues/21355,
            #                https://scylladb.atlassian.net/browse/SCT-253
            if (k in {"client_encryption_options", "system_info_encryption", "user_info_encryption"} and
                    k in scylla_config_values_dict and 'enabled' in scylla_config_values_dict[k]):
                scylla_config_values_dict[k]['enabled'] = to_bool(scylla_config_values_dict[k]['enabled'])
                # scylla.yaml may quote it as well, e.g. `enabled: "true"`
                if isinstance(v, dict) and 'enabled' in v:
                    v['enabled'] = to_bool(v['enabled'])

            if k == "kms_hosts" and k in scylla_config_values_dict:
                for sub_key in ["aws_use_ec2_credentials", "aws_use_ec2_region"]:
                    if sub_key in scylla_config_values_dict[k]:
                        scylla_config_values_dict[k][sub_key] = to_bool(scylla_config_values_dict[k][sub_key])

            # Skip keys that are not in system.config table - these are not supported by the current Scylla
            # version.
            # Also skip keys from the skip_keys set which includes keys with known issues.
            if k not in scylla_config_values_dict or k in skip_keys:
                continue

            if scylla_config_values_dict[k] != self.__coerce_yaml_type(config_types[k], v):
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

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'recommended_compression': ConfigParameter(
                default='all',
                description='Recommended internode compression setting.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that internode compression is fully enabled.
        """

        recommended_compression = self._get_config_value("recommended_compression")

        compression = vitals[self.__collector].data.get("internode_compression", "none")
        if compression != recommended_compression:
            self.status = AnalyzerStatus.WARNING
            self.message = f"Internode compression is set to '{compression}', " \
                           f"but it should be '{recommended_compression}'"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"Internode compression is set to '{compression}'"


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

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'check_provider_snitch': ConfigParameter(
                default_description='unset (provider snitch check enabled)',
                description='Verify provider-specific snitch on AWS/GCP. Set to no/0/false/off to disable.',
            ),
        }

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
        skip_check_provider = (
            (self._get_config_value('check_provider_snitch') or '').lower() in self.config_run_skip_values
        )
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
