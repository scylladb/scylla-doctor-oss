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

from typing import Dict, List, Set

from analyzers_base import Analyzer, AnalyzerStatus
from analyzers.helpers import InvalidVersionFormat, compare_versions, get_url_content
from common import ConfigParameter, DictView


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

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'skip_autostarts_check': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated services to skip in enabled/auto-start checks.',
            ),
            'disable_autostarts': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated services that must not be enabled/auto-started.',
            ),
            'skip_active_check': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated services to skip in active-service checks.',
            ),
            'disable_active': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated services that must be inactive.',
            ),
        }

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
        skip_autostart_check = self._get_config_value("skip_autostarts_check")
        autostart_disabled_services = self._get_config_value("disable_autostarts")
        skip_active_check = self._get_config_value("skip_active_check")
        disabled_services = self._get_config_value("disable_active")
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

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'oss_minimum_version': ConfigParameter(
                default='6.1',
                description='Minimum supported OSS Scylla version.',
            ),
            'enterprise_minimum_version': ConfigParameter(
                default='2024.1',
                description='Minimum supported Enterprise Scylla version.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that Scylla version has not reached EOL yet.
        """
        minimum_version = {
            'oss': self._get_config_value('oss_minimum_version'),
            'enterprise': self._get_config_value('enterprise_minimum_version')
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

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'oss_latest_version': ConfigParameter(
                default_description='fetched from repositories.scylladb.com when unset',
                description='OSS version treated as latest.',
            ),
            'enterprise_latest_version': ConfigParameter(
                default_description='fetched from repositories.scylladb.com when unset',
                description='Enterprise version treated as latest.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that scylla is upgraded to latest version, that' known to be stable.
        """
        current_version = vitals[self.__collector].data['version']
        current_edition = vitals[self.__collector].data['edition']
        if current_edition == "enterprise":
            latest_version = self._get_config_value('enterprise_latest_version')
        else:
            latest_version = self._get_config_value('oss_latest_version')

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
