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

from typing import Dict, Set

from analyzers_base import Analyzer, AnalyzerStatus
from common import ConfigParameter, DictView


class NICsAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Analyze NICs"

    @property
    def __collector_nics(self):
        return "NICsCollector"

    @property
    def __collector_provider(self):
        return "InfrastructureProviderCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_nics, self.__collector_provider}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'speed': ConfigParameter(
                default='10000',
                param_type=int,
                unit='Mbps',
                description='Suggested minimum NIC speed.',
            ),
            'skip_nic_speed_check': ConfigParameter(
                default_description='true on AWS/GCP, false otherwise when unset',
                description='Skip NIC speed threshold check.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that there is a NIC with a speed over recommended threshold.
        For AWS, check that VPC support and enhanced networking is enabled.
        """
        provider = vitals[self.__collector_provider].data['provider']
        skip_nic_speed_check = self._get_config_value('skip_nic_speed_check')
        # Let's not check NIC speed on AWS and GCP by default since they don't expose NIC's link speed via
        # 'ethtool <nic>'.
        if skip_nic_speed_check is None and provider in {"AWS", "GCP"}:
            skip_nic_speed_check = True

        warn = []
        messages = []
        if not skip_nic_speed_check:
            nics = vitals[self.__collector_nics].data['nics']

            suggested_speed = self._get_config_value('speed')
            suggested_nic_count = len([nic for nic, nic_data in nics.items()
                                       if nic_data['speed'] and nic_data['speed'] >= suggested_speed])

            if suggested_nic_count == 0:
                warn.append(f"There is no NIC available that matches recommended speed threshold of {suggested_speed}.")
        else:
            messages.append("Skipped NIC speed check.")

        # provider-specific checks
        if provider == "AWS":
            if not vitals[self.__collector_provider].data['extra'].get('enhanced_networking_nic_type'):
                warn.append("EC2 instance class does not support enhanced networking.")
            elif not vitals[self.__collector_provider].data['extra'].get('vpc_enabled_from_nics'):
                warn.append("VPC is not enabled and it is required to have enhanced networking support.")
            elif not vitals[self.__collector_provider].data['extra'].get('enhanced_networking_driver_support'):
                warn.append("Enhanced networking is disabled.")

        if warn:
            self.status = AnalyzerStatus.WARNING
            self.message = " ".join(warn)
        else:
            self.status = AnalyzerStatus.PASSED
            messages.append("Networking setup is ok.")
            self.message = " ".join(messages)


class ScyllaSeedsAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla seeds availability"

    @property
    def __collector(self) -> str:
        return "ScyllaSeedsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all scylla seed nodes are reachable.
        """
        seeds = vitals[self.__collector].data
        if len(seeds) == 0:
            self.status = AnalyzerStatus.FAILED
            self.message = "No seeds detected"
            return

        unavailable_seeds = [seed for seed in seeds if seeds[seed] != 0]
        if len(unavailable_seeds) > 0:
            self.status = AnalyzerStatus.WARNING
            self.message = f"Some seeds are unreachable: {', '.join(unavailable_seeds)}"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "All seeds are reachable"
