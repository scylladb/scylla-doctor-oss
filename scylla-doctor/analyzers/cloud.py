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

from typing import Dict, List, Set

from analyzers_base import Analyzer, AnalyzerStatus
from common import ConfigParameter, DictView


class CloudCPUPlatformAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Cloud VM CPU Platform"

    @property
    def __infrastructure_provider_collector(self) -> str:
        return "InfrastructureProviderCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__infrastructure_provider_collector}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'expected_cpu_platform': ConfigParameter(
                default_description='unset (analyzer skipped)',
                description='Expected CPU platform name (e.g. Intel Ice Lake).',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check the VM has the requested CPU Platform.
        In case the host is not the VM or is a VM on a platform that doesn't support
        dynamic CPU Platform (currently only GCP supports it) the result is going to be
        'SKIPPED'.
        """
        expected_cpu_platform = self._get_config_value("expected_cpu_platform")
        current_cpu_platform = None
        infra_provider_info = vitals[self.__infrastructure_provider_collector].data
        if infra_provider_info['provider']:
            current_cpu_platform = infra_provider_info['cpu_platform']

        if not (expected_cpu_platform and current_cpu_platform):
            self.status = AnalyzerStatus.SKIPPED
            self.message = "'expected_cpu_platform' is not specified or CPU Platform is not dynamic"
        elif current_cpu_platform != expected_cpu_platform:
            self.status = AnalyzerStatus.FAILED
            self.message = f"CPU platform is '{current_cpu_platform}' while expecting '{expected_cpu_platform}'"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"CPU platform is '{current_cpu_platform}'"


class NodeInstanceTypeAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Node instance type"

    @property
    def __collector(self) -> str:
        return "InfrastructureProviderCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __recommended_instance_types(self) -> Dict[str, List[str]]:
        return {
            "AZURE": [
                "Standard_L8s_v2",
                "Standard_L16s_v2",
                "Standard_L32s_v2",
                "Standard_L48s_v2",
                "Standard_L64s_v2",
                "Standard_L80s_v2",
                "Standard_L8s_v3",
                "Standard_L16s_v3",
                "Standard_L32s_v3",
                "Standard_L48s_v3",
                "Standard_L64s_v3",
                "Standard_L80s_v3"
            ],
            "AWS": [
                "i3.large",
                "i3.xlarge",
                "i3.2xlarge",
                "i3.4xlarge",
                "i3.8xlarge",
                "i3.16xlarge",
                "i3.metal",
                "i3en.large",
                "i3en.xlarge",
                "i3en.2xlarge",
                "i3en.3xlarge",
                "i3en.6xlarge",
                "i3en.12xlarge",
                "i3en.24xlarge",
                "i4i.large",
                "i4i.xlarge",
                "i4i.2xlarge",
                "i4i.4xlarge",
                "i4i.8xlarge",
                "i4i.12xlarge",
                "i4i.16xlarge",
                "i4i.24xlarge",
                "i4i.32xlarge",
                "i4i.metal",
                "i7i.large",
                "i7i.xlarge",
                "i7i.2xlarge",
                "i7ie.large",
                "i7ie.xlarge",
                "i7ie.2xlarge",
                "i7ie.3xlarge",
                "i7ie.6xlarge",
                "i7ie.12xlarge",
                "i7ie.18xlarge",
                "i7ie.24xlarge",
                "i7ie.48xlarge",
                "i8g.large",
                "i8g.xlarge",
                "i8g.2xlarge",
                "i8g.4xlarge",
                "i8g.8xlarge",
                "i8g.12xlarge",
                "i8g.16xlarge",
                "i8g.24xlarge",
                "i8g.48xlarge",
                "i8g.metal-24xl",
                "i8g.metal-48xl",
                "i8ge.large",
                "i8ge.xlarge",
                "i8ge.2xlarge",
                "i8ge.3xlarge",
                "i8ge.6xlarge",
                "i8ge.12xlarge",
                "i8ge.18xlarge",
                "i8ge.24xlarge",
                "i8ge.48xlarge",
                "i8ge.metal-24xl",
                "i8ge.metal-48xl",
            ],
            "GCP": [
                "n2-highmem-2",
                "n2-highmem-4",
                "n2-highmem-8",
                "n2-highmem-16",
                "n2-highmem-32",
                "n2-highmem-48",
                "n2-highmem-64",
                "n2-highmem-80",
                "n2-highmem-96",
                "n2d-highmem-2",
                "n2d-highmem-4",
                "n2d-highmem-8",
                "n2d-highmem-16",
                "n2d-highmem-32",
                "n2d-highmem-48",
                "n2d-highmem-64",
                "n2d-highmem-80",
                "n2d-highmem-96",
                "z3-highmem-8-highlssd",
                "z3-highmem-16-highlssd",
                "z3-highmem-22-highlssd",
                "z3-highmem-32-highlssd",
                "z3-highmem-44-highlssd",
                "z3-highmem-88-highlssd",
                "z3-highmem-14-standardlssd",
                "z3-highmem-22-standardlssd",
                "z3-highmem-44-standardlssd",
                "z3-highmem-88-standardlssd",
                "z3-highmem-176-standardlssd",
            ],
            "OCI": [
                "VM.DenseIO.E4.Flex",
                "VM.DenseIO.E5.Flex",
                "VM.DenseIO.E6.Ax.Flex",
                "BM.DenseIO.E4.128",
                "BM.DenseIO.E5.128",
                "BM.DenseIO.E6.Ax.192",
            ]
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that for cloud installations, recommended instance types are used.
        """
        provider = vitals[self.__collector].data['provider']
        if not provider:
            self.status = AnalyzerStatus.PASSED
            self.message = "Not a cloud instance"
            return

        instance_type = vitals[self.__collector].data['instance_type']
        if not instance_type:
            self.status = AnalyzerStatus.WARNING
            self.message = "Cannot determine node instance type"
            return

        self.message = f"'{instance_type}' instance type"
        if instance_type in self.__recommended_instance_types.get(provider, []):
            self.status = AnalyzerStatus.PASSED
            self.message += " is listed as recommended"
        else:
            self.status = AnalyzerStatus.WARNING
            self.message += " is not listed as recommended"


class ScheduledMaintenanceEventAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scheduled Maintenance Event Analyzer"

    @property
    def __collector(self) -> str:
        return "MaintenanceEventsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that for cloud installations that support retrieving scheduled events,
        that there are no pending maintenance events.
        """
        events = vitals[self.__collector].data.get('scheduled_maintenance_events')

        if events is None:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "Pending maintenance events cannot be detected for the instance type and/or platform."
            return

        if not events:
            self.status = AnalyzerStatus.PASSED
            self.message = "No pending maintenance events detected."
            return

        self.status = AnalyzerStatus.FAILED
        self.message = f"The instance has a number of {len(events)} pending maintenance events."
