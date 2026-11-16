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

from typing import Dict, Set, Iterable, Union, Sequence

from common import DictView, NodePlatform, ConfigParameter
from collectors_base import CollectorStatus, Collector
from models.output_entry import OutputEntryType, Level

from utils import CloudProviderAWS, Executor, InfrastructureProvider, running_in_container

# Shared by the collectors that talk to the cloud provider metadata API.
_CLOUD_PROVIDER_API_CONFIG_PARAMETERS: Dict[str, ConfigParameter] = {
    'timeout': ConfigParameter(
        default='1',
        param_type=float,
        unit='seconds',
        description='Cloud Provider Metadata Server API access timeout.',
    ),
    'retries': ConfigParameter(
        default='0',
        param_type=int,
        description='Number of retries when Cloud Provider Metadata Server API access fails.',
    ),
    'retry_interval': ConfigParameter(
        default='0',
        param_type=float,
        unit='seconds',
        description='Delay in seconds between retries.',
    ),
}


class HypervisorTypeCollector(Collector):
    """
    Collect the Hypervisor type, e.g. 'kvm' or 'xen'.
    It's 'none' for bare-metal hosts.
    """
    @property
    def name(self) -> str:
        return "Hypervisor type"

    def _collect(self, vitals: DictView) -> None:
        command = "systemd-detect-virt"
        # systemd-detect-virt will return a non-zero return code on non-virtualized hosts. Let's ignore it.
        output = Executor.run_command(command=command, check=False)
        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
        self._data['hypervisor'] = output.stdout.split("\n")[0].strip()
        self.status = CollectorStatus.PASSED


class InfrastructureProviderCollector(Collector):
    @property
    def name(self) -> str:
        return "Detect infrastructure provider"

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return dict(_CLOUD_PROVIDER_API_CONFIG_PARAMETERS)

    @property
    def __collector_nics(self) -> str:
        return "NICsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_nics}

    def _collect(self, vitals: DictView) -> None:
        timeout = self._get_config_value('timeout')
        retries = self._get_config_value('retries')
        retry_interval = self._get_config_value('retry_interval')
        provider = InfrastructureProvider().identify(timeout=timeout,
                                                     retries=retries,
                                                     retry_interval=retry_interval)
        if provider:
            self._data = {
                'provider': provider.name,
                'instance_type': provider.instance_type,
                'cpu_platform': provider.cpu_platform,
            }

            self._output.put(OutputEntryType.VALUE, "provider", provider.name, level=Level.VERBOSE)
            self._output.put(OutputEntryType.VALUE, "instance_type", f"{provider.instance_type}",
                             level=Level.VERBOSE)

            # provider-specific additional info
            if isinstance(provider, CloudProviderAWS):
                nics = vitals[self.__collector_nics].data['nics']
                self._data['extra'] = provider.get_extra(nics=nics)
                self._output.put(OutputEntryType.VALUE, "provider.extra",
                                 f"{json.dumps(self._data['extra'], indent=4)}",
                                 level=Level.VERBOSE)
        else:
            self._data = {
                'provider': None
            }
        self.status = CollectorStatus.PASSED


class MaintenanceEventsCollector(Collector):
    @property
    def name(self) -> str:
        return "Gather scheduled maintenance events from cloud provider"

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return dict(_CLOUD_PROVIDER_API_CONFIG_PARAMETERS)

    def _collect(self, vitals: DictView) -> None:
        timeout = self._get_config_value('timeout')
        retries = self._get_config_value('retries')
        retry_interval = self._get_config_value('retry_interval')
        provider = InfrastructureProvider().identify(timeout=timeout,
                                                     retries=retries,
                                                     retry_interval=retry_interval)

        if provider is None:
            self.status = CollectorStatus.SKIPPED
            self._message = "Cannot identify infrastructure provider, skipping maintenance events collection"
            return

        self._data['scheduled_maintenance_events'] = provider.scheduled_maintenance_events
        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Let's exclude this collector from comparison - scheduled maintenance events are expected to differ between
        nodes, and they are not critical for most of the analyses, so excluding them from comparison will reduce noise
        in drift checking results.
        """
        return ['*']


class NodePlatformCollector(Collector):
    @property
    def name(self) -> str:
        return "Determine node platform"

    @property
    def __collector_provider(self) -> str:
        return "InfrastructureProviderCollector"

    @property
    def __collector_cpu(self) -> str:
        return "CPUSpecificationsCollector"

    @property
    def depends_on(self) -> Set[str]:
        # Container detection needs no other collector. Dropping the dependencies there keeps the platform available
        # in images without ethtool or lscpu.
        if running_in_container():
            return set()
        return {self.__collector_provider, self.__collector_cpu}

    def _collect(self, vitals: DictView) -> None:
        running_platform = None
        if running_in_container():
            running_platform = NodePlatform.CONTAINER
        elif vitals[self.__collector_provider].data['provider']:
            running_platform = NodePlatform.CLOUD
        elif "hypervisor" in vitals[self.__collector_cpu].data['flags']:
            running_platform = NodePlatform.VM
        else:
            running_platform = NodePlatform.BAREMETAL

        self.status = CollectorStatus.PASSED
        self._data = {
            'platform': running_platform
        }
        self._output.put(OutputEntryType.VALUE, "platform", f"{running_platform}", level=Level.VERBOSE)
