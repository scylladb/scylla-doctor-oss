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

import abc
import argparse
import csv
import glob
import ipaddress
import json
import os
import pathlib
import re
import shutil
import socket
import yaml
import zipfile

from typing import Dict, Optional, Set, List, Iterable, Union, Sequence, Tuple, Generic, TypeVar

from common import DictView, Paths, NodePlatform
from collectors_base import CollectorStatus, Collector, ScyllaRestApiAwareCollector
from common import GossipInfoInvariantValues, InvalidConfigurationException
from models.output_entry import OutputEntryType, Level

from utils import CloudProviderAWS, Executor
from utils import InfrastructureProvider, CqlFailedException, ServiceManager

###############################################################################
# Type variables ##############################################################
###############################################################################
T = TypeVar("T")


###############################################################################
# Classes: Tests ##############################################################
###############################################################################
class PathsCollector(Collector):
    @property
    def name(self) -> str:
        return "System paths"

    def _collect(self, vitals: DictView) -> None:
        self._data = dict(self._paths)
        self._output.put(OutputEntryType.VALUE, "paths", f"{json.dumps(dict(self._paths), indent=4)}",
                         level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class ClockSourceCollector(Collector):
    @property
    def name(self) -> str:
        return "Clock source setup collection"

    @property
    def __clocksource_file(self) -> str:
        return "/sys/devices/system/clocksource/clocksource0/current_clocksource"

    def _collect(self, vitals: DictView) -> None:
        if not os.path.isfile(self.__clocksource_file):
            self.status = CollectorStatus.FAILED
            self._message = f"Clock source cannot be determined, check {self.__clocksource_file}"
            return

        self._data = {
            'clocksource': Executor.read_file_content(self.__clocksource_file)[0].strip()
        }
        self._output.put(OutputEntryType.FILE, self.__clocksource_file, [f"{self._data['clocksource']}\n"],
                         level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class CPUSpecificationsCollector(Collector):
    @property
    def name(self) -> str:
        return "CPU Specifications"

    def _collect(self, vitals: DictView) -> None:
        command = "lscpu"
        lscpu_output = Executor.run_command(command)
        if not lscpu_output:
            self.status = CollectorStatus.FAILED
            self._message = f"{command} call failed"
            return

        self._output.put(OutputEntryType.STDOUT, command, lscpu_output.stdout, level=Level.VERBOSE)

        filename = "/proc/cpuinfo"
        cpuinfo_content = Executor.read_file_content(filename)
        self._output.put(OutputEntryType.FILE, filename, cpuinfo_content, level=Level.VERBOSE)

        cpu_flags = Executor.search_string("^Flags", lscpu_output.stdout.split("\n"))[0].split()
        del cpu_flags[0]

        detected_cpu_lcores = Executor.search_string(r"^CPU\(s\)", lscpu_output.stdout.split("\n"))
        cpu_lcores = int(detected_cpu_lcores[0].split(":")[1].strip())

        self.status = CollectorStatus.PASSED
        self._data = {
            'flags': cpu_flags,
            'logical_cores': cpu_lcores
        }

        return


class CPUScalingCollector(Collector):
    @property
    def name(self) -> str:
        return "CPU scaling setup"

    @property
    def __scaling_governor_file(self) -> str:
        return "/sys/devices/system/cpu/cpufreq/policy0/scaling_governor"

    @property
    def __cpu_scaling_services(self) -> Set[str]:
        return {
            "cpufrequtils",
            "cpupower-frequency-set",
            "cpupower",
            "scylla-cpupower"
        }

    def _collect(self, vitals: DictView) -> None:
        scaling_governor = None
        if os.path.isfile(self.__scaling_governor_file):
            scaling_governor = Executor.read_file_content(self.__scaling_governor_file)[0].strip()

        service_manager = ServiceManager()
        services = dict()
        for service in self.__cpu_scaling_services:
            services[service] = {
                'active': service_manager.service_active(service)
            }

        self.status = CollectorStatus.PASSED
        self._data = {
            'scaling_governor': scaling_governor,
            'services': services
        }

        self._output.put(OutputEntryType.FILE, self.__scaling_governor_file, [f"{scaling_governor}\n"],
                         level=Level.VERBOSE)
        self._output.put(OutputEntryType.VALUE, "active services", f"{json.dumps(services, indent=4)}",
                         level=Level.VERBOSE)
        return


class CPUSetCollector(Collector):
    @property
    def name(self) -> str:
        return "cpuset setup"

    @property
    def __collector(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        cpuset_content = vitals[self.__collector].data['files'].get('cpuset.conf', {})
        cpuset = cpuset_content.get('CPUSET')

        if not cpuset_content or not cpuset:
            self.status = CollectorStatus.SKIPPED
            self._message = "cpuset setup was not done"
            return

        parser = argparse.ArgumentParser()
        parser.add_argument("--cpuset")
        cpuset_list = parser.parse_known_args(cpuset.split(' '))[0].cpuset
        if cpuset_list is None:
            self.status = CollectorStatus.SKIPPED
            self._message = "cpuset setup was not performed using Scylla tools: '--cpuset' is not used in CPUSET"
            return

        hwloc_calc_cmd = f"{self._paths['scylla_directory']}/bin/hwloc-calc"

        # cpuset_list = re.sub(r'^--cpuset (.+)$', r'\1', cpuset).strip()
        hwloc_cmd = f"{hwloc_calc_cmd}" + " -p --pi {}". \
            format(" ".join(['PU:{}'.format(c) for c in cpuset_list.split(",")])).strip("\n")
        cpusetconf_mask = Executor.run_command(hwloc_cmd).stdout

        self._output.put(OutputEntryType.STDOUT, hwloc_cmd, cpusetconf_mask, Level.VERBOSE)

        options_file = f"{self._paths['scylla_directory_configs']}/perftune.yaml"
        if not os.path.isfile(options_file):
            self.status = CollectorStatus.FAILED
            self._message = "perftune.yaml is not found"
            return

        perftune_file = f"{self._paths['scylla_directory_scripts']}/perftune.py"
        command = f"{perftune_file} --get-cpu-mask --options-file {options_file}"
        perftune_mask = Executor.run_command(command).stdout

        self._output.put(OutputEntryType.STDOUT, command, perftune_mask, Level.VERBOSE)

        # calculate bitwise-and intersection between cpusetconf and perftune masks
        hwloc_cmd = f"{hwloc_calc_cmd} --restrict {cpusetconf_mask} {perftune_mask} --intersect PU -p"
        cpusetconf_intersect_perftune_list = Executor.run_command(hwloc_cmd).stdout

        self._output.put(OutputEntryType.STDOUT, hwloc_cmd, cpusetconf_intersect_perftune_list, Level.VERBOSE)

        hwloc_cmd = f"{hwloc_calc_cmd}" + " -p --pi {}". \
            format(" ".join(['PU:{}'.format(c) for c in cpusetconf_intersect_perftune_list.split(",")]))
        cpusetconf_intersect_perftune_mask = Executor.run_command(hwloc_cmd).stdout

        self._output.put(OutputEntryType.STDOUT, hwloc_cmd, cpusetconf_intersect_perftune_mask, Level.VERBOSE)

        self._data = {
            'cpusetconf_mask': cpusetconf_mask,
            'perftune_mask': perftune_mask,
            'cpusetconf_intersect_perftune_mask': cpusetconf_intersect_perftune_mask
        }
        self.status = CollectorStatus.PASSED


class CoredumpCollector(Collector):
    @property
    def name(self) -> str:
        return "Coredump setup"

    def _collect(self, vitals: DictView) -> None:
        self._data = {
            'files': {},
            'services': {}
        }

        for file in [
            "/etc/sysctl.d/99-scylla-coredump.conf",
            "/usr/lib/sysctl.d/50-coredump.conf"
        ]:
            if os.path.isfile(file):
                self._data['files'][file] = Executor.read_file_content(file)
                self._output.put(OutputEntryType.FILE, file, self._data['files'][file], level=Level.VERBOSE)

        service_name = "var-lib-systemd-coredump.mount"
        self._data['services'][service_name] = {
            'active': ServiceManager().service_active(service_name)
        }
        self._output.put(OutputEntryType.VALUE, f"active {service_name} service",
                         f"{self._data['services'][service_name]}", level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED


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


class FirewallRulesCollector(Collector):
    @property
    def name(self) -> str:
        return "Gather firewall rules"

    @property
    def privileged(self) -> bool:
        return True

    def _collect(self, vitals: DictView) -> None:

        if not shutil.which('iptables'):
            self.status = CollectorStatus.FAILED
            self._message = "'iptables' is required. Please install it. "
            return

        command = "iptables -L -v"
        rules = Executor.run_command(command)

        if not rules or not rules.stdout:
            self.status = CollectorStatus.FAILED
            self._message = f"`iptables` call failed. Please check it: `{command}`"
        else:
            self.status = CollectorStatus.PASSED
            self._output.put(OutputEntryType.STDOUT, command, rules.stdout, level=Level.VERBOSE)

        return


class MaintenanceEventsCollector(Collector):
    @property
    def name(self) -> str:
        return "Gather scheduled maintenance events from cloud provider"

    def _collect(self, vitals: DictView) -> None:
        timeout = float(self.config.get("timeout", 1))
        retries = int(self.config.get("retries", 0))
        retry_interval = float(self.config.get("retry_interval", 0))
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


class InfrastructureProviderCollector(Collector):
    @property
    def name(self) -> str:
        return "Detect infrastructure provider"

    @property
    def __collector_nics(self) -> str:
        return "NICsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_nics}

    def _collect(self, vitals: DictView) -> None:
        timeout = float(self.config.get("timeout", 1))
        retries = int(self.config.get("retries", 0))
        retry_interval = float(self.config.get("retry_interval", 0))
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


class IPAddressesCollector(Collector):
    @property
    def name(self) -> str:
        return "Network interface controller addresses"

    @property
    def __collector(self):
        return "NICsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        for nic in vitals[self.__collector].data['nics']:
            command = f"ip addr show {nic}"
            content = Executor.run_command(command)
            self._output.put(OutputEntryType.STDOUT, command, content.stdout, level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ['*']


class KernelRingBufferCollector(Collector):
    @property
    def name(self) -> str:
        return "Kernel ring buffer (dmesg)"

    @property
    def privileged(self) -> bool:
        return True

    def _collect(self, vitals: DictView) -> None:
        command = "dmesg -T"
        output = Executor.run_command(command)
        if output:
            self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
            self.status = CollectorStatus.PASSED
        else:
            self._message = f"Cannot collect `{command}`, please check it's availability"
            self.status = CollectorStatus.FAILED


class NICsCollector(Collector):
    @property
    def name(self) -> str:
        return "Gather all available NICs"

    def _collect(self, vitals: DictView) -> None:
        if not shutil.which('ethtool'):
            self.status = CollectorStatus.FAILED
            self._message = "'ethtool' utility is required, please install it"
            return

        self._data['nics'] = dict()
        for nic_path in sorted(glob.glob("/sys/class/net/*")):
            nic_pathlib_path = pathlib.Path(nic_path)

            # NICs are represented by symlinks in /sys/class/net/. Let's skip everything other than symlinks.
            if not nic_pathlib_path.is_symlink():
                continue

            nic = nic_pathlib_path.name

            if nic == "lo":
                continue

            command_i = f"ethtool -i {nic}"
            output_i = Executor.run_command(command_i)
            self._output.put(OutputEntryType.STDOUT, command_i, output_i.stdout, level=Level.VERBOSE)

            command = f"ethtool {nic}"
            output = Executor.run_command(command)
            self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

            driver, speed = None, None
            if output_i:
                driver_line = Executor.search_string(r"^driver: ", output_i.stdout.split("\n"))
                driver = driver_line[0].split()[1] if driver_line else None

            if output:
                speed_line = Executor.search_string(r"Speed:", output.stdout.split("\n"))
                if speed_line:
                    speed_str = speed_line[0].split()[1]
                    speed = None if speed_str == "Unknown!" else int(speed_str.replace('Mb/s', ''))

            self._data['nics'][nic] = {
                'driver': driver,
                'speed': speed
            }

        self.status = CollectorStatus.PASSED

    @property
    def legacy_data(self) -> dict:
        return {
            'specs': {
                'network': self._data
            }
        }

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
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
        return {self.__collector_provider, self.__collector_cpu}

    def _collect(self, vitals: DictView) -> None:
        running_platform = None
        if os.path.isfile("/run/.containerenv") or os.path.isfile("/run/.dockerenv") or os.path.isfile("/.dockerenv"):
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


class NTPStatusCollector(Collector):
    @property
    def name(self) -> str:
        return "NTPStatusCollector"

    def _collect(self, vitals: DictView) -> None:
        """
        Collects whether NTP is enabled, and whether the system clock is synchronized.
        Sets 'ntp_enabled' and 'ntp_synchronized' in the data collection.
        """
        ntp_properties = {'ntp_enabled': 'NTP', 'ntp_synchronized': 'NTPSynchronized'}
        collected_data = {}

        for ntp_key, ntp_property in ntp_properties.items():
            # The command will output yes/no for the given property.
            command = f"timedatectl show --property {ntp_property} --value"
            output = Executor.run_command(command)
            self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
            collected_data[ntp_key] = (output.stdout.strip() == 'yes')

        self._data = collected_data
        self.status = CollectorStatus.PASSED


class NTPServicesCollector(Collector):
    @property
    def name(self) -> str:
        return "NTPServicesCollector"

    @property
    def __ntp_services(self) -> Set[str]:
        return {
            "systemd-timesyncd",
            "chronyd",
            "chrony",
            "ntpd",
            "ntp"
        }

    def _collect(self, vitals: DictView) -> None:
        service_manager = ServiceManager()

        services = {service: {
            'active': service_manager.service_active(service)
        } for service in self.__ntp_services}

        self._data = {
            'services': services
        }

        self._output.put(OutputEntryType.VALUE, "NTP services",
                         f"{json.dumps(self._data['services'], indent=4)}", level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED


class ComputerArchitectureCollector(Collector):
    @property
    def name(self) -> str:
        return "Computer Architecture and kernel version"

    def _collect(self, vitals: DictView) -> None:
        command = "uname --all"
        output = Executor.run_command(command)

        # Output check
        if not output:
            self.status = CollectorStatus.FAILED
            self._message = "'uname' usage failed"
            return

        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

        detected_architecture = output.stdout.split()[-2]
        kernel_version = output.stdout.split()[2]
        self._data = {
            'architecture': detected_architecture,
            'kernel_version': kernel_version
        }

        self.status = CollectorStatus.PASSED


class OSCollector(Collector):
    @property
    def name(self) -> str:
        return "Operating system"

    def _collect(self, vitals: DictView) -> None:
        command = "/etc/os-release"
        content = Executor.read_file_content(command)

        reader = csv.reader(content, delimiter="=")
        os_release = {row[0]: row[1] for row in reader if row}  # some rows are empty

        distro = os_release.get('ID', '')
        version_id = os_release.get('VERSION_ID', '')

        # Output check
        if not all([os_release, distro, version_id]):
            self.status = CollectorStatus.FAILED
            self._message = f"Information gathering from '{command}' failed"
            return

        self._output.put(OutputEntryType.FILE, command, content, level=Level.VERBOSE)

        detected_version_major = version_id
        detected_version_minor = detected_version_major

        # Depending on VERSION_ID's value (sometimes it's X and sometimes X.Y)
        # set the right major and minor versions
        if "." in detected_version_major:
            detected_version_major = detected_version_major.split(".")[0]

        if distro in ["rhel", "centos", "rocky"]:
            command = "/etc/centos-release" if distro == "centos" else "/etc/redhat-release"
            content = Executor.read_file_content(command)
            detected_version_minor = content[0].split(" release ")[1]

            self._output.put(OutputEntryType.FILE, command, content, level=Level.VERBOSE)

        self._data = {
            'name': distro.strip(),
            'version': detected_version_major.strip(),
            'version_minor': detected_version_minor.strip()
        }
        self.status = CollectorStatus.PASSED


class PerftuneSystemConfigurationCollector(Collector):
    @property
    def name(self) -> str:
        return "System configuration suggested by perftune.py"

    @property
    def __storage_collector(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def __hypervisor_type_collector(self) -> str:
        return "HypervisorTypeCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__storage_collector, self.__hypervisor_type_collector}

    def __get_nvme_smp_affinity_files(self, dir_data: Dict, perftune_file: str) -> Set[str]:
        """
        :param dir_data: Data of StorageConfigurationCollector
        :param perftune_file: path to a perftune.py
        :return: Names of NVMe disks smp_affinity files.
        """
        nvme_devs = set()
        for dirs in dir_data.values():
            for one_dir in dirs.values():
                nvme_devs |= set(one_dir['devices']['nvme'])

        # If there are no NVMe disks - return
        if not nvme_devs:
            return set()

        dev_command = ' '.join([f"--dev {d}" for d in nvme_devs])
        command = f"{perftune_file} --tune disks {dev_command} --dry-run"
        output = Executor.run_command(command)
        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

        smp_affinity_lines = Executor.search_string(r"smp_affinity", output.stdout.split("\n"))
        # strings like "echo 00000001 > proc/irq/41/smp_affinity"
        return set([smp_affinity_line.split(maxsplit=3)[3] for smp_affinity_line in smp_affinity_lines])

    def _collect(self, vitals: DictView) -> None:
        options_file = f"{self._paths['scylla_directory_configs']}/perftune.yaml"
        if not os.path.isfile(options_file):
            self.status = CollectorStatus.FAILED
            self._message = "perftune.yaml is not found"
            return

        dir_data = vitals[self.__storage_collector].data
        scylla_dirs = set().union(*[[d for d in dirs.keys()] for dirs in dir_data.values()])

        dir_command = " ".join([f"--dir {dir}" for dir in scylla_dirs])
        perftune_file = f"{self._paths['scylla_directory_scripts']}/perftune.py"
        command = f"{perftune_file} --tune disks {dir_command} --dry-run --options-file {options_file}"
        output = Executor.run_command(command)

        if not output or output.returncode != 0:
            self.status = CollectorStatus.FAILED
            self._message = f"'{options_file}' contains invalid values"
            return

        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

        # If we are running on any platform but Xen VM let's filter out NVMe cards IRQs' smp_affinity files because
        # kernel is not going to allow perftune.py to change their content.
        smp_affinity_files_to_skip = set()
        if vitals[self.__hypervisor_type_collector].data['hypervisor'] != 'xen':
            smp_affinity_files_to_skip = self.__get_nvme_smp_affinity_files(dir_data, perftune_file)

        self._data = {
            'perftune': {
                'files': {},
                'sysctl': {}
            },
            'files': {},
            'sysctl': {}
        }

        files_affected = Executor.search_string(r"^echo(\s+\S+\s*)+>", output.stdout.split("\n"))
        for file_affected in files_affected:
            # strings like "echo 00000001 > proc/irq/41/smp_affinity"
            # or "echo 493986 658648 987971 > /proc/sys/net/ipv4/tcp_mem"
            echo_value, file = file_affected.split(">", maxsplit=1)
            # echo_value is always "echo <token(s)>" because the regex requires \s+\S+ before '>',
            # so split(maxsplit=1)[1] is guaranteed to exist.
            value = echo_value.split(maxsplit=1)[1].strip()
            file = file.strip()
            if file not in smp_affinity_files_to_skip:
                try:
                    file_value = Executor.read_file_content(file)[0].strip("\n") if os.path.isfile(file) else None
                    if file_value is not None:
                        self._output.put(OutputEntryType.FILE, file, [f"{file_value}\n"], level=Level.VERBOSE)
                    self._data['perftune']['files'][file] = value
                    self._data['files'][file] = file_value
                # Reading a sysfs file can fail for at least two reasons: 'perftune.py --dry-run' may list
                # Rx/Tx queue files that vanish once the queue count is reduced, or a sysfs file
                # may exist but be inaccessible due to permissions or kernel restrictions.
                except (OSError, FileNotFoundError, PermissionError, IndexError) as e:
                    self._output.put(OutputEntryType.STDOUT, f"cat {file}", f"{e}",
                                     level=Level.VERBOSE)

        params_affected = Executor.search_string("^sysctl -w", output.stdout.split("\n"))
        for param_affected in params_affected:
            # strings like "sysctl -w net.core.rps_sock_flow_entries=32768"
            name, value = param_affected.split(maxsplit=2)[2].split('=', maxsplit=1)
            cmd = "sysctl " + name
            # Output is a string like "net.core.rps_sock_flow_entries = 0"
            current_value = Executor.run_command(cmd).stdout.split("\n")[0].split(maxsplit=2)[2]
            self._output.put(OutputEntryType.STDOUT, cmd, current_value, level=Level.VERBOSE)
            self._data['perftune']['sysctl'][name] = value
            self._data['sysctl'][name] = current_value

        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ['*']


class PerftuneYamlDefaultCollector(Collector):
    @property
    def name(self) -> str:
        return "Default content of perftune.yaml, generated by perftune.py"

    @property
    def __collector_systemwide(self) -> str:
        return "ScyllaSystemConfigurationFilesCollector"

    @property
    def __collector_platform(self) -> str:
        return "NodePlatformCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_systemwide, self.__collector_platform}

    def _collect(self, vitals: DictView) -> None:
        if vitals[self.__collector_platform].data['platform'] == NodePlatform.CONTAINER:
            self.status = CollectorStatus.SKIPPED
            self._message = "perftune.py is not available for containers"
            return

        scylla_server_config = vitals[self.__collector_systemwide].data['files'].get('scylla-server')

        if not scylla_server_config:
            self.status = CollectorStatus.FAILED
            self._message = "`scylla-server` config not found"
            return

        pt_parameters = ""

        nic = scylla_server_config.get('IFNAME', 'eth0')
        pt_parameters += f'--tune net --nic {nic}'

        if scylla_server_config.get('SET_CLOCKSOURCE', '').lower() == "yes":
            pt_parameters += ' --tune system --tune-clock'

        if scylla_server_config.get('DISABLE_WRITEBACK_CACHE', '').lower() == "yes":
            pt_parameters += ' --write-back-cache=false'

        perftune_py_path = os.path.join(self._paths['scylla_directory_scripts'], 'perftune.py')
        command = f"{perftune_py_path} {pt_parameters} --dump-options-file"
        perftune_output = Executor.run_command(command)

        if not perftune_output or perftune_output.returncode != 0:
            self.status = CollectorStatus.FAILED
            self._message = "perftune.py execution failed"
            if perftune_output:
                self._message += f": {perftune_output.stdout}"
            return

        self._output.put(OutputEntryType.STDOUT, command, perftune_output.stdout, level=Level.VERBOSE)

        command = f"{perftune_py_path} {pt_parameters} --get-cpu-mask"
        perftune_cpu_mask = Executor.run_command(command)
        self._output.put(OutputEntryType.STDOUT, command, perftune_cpu_mask.stdout, level=Level.VERBOSE)

        self._data = {
            'perftune.yaml': Executor.sort_dictionary(yaml.load(perftune_output.stdout, Loader=yaml.FullLoader)),
            'cpu_mask': perftune_cpu_mask.stdout
        }
        self.status = CollectorStatus.PASSED


class RAIDSetupCollector(Collector):
    @property
    def name(self) -> str:
        return "RAID Setup"

    def _collect(self, vitals: DictView) -> None:
        filename = "/proc/mdstat"
        content = Executor.read_file_content(filename)

        if not content:
            self.status = CollectorStatus.FAILED
            self._message = f"Cannot read {filename}"
        else:
            self.status = CollectorStatus.PASSED
            self._data = {
                filename: content
            }
            self._output.put(OutputEntryType.FILE, filename, content, level=Level.VERBOSE)

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ["/proc/mdstat"]


class RAMCollector(Collector):
    @property
    def name(self) -> str:
        return "RAM availability"

    def _collect(self, vitals: DictView) -> None:
        free_command = "free"
        free_output = Executor.run_command(free_command)
        if not free_output:
            self.status = CollectorStatus.FAILED
            self._message = "'free' usage failed"
            return

        self._output.put(OutputEntryType.STDOUT, free_command, free_output.stdout, level=Level.VERBOSE)

        meminfo_filename = "/proc/meminfo"
        meminfo_content = Executor.read_file_content(meminfo_filename)
        self._output.put(OutputEntryType.FILE, meminfo_filename, meminfo_content, level=Level.VERBOSE)

        ram_line = Executor.search_string("Mem:", free_output.stdout.split("\n"))[0]
        total_ram = int(ram_line.split()[1])

        self._data = {
            'total': total_ram
        }
        self.status = CollectorStatus.PASSED


class RsyslogCollector(Collector):
    @property
    def name(self) -> str:
        return "Rsyslog setup"

    def _collect(self, vitals: DictView) -> None:
        filename = "/etc/rsyslog.d/scylla.conf"
        content = Executor.read_file_content(filename) if os.path.isfile(filename) else None

        self._data = {
            'files': {
                filename: content
            }
        }
        if content:
            self._output.put(OutputEntryType.FILE, filename, content, level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class SysctlCollector(Collector):
    @property
    def name(self) -> str:
        return "Sysctl values"

    @property
    def __values(self) -> Set[str]:
        """Sysctl values to be collected"""
        return {"fs.aio-max-nr", "fs.file-max", "fs.nr_open"}

    def _collect(self, vitals: DictView) -> None:
        for value in self.__values:
            command = f"sysctl --values {value}"
            output = Executor.run_command(command)
            if not output:
                self.status = CollectorStatus.FAILED
                self._message = "sysctl call failed"
                return
            self._data[value] = int(output.stdout)

        command = "sysctl -a"
        self._output.put(OutputEntryType.STDOUT, command, Executor.run_command(command).stdout, level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED


class IPRoutesCollector(Collector):
    @property
    def name(self) -> str:
        return "IP routing"

    @property
    def __collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        addresses = {
            vitals[self.__collector].data['listen_address']['value'],
            vitals[self.__collector].data['broadcast_address']['value'],
            vitals[self.__collector].data['rpc_address']['value'],
            vitals[self.__collector].data['broadcast_rpc_address']['value'],
            vitals[self.__collector].data['api_address']['value']
        }

        for address in addresses:
            if address:
                ip_addr = ipaddress.ip_address(address if address != "localhost" else "127.0.0.1")
                if not ip_addr.is_loopback:
                    cmd = f"ip {'-6' if isinstance(ip_addr, ipaddress.IPv6Address) else ''} route show match {address}"
                    self._data[address] = Executor.run_command(cmd).stdout
                    self._output.put(OutputEntryType.STDOUT, cmd, self._data[address], level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ['*']


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


class ScyllaClusterSchemaDescriptionCollector(Collector):
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

    def _collect(self, vitals: DictView) -> None:
        command = "DESC SCHEMA"
        output = Executor.cqlsh(command, vitals[self.__collector_config].data)

        if not output:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrieve schema description"
            return

        self._output.put(OutputEntryType.CQL, command, output.stdout, level=Level.VERBOSE)
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


class RaftTopologyRPCStatusCollector(ScyllaRestApiAwareCollector):
    @property
    def name(self) -> str:
        return "Ongoing Raft topology RPC status"

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

        # The REST API above returns a '"none"' string if there is no ongoing Raft topology RPC or a following string if
        # there is:
        # '"<RPC name>[<some index>]: <coma separated list of IPs of nodes with pending responses>"'
        #
        # For example: '"move_raft_membership[17]: 1.2.3.4,2.3.4.5,3.4.5.6"'
        #
        # Ref: https://github.com/scylladb/scylladb/issues/25736
        self._data = self._read_scylla_rest_api(endpoint="/storage_service/raft_topology/cmd_rpc_status",
                                                api_address=api_address, api_port=api_port)
        self.status = CollectorStatus.PASSED


class ScyllaClusterStatusCollector(ScyllaRestApiAwareCollector):
    @property
    def name(self) -> str:
        return "Nodes status"

    @property
    def __collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        if not ServiceManager().scylla_server_service_active:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrieve nodes information because 'scylla' service is down"
            return

        api_address = vitals[self.__collector].data['api_address']['value']
        api_port = int(vitals[self.__collector].data['api_port']['value'])

        # status: endpoint
        endpoints = {
            'up': "/gossiper/endpoint/live/",
            'down': "/gossiper/endpoint/down/",
            'joining': "/storage_service/nodes/joining",
            'leaving': "/storage_service/nodes/leaving",
            'moving': "/storage_service/nodes/moving"
        }

        responses = {}
        for s, e in endpoints.items():
            responses[s] = self._read_scylla_rest_api(endpoint=e, api_address=api_address, api_port=api_port)

        self._data = {status: response for status, response in responses.items()}
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
            table_name = 'system_schema.tables'
            query, rows = Executor.read_cql_table(vitals[self.__collector_config].data, table_name)
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

            for row in rows:
                keyspace = row['keyspace_name'].strip()
                table = row['table_name'].strip()
                self._data.setdefault(keyspace, {})[table] = row
            self.status = CollectorStatus.PASSED
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"


class ScyllaConfigurationFileCollector(Collector):
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

        scylla_config_raw = Executor.read_file_content(scylla_config_path)
        self._output.put(OutputEntryType.FILE, scylla_config_path, scylla_config_raw, level=Level.VERBOSE)

        scylla_config = Executor.parse_config_file_to_dict(scylla_config_path, "yaml", deep_sort=False)
        if not scylla_config:
            self.status = CollectorStatus.FAILED
            self._message = f"'{scylla_config_path}' exists, but it cannot be opened or parsed"
            return

        # Store a raw content of scylla.yaml as a special value. We will need it for a
        # ScyllaConfigurationConsistencyAnalyzer.
        scylla_config['pure_scylla_yaml'] = dict(scylla_config)

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


class ScyllaConfigurationFileNoParsingCollector(Collector):
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

        scylla_config = Executor.parse_config_file_to_dict(scylla_config_path, "yaml",
                                                           deep_sort=False, no_yaml_values_parsing=True)
        if not scylla_config:
            self.status = CollectorStatus.FAILED
            self._message = f"'{scylla_config_path}' exists, but it cannot be opened or parsed"
            return

        self._data = scylla_config
        self.status = CollectorStatus.PASSED


class ScyllaExtraConfigurationFilesCollector(Collector):

    @property
    def name(self) -> str:
        return "Extra configuration files"

    @property
    def __identical_files(self) -> Set[str]:
        return {"cpuset.conf", "dev-mode.conf", "io_properties.yaml"}

    def _collect(self, vitals: DictView) -> None:
        dir = self._paths['scylla_directory_configs']
        if not os.path.isdir(dir):
            self.status = CollectorStatus.FAILED
            self._message = f"Scylla config directory {dir} is not found"
            return

        self._data['files'] = dict()
        all_extra_files = sorted(glob.glob(dir + "/*"))
        self._output.put(OutputEntryType.VALUE, f"Files in {dir}", f"{json.dumps(all_extra_files, indent=4)}",
                         level=Level.VERBOSE)
        for config_file in all_extra_files:
            if os.path.isdir(config_file):
                continue

            config_file_ext = os.path.splitext(config_file)[1].strip('.')
            parsed_file = Executor.parse_config_file_to_dict(config_file, config_file_ext)
            filename = os.path.basename(config_file)
            self._data['files'][filename] = parsed_file

            # these files must be identical between all nodes, so we put them into detailed output for strict comparison
            if filename in self.__identical_files:
                self._output.put(OutputEntryType.PARSED_FILE, filename, parsed_file, level=Level.DETAILED)
            elif parsed_file:
                self._output.put(OutputEntryType.PARSED_FILE, filename, parsed_file, level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED


class ScyllaBinaryCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla binary location"

    def _collect(self, vitals: DictView) -> None:
        scylla_bin = shutil.which("scylla")
        if not scylla_bin:
            self.status = CollectorStatus.FAILED
            self._message = "'scylla' binary was not found in $PATH"

            scylla_bin = os.path.join(self._paths['scylla_directory_bin'], "scylla")
            if not os.path.isdir(self._paths['scylla_directory']):
                self._message = "Scylla is not installed"
            elif not os.path.isfile(scylla_bin):
                self._message = f"'{scylla_bin}' does not exist or does not have the right permissions"
        else:
            self.status = CollectorStatus.PASSED
            self._data['scylla_bin'] = scylla_bin
            self._output.put(OutputEntryType.VALUE, "Scylla binary location", scylla_bin, Level.VERBOSE)


class ScyllaLimitNOFILECollector(Collector):
    @property
    def name(self) -> str:
        return "LimitNOFILE"

    @property
    def __collector_platform(self) -> str:
        return "NodePlatformCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_platform}

    def _collect(self, vitals: DictView) -> None:
        if vitals[self.__collector_platform].data['platform'] == NodePlatform.CONTAINER:
            self.status = CollectorStatus.SKIPPED
            self._message = "Not available for containers"
            return

        command = "id -u scylla"
        output = Executor.run_command(command)
        if not output:
            self.status = CollectorStatus.FAILED
            self._message = "'scylla' user does not exist"
            return
        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

        service_env = ServiceManager().service_environment("scylla-server.service")
        if service_env is None:
            self.status = CollectorStatus.FAILED
            self._message = "'LimitNOFILE' value cannot get retrieved"
            return
        self._output.put(OutputEntryType.STDOUT, command, service_env, level=Level.VERBOSE)

        try:
            limitnofile_line = Executor.search_string("^LimitNOFILE", service_env.split("\n"))
            limitnofile = int(limitnofile_line[0].split("=")[1])
        except Exception:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrive 'LimitNOFILE' value"
            return

        self._data = {
            'limitnofile': limitnofile
        }
        self.status = CollectorStatus.PASSED


class ScyllaLogsCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla logs"

    @property
    def __collector_platform(self) -> str:
        return "NodePlatformCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_platform}

    def _collect(self, vitals: DictView) -> None:
        if vitals[self.__collector_platform].data['platform'] == NodePlatform.CONTAINER:
            self.status = CollectorStatus.SKIPPED
            self._message = "Not available for containers"
            return

        since_date = self.config.get('since_date')

        since_date_parameter = f"--since={since_date}" if since_date else ""

        file = Executor.generate_output_filename(prefix="scylla_logs_", extension=".txt")
        command = f"journalctl --utc --no-pager --unit=scylla-server {since_date_parameter}".strip()
        output = Executor.run_command(command, output_file=file, output_file_compression=True)
        if not output:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot gather Scylla logs"
        else:
            self.status = CollectorStatus.PASSED
            self._message = f"Scylla logs gathered successfully to [{file}]"
            self._output.put(OutputEntryType.STDOUT, command, self.message, level=Level.VERBOSE)


class ScyllaServicesCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla services"

    @property
    def __scylla_services(self) -> Set[str]:
        return {
            "scylla-server",
            "scylla",
            "scylla-jmx",
            "node-exporter",
            "scylla-node-exporter",
            "scylla-housekeeping-daily",
            "scylla-housekeeping",
            "scylla-fstrim.timer",
            "scylla-manager-agent"
        }

    def _collect(self, vitals: DictView) -> None:
        service_manager = ServiceManager()

        for service in self.__scylla_services:
            if service_manager.service_exists(service):
                self._data[service] = {
                    'active': service_manager.service_active(service),
                    'autostarts': service_manager.service_autostarts(service)
                }

        self.status = CollectorStatus.PASSED
        self._output.put(OutputEntryType.VALUE, "Scylla Services", f"{json.dumps(self._data, indent=4)}",
                         level=Level.VERBOSE)


class ScyllaSeedsCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla seeds"

    @property
    def __collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        scylla_config = vitals[self.__collector].data
        seed_provider = scylla_config.get('seed_provider')
        if not seed_provider:
            self.status = CollectorStatus.FAILED
            self._message = "'seed_provider' was not set"
            return

        try:
            detected_seeds = seed_provider[0]['parameters'][0]['seeds'].split(",")
        except Exception:
            self.status = CollectorStatus.FAILED
            self._message = "Malformed of scylla.yaml file: 'seeds' field is not properly defined!"
            return

        use_ssl = scylla_config.get('server_encryption_options', {}).get('internode_encryption', 'none') != 'none'
        rpc_port = scylla_config['ssl_storage_port'] if use_ssl else scylla_config['storage_port']

        for seed in detected_seeds:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as seed_socket:
                    self._data[seed] = seed_socket.connect_ex((seed, rpc_port))
            except Exception:
                self._data[seed] = -1
        self.status = CollectorStatus.PASSED


class ScyllaSSTablesCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla sstables"

    def _collect(self, vitals: DictView) -> None:
        data_glob = os.path.join(self._paths['scylla_directory_var'], "data/**/*")
        self._data['files'] = [file for file in glob.glob(data_glob, recursive=True) if not os.path.isdir(file)]
        self._output.put(OutputEntryType.VALUE, f"All SSTables in {data_glob}", "\n".join(self._data['files']),
                         level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ['*']


class ScyllaSystemConfigurationFilesCollector(Collector):
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
                content = Executor.parse_config_file_to_dict(file)
                self._data['files'][filename] = content
                self._output.put(OutputEntryType.VALUE, "Directory", current_directory, level=Level.VERBOSE)
                self._output.put(OutputEntryType.PARSED_FILE, filename, content, level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED


class InvalidGossipInfo(Exception):
    pass


class GossipInfoCollector(ScyllaRestApiAwareCollector):
    @property
    def name(self) -> str:
        return "Collect gossipinfo data"

    @property
    def __collector_scylla_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_scylla_config}

    def __parse_one_gossipinfo_entry(self, entry: DictView) -> Tuple[str | None, Dict]:
        """
        Parse a single host gossipinfo entry creating an ordered dictionary with fields that are supposed to be the same
        on all nodes.

        :param entry: raw gossipinfo single host entry returned by the REST API
        :return: Host address and a dictionary with parsed gossipinfo entry values that we want to compare between
                 different nodes.
        """
        # Gossipinfo has the following structure:
        #  [ {
        #      "addrs": <Host0 broadcast address>,
        #      "generation": <gossip generation>,
        #      "version": <gossip version>,
        #      "update_time": <timestamp>,
        #      "is_alive": <host0 alive state: 'true' or 'false'>,
        #      "application_state": [
        #            {
        #               "application_state": <state code>,
        #               "value": <state value>,
        #               "version": <state version"
        #            },
        #            ...
        #       ],
        #     },
        #     ...
        #  ]
        # Application state items have following codes
        # enum class application_state {
        #     STATUS = 0,
        #     LOAD,
        #     SCHEMA,
        #     DC,
        #     RACK,
        #     RELEASE_VERSION,
        #     REMOVAL_COORDINATOR,
        #     INTERNAL_IP,
        #     RPC_ADDRESS,
        #     X_11_PADDING, // padding specifically for 1.1
        #     SEVERITY,
        #     NET_VERSION,
        #     HOST_ID,
        #     TOKENS,
        #     SUPPORTED_FEATURES,
        #     CACHE_HITRATES,
        #     SCHEMA_TABLES_VERSION,
        #     RPC_READY,
        #     VIEW_BACKLOG,
        #     SHARD_COUNT,
        #     IGNORE_MSB_BITS,
        #     CDC_GENERATION_ID,
        #     SNITCH_NAME,
        # }

        result = {}
        host_address = entry.get('addrs')

        # Transform an application state list into a map by the app-state value
        app_state_dict = {int(app_entry['application_state']): app_entry for app_entry in entry['application_state']}

        # Fetch cross-nodes comparable entries
        for state_code in GossipInfoInvariantValues:
            if state_code in app_state_dict:
                result[state_code.name] = app_state_dict[state_code]['value']

        # Parse 'SUPPORTED_FEATURES' value into a sorted Python List
        if GossipInfoInvariantValues.SUPPORTED_FEATURES.name in result:
            supported_features_str = result[GossipInfoInvariantValues.SUPPORTED_FEATURES.name]
            result[GossipInfoInvariantValues.SUPPORTED_FEATURES.name] = sorted(supported_features_str.split(','))

        if GossipInfoInvariantValues.TOKENS.name in result:
            # Parse 'TOKENS' value into a sorted Python List
            tokens_str = result[GossipInfoInvariantValues.TOKENS.name]
            result[GossipInfoInvariantValues.TOKENS.name] = sorted(tokens_str.split(';'))

        # STATUS value has the following format: <STATUS, e.g. NORMAL>[,<Numeric value X>]*
        # Let's strip away numeric values and leave only the status value.
        if GossipInfoInvariantValues.STATUS.name in result:
            full_status_str = result[GossipInfoInvariantValues.STATUS.name]
            result[GossipInfoInvariantValues.STATUS.name] = full_status_str.split(',')[0]

        return host_address, result

    def _collect(self, vitals: DictView) -> None:
        """
        Collect gossipinfo data

        :param vitals: vitals collected by dependencies
        """
        if not ServiceManager().scylla_server_service_active:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrieve nodes information because 'scylla' service is down"
            return

        api_address = vitals[self.__collector_scylla_config].data['api_address']['value']
        api_port = int(vitals[self.__collector_scylla_config].data['api_port']['value'])

        response_json = self._read_scylla_rest_api(endpoint="/failure_detector/endpoints/",
                                                   api_address=api_address, api_port=api_port)

        # The _data['gossip_info'] structure is a Dict with a host address as a key and Dict of
        # parsed GossipInfoComparableValues values as a value with a GossipInfoComparableValues names as keys:
        #
        # "data": {
        #       "gossip_info": {
        #         "172.17.144.64": {
        #           "SCHEMA": "fae808bd-d947-31cf-9516-f0e12a8410ab",
        #           "DC": "asia-south1",
        #           "RACK": "a",
        #           ....
        try:
            hosts_info: List[Tuple[str | None, Dict[str, Union[str, List[str]]]]] = []
            for host_info in response_json:
                addr, parsed_info = self.__parse_one_gossipinfo_entry(host_info)

                # Skip decommissioned nodes: decommissioned nodes are intentionally kept for additional 3 days in the
                # GossipInfo/ClusterStatus while they are removed from Raft state and from system.peers.
                # Ref: https://github.com/scylladb/scylla-doctor/issues/8
                if parsed_info.get(GossipInfoInvariantValues.STATUS.name) == "LEFT":
                    continue

                hosts_info.append((addr, parsed_info))

            self._data = {
                'gossip_info': sorted(hosts_info, key=lambda x: x[0])
            }
            self.status = CollectorStatus.PASSED
        except InvalidGossipInfo as e:
            self._message = f"{e}"
            self.status = CollectorStatus.FAILED


class TokenMetadataHostsMappingCollector(ScyllaRestApiAwareCollector):
    @property
    def name(self) -> str:
        return "Collect token_metadata hosts IP to UUID mapping"

    @property
    def __collector_scylla_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_scylla_config}

    def _collect(self, vitals: DictView) -> None:
        """
        Collect token_metadata hosts IP to UUID mapping

        :param vitals: vitals collected by dependencies
        """
        if not ServiceManager().scylla_server_service_active:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrieve nodes information because 'scylla' service is down"
            return

        api_address = vitals[self.__collector_scylla_config].data['api_address']['value']
        api_port = int(vitals[self.__collector_scylla_config].data['api_port']['value'])
        response_json = self._read_scylla_rest_api(endpoint="/storage_service/host_id", api_address=api_address,
                                                   api_port=api_port)

        ip_to_uuid: Dict[str, str] = {}
        errors = []
        for tm_item in response_json:
            addr = tm_item['key']
            if addr in ip_to_uuid:
                errors.append(f"Multiple Token Metadata entries for {addr}")
                continue

            ip_to_uuid[addr] = tm_item['value']

        if errors:
            self._message = ", ".join(errors)
            self.status = CollectorStatus.FAILED
            return

        # _data['hosts'] is a map from a host broadcast address to its UUID
        self._data = {
            'hosts': ip_to_uuid
        }
        self.status = CollectorStatus.PASSED


class InvalidRaftConfiguration(Exception):
    pass


class RaftGroup0Collector(Collector):
    def __init__(self, configuration: DictView, paths: Paths):
        super().__init__(configuration, paths)

        self.__system_scylla_local_rows: Optional[List[Dict[str, str]]] = None

    @property
    def name(self) -> str:
        return "Collects Raft Group0 state and members"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_scylla_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_scylla_config}

    def __read_system_scylla_local_rows(self, vitals: DictView) -> List[Dict[str, str]]:
        """
        :param vitals: vitals collected by dependencies
        :return: parsed rows of system.scylla_local table
        """
        if self.__system_scylla_local_rows is None:
            table_name = 'system.scylla_local'
            query, self.__system_scylla_local_rows = (
                Executor.read_cql_table(vitals[self.__collector_scylla_config].data, table_name))
            self._output.put(OutputEntryType.CQL, query, self.__system_scylla_local_rows, Level.VERBOSE)

        return self.__system_scylla_local_rows

    def __get_system_scylla_local_value(self, key: str, vitals: DictView) -> Optional[str]:
        rows = self.__read_system_scylla_local_rows(vitals)
        key_rows = list(filter(lambda row: row and row['key'] == key, rows))

        if not key_rows:
            return None

        return key_rows[0]['value']

    def __collect_group0_hosts_ids(self, vitals: DictView, group0_id: str) -> List[str]:
        """
        Collect IDs of all members of Group0 from system.raft_state.

        :param vitals: vitals collected by dependencies
        :param group0_id: ID of Raft Group0
        :return: Sorted list of IDs of hosts belonging to Raft Group0 with the given ID
        """
        table_name = 'system.raft_state'
        query, rows = (
            Executor.read_cql_table(vitals[self.__collector_scylla_config].data, table_name))
        self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

        return sorted([row['server_id'] for row in filter(lambda row: row and row['group_id'] == group0_id, rows)])

    def _collect(self, vitals: DictView) -> None:
        """
        - Checks whether raft is enabled or not.
        - If raft is enabled collect Raft Group0 and IDs of all members of Raft Group0.

        :param vitals: vitals collected by dependencies
        """
        try:
            group0_upgrade_state = self.__get_system_scylla_local_value('group0_upgrade_state', vitals)
            self._data = {
                'group0_upgrade_state': group0_upgrade_state
            }

            group0_id = self.__get_system_scylla_local_value('raft_group0_id', vitals)
            if group0_id:
                self._data.update({
                    'group0_id': group0_id,
                    'hosts': self.__collect_group0_hosts_ids(vitals, group0_id)
                })
            else:
                self._data.update({
                    'group0_id': None,
                    'hosts': []
                })

            self.status = CollectorStatus.PASSED
        except Exception as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"


class SystemPeersLocalCollector(Collector):
    @property
    def name(self) -> str:
        return "Collects system.peers and system.local content"

    @property
    def __collector_cql(self) -> str:
        return "CqlshCollector"

    @property
    def __collector_scylla_config(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cql, self.__collector_scylla_config}

    def __get_peers_info(self, vitals: DictView, table_name: str, address_column: str) \
            -> Dict[str, Dict[str, Union[str, List[str]]]]:
        """
        Read content of a given table using given column names and generate a map of peer broadcast address to peer's
        info.
        :param vitals: vitals collected by dependencies
        :param table_name: Name of the table to read
        :param address_column: Name of the column which contains the IP address.
        :return: map of a peer address to peer's info defined by the "peer's info" subset of columns
        """
        query, rows = Executor.read_cql_table(vitals[self.__collector_scylla_config].data, table_name)
        self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

        # Since peers are inherently different between nodes, we can't store all data from system.peers and
        # system.local. This would show up as a reported inconsistency. Instead we only store the common columns
        # between the two tables. The superset of data from the two tables is identical for use and comparison.
        common_columns = ['host_id', 'data_center', 'rack', 'release_version', 'rpc_address', 'schema_version',
                          'supported_features', 'tokens']

        result: Dict[str, Dict[str, Union[str, List[str]]]] = {}

        for row in rows:
            new_row: Dict[str, Union[str, List[str]]] = {key: row[key] for key in common_columns}
            new_row['supported_features'] = sorted(str(new_row['supported_features']).split(","))
            result[row[address_column]] = new_row

        return result

    def _collect(self, vitals: DictView) -> None:
        """
        Collect a mapping of hosts broadcast address to host info as they appear in system.peers and system.local
        content.
        :param vitals: vitals collected by dependencies
        """
        peers_to_info = {}
        system_local_rows = None
        try:
            # Read common columns from system.peers
            table_name = 'system.peers'
            peers_to_info.update(self.__get_peers_info(vitals, table_name, 'peer'))

            # Read common columns from system.local
            table_name = 'system.local'
            peers_to_info.update(self.__get_peers_info(vitals, table_name, 'broadcast_address'))

            # Read the whole contents of system.local
            _, system_local_rows = Executor.read_cql_table(vitals[self.__collector_scylla_config].data, table_name)
            if not system_local_rows:
                self.status = CollectorStatus.FAILED
                self._message = "system.local table is empty"
                return
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"
            return

        self._data = {
            'hosts': peers_to_info,
            # System.local contains only one row
            'local': system_local_rows[0]
        }

        # Substitute default values for possibly missing entries in system.local.
        # (this should never happen, but just in case).
        for key, value_callable in {
            'rpc_address': lambda: '127.0.0.1',
            'listen_address': lambda: '127.0.0.1',
            'broadcast_address': lambda: self._data['local']['listen_address']
        }.items():
            if not self._data['local'].get(key):
                self._data['local'][key] = value_callable()
                self._message = ",".join([self._message,
                                          f"'{key}' entry is missing in system.local, substituted "
                                          f"with '{value_callable()}'"])

        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        return ['local']  # system.local is different on each node


class SystemClusterStatusCollector(Collector):
    @property
    def name(self) -> str:
        return "Collects system.cluster_status content"

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
        """
        Collect a mapping of hosts broadcast address to host info as they appear in system.cluster_status content.
        :param vitals: vitals collected by dependencies
        """
        hosts_key = 'hosts'
        try:
            table_name = 'system.cluster_status'
            query, rows = (Executor.read_cql_table(vitals[self.__collector_scylla_config].data, table_name))
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

            addr_to_info = {}
            for row in rows:
                # 'load' value can have a slightly different value for the same host when read on different nodes due to
                # a delay in the gossip data propagation. Therefore, let's not include it in the _data for SDC purposes.
                row.pop('load')
                addr_to_info[row.pop('peer')] = row

            # Skip decommissioned nodes: decommissioned nodes are intentionally kept for additional 3 days in the
            # GossipInfo/ClusterStatus while they are removed from Raft state and from system.peers.
            # Ref: https://github.com/scylladb/scylla-doctor/issues/8
            addr_to_info_clean = dict(filter(lambda it: it[1]['status'] != 'LEFT', addr_to_info.items()))

            self._data = {hosts_key: addr_to_info_clean}
            self.status = CollectorStatus.PASSED
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"
            return


class SystemTopologyCollector(Collector):
    @property
    def name(self) -> str:
        return "Collects system.topology content"

    @property
    def __cqlsh_collector(self) -> str:
        return "CqlshCollector"

    @property
    def __gossip_info_collector(self) -> str:
        return "GossipInfoCollector"

    @property
    def __scylla_config_collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def __system_peers_local_collector(self) -> str:
        return "SystemPeersLocalCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__cqlsh_collector, self.__gossip_info_collector, self.__scylla_config_collector,
                self.__system_peers_local_collector}

    @property
    def __consistent_topology_feature_name(self) -> str:
        return "SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES"

    @property
    def __system_topology_rows_data_key(self) -> str:
        return "system_topology_rows"

    @property
    def __consistent_topology_supported_data_key(self) -> str:
        return "consistent_topology_supported"

    def _collect(self, vitals: DictView) -> None:
        """
        Collect the content of system.topology table.
        :param vitals: vitals collected by dependencies
        """
        messages = []
        collector_data: Dict[str, List | bool | None] = {
            self.__system_topology_rows_data_key: [],
            # If this remains None this means that we couldn't identify if Consistent Topology is supported
            self.__consistent_topology_supported_data_key: None
        }

        # Check if Consistent Topology is supported by the installed Scylla version:
        # SUPPORTS_CONSISTENT_TOPOLOGY_CHANGES must be in the SUPPORTED_FEATURES list of the node.
        try:
            broadcast_address = vitals[self.__system_peers_local_collector].data['local']['broadcast_address']
            gossip_info = vitals[self.__gossip_info_collector].data['gossip_info']
            broadcast_address_gossip_entries = list(filter(lambda item: item[0] == broadcast_address, gossip_info))

            # Find the Gossip Info entry for the local host according to its broadcast_address
            if not broadcast_address_gossip_entries:
                messages.append(f"Own broadcast address {broadcast_address} not found in gossip_info")
                broadcast_address_gossip_info = None
            else:
                if len(broadcast_address_gossip_entries) > 1:
                    messages.append(f"Multiple broadcast address {broadcast_address} entries found in gossip_info. "
                                    f"Using the first one.")
                _, broadcast_address_gossip_info = broadcast_address_gossip_entries[0]

            # Check of Consistent Topology feature is supported.
            if broadcast_address_gossip_info:
                if (self.__consistent_topology_feature_name not in
                        broadcast_address_gossip_info.get(GossipInfoInvariantValues.SUPPORTED_FEATURES.name, [])):
                    messages.append(f"Scylla version does not support "
                                    f"{self.__consistent_topology_feature_name} feature")
                    collector_data[self.__consistent_topology_supported_data_key] = False
                else:
                    collector_data[self.__consistent_topology_supported_data_key] = True

            # Try to read 'system.topology' table
            query, rows = Executor.read_cql_table(vitals[self.__scylla_config_collector].data, 'system.topology')
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)

            # If tokens are present - sort them so that this collector's data is comparable to the corresponding
            # data collected on different nodes of the same cluster.
            for row in rows:
                if "tokens" in row:
                    tokens = row.pop("tokens")
                    # 'token' key's value is of this format: "{'token1', 'token2', ..., 'tokenN'}"
                    row["tokens"] = f"{{{', '.join(sorted(tokens.strip('{}').split(', ')))}}}"

            collector_data[self.__system_topology_rows_data_key] = rows
            self.status = CollectorStatus.PASSED
        except Exception as e:
            messages.append(f"{e}")
            self.status = CollectorStatus.FAILED

        self._data = collector_data
        self._message = ". ".join(messages)


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

    def _collect(self, vitals: DictView) -> None:
        max_rows = int(self.config.get('max_rows', -1))
        self._data = {}
        for table_name in ('system.large_partitions', 'system.large_cells', 'system.large_rows'):
            query, rows = Executor.read_cql_table(
                vitals[self.__collector_scylla_config].data, table_name, max_rows=max_rows)
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)
            self._data[table_name] = rows

        self.status = CollectorStatus.PASSED
        if max_rows >= 0:
            self._message = f"Collected {max_rows} rows per table (user configuration)"


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


class SystemConfigCollector(Collector):
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

    def _collect(self, vitals: DictView) -> None:
        """
        - Collects system.config parameters their values and appropriately casts them (e.g. bool, int, list).
        - Collects the source of values set for system.config parameters (e.g. default, API, etc.)
        - Collects types of values set for system.config parameters (e.g. 'string', 'int', 'restriction mode')
        """
        string_value_keys = self._parse_comma_separated_config("string_value_keys")

        # Set 'object_storage_endpoints' has a non-JSON value.
        # Ref https://scylladb.atlassian.net/browse/SCYLLADB-1658
        string_value_keys.add("object_storage_endpoints")

        try:
            table_name = 'system.config'
            query, rows = Executor.read_cql_table(vitals[self.__collector_config].data, table_name)
            self._output.put(OutputEntryType.CQL, query, rows, Level.VERBOSE)
        except CqlFailedException as e:
            self.status = CollectorStatus.FAILED
            self._message = f"{e}"
            return

        self._data = {}
        for row in rows:
            parameter_name = row.pop('name')
            if parameter_name not in string_value_keys:
                # The value is a JSON value.
                row["value"] = json.loads(row["value"])

            self._data[parameter_name] = row

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


class ScyllaVersionCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla version and edition"

    def _collect(self, vitals: DictView) -> None:
        output = Executor.run_command(f"{self._paths['scylla_directory']}/bin/scylla --version")
        if not output:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot get Scylla version"
            return

        version = output.stdout.rstrip("\n")
        self._output.put(OutputEntryType.VALUE, "Scylla version", version, level=Level.VERBOSE)

        # there are many rpm/deb based distributions, so let's just try both variants
        commands = ["rpm -qa", "dpkg -l"]
        for command in commands:
            output = Executor.run_command(command, shell=True, check=False)
            if output and output.returncode == 0:
                break

        self._output.put(OutputEntryType.STDOUT, " or ".join(commands), output.stdout, level=Level.VERBOSE)

        # subprocess.run can't really handle piping such as " | grep scylla" so we'll do it here
        scylla_packages = sorted(Executor.search_string("scylla", output.stdout.split('\n'), re.IGNORECASE))
        # normalize number of whitespaces in putput to improve readability and ease up comparison
        scylla_packages = [' '.join(p.split()) for p in scylla_packages]
        if any(["enterprise" in package for package in scylla_packages]):
            edition = "enterprise"
        elif any(["dev" in package for package in scylla_packages]):
            edition = "development"
        else:
            edition = "oss"
        self._data = {
            'version': version,
            'edition': edition,
            'packages': scylla_packages
        }
        self.status = CollectorStatus.PASSED


class SELinuxCollector(Collector):
    @property
    def name(self) -> str:
        return "SELinux setup"

    def _collect(self, vitals: DictView) -> None:
        file = "/etc/selinux/config"
        self._data['files'] = {
            file: Executor.read_file_content(file) if os.path.isfile(file) else None
        }
        if os.path.isfile(file):
            self._output.put(OutputEntryType.FILE, file, self._data['files'][file], level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class ServiceManagerCollector(Collector):

    @property
    def name(self):
        return "Detect service manager"

    def _collect(self, vitals: DictView) -> None:

        detected_service_manager = ServiceManager().interface

        self.status = CollectorStatus.PASSED if detected_service_manager else CollectorStatus.FAILED
        self._data = {
            'service_manager': detected_service_manager
        }
        self._output.put(OutputEntryType.VALUE, "Service manager", f"{detected_service_manager}",
                         level=Level.VERBOSE)


class StorageConfigurationCollector(Collector):
    @property
    def name(self) -> str:
        return "Storage configuration"

    @property
    def __collector_platform(self) -> str:
        return "NodePlatformCollector"

    @property
    def __collector_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_platform, self.__collector_config}

    def _collect(self, vitals: DictView) -> None:
        # One of the things we are going to collect are mount options for each data directory of our interest.
        # A typical 'mount' line looks as follows:
        #
        # /dev/nvme0n1 on /var/lib/systemd/coredump type xfs (rw,noatime,attr2,inode64,logbufs=8,logbsize=32k,noquota)
        #
        # Mount options are at the end between '(' and ')'
        # Let's find everything between '(' and ')' then...
        mount_options_expr = re.compile(r'.*\((.*)\).*')

        # Cache all mount lines
        mount_lines = []
        command = "mount"
        output = Executor.run_command(command)
        if output:
            mount_lines = output.stdout.split("\n")
            self._output.put(OutputEntryType.STDOUT, "mount", output.stdout, level=Level.VERBOSE)

        scylla_config = vitals[self.__collector_config].data
        scylla_workdir = scylla_config['workdir,W']['value'] or self._paths['scylla_directory_var']
        dirs = {
            'data_file_directories': scylla_config['data_file_directories']['value'] or [os.path.join(scylla_workdir, 'data')],  # noqa: E501
            'commitlog_directories': [scylla_config['commitlog_directory']['value'] or os.path.join(scylla_workdir, 'commitlog')],  # noqa: E501
            'hints_directories': [scylla_config['hints_directory']['value'] or os.path.join(scylla_workdir, 'hints')],  # noqa: E501
            'view_hints_directories': [scylla_config['view_hints_directory']['value'] or os.path.join(scylla_workdir, 'view_hints')],  # noqa: E501
        }

        for dir, paths in dirs.items():
            self._data[dir] = {}
            for path in paths:
                # detect disks
                command = "{}/perftune.py --dir {} --tune disks --dry-run" \
                    .format(self._paths["scylla_directory_scripts"], path)
                output = Executor.run_command(command)
                if not output or not output.stdout:
                    self.status = CollectorStatus.FAILED
                    self._message = f"Failed to run {command}"
                    return
                self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

                nvme = Executor.search_string("Setting NVMe disks", output.stdout.split("\n"))
                nvme_devices = sorted(set(nvme[0].split(":")[1].strip()[:-3].split(", ")) if nvme else set())

                non_nvme = Executor.search_string("Setting non-NVMe disks", output.stdout.split("\n"))
                non_nvme_devices = sorted(set(non_nvme[0].split(":")[1].strip()[:-3].split(", ")) if non_nvme else set())  # noqa: E501

                # Check storage filesystem and size
                command = "df -T {}".format(path)
                output = Executor.run_command(command)
                self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

                filesystem: Optional[str] = None
                mountpoint: Optional[str] = None
                if output:
                    path_info = output.stdout.split("\n")[1].split()
                    filesystem = path_info[1].lower()
                    mountpoint = path_info[6]

                mount_options: List[str] = []
                if mountpoint:
                    mpoint_expr = re.compile(rf'\s+{mountpoint}\s+')
                    for scylla_mount_line in filter(lambda ln: mpoint_expr.search(ln) is not None, mount_lines):
                        # Theoretically there may be no mount options
                        opts = mount_options_expr.match(scylla_mount_line)
                        if opts:
                            mount_options = opts.group(1).split(",")

                storage_stats = os.statvfs(path)
                storage_size_kb = storage_stats.f_frsize * storage_stats.f_blocks / 1024
                free_storage_size_kb = storage_stats.f_frsize * storage_stats.f_bfree / 1024

                self._data[dir][path] = {
                    'devices': {
                        'nvme': nvme_devices,
                        'non_nvme': non_nvme_devices
                    },
                    'filesystem': filesystem,
                    'mountpoint': mountpoint,
                    'mount_options': mount_options,
                    'storage_size_kb': storage_size_kb,
                    'free_storage_size_kb': free_storage_size_kb
                }
        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        # No need to compare free storage size between nodes
        return [("*", "*", "free_storage_size_kb")]


class SwapCollector(Collector):
    @property
    def name(self) -> str:
        return "Swap configuration"

    def _collect(self, vitals: DictView) -> None:
        file = "/proc/swaps"
        if not os.path.isfile(file):
            self.status = CollectorStatus.FAILED
            self._message = f"Cannot collect {file}"
            return
        content = Executor.read_file_content(file)

        self._output.put(OutputEntryType.FILE, file, content, level=Level.VERBOSE)
        self._data['total'] = sum([int(line.split()[2]) for line in content[1:]])  # skip first line, it's a header
        self.status = CollectorStatus.PASSED


class TCPConnectionsCollector(Collector):
    @property
    def name(self) -> str:
        return "TCP connections"

    def _collect(self, vitals: DictView) -> None:
        command = "ss --all --tcp"
        output = Executor.run_command(command)
        if not output or not output.stdout:
            self.status = CollectorStatus.FAILED
            self._message = "'ss' usage failed"
        else:
            self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
            self.status = CollectorStatus.PASSED


class SDVersionCollector(Collector):
    @property
    def name(self) -> str:
        return "SD Version"

    def _collect(self, vitals: DictView) -> None:

        script_path = os.path.dirname(__file__)
        verfile_name = 'version'
        if os.path.isfile(script_path):
            try:
                archive = zipfile.ZipFile(script_path, 'r')
                self._data['version'] = archive.read(verfile_name).decode().strip()
                self._output.put(OutputEntryType.FILE, verfile_name, [f"{self._data['version']}\n"],
                                 level=Level.VERBOSE)
            except Exception as e:
                self._message = f"Failed to read version data: {e}. Please, report!"
                self.status = CollectorStatus.FAILED
                return
        else:
            buildversion = os.path.join(script_path, verfile_name)
            if os.path.isfile(buildversion):
                with open(buildversion) as f:
                    self._data['version'] = f.readline().strip()
                    self._output.put(OutputEntryType.FILE, verfile_name, [f"{self._data['version']}\n"],
                                     level=Level.VERBOSE)
            else:
                self._message = "Couldn't find SD version file, did you run 'make version' ?"
                self.status = CollectorStatus.FAILED
                return

        self.status = CollectorStatus.PASSED
        self._message = f"SD version: {self._data['version']}"


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

        # Check that systemd-detect-virt is present
        try:
            Executor.run_command(command=f"which {command}", shell=True)
        except Exception:
            self.status = CollectorStatus.FAILED
            self._message = f"{command} is not found. Can't collect the hypervisor type."
            return

        # systemd-detect-virt will return a non-zero return code on non-virtualized hosts. Let's ignore it.
        output = Executor.run_command(command=command, check=False)
        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
        self._data['hypervisor'] = output.stdout.split("\n")[0].strip()
        self.status = CollectorStatus.PASSED


class ProcInterruptsCollector(Collector):
    """
    Collect the content of /proc/interrupts
    """
    @property
    def name(self) -> str:
        return "/proc/interrupts"

    def _collect(self, vitals: DictView) -> None:
        file_name = "/proc/interrupts"
        interrupts = Executor.read_file_content(file_name)
        self._output.put(OutputEntryType.FILE, file_name, interrupts, level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class LSPCICollector(Collector):
    """
    Collect the output of 'lspci -vvv'
    """
    @property
    def name(self) -> str:
        return "lspci -vvv"

    def _collect(self, vitals: DictView) -> None:
        command = "lspci -vvv"
        output = Executor.run_command(command)
        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class SeastarCPUMapCollector(Collector):
    """
    Collect the output of 'seastar-cpu-map.sh -n scylla'
    """
    @property
    def name(self) -> str:
        return "seastar-cpu-map.sh -n scylla"

    def _collect(self, vitals: DictView) -> None:
        short_command = "seastar-cpu-map.sh -n scylla"
        full_command = f"{self._paths['scylla_directory_scripts']}/{short_command}"
        output = Executor.run_command(full_command)
        self._output.put(OutputEntryType.STDOUT, short_command, output.stdout, level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class NodetoolCFStatsCollector(Collector):
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


class ScyllaSimplePerTableRestApiCollector(ScyllaRestApiAwareCollector, Generic[T], abc.ABC):
    """
    Base class for Scylla REST API collectors that collect per-table information
    where the endpoint returns a simple value (int, float, etc.).
    The specific endpoint is defined in the subclass.
    The collected data is a nested dictionary mapping keyspace names to table names to the collected value.
    E.g.:
    {
        "keyspace1": {
            "table1": value1,
            "table2": value2,
            ...
        },
        "keyspace2": {
            "table3": value3,
            ...
        },
        ...
    }

    The REST API endpoint is expected to be of the form: /<endpoint>/{keyspace}:{table}
    """
    @property
    @abc.abstractmethod
    def _endpoint(self) -> str:
        pass

    @abc.abstractmethod
    def _endpoint_value_converter(self, value: str) -> T:
        pass

    @property
    def __collector_tables_description(self) -> str:
        return "ScyllaClusterTablesDescriptionCollector"

    @property
    def __collector_scylla_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_tables_description, self.__collector_scylla_config}

    def _collect(self, vitals: DictView) -> None:
        api_address = vitals[self.__collector_scylla_config].data['api_address']['value']
        api_port = int(vitals[self.__collector_scylla_config].data['api_port']['value'])

        tables_endpoint_info: Dict[str, Dict[str, T]] = {}
        tables_description_info = vitals[self.__collector_tables_description].data
        for keyspace, tables in tables_description_info.items():
            for table in tables:
                response_json = self._read_scylla_rest_api(endpoint=self._endpoint,
                                                           endpoint_parameters=f"/{keyspace}:{table}",
                                                           api_address=api_address, api_port=api_port)
                tables_endpoint_info.setdefault(keyspace, {})[table] = self._endpoint_value_converter(response_json)

        self._data = tables_endpoint_info
        self.status = CollectorStatus.PASSED


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
