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

from typing import Dict, Mapping, Set

from analyzers_base import Analyzer, AnalyzerStatus
from analyzers.helpers import InvalidVersionFormat, compare_versions, get_url_content
from common import HumanBytesUnitFormat, ConfigParameter, DictView, NodePlatform, SYSTEMD_INFINITY
from models.os_support import OSSupportMatrix, OSSupportMatrixError


def effective_limitnofile(limitnofile_data: Mapping, sysctl_data: Mapping) -> int:
    """
    Returns the number of file descriptors 'scylla-server.service' effectively gets.

    'scylla-server.service' ships 'LimitNOFILE=infinity' since scylladb/scylladb@78c8598, which does not grant
    an unlimited number of descriptors: the kernel refuses a NOFILE hard limit above 'fs.nr_open', so systemd
    clamps it there and that is the ceiling the service actually runs with.
    :param limitnofile_data: 'ScyllaLimitNOFILECollector' vitals data
    :param sysctl_data: 'SysctlCollector' vitals data
    :return: The effective LimitNOFILE value
    """
    if limitnofile_data['limitnofile'] == SYSTEMD_INFINITY:
        return sysctl_data['fs.nr_open']

    return int(limitnofile_data['limitnofile'])


class AIOMAXNRAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "aio-max-nr parameter"

    @property
    def __collector_sysctl(self) -> str:
        return "SysctlCollector"

    @property
    def __collector_cpu(self) -> str:
        return "CPUSpecificationsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_sysctl, self.__collector_cpu}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that fs.aio-max-nr sysctl value is greater than recommended value (per shard/CPU).
        """
        aiomaxnr = vitals[self.__collector_sysctl].data['fs.aio-max-nr']
        shards = vitals[self.__collector_cpu].data['logical_cores']

        # Defined based on expert knowledge (aka 'black magic')
        black_magic_number = shards * 11026 + 65536

        if aiomaxnr >= black_magic_number:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{aiomaxnr} is equal or greater than {black_magic_number} (recommended value)"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"{aiomaxnr} is less than {black_magic_number} (recommended value)"


class CPUScalingAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "CPU scaling setup"

    @property
    def __collector(self) -> str:
        return "CPUScalingCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that CPU scaling is supported, and respective services are active.
        """
        scaling_governor = vitals[self.__collector].data['scaling_governor']
        if not scaling_governor:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "CPU does not support scaling"
        else:
            active_services = [service for service in vitals[self.__collector].data['services']
                               if vitals[self.__collector].data['services'][service]['active']]
            if len(active_services) == 0:
                self.status = AnalyzerStatus.FAILED
                self.message = "CPU scaling setup was not done"
            else:
                self.status = AnalyzerStatus.PASSED
                self.message = f"{active_services} scaling services are active"


class ClockSourceAnalyzer(Analyzer):
    @property
    def __preferred_sources(self) -> Set[str]:
        return {"tsc", "kvm-clock", "hyperv_clocksource_tsc_page", "arch_sys_counter"}

    @property
    def name(self) -> str:
        return "Clock source setup analysis"

    @property
    def __collector(self):
        return "ClockSourceCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that clocksource is set up to a recommended value.
        """
        clocksource = vitals[self.__collector].data['clocksource']
        if clocksource:
            if clocksource in self.__preferred_sources:
                self.status = AnalyzerStatus.PASSED
                self.message = f"{clocksource} is used as clock source"
            else:
                self.status = AnalyzerStatus.WARNING
                self.message = f"{clocksource} is used as clock source, which is not recommended"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = "Clock source setup was not done"


class CoredumpAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Coredump setup"

    @property
    def __collector(self) -> str:
        return "CoredumpCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __coredump_service(self) -> str:
        return "var-lib-systemd-coredump.mount"

    @property
    def __user_generated_filename(self) -> str:
        return "/usr/lib/sysctl.d/50-coredump.conf"

    @property
    def __scylla_generated_filename(self) -> str:
        return "/etc/sysctl.d/99-scylla-coredump.conf"

    @property
    def __scylla_generated_file_content(self) -> str:
        return 'kernel.core_pattern=|/usr/lib/systemd/systemd-coredump %p %u %g %s %t %e"'

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that coredump setup is done for scylla.
        """
        if self.__coredump_service not in vitals[self.__collector].data['services'] \
                or not vitals[self.__collector].data['services'][self.__coredump_service]['active']:
            self.status = AnalyzerStatus.FAILED
            self.message = "Coredump setup was not done, please run scylla_coredump_setup.py"
            return

        if self.__user_generated_filename in vitals[self.__collector].data['files']:
            self.status = AnalyzerStatus.PASSED
            self.message = "Coredump optimized"
            return

        if self.__scylla_generated_filename in vitals[self.__collector].data['files']:
            self.status = AnalyzerStatus.PASSED
            self.message = "Coredump optimized"

            file_content = vitals[self.__collector].data['files'][self.__scylla_generated_filename]
            lineno = 0

            # Check that except for comments and empty lines the only meaningful content in the file
            # is the one generated by scylla_coredump_setup.py.
            for line in file_content:
                lineno += 1
                clean_line = line.strip()

                # Skip comments and empty lines
                if len(clean_line) == 0 or clean_line[0] == '#':
                    continue

                if clean_line != self.__scylla_generated_file_content:
                    self.status = AnalyzerStatus.FAILED
                    self.message = f"Unexpected content in {self.__scylla_generated_filename}: " \
                                   f"line: {lineno}: {line}, please run scylla_coredump_setup.py"
                    break

            return

        self.status = AnalyzerStatus.FAILED
        self.message = "Coredump setup was not done properly, please run scylla_coredump_setup.py"


class FSFILEMAXAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "'fs.file-max' value"

    @property
    def __collector_sysctl(self) -> str:
        return "SysctlCollector"

    @property
    def __collector_limitnofile(self) -> str:
        return "ScyllaLimitNOFILECollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_sysctl, self.__collector_limitnofile}

    @property
    def __recommended_value(self) -> int:
        """
        Black magic recommended value
        """
        return 9223372036854775807

    def _analyze(self, vitals: DictView) -> None:
        """
        Check fs.file-max limit is huge enough.
        """
        sysctl_data = vitals[self.__collector_sysctl].data
        limitnofiles_value = effective_limitnofile(vitals[self.__collector_limitnofile].data, sysctl_data)
        filemax_value = sysctl_data['fs.file-max']

        if filemax_value < limitnofiles_value:
            self.status = AnalyzerStatus.FAILED
            self.message = f"fs.file-max value {filemax_value} is less than LimitNOFILE value {limitnofiles_value}"
        elif filemax_value < self.__recommended_value:
            self.status = AnalyzerStatus.WARNING
            self.message = f"fs.file-max value {filemax_value} is less than recommended value {self.__recommended_value}"  # noqa: E501
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"fs.file-max value {filemax_value} is greater than recommended value"


class FSNROPENAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "'fs.nr_open' value"

    @property
    def __collector_sysctl(self) -> str:
        return "SysctlCollector"

    @property
    def __collector_limitnofile(self) -> str:
        return "ScyllaLimitNOFILECollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_sysctl, self.__collector_limitnofile}

    @property
    def __recommended_value(self) -> int:
        """
        Black magic recommended value
        """
        return 1073741816

    def _analyze(self, vitals: DictView) -> None:
        """
        Check fs.nr_open limit is huge enough.
        """
        sysctl_data = vitals[self.__collector_sysctl].data
        limitnofiles_value = effective_limitnofile(vitals[self.__collector_limitnofile].data, sysctl_data)
        nropen_value = sysctl_data['fs.nr_open']

        if nropen_value < limitnofiles_value:
            self.status = AnalyzerStatus.FAILED
            self.message = f"fs.nr_open value {nropen_value} is less than LimitNOFILE value {limitnofiles_value}"
        elif nropen_value < self.__recommended_value:
            self.status = AnalyzerStatus.WARNING
            self.message = f"fs.nr_open value {nropen_value} is less than recommended value {self.__recommended_value}"  # noqa: E501
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"fs.nr_open value {nropen_value} is greater than recommended value"


class KernelVersionAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Kernel version"

    @property
    def __collector(self) -> str:
        return "ComputerArchitectureCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __minimal_version(self) -> str:
        return "3.15"

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that kernel version is officially supported.
        """
        current_kernel_version = vitals[self.__collector].data['kernel_version']
        try:
            if compare_versions(current_kernel_version, self.__minimal_version, ">="):
                self.status = AnalyzerStatus.PASSED
                self.message = f"Kernel version {current_kernel_version} is supported"
            else:
                self.status = AnalyzerStatus.FAILED
                self.message = f"Kernel version is lower than {self.__minimal_version}"
        except InvalidVersionFormat as e:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Failed to analyze a kernel version: {e}"


class OSSupportAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Operating system"

    @property
    def __os_collector(self) -> str:
        return "OSCollector"

    @property
    def __scylla_version_collector(self) -> str:
        return "ScyllaVersionCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__os_collector, self.__scylla_version_collector}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'os_support_url': ConfigParameter(
                default='https://docs.scylladb.com/stable/_static/data/os-support.json',
                description='URL of the ScyllaDB OS support matrix JSON.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that OS is officially supported for the running ScyllaDB version.

        The matrix is fetched from `os_support_url` at runtime. Outcomes: matrix
        retrieval fails -> SKIPPED; the fetched matrix is malformed -> FAILED; the
        running ScyllaDB version has no entry in the matrix -> SKIPPED; the host OS
        is not listed -> FAILED; listed with a '*' suffix -> WARNING; otherwise PASSED.
        """
        current_version = vitals[self.__scylla_version_collector].data['version']

        url = self._get_config_value('os_support_url')
        payload = get_url_content(url)
        if payload is None:
            self.status = AnalyzerStatus.SKIPPED
            self.message = (f"Cannot retrieve OS support matrix from {url}; "
                            "the check is skipped on hosts without network egress")
            return
        try:
            matrix = OSSupportMatrix.from_json(payload, url)
        except OSSupportMatrixError as e:
            self.status = AnalyzerStatus.FAILED
            self.message = str(e)
            return

        entry = matrix.find_version_entry(current_version)
        if entry is None:
            self.status = AnalyzerStatus.SKIPPED
            self.message = f"No OS support matrix entry for Scylla version {current_version}"
            return

        distro = vitals[self.__os_collector].data['name']
        version = vitals[self.__os_collector].data['version']
        full_version_minor = vitals[self.__os_collector].data['version_minor']
        split_version_minor = full_version_minor.split()
        version_minor = split_version_minor[0] if split_version_minor else ""
        matrix_label = entry.version
        restricted = entry.match_os(distro, version, version_minor)

        os_label = f"'{distro} {full_version_minor}'"
        if restricted is None:
            self.status = AnalyzerStatus.FAILED
            self.message = f"{os_label} is not officially supported for {matrix_label}"
            return

        if restricted:
            self.status = AnalyzerStatus.WARNING
            self.message = f"{os_label} is supported for {matrix_label} with restrictions"
            return

        self.status = AnalyzerStatus.PASSED
        self.message = f"{os_label} is officially supported for {matrix_label}"


class RsyslogAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Rsyslog setup"

    @property
    def __collector(self) -> str:
        return "RsyslogCollector"

    @property
    def __collector_platform(self) -> str:
        return "NodePlatformCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector, self.__collector_platform}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that rsyslog collection is set up for Scylla.
        """
        if vitals[self.__collector_platform].data['platform'] == NodePlatform.CONTAINER:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "Not available for containers"
            return

        if vitals[self.__collector].data['files']['/etc/rsyslog.d/scylla.conf']:
            self.status = AnalyzerStatus.PASSED
            self.message = "Rsyslog setup was done"
        else:
            self.status = AnalyzerStatus.WARNING
            self.message = "Rsyslog setup was not done"


class SELinuxAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "SELinux setup"

    @property
    def __collector(self) -> str:
        return "SELinuxCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that SELinux is disabled (due to performance penalty).
        """
        content = vitals[self.__collector].data['files']['/etc/selinux/config']
        if not content:
            self.status = AnalyzerStatus.PASSED
            self.message = "SELinux is not present"
            return

        selinux_config = [s for s in content if re.search("^SELINUX=", s)]
        selinux_mode = selinux_config[0].split('=')[1].strip() if selinux_config else None
        if not selinux_mode:
            self.status = AnalyzerStatus.WARNING
            self.message = "SELinux status cannot be determined"
        elif selinux_mode == "disabled":
            self.status = AnalyzerStatus.PASSED
            self.message = "SELinux is disabled"
        else:
            self.status = AnalyzerStatus.WARNING
            self.message = "SELinux is working in {} mode".format(selinux_mode)


class ScyllaLimitNOFILEAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "LimitNOFILE"

    @property
    def __collector(self) -> str:
        return "ScyllaLimitNOFILECollector"

    @property
    def __collector_sysctl(self) -> str:
        return "SysctlCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector, self.__collector_sysctl}

    @property
    def __limitnofile_minimum(self) -> int:
        return 10000

    @property
    def __limitnofile_recommended(self) -> int:
        return 500000

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that LimitNOFILE value is big enough for scylla service.
        """
        limitnofile_data = vitals[self.__collector].data
        limitnofile = effective_limitnofile(limitnofile_data, vitals[self.__collector_sysctl].data)

        # Name where an 'infinity' value came from, otherwise the number in the message has no visible source.
        if limitnofile_data['limitnofile'] == SYSTEMD_INFINITY:
            value_description = f"'{SYSTEMD_INFINITY}', effectively fs.nr_open ({limitnofile}),"
        else:
            value_description = f"{limitnofile}"

        if limitnofile < self.__limitnofile_minimum:
            self.status = AnalyzerStatus.FAILED
            self.message = f"{value_description} is less than {self.__limitnofile_minimum} (minimum value)"
        elif limitnofile < self.__limitnofile_recommended:
            self.status = AnalyzerStatus.WARNING
            self.message = f"{value_description} is less than {self.__limitnofile_recommended} (recommended value)"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{value_description} is greater than {self.__limitnofile_recommended} (recommended value)"


class SwapAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Swap configuration"

    @property
    def __collector_swap(self) -> str:
        return "SwapCollector"

    @property
    def __collector_ram(self) -> str:
        return "RAMCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_swap, self.__collector_ram}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'swap_minimum_total': ConfigParameter(
                default='16777216',
                param_type=int,
                unit='KB',
                description='Minimum swap partition size.',
            ),
            'ram_swap_ratio': ConfigParameter(
                default='3',
                param_type=float,
                description='Recommended RAM-to-swap ratio used to compute suggested swap size.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that sufficient amount of swap is configured.
        """
        swap_minimum = self._get_config_value('swap_minimum_total')
        recommended_ratio = self._get_config_value('ram_swap_ratio')
        suggested_swap = min(swap_minimum, vitals[self.__collector_ram].data['total'] / recommended_ratio)
        detected_swap = vitals[self.__collector_swap].data['total']

        if detected_swap == 0:
            self.status = AnalyzerStatus.FAILED
            self.message = "No swap configuration detected"
            return

        if detected_swap >= suggested_swap:
            unit_human = HumanBytesUnitFormat.get_format_for_kib(detected_swap)
            self.status = AnalyzerStatus.PASSED
            self.message = f"{self.format_float(unit_human.translate_kib(detected_swap))} {unit_human} were detected"
        else:
            unit_human = HumanBytesUnitFormat.get_differentiating_format_for_kib(detected_swap, suggested_swap)
            self.status = AnalyzerStatus.WARNING
            self.message = \
                (f"{self.format_float(unit_human.translate_kib(detected_swap))} {unit_human} were "
                 f"detected but it is less than "
                 f"{self.format_float(unit_human.translate_kib(suggested_swap))} (recommended)")
