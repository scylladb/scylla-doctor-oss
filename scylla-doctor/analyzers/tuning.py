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

import ipaddress
import os
import re
import socket

from typing import Dict, List, Set, Tuple

from analyzers_base import Analyzer, AnalyzerStatus
from common import ConfigParameter, DictView


class AssignedNICsAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "NICs assigned to Scylla"

    @property
    def __collector_nics(self) -> str:
        return "NICsCollector"

    @property
    def __collector_iproutes(self) -> str:
        return "IPRoutesCollector"

    @property
    def __collector_extra(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def __collector_system(self) -> str:
        return "ScyllaSystemConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_nics, self.__collector_iproutes, self.__collector_system, self.__collector_extra}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all NICs that Scylla adresses route thorugh, are tuned by perftune.
        """
        scylla_server = vitals[self.__collector_system].data['files'].get('scylla-server')
        if scylla_server is not None:
            set_nic_and_disks = scylla_server.get('SET_NIC_AND_DISKS', '')
            if set_nic_and_disks.lower() != "yes":
                self.status = AnalyzerStatus.SKIPPED
                self.message = "SET_NIC_AND_DISKS is not set"
                return
        else:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "scylla-server is not part of vitals!"
            return

        perftune_yaml = vitals[self.__collector_extra].data['files'].get('perftune.yaml')
        if not perftune_yaml:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "perftune.yaml is not found"
            return

        perftune_nics = perftune_yaml.get('nic')
        if isinstance(perftune_nics, str):
            perftune_nics = [perftune_nics]

        iproutes = [route for (addr, route) in vitals[self.__collector_iproutes].data.items()
                    if addr == "localhost" or int(ipaddress.ip_address(addr) != socket.INADDR_ANY)]
        all_nics = vitals[self.__collector_nics].data['nics'].keys()

        assigned_nics = set([nic for nic in all_nics
                             if any(nic in iproute for iproute in iproutes)])

        if not assigned_nics or not assigned_nics.issubset(perftune_nics):
            self.status = AnalyzerStatus.WARNING
            self.message = f"NICs assigned to scylla ({assigned_nics}) are not set up according to perftune.yaml ({perftune_nics})"  # noqa: E501
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{len(assigned_nics)} NIC(s) are assigned to Scylla"


class CPUSetAnalyzer(Analyzer):

    @property
    def name(self) -> str:
        return "cpuset setup"

    @property
    def __collector(self) -> str:
        return "CPUSetCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Scylla CPU set defined on cpuset.conf should be a subset of the
        maximum CPU set allowed by the configuration in the peftune.yaml.
        """
        cpusetconf_mask = vitals[self.__collector].data['cpusetconf_mask']
        cpusetconf_intersect_perftune_mask = vitals[self.__collector].data['cpusetconf_intersect_perftune_mask']

        if cpusetconf_intersect_perftune_mask != cpusetconf_mask:
            self.status = AnalyzerStatus.FAILED
            self.message = "cpuset value in cpuset.conf is not a subset of cpu_mask in perftune.yaml"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "cpuset is configured properly"


class DeveloperModeAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Developer Mode setup"

    @property
    def __collector(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that dev-mode is disabled for Scylla.
        """
        devmode_content = vitals[self.__collector].data['files'].get("dev-mode.conf", {})
        if devmode_content:
            devmode_value = devmode_content.get('DEV_MODE', "")
            if "1" in devmode_value:
                self.status = AnalyzerStatus.WARNING
                self.message = "Developer mode is enabled"
                return

        self.status = AnalyzerStatus.PASSED
        self.message = "Developer mode is not enabled"


class IOSetupAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "I/O setup"

    @property
    def __collector_config(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def __collector_paths(self) -> str:
        return "PathsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_config, self.__collector_paths}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that I/O setup was done, and io.conf content matches io_properties.yaml content.
        """
        io_file = "io.conf"
        ioproperties_file = "io_properties.yaml"
        seastar_io_option = "SEASTAR_IO"
        scylla_config_dir = vitals[self.__collector_paths].data['scylla_directory_configs']
        seastar_io_recommended_value = f"--io-properties-file[= ]{os.path.join(scylla_config_dir, ioproperties_file)}"

        io_file_content = vitals[self.__collector_config].data['files'].get(io_file, {})
        if not io_file_content or not io_file_content.get(seastar_io_option):
            self.status = AnalyzerStatus.WARNING
            self.message = "I/O setup was not done"
            return

        seastar_io_value = io_file_content[seastar_io_option]
        ioproperties_file_content = vitals[self.__collector_config].data['files'].get(ioproperties_file, {})
        if re.search(seastar_io_recommended_value, seastar_io_value):
            if ioproperties_file_content:
                # TODO: Check if io_properties.yaml content is valid
                self.status = AnalyzerStatus.PASSED
                self.message = "I/O setup was done"
            else:
                self.status = AnalyzerStatus.WARNING
                self.message = "I/O setup has its configuration broken (io_properties.yaml is missing)"
        else:
            if ioproperties_file_content:
                self.status = AnalyzerStatus.WARNING
                self.message = "I/O setup has its configuration broken (io_properties.yaml isn't being used)"
            else:  # some customized confgiuration
                self.status = AnalyzerStatus.PASSED
                self.message = "I/O setup was done"


class MemoryTuningAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Memory tuning configuration"

    @property
    def __collector(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that memory tweaking was done.
        """
        memory_file = vitals[self.__collector].data['files'].get("memory.conf", {})
        if not memory_file or not memory_file.get('MEM_CONF'):
            self.status = AnalyzerStatus.WARNING
            self.message = "Memory setup was not done, please check memory.conf"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "Memory setup was done"


class PerftuneAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Perftune.py"

    @property
    def __collector(self) -> str:
        return "PerftuneSystemConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'skip_files': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated file paths to skip in perftune file value checks.',
            ),
            'skip_sysctls': ConfigParameter(
                default='',
                comma_separated=True,
                description='Comma-separated sysctl names to skip in perftune sysctl checks.',
            ),
        }

    def __compare_str_or_int16_list(self, a: str, b: str) -> bool:
        """
        Compare two strings, which can be either plain strings or lists of hex values (e.g. "ff", "0a,ff,00").
        :param a: First string to compare
        :param b: Second string to compare
        :return: True if strings contain values that compare as equal.

        Two string values are considered equal if:
          - They are equal lexicographically.
          - Strings contain comma-separated list of hex values. In such a case corresponding integer lists are aligned
            to have the same length by prepending a required number of zero values to the shorter list. After that
            lists are compared following tuples comparison rule.
          - Strings contain space-separated lists of hex values. In this case lists are compared as tuples without
            aligning.
        """
        def compare_int16_lists(aa: str, bb: str, separator: None | str, pad_with_zeros: bool) -> bool:
            def parse_hex_list(s: str) -> List[int]:
                return [int(p.strip(), 16) for p in s.split(separator)]

            try:
                # Compare lists of hex values or plain hex values.
                # Note: split(',') on a string without commas returns a single-element list,
                # so this handles both hex lists and plain hex cases uniformly.
                # When lists differ in length, the shorter one is prepended with zeros if pad_with_zeros == True
                a_ints = parse_hex_list(aa)
                b_ints = parse_hex_list(bb)
                if pad_with_zeros:
                    pad = len(a_ints) - len(b_ints)
                    if pad > 0:
                        b_ints = [0] * pad + b_ints
                    elif pad < 0:
                        a_ints = [0] * (-pad) + a_ints
                return a_ints == b_ints
            except (ValueError, TypeError):
                return False

        # String comparison
        if a == b:
            return True
        elif not a or not b:
            # If only one of the values is an empty string - return False
            # At this point we already established that a != b thanks to a previous condition
            return False

        # Integers lists comparison
        for separator, pad_with_zeros in [(None, False), (",", True)]:
            if compare_int16_lists(a, b, separator, pad_with_zeros):
                return True

        return False

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all tweakings suggested by perftune (based on perftune.yaml content) are actually applied.
        """
        def inconsistent_message(kind: str, where: str, read_value: str, should_be_value: str) -> str:
            """
            :param kind: "file" or "sysctl"
            :param where: a file or a sysctl name
            :param read_value: actual value
            :param should_be_value: expected value
            :return: Resulting message
            """
            return f"Inconsistent value found for {kind} {where}: {read_value} instead of {should_be_value}"

        def append_new_status(
                status_list: List[Tuple[str, AnalyzerStatus]], message: str, status: AnalyzerStatus) -> None:
            """
            Append a given message and an Analyzer status to the list.
            If the list is not empty - make sure the first word of the message uses lower case characters.
            :param status_list: List of status tuples to append new info to
            :param message: message to append
            :param status: Analyzer status
            """
            if not status_list:
                status_list.append((message, status))
            else:
                split_message = message.split()

                # Sanity
                if not split_message:
                    status_list.append((message, status))
                    return

                # lowercase the first word
                status_list.append((" ".join([split_message[0].lower()] + split_message[1:]), status))

        skip_files: Set[str] = self._get_config_value('skip_files')
        skip_sysctls: Set[str] = self._get_config_value('skip_sysctls')

        inconsistency_status: List[Tuple[str, AnalyzerStatus]] = []

        files = vitals[self.__collector].data['perftune'].get('files')
        if files:
            for file, content in files.items():
                if file in skip_files:
                    continue
                # Special case 'scheduler' files: their content goes as follows:
                # <val1> [<val2>] val3 val4 ...
                # Where the value in [] is the actually configured value (val2 in the example above)
                if os.path.basename(file) == 'scheduler':
                    res = re.match(r".*\[(.*)].*", vitals[self.__collector].data['files'][file])
                    if res:
                        file_content = res.group(1)
                    else:
                        append_new_status(inconsistency_status, f"Unexpected format in {file}",
                                          AnalyzerStatus.FAILED)
                        continue
                else:
                    file_content = vitals[self.__collector].data['files'][file]
                if not self.__compare_str_or_int16_list(content, file_content):
                    append_new_status(inconsistency_status,
                                      inconsistent_message(
                                          "file", file, file_content, content), AnalyzerStatus.WARNING)

        sysctls = vitals[self.__collector].data['perftune'].get('sysctl')
        if sysctls:
            for param, value in sysctls.items():
                if param in skip_sysctls:
                    continue
                sysctl_value = vitals[self.__collector].data['sysctl'][param]
                if value != sysctl_value:
                    append_new_status(inconsistency_status,
                                      inconsistent_message(
                                          "sysctl", param, sysctl_value, value), AnalyzerStatus.WARNING)

        if not inconsistency_status:
            self.status = AnalyzerStatus.PASSED
            message = "Verified perftune.py modifications are intact"
            if skip_files:
                message += f" (not checked files: {skip_files})"
            if skip_sysctls:
                message += f" (not checked sysctls: {skip_sysctls})"
            self.message = message

        else:
            self.status = AnalyzerStatus.combine([s[1] for s in inconsistency_status])
            self.message = ", ".join([s[0] for s in inconsistency_status])


class PerftuneCpuMaskAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Check CPU mask against defaults"

    @property
    def __collector_cpuset(self) -> str:
        return "CPUSetCollector"

    @property
    def __collector_default(self) -> str:
        return "PerftuneYamlDefaultCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_cpuset, self.__collector_default}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that cpu_mask generated using mode specified in perftune.yaml,
        matches the one generated by perftune.py with default settings (as in scylla_setup)
        """
        cpu_mask_actual = vitals[self.__collector_cpuset].data.get('perftune_mask', '').strip()
        cpu_mask_default = vitals[self.__collector_default].data.get('cpu_mask', '').strip()

        if cpu_mask_actual == cpu_mask_default:
            self.status = AnalyzerStatus.PASSED
            self.message = f"Actual cpu mask ({cpu_mask_actual}) matches default"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Actual cpu mask content ({cpu_mask_actual}) differs from default ({cpu_mask_default})"


class PerftuneYamlAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Check perftune.yaml content against defaults"

    @property
    def __collector_actual(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def __collector_default(self) -> str:
        return "PerftuneYamlDefaultCollector"

    @property
    def __ignore_keys(self) -> Set:
        return {'mode', 'irq_cpu_mask'}

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_actual, self.__collector_default}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that perftune.yaml on disk has the content that would have been generated by `scylla_sysconfig_setup`.
        """
        perftune_actual_content = vitals[self.__collector_actual].data['files'].get('perftune.yaml', {})
        perftune_default_content = vitals[self.__collector_default].data.get('perftune.yaml', {})

        if {k: v for k, v in perftune_actual_content.items() if k not in self.__ignore_keys} == \
                {k: v for k, v in perftune_default_content.items() if k not in self.__ignore_keys}:
            self.status = AnalyzerStatus.PASSED
            self.message = "Actual perftune.yaml content matches default"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = "Actual perftune.yaml content differs from default"


class ScyllaNICsDisksSetupAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla NICs and disks setup"

    @property
    def __collector(self) -> str:
        return "ScyllaSystemConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that SET_NIC_AND_DISKS option is enabled
        (responsible for NIC's and disks' interrupts, RPS, XPS, nomerges and I/O scheduler)
        """
        server_config = vitals[self.__collector].data['files'].get('scylla-server')
        if not server_config:
            self.status = AnalyzerStatus.FAILED
            self.message = "Scylla server config not found"
            return

        if server_config.get('SET_NIC_AND_DISKS', '').lower() != "yes":
            self.status = AnalyzerStatus.WARNING
            self.message = "SET_NIC_AND_DISKS should be set to 'yes'"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "SET_NIC_AND_DISKS is enabled"
