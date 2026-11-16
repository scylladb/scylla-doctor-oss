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
from common import HumanBytesUnitFormat, ConfigParameter, DictView, AbortedException


class CPUInstructionSetAnalyzer(Analyzer):
    @property
    def __cpu_spec_collector(self) -> str:
        return "CPUSpecificationsCollector"

    @property
    def __comp_arch_collector(self) -> str:
        return "ComputerArchitectureCollector"

    @property
    def name(self) -> str:
        return "CPU instruction set"

    @property
    def __required_flags(self) -> Set[str]:
        return {"sse4_2"}

    @property
    def __archs_with_sse4_2(self) -> Set[str]:
        return {"x86_64", "i386", "i686"}

    @property
    def depends_on(self) -> Set[str]:
        return {self.__cpu_spec_collector, self.__comp_arch_collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check if CPU has required flags.
        """
        arch = vitals[self.__comp_arch_collector].data['architecture']
        if arch not in self.__archs_with_sse4_2:
            self.status = AnalyzerStatus.SKIPPED
            self.message = f"SSE4.2 CPU instruction set is not supported on {arch}"
            return

        missing_flags = {flag for flag in self.__required_flags
                         if flag not in vitals[self.__cpu_spec_collector].data['flags']}
        if len(missing_flags) == 0:
            self.status = AnalyzerStatus.PASSED
            self.message = "All required CPU flags are present"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"Required CPU flags {', '.join(missing_flags)} are not present"


class ComputerArchitectureAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Computer architecture"

    @property
    def __collector(self) -> str:
        return "ComputerArchitectureCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @property
    def __supported_arch(self) -> Set[str]:
        return {"x86_64", "arm64", "ppc64", "aarch64"}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check whether architecture is officially supported.
        """
        arch = vitals[self.__collector].data['architecture']
        if arch in self.__supported_arch:
            self.status = AnalyzerStatus.PASSED
            self.message = f"{arch} is officially supported"
        else:
            self.status = AnalyzerStatus.FAILED
            self.message = f"{arch} is not officially supported"


class RAMAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "RAM availablity"

    @property
    def __collector_ram(self) -> str:
        return "RAMCollector"

    @property
    def __collector_cpu(self) -> str:
        return "CPUSpecificationsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_ram, self.__collector_cpu}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'ram_minimum_total': ConfigParameter(
                default='4194304',
                param_type=int,
                unit='KB',
                description='Minimum recommended total RAM size.',
            ),
            'ram_minimum_per_lcore': ConfigParameter(
                default='524288',
                param_type=int,
                unit='KB',
                description='Minimum recommended RAM per logical core.',
            ),
            'ram_recommended_total': ConfigParameter(
                default='16777216',
                param_type=int,
                unit='KB',
                description='Recommended total RAM size.',
            ),
            'ram_recommended_per_lcore': ConfigParameter(
                default='4194304',
                param_type=int,
                unit='KB',
                description='Recommended RAM per logical core.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that available RAM is greater than recommended (or at least, minimal required),
        both total and per logical core.
        """
        ram_minimum_total = self._get_config_value('ram_minimum_total')
        ram_minimum_per_lcore = self._get_config_value('ram_minimum_per_lcore')
        ram_recommended_total = self._get_config_value('ram_recommended_total')
        ram_recommended_per_lcore = self._get_config_value('ram_recommended_per_lcore')

        if any([ram_minimum_total > ram_recommended_total,
                ram_minimum_per_lcore > ram_recommended_per_lcore]):
            raise AbortedException(f"Sanity check failed for {self.id}: please check configuration parameters: "
                                   f"ram_minimum_total, ram_minimum_per_lcore, "
                                   f"ram_recommended_total, ram_recommended_per_lcore")

        detected_available_ram = vitals[self.__collector_ram].data['total']
        logical_cores = vitals[self.__collector_cpu].data['logical_cores']

        suggested_minimum_ram = max(ram_minimum_total, ram_minimum_per_lcore * logical_cores)
        suggested_recommended_ram = max(ram_recommended_total, ram_recommended_per_lcore * logical_cores)

        if detected_available_ram < suggested_minimum_ram:
            memory_unit = HumanBytesUnitFormat.get_differentiating_format_for_kib(detected_available_ram,
                                                                                  suggested_minimum_ram)
            detected_human = f"{self.format_float(memory_unit.translate_kib(detected_available_ram))} {memory_unit}"
            minimum_human = f"{self.format_float(memory_unit.translate_kib(suggested_minimum_ram))} {memory_unit}"

            self.status = AnalyzerStatus.FAILED
            self.message = f"{detected_human} were detected but it is less than {minimum_human} (minimum required)"
        elif detected_available_ram < suggested_recommended_ram:
            memory_unit = HumanBytesUnitFormat.get_differentiating_format_for_kib(detected_available_ram,
                                                                                  suggested_recommended_ram)
            detected_human = f"{self.format_float(memory_unit.translate_kib(detected_available_ram))} {memory_unit}"
            recommended_human = (f"{self.format_float(memory_unit.translate_kib(suggested_recommended_ram))} "
                                 f"{memory_unit}")

            self.status = AnalyzerStatus.WARNING
            self.message = f"{detected_human} were detected but it is less than {recommended_human} (recommended)"
        else:
            memory_unit = HumanBytesUnitFormat.get_format_for_kib(detected_available_ram)
            detected_human = f"{self.format_float(memory_unit.translate_kib(detected_available_ram))} {memory_unit}"

            self.status = AnalyzerStatus.PASSED
            self.message = f"{detected_human} were detected"
