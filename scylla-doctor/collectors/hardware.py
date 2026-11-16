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

from common import DictView
from collectors_base import CollectorStatus, Collector
from models.output_entry import OutputEntryType, Level

from utils import Executor, running_in_container


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


class LSPCICollector(Collector):
    @property
    def include_output_default(self) -> bool:
        return True

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


class ProcInterruptsCollector(Collector):
    @property
    def include_output_default(self) -> bool:
        return True

    """
    Collect the content of /proc/interrupts
    """
    @property
    def name(self) -> str:
        return "/proc/interrupts"

    def _collect(self, vitals: DictView) -> None:
        file_name = "/proc/interrupts"
        # Container runtimes mask /proc/interrupts: bind-mounted from /dev/null when unprivileged (a character
        # device, so read_file_content raises), an empty regular file when privileged.
        try:
            interrupts = Executor.read_file_content(file_name)
        except FileNotFoundError:
            interrupts = []
        if not interrupts:
            if running_in_container():
                self.status = CollectorStatus.SKIPPED
                self._message = f"{file_name} is not readable from this container"
                return
            self.status = CollectorStatus.FAILED
            self._message = f"Cannot read {file_name}"
            return
        self._output.put(OutputEntryType.FILE, file_name, interrupts, level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


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
