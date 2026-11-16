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

from typing import Dict, Optional

from common import DictView, ConfigParameter
from collectors_base import CollectorStatus, Collector, PERMISSION_REFUSED_RE
from models.output_entry import OutputEntryType, Level

from utils import Executor, ServiceManager, running_in_container


class KernelRingBufferCollector(Collector):
    @property
    def include_output_default(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "Kernel ring buffer (dmesg)"

    @property
    def privileged(self) -> bool:
        return True

    def _collect(self, vitals: DictView) -> None:
        command = "dmesg -T"
        output = Executor.run_command(command, check=False)
        if output.returncode == 0:
            self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
            self.status = CollectorStatus.PASSED
            return

        # Reading the ring buffer needs CAP_SYSLOG on the host. Privileged rootful containers have it, unprivileged
        # and rootless ones (Docker or Podman alike) do not, so try first and only skip a container that was refused.
        if running_in_container() and PERMISSION_REFUSED_RE.search(output.stderr):
            self.status = CollectorStatus.SKIPPED
            self._message = "Kernel ring buffer not collected: dmesg needs CAP_SYSLOG on the host, which this " \
                            f"container lacks (a rootful --privileged container has it): {output.stderr.strip()}"
            return

        self.status = CollectorStatus.FAILED
        self._message = f"Cannot collect `{command}`: {output.stderr.strip()}"


class ScyllaLogsCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla logs"

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'since_date': ConfigParameter(
                default_description='unset (--since not used)',
                description='Value passed to journalctl --since.',
            ),
        }

    @property
    def skip_in_container(self) -> Optional[str]:
        return "journalctl reads the host journal, which a container usually does not have"

    def _collect(self, vitals: DictView) -> None:
        since_date = self._get_config_value('since_date')

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


class ScyllaManagerAgentLogsCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla Manager Agent logs"

    @property
    def skip_in_container(self) -> Optional[str]:
        return "journalctl reads the host journal, which a container usually does not have"

    @property
    def __service_name(self) -> str:
        return "scylla-manager-agent"

    def _collect(self, vitals: DictView) -> None:
        # Scylla Manager Agent is optional - skip when it is not installed on this node
        if not ServiceManager().service_exists(self.__service_name):
            self.status = CollectorStatus.SKIPPED
            self._message = f"{self.__service_name} service is not installed"
            return

        since_date = self.config.get('since_date')

        since_date_parameter = f"--since={since_date}" if since_date else ""

        file = Executor.generate_output_filename(prefix="scylla_manager_agent_logs_", extension=".txt")
        command = f"journalctl --utc --no-pager --unit={self.__service_name} {since_date_parameter}".strip()
        output = Executor.run_command(command, output_file=file, output_file_compression=True)
        if not output:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot gather Scylla Manager Agent logs"
        else:
            self.status = CollectorStatus.PASSED
            self._message = "Scylla Manager Agent logs gathered successfully"
            self._output.put(OutputEntryType.STDOUT, command, f"{self.message} to [{file}]", level=Level.VERBOSE)
