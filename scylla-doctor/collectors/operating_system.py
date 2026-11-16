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

import csv
import json
import os

from typing import Optional, Set

from common import DictView, SYSTEMD_INFINITY
from collectors_base import CollectorStatus, Collector
from models.output_entry import OutputEntryType, Level

from utils import Executor, ServiceManager


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

    @property
    def skip_in_container(self) -> Optional[str]:
        return "CPU scaling services run on the host, and a container's service manager usually cannot see them"

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


class CoredumpCollector(Collector):
    @property
    def name(self) -> str:
        return "Coredump setup"

    @property
    def skip_in_container(self) -> Optional[str]:
        return ("coredump handling is set up on the host (systemd-coredump mount unit, sysctl drop-ins), which a "
                "container usually cannot see")

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


class ScyllaLimitNOFILECollector(Collector):
    @property
    def name(self) -> str:
        return "LimitNOFILE"

    @property
    def skip_in_container(self) -> Optional[str]:
        return "it reads the scylla-server unit through systemd, which a container usually does not run"

    def _collect(self, vitals: DictView) -> None:
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

        try:
            limitnofile_line = Executor.search_string("^LimitNOFILE=", service_env.split("\n"))
            limitnofile_value = limitnofile_line[0].split("=", 1)[1].strip()
        except Exception:
            self.status = CollectorStatus.FAILED
            self._message = "Cannot retrive 'LimitNOFILE' value"
            return
        # Only the line used: the rest of 'systemctl show' can hold credentials, e.g. an Environment= with AWS keys
        # set through 'systemctl edit' or a password flag in an overridden ExecStart= (DOCTOR-130).
        self._output.put(OutputEntryType.VALUE, "LimitNOFILE (systemd)", f"{limitnofile_line[0]}\n",
                         level=Level.VERBOSE)

        # 'scylla-server.service' ships 'LimitNOFILE=infinity' since scylladb/scylladb@78c8598 and systemd reports
        # that literal back, so the value is kept as a string. Validate it here - the stripped build has no
        # analyzers, and a collector is the only place that can report an unparsable value.
        if limitnofile_value != SYSTEMD_INFINITY and not limitnofile_value.isdigit():
            self.status = CollectorStatus.FAILED
            self._message = f"Cannot retrive 'LimitNOFILE' value: unexpected value '{limitnofile_value}'"
            return

        self._data = {
            'limitnofile': limitnofile_value
        }
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
