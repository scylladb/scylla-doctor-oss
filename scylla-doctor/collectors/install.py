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

import datetime
import json
import os
import re
import shutil
import zipfile

from typing import Iterable, Sequence, Set, Union

from common import DictView, scylla_doctor_root
from collectors_base import CollectorStatus, Collector
from models.output_entry import OutputEntryType, Level

from utils import Executor, ServiceManager


class CollectionTimeCollector(Collector):
    @property
    def name(self) -> str:
        return "Vitals collection time"

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Nodes are collected one after another, so their collection times always differ: leave them out of the cluster
        diff.
        """
        return ['*']

    def _collect(self, vitals: DictView) -> None:
        # Local time with its UTC offset: it lines up with the node's own logs and still compares across time zones.
        self._data = {'collected_at': datetime.datetime.now().astimezone().isoformat(timespec='seconds')}
        self._output.put(OutputEntryType.VALUE, 'collected_at', self._data['collected_at'], level=Level.VERBOSE)
        self._message = "Collection time recorded"
        self.status = CollectorStatus.PASSED


class PathsCollector(Collector):
    @property
    def name(self) -> str:
        return "System paths"

    def _collect(self, vitals: DictView) -> None:
        self._data = dict(self._paths)
        self._output.put(OutputEntryType.VALUE, "paths", f"{json.dumps(dict(self._paths), indent=4)}",
                         level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class SDVersionCollector(Collector):
    @property
    def name(self) -> str:
        return "SD Version"

    def _collect(self, vitals: DictView) -> None:

        script_path = scylla_doctor_root()
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
        # 2025.1+ is a single Enterprise distribution; package names no longer contain "enterprise".
        version_match = re.match(r'^(\d+)\.(\d+)', version.strip())
        if any("dev" in package for package in scylla_packages):
            edition = "development"
        elif version_match and (int(version_match.group(1)), int(version_match.group(2))) >= (2025, 1):
            edition = "enterprise"
        elif any("enterprise" in package for package in scylla_packages):
            edition = "enterprise"
        else:
            edition = "oss"
        self._data = {
            'version': version,
            'edition': edition,
            'packages': scylla_packages
        }
        self.status = CollectorStatus.PASSED
