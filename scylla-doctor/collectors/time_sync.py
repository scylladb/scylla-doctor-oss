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
import os
import re
import shutil

from typing import Optional, Set

from common import DictView
from collectors_base import CollectorStatus, Collector
from models.output_entry import OutputEntryType, Level

from utils import Executor, ServiceManager


class ChronyStatusCollector(Collector):
    @property
    def name(self) -> str:
        return "Chrony status collection"

    @property
    def __not_synchronized_leap_status(self) -> str:
        # Ref https://chrony-project.org/doc/4.0/chronyc.html (tracking: Leap status)
        return 'Not synchronised'

    def _collect(self, vitals: DictView) -> None:
        """
        Collects whether the system clock is synchronized via chrony.
        Sets 'chrony_synchronized' and 'leap_status' in the data collection.
        """
        if not shutil.which('chronyc'):
            self.status = CollectorStatus.SKIPPED
            self._message = "chronyc is not installed, skipping chrony status collection"
            return

        command = "chronyc tracking"
        output = Executor.run_command(command, check=False)
        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

        if output.returncode != 0:
            self.status = CollectorStatus.SKIPPED
            self._message = "chronyc tracking failed, chrony may not be in use"
            return

        leap_status = None
        for line in output.stdout.splitlines():
            match = re.match(r'^\s*Leap status\s*:\s*(.+)\s*$', line)
            if match:
                leap_status = match.group(1)
                break

        if leap_status is None:
            self.status = CollectorStatus.FAILED
            self._message = "Could not determine chrony leap status from chronyc tracking output"
            return

        self._data = {
            'chrony_synchronized': leap_status != self.__not_synchronized_leap_status,
            'leap_status': leap_status,
        }
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

    @property
    def skip_in_container(self) -> Optional[str]:
        return ("time synchronisation is the host's job, and a container's service manager usually cannot see host "
                "services")

    def _collect(self, vitals: DictView) -> None:
        service_manager = ServiceManager()

        services = {service: {
            'active': service_manager.service_active(service)
        } for service in self.__ntp_services}

        self._data = {
            # chronyd lives in /usr/sbin, which a non-root PATH may lack
            'chrony_installed': shutil.which('chronyd', path=os.pathsep.join(['/usr/sbin', '/sbin', '/usr/bin']))
            is not None,
            'services': services
        }

        self._output.put(OutputEntryType.VALUE, "NTP services",
                         f"{json.dumps(self._data['services'], indent=4)}", level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED


class NTPStatusCollector(Collector):
    @property
    def name(self) -> str:
        return "NTPStatusCollector"

    @property
    def skip_in_container(self) -> Optional[str]:
        return "timedatectl needs systemd-timedated, which a container usually does not run"

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
