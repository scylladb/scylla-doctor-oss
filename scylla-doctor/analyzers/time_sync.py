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

from typing import Set

from analyzers_base import Analyzer, AnalyzerStatus
from common import DictView


class ChronyStatusAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Chrony Status Analyzer"

    @property
    def __collector(self) -> str:
        return "ChronyStatusCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that chrony leap status from chronyc tracking is synchronized.
        """
        chrony_synchronized = vitals[self.__collector].data.get('chrony_synchronized', False)

        if not chrony_synchronized:
            self.status = AnalyzerStatus.FAILED
            self.message = "The system clock is not chrony synchronized."
            return

        self.status = AnalyzerStatus.PASSED
        self.message = "The system clock is chrony synchronized."


class NTPServicesAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "NTP Services Setup"

    @property
    def __collector(self) -> str:
        return "NTPServicesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that at least one NTP-related service is enabled, and that chrony is the one used when installed.
        """
        data = vitals[self.__collector].data
        ntp_services = data['services']
        active_services = sorted(service for service in ntp_services if ntp_services[service]['active'] is True)
        if len(active_services) == 0:
            self.status = AnalyzerStatus.FAILED
            self.message = "NTP setup was not done"
        elif data.get('chrony_installed') and not {'chronyd', 'chrony'} & set(active_services):
            self.status = AnalyzerStatus.WARNING
            self.message = (f"Chrony is installed, but time is kept by {', '.join(active_services)}. "
                            f"Chronyd is more accurate.")
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "NTP setup was done"


class NTPStatusAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "NTP Status Analyzer"

    @property
    def __collector(self) -> str:
        return "NTPStatusCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that NTP is enabled, and the system clock is synchronized.
        """
        ntp_enabled = vitals[self.__collector].data.get('ntp_enabled', False)
        ntp_synchronized = vitals[self.__collector].data.get('ntp_synchronized', False)

        if not ntp_enabled:
            self.status = AnalyzerStatus.FAILED
            self.message = "NTP is not enabled."
            return

        if not ntp_synchronized:
            self.status = AnalyzerStatus.FAILED
            self.message = "The system clock is not NTP synchronized."
            return

        self.status = AnalyzerStatus.PASSED
        self.message = "NTP is enabled and the system clock is synchronized."
