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
import enum
from typing import Dict, Optional, Set, List

from collectors_base import CollectorResult, CollectorStatus
from common import HumanBytesUnitFormat, DictView, ConfigValuesParser


class AnalyzerStatus(enum.IntEnum):
    PASSED = 0
    SKIPPED = 1
    WARNING = 2
    FAILED = 3

    def __bool__(self):
        raise NotImplementedError(
            f"Implicit cast to boolean is not allowed. Use explicit comparison to {self.__class__.__name__} values instead.")  # noqa: E501

    @staticmethod
    def combine(status_list: List["AnalyzerStatus"]) -> "AnalyzerStatus":
        """
        Return the combined status of a list of analyzers statuses.
        :param status_list: List of AnalyzerStatus values
        :return: The worst result
        """
        # Perform an explicit cast in order to verify that the values in the 'status_list' are compatible with the
        # expected AnalyzerStatus type.
        return max([AnalyzerStatus(s) for s in status_list])


class Analyzer(ConfigValuesParser, abc.ABC):
    """Analyzers are meant to analyze passed vitals and provide a diagnosis """

    @staticmethod
    def format_float(value: float) -> str:
        # TODO: consider parametrizing this and then the actual format would depend on values in self.config
        return HumanBytesUnitFormat.default_float_formatter(value)

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable name. Must be specified. """
        pass

    @property
    @abc.abstractmethod
    def depends_on(self) -> Set[str]:
        """
        Set of Collectors id's, which should have gathered info necessary for analysis.
        Only vitals gathered by Collectors specified in depends_on will be passed as input.
        These names should be present either in current Doctor session, or in vitals.json file.
        """
        pass

    _status: Optional[AnalyzerStatus]
    message: Optional[str]

    def __init__(self, configuration: DictView):
        self._status = None
        self.message = None

        self._config = configuration.get(self.id, {})

    @property
    def config(self) -> DictView:
        return self._config

    @property
    def id(self) -> str:
        return self.__class__.__name__

    @property
    def config_run_parameter(self):
        return "run"

    @property
    def config_run_skip_values(self):
        return ["0", "no", "false", "off"]

    @property
    def run(self):
        return self.config.get(self.config_run_parameter, '').lower() not in self.config_run_skip_values

    @property
    def status(self) -> AnalyzerStatus:
        if not self.executed:
            raise AttributeError(f"Status is empty, probably {self.id} was never executed")
        return self._status  # type: ignore[return-value]

    @status.setter
    def status(self, value: AnalyzerStatus):
        if not isinstance(value, AnalyzerStatus):
            cls = __class__  # type: ignore[name-defined]
            raise TypeError(f"{cls}.status must be an instance of {cls}.Status enum")
        self._status = value

    @property
    def executed(self) -> bool:
        return self._status is not None

    def analyze(self, vitals: Dict[str, CollectorResult]) -> None:
        # This is needed for CI so that we can reuse the same instance of the Analyzer in different tests
        self._status = None
        self.message = None

        if not self.run:
            self.status = AnalyzerStatus.SKIPPED
            self.message = "Disabled in configuration"
            return

        error_messages = []
        dependency_skipped = False
        dependency_failed = False
        for dep in self.depends_on:
            if dep not in vitals:
                self.status = AnalyzerStatus.FAILED
                error_messages.append(f"Required {dep} results not found")
                continue

            if vitals[dep].status == CollectorStatus.SKIPPED:
                dependency_skipped = True
                error_messages.append(f"Required {dep} was skipped")
            elif vitals[dep].status == CollectorStatus.FAILED:
                dependency_failed = True
                error_messages.append(f"Required {dep} was not successful")

        # If any dependency was skipped - skip the current Analyzer as well, even if any other dependency failed.
        # Skipped status means that either the user disabled the dependency in configuration, or the HW/SW state doesn't
        # allow to run it (e.g. insufficient privileges, missing files, etc.).
        # In this case the current Analyzer should be skipped as well, because it effectively means that same reasons
        # don't allow it to be executed too.
        # Otherwise, if any dependency failed - fail the current Analyzer as well.
        if dependency_skipped:
            self.status = AnalyzerStatus.SKIPPED
        elif dependency_failed:
            self.status = AnalyzerStatus.FAILED

        if self._status in [AnalyzerStatus.SKIPPED, AnalyzerStatus.FAILED]:
            self.message = ", ".join(error_messages)
            return

        self._analyze(DictView(vitals, self.depends_on))

    @abc.abstractmethod
    def _analyze(self, vitals: DictView) -> None:
        """
        Should give out some conclusion via status field (human-readable form should be stored in self.message).
        Only vitals gathered by Collectors specified in depends_on will be passed as input.
        """
        pass
