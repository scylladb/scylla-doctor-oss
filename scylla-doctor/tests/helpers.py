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

import time
from typing import Optional, List, Tuple, Dict

from analyzers_base import AnalyzerStatus, Analyzer
from collectors_base import Collector, CollectorStatus, CollectorResult, ScyllaRestApiAwareCollector
from models.output_entry import OutputEntryType


def orig_get_url_content(url: str, headers=None, timeout=2, retries=3, retry_interval=2, check=False):
    """
    A placeholder method that is meant to hold the original implementation of Executor.get_url_content().
    """
    return ""


def orig_read_cql_table(scylla_config, table_name: str,
                        columns: Optional[List[str]] = None) -> Tuple[str, List[Dict[str, str]]]:
    """
    A placeholder method that is meant to hold the original implementation of Executor.read_cql_table().
    """
    return "", []


# Helper stubs, dummy collectors and analyzers for tests
class DummyBaseCollector(Collector):
    name = "DummyBaseCollector"

    def _collect(self, vitals):
        self.status = CollectorStatus.PASSED
        self.launched_ts = time.time()


class DummyScyllaRestAPIAwareCollector(ScyllaRestApiAwareCollector):
    name = "DummyBaseCollector"

    def _collect(self, vitals):
        self.status = CollectorStatus.PASSED
        self.launched_ts = time.time()


class DummyCollector(Collector):
    name = "Dummy"

    def _collect(self, vitals):
        self.status = CollectorStatus.PASSED
        self.launched_ts = time.time()

    @property
    def depends_on(self):
        return {"DummyBaseCollector"}


class DummyFailedCollector(Collector):
    name = "DummyFailedCollector"

    def _collect(self, vitals):
        self.status = CollectorStatus.FAILED


class DummyDependsOnFailedCollector(Collector):
    name = "Dummy"

    def _collect(self, vitals):
        self.status = CollectorStatus.PASSED

    @property
    def depends_on(self):
        return {"DummyFailedCollector"}


class DummyCycle1Collector(Collector):
    name = "DummyCycle1Collector"

    def _collect(self, vitals):
        self.status = CollectorStatus.PASSED

    @property
    def depends_on(self):
        return {"DummyCycle2Collector"}


class DummyCycle2Collector(Collector):
    name = "DummyCycle2Collector"

    def _collect(self, vitals):
        self.status = CollectorStatus.PASSED

    @property
    def depends_on(self):
        return {"DummyCycle1Collector"}


class DummyRaisesCollector(Collector):
    name = "DummyRaisesCollector"

    def _collect(self, session):
        raise Exception("Something horrible")


class DummySkippedCollector(Collector):
    name = "DummySkippedCollector"

    def _collect(self, vitals):
        self.status = CollectorStatus.SKIPPED


class DummyDependsOnSkippedCollector(Collector):
    name = "DummyDependsOnSkippedCollector"

    def _collect(self, vitals):
        self.status = CollectorStatus.PASSED

    @property
    def depends_on(self):
        return {"DummySkippedCollector", "DummyFailedCollector"}


class DummyDependsOnSkippedAndFailedAnalyzer(Analyzer):
    name = "DummyDependsOnSkippedAndFailedAnalyzer"

    @property
    def depends_on(self):
        return {"DummySkippedCollector", "DummyFailedCollector"}

    def _analyze(self, vitals):
        self.status = AnalyzerStatus.PASSED


class DummyDependsOnFailedAnalyzer(Analyzer):
    name = "DummyDependsOnFailedAnalyzer"

    @property
    def depends_on(self):
        return {"DummyFailedCollector", "DummyPassedCollector"}

    def _analyze(self, vitals):
        self.status = AnalyzerStatus.PASSED


def assert_output_gathered(result: CollectorResult, type: OutputEntryType, name: str,
                           empty_value_allowed: bool = False, value_content: Optional[str] = None) -> None:
    """
    Checks that an entry of given type and name is present in result.output

    :param result: Collector result object to check
    :param type: Entry type
    :param name: Entry name
    :param empty_value_allowed: If True an empty value is allowed, otherwise a non-empty value must be present
    :param value_content: If not None, checks that the value contains this content
    """
    for entry in result.output:
        if (entry.type == type and name == entry.name and
                (empty_value_allowed or (entry.value and (value_content is None or value_content in entry.value)))):
            return
    assert False, f"{type} {name} not found in the output"


def assert_output_not_gathered(result: CollectorResult, type: OutputEntryType, name: str) -> None:
    """
    Checks that an entry of given type and name is not present in result.output

    :param result: Collector result object to check
    :param type: Entry type
    :param name: Entry name
    """
    for entry in result.output:
        if entry.type == type and name == entry.name:
            assert False, f"{type} {name} found in the output, but it should not be"
