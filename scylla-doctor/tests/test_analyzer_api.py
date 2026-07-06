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

import random

from analyzers_base import AnalyzerStatus
from tests.helpers import DummyDependsOnSkippedAndFailedAnalyzer, DummyDependsOnFailedAnalyzer, DummyFailedCollector, \
    DummySkippedCollector, DummyBaseCollector


def test_config_skip(doctor_factory):
    # all analyzers and no collectors
    doctor = doctor_factory(collectors=[], analyzers=None)
    disable_all_config = [(analyzer.id, "run", random.choice(["False", "no", "0", "off"]))
                          for analyzer in doctor.analyzers.values()]
    doctor = doctor_factory(collectors=[], analyzers=None, config_options=disable_all_config)
    doctor.run()
    for analyzer in doctor.analyzers.values():
        assert analyzer.status == AnalyzerStatus.SKIPPED


def test_analyzer_skip_due_to_skipped_collector(doctor_factory):
    """
    An Analyzer depending on a SKIPPED Collector should be SKIPPED too, even if another dependency FAILED
    """
    doctor = doctor_factory(collectors=[DummyFailedCollector, DummySkippedCollector],
                            analyzers=[DummyDependsOnSkippedAndFailedAnalyzer])
    doctor.run()
    for analyzer in doctor.analyzers.values():
        assert analyzer.status == AnalyzerStatus.SKIPPED
        # Verify that a skipped analyzer's message has the information about both failed and skipped dependencies
        assert f"Required {DummyFailedCollector.name} was not successful" in analyzer.message
        assert f"Required {DummySkippedCollector.name} was skipped" in analyzer.message


def test_analyzer_fail_due_to_failed_collector(doctor_factory):
    """
    An Analyzer depending on a FAILED Collector should be FAILED too
    """
    doctor = doctor_factory(collectors=[DummyFailedCollector, DummyBaseCollector],
                            analyzers=[DummyDependsOnFailedAnalyzer])
    doctor.run()
    for analyzer in doctor.analyzers.values():
        assert analyzer.status == AnalyzerStatus.FAILED
        # Verify that a failed analyzer's message has the information about failed dependencies
        assert f"Required {DummyFailedCollector.name} was not successful" in analyzer.message
