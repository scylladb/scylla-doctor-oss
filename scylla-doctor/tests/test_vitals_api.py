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

import pytest

import collectors
import scylla_doctor
from analyzers_base import AnalyzerStatus, Analyzer
from collectors_base import CollectorResult, CollectorStatus, Output
from models.output_entry import Level, OutputEntryType


def _result(data=None, message="ok", status=CollectorStatus.PASSED, verbose_value=None):
    output = Output()
    if verbose_value is not None:
        output.put(OutputEntryType.VALUE, "verbose_entry", verbose_value, level=Level.VERBOSE)
    return CollectorResult(status=status, data=data if data is not None else {}, output=output, message=message)


class _RecordingAnalyzer(Analyzer):
    """Analyzer that records the vitals it was handed, so tests can assert what analysis actually saw."""
    name = "RecordingAnalyzer"
    seen = None

    @property
    def depends_on(self):
        return {"DummyBaseCollector"}

    def _analyze(self, vitals):
        # Snapshot the data and verbose output visible to analysis
        result = vitals["DummyBaseCollector"]
        type(self).seen = {
            "data": dict(result.data),
            "verbose_output": [entry.value for entry in result.output if entry.level >= Level.VERBOSE],
        }
        self.status = AnalyzerStatus.PASSED


def test_set_vitals_filters_skipped_collectors(doctor_factory):
    """set_vitals must drop vitals of collectors disabled in configuration, like load_vitals."""
    doctor = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=(),
                            config_options=[("SDVersionCollector", "run", "no")])

    doctor.set_vitals({
        "SDVersionCollector": _result(data={"version": "1.2.3"}),
        "SomeOtherCollector": _result(data={"foo": "bar"}),
    })

    assert "SDVersionCollector" not in doctor.vitals
    assert "SomeOtherCollector" in doctor.vitals


def test_set_vitals_matches_load_vitals(doctor_factory, tmp_path):
    """set_vitals(decoded) and load_vitals(file) must select the same collectors."""
    vitals_json = {
        "SDVersionCollector": {"status": CollectorStatus.PASSED.value, "data": {"version": "1.2.3"},
                               "output": [], "message": "ok"},
        "SomeOtherCollector": {"status": CollectorStatus.PASSED.value, "data": {"foo": "bar"},
                               "output": [], "message": "ok"},
    }
    vitals_file = tmp_path / "vitals.json"
    vitals_file.write_text(json.dumps(vitals_json))

    loaded = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=(),
                            config_options=[("SDVersionCollector", "run", "no")])
    loaded.load_vitals(str(vitals_file))

    in_memory = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=(),
                               config_options=[("SDVersionCollector", "run", "no")])
    decoded = {k: CollectorResult.decode(v) for k, v in vitals_json.items()}
    in_memory.set_vitals(decoded)

    assert set(loaded.vitals.keys()) == set(in_memory.vitals.keys())


def test_analyze_vitals_runs_analyzers(doctor_factory, monkeypatch):
    """analyze_vitals must execute analyzers against in-memory vitals without reading a file."""
    from tests.helpers import DummyBaseCollector

    monkeypatch.setattr(scylla_doctor.Doctor, "read_tool_version", staticmethod(lambda: "test-ver"))

    class _PassAnalyzer(Analyzer):
        name = "PassAnalyzer"

        @property
        def depends_on(self):
            return {"DummyBaseCollector"}

        def _analyze(self, vitals):
            self.status = AnalyzerStatus.PASSED

    doctor = doctor_factory(collectors=[DummyBaseCollector], analyzers=[_PassAnalyzer])
    doctor.analyze_vitals({
        "SDVersionCollector": _result(data={"version": "test-ver"}),
        "DummyBaseCollector": _result(data={"ok": True}),
    })

    analyzer = doctor.analyzers["_PassAnalyzer"]
    assert analyzer.executed
    assert analyzer.status == AnalyzerStatus.PASSED


def test_analyze_vitals_passes_unstripped_data_to_analyzers(doctor_factory, monkeypatch):
    """
    Analyzers must receive the full, unstripped vitals: verbose output and all data keys present.
    This is what makes the cluster runner's 'analyze before check_vitals strips' ordering correct.
    """
    from tests.helpers import DummyBaseCollector

    monkeypatch.setattr(scylla_doctor.Doctor, "read_tool_version", staticmethod(lambda: "test-ver"))

    _RecordingAnalyzer.seen = None
    doctor = doctor_factory(collectors=[DummyBaseCollector], analyzers=[_RecordingAnalyzer])
    doctor.analyze_vitals({
        "SDVersionCollector": _result(data={"version": "test-ver"}),
        "DummyBaseCollector": _result(data={"keep": "value"}, verbose_value="verbose-detail"),
    })

    assert _RecordingAnalyzer.seen is not None, "analyzer did not run"
    assert _RecordingAnalyzer.seen["data"] == {"keep": "value"}
    assert _RecordingAnalyzer.seen["verbose_output"] == ["verbose-detail"]


def test_analyze_vitals_version_mismatch_exits(doctor_factory, tmp_path, monkeypatch):
    """analyze_vitals enforces the vitals/tool version check, mirroring the load-vitals path of run()."""
    import os

    version_file = tmp_path / "version"
    version_file.write_text("1.0.0\n")
    monkeypatch.setattr(os.path, 'isfile', lambda p: p == str(version_file))
    monkeypatch.setattr(os.path, 'dirname', lambda _: str(tmp_path))

    doctor = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=())

    with pytest.raises(SystemExit) as exc_info:
        doctor.analyze_vitals({"SDVersionCollector": _result(data={"version": "9.9.9"})})
    assert exc_info.value.code == 1


def test_analyze_vitals_version_match_ok(doctor_factory, tmp_path, monkeypatch):
    import os

    version_file = tmp_path / "version"
    version_file.write_text("7.7.7\n")
    monkeypatch.setattr(os.path, 'isfile', lambda p: p == str(version_file))
    monkeypatch.setattr(os.path, 'dirname', lambda _: str(tmp_path))

    doctor = doctor_factory(collectors=[collectors.SDVersionCollector], analyzers=())
    # Should not raise/exit
    doctor.analyze_vitals({"SDVersionCollector": _result(data={"version": "7.7.7"})})


# save_vitals output omission #################################################


def test_decode_tolerates_missing_output():
    result = CollectorResult.decode({
        "status": CollectorStatus.PASSED.value,
        "data": {"k": "v"},
        "message": "ok",
    })
    assert result.data == {"k": "v"}
    assert list(result.output) == []


def test_strip_missing_output_keeps_data_for_cluster_diff():
    """Cluster DeepDiff uses strip(); empty output must still leave data comparable."""
    result = CollectorResult.decode({
        "status": CollectorStatus.PASSED.value,
        "data": {"files": {"io.conf": {"a": "1"}}},
        "message": "ok",
    })
    stripped = result.strip()
    assert stripped.data == {"files": {"io.conf": {"a": "1"}}}
    assert list(stripped.output) == []


def test_save_vitals_omits_output_by_default(doctor_factory, tmp_path):
    from tests.helpers import DummyBaseCollector

    doctor = doctor_factory(collectors=[DummyBaseCollector], analyzers=())
    doctor.vitals["DummyBaseCollector"] = _result(data={"x": 1}, verbose_value="detail")
    path = tmp_path / "vitals.json"
    doctor.save_vitals(str(path))

    saved = json.loads(path.read_text())
    entry = saved["DummyBaseCollector"]
    assert "output" not in entry
    assert entry["data"] == {"x": 1}
    assert entry["status"] == CollectorStatus.PASSED.value
    assert entry["message"] == "ok"


@pytest.mark.parametrize("how", ["flag", "general"])
def test_save_vitals_include_output_global(doctor_factory, tmp_path, how):
    from tests.helpers import DummyBaseCollector

    config = [("General", "include_output", "yes")] if how == "general" else ()
    doctor = doctor_factory(collectors=[DummyBaseCollector], analyzers=(), config_options=config)
    if how == "flag":
        doctor.environment.args.include_output = True
    doctor.vitals["DummyBaseCollector"] = _result(data={"x": 1}, verbose_value="detail")
    path = tmp_path / "vitals.json"
    doctor.save_vitals(str(path))

    entry = json.loads(path.read_text())["DummyBaseCollector"]
    assert "output" in entry
    assert entry["output"][0]["value"] == "detail"


def test_encoder_include_output_kwarg():
    result = _result(data={"x": 1}, verbose_value="detail")
    omitted = json.loads(json.dumps(result, cls=CollectorResult.Encoder, include_output=False))
    assert "output" not in omitted
    included = json.loads(json.dumps(result, cls=CollectorResult.Encoder, include_output=True))
    assert included["output"][0]["value"] == "detail"


def test_save_vitals_encoder_keeps_new_fields(doctor_factory, tmp_path):
    """Omit path still encodes every CollectorResult field except output."""
    from tests.helpers import DummyBaseCollector

    doctor = doctor_factory(collectors=[DummyBaseCollector], analyzers=())
    doctor.vitals["DummyBaseCollector"] = _result(data={"x": 1}, verbose_value="detail")
    path = tmp_path / "vitals.json"
    doctor.save_vitals(str(path))

    entry = json.loads(path.read_text())["DummyBaseCollector"]
    assert set(entry.keys()) == {"status", "data", "message", "mask"}
    assert "output" not in entry


def test_output_disabled_put_is_noop():
    output = Output(enabled=False)
    output.put(OutputEntryType.VALUE, "k", "v", level=Level.VERBOSE)
    assert list(output) == []


def test_collector_store_output_disabled(doctor_factory):
    from tests.helpers import DummyBaseCollector

    doctor = doctor_factory(collectors=[DummyBaseCollector], analyzers=())
    assert doctor.should_store_output() is False
    doctor.collectors["DummyBaseCollector"].set_store_output(doctor.should_store_output())
    assert doctor.collectors["DummyBaseCollector"].output.enabled is False


def test_collector_store_output_enabled_with_verbose(doctor_factory):
    from tests.helpers import DummyBaseCollector

    doctor = doctor_factory(collectors=[DummyBaseCollector], analyzers=())
    doctor.environment.args.verbose = True
    doctor.collectors["DummyBaseCollector"].set_store_output(doctor.should_store_output())
    assert doctor.collectors["DummyBaseCollector"].output.enabled is True
