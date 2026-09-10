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
import sys
from pathlib import Path

import pytest

from collectors_base import CollectorStatus
from scylla_doctor_cluster import (
    Configuration,
    analyze_cluster,
    verify_cluster_vitals_versions,
    remove_key,
    strip_similar,
)


# Utility functions ###########################################################

@pytest.mark.parametrize("container,key,expected", [
    ({'a': 1, 'b': 2}, 'a', {'b': 2}),
    ({'nested': {'a': 1, 'b': 2}}, 'a', {'nested': {'b': 2}}),
    ([{'a': 1}, {'b': 2}], 'a', [{}, {'b': 2}]),
])
def test_remove_key(container, key, expected):
    remove_key(container, key)
    assert container == expected


def test_strip_similar_removes_negligible_numeric_diff():
    deep_diff = {
        'values_changed': {
            "root['x']": {'new_value': 100, 'old_value': 100.5},
            "root['y']": {'new_value': 1, 'old_value': 10},
        }
    }
    strip_similar(deep_diff, max_normalised_diff_percent=1)
    assert "root['x']" not in deep_diff['values_changed']
    assert "root['y']" in deep_diff['values_changed']


def test_strip_similar_drops_empty_values_changed():
    deep_diff = {'values_changed': {"root['x']": {'new_value': 100, 'old_value': 100.5}}}
    strip_similar(deep_diff, max_normalised_diff_percent=1)
    assert 'values_changed' not in deep_diff


# Configuration ###############################################################

def test_configuration_exclude_from_diff(monkeypatch):
    monkeypatch.setattr(
        sys,
        'argv',
        ['scylla_doctor_cluster.py', '--dir', '/tmp', '-sov', 'ExcludeFromDiff,IPRoutesCollector,'],
    )
    config = Configuration()
    assert 'IPRoutesCollector' in config.excluded_from_diff_collectors


def test_configuration_skip_test(monkeypatch):
    monkeypatch.setattr(
        sys,
        'argv',
        ['scylla_doctor_cluster.py', '--dir', '/tmp', '-sov', 'SkipTest,CPUScalingAnalyzer,'],
    )
    config = Configuration()
    assert 'CPUScalingAnalyzer' in config.skipped_analyzers


def test_configuration_max_normalised_diff_percent(monkeypatch):
    monkeypatch.setattr(
        sys,
        'argv',
        ['scylla_doctor_cluster.py', '--dir', '/tmp', '-sov', 'General,max_normalised_diff_percent,2.5'],
    )
    config = Configuration()
    assert config.max_normalised_diff_percent == 2.5


def test_configuration_from_ini_file(monkeypatch, tmp_path):
    config_file = tmp_path / "cluster.ini"
    config_file.write_text(
        "[General]\n"
        "max_normalised_diff_percent = 3\n"
        "\n"
        "[ExcludeFromDiff]\n"
        "ClockSourceCollector\n"
    )
    monkeypatch.setattr(
        sys,
        'argv',
        ['scylla_doctor_cluster.py', '--dir', '/tmp', '--config-file', str(config_file)],
    )
    config = Configuration()
    assert config.max_normalised_diff_percent == 3.0
    assert 'ClockSourceCollector' in config.excluded_from_diff_collectors


def test_shipped_ini_excludes_scylla_logs_collector(monkeypatch):
    """
    ScyllaLogsCollector.message embeds a per-run timestamped log file path, so it always differs
    across nodes/runs. The shipped scylla_doctor_cluster.ini excludes it from diff to avoid a
    spurious "inconsistency" report when loaded via --config-file (see #296). Not applied unless
    --config-file points at it, same as the other pre-existing shipped exclusions.
    """
    shipped_ini = Path(__file__).parent.parent / "scylla_doctor_cluster.ini"
    monkeypatch.setattr(
        sys,
        'argv',
        ['scylla_doctor_cluster.py', '--dir', '/tmp', '--config-file', str(shipped_ini)],
    )
    config = Configuration()
    assert 'ScyllaLogsCollector' in config.excluded_from_diff_collectors


# analyze_cluster #############################################################

import scylla_doctor as _scylla_doctor  # noqa: E402

TOOL_VERSION = _scylla_doctor.Doctor.read_tool_version()


def _collector_json(data, output=None, status=CollectorStatus.PASSED):
    return {'status': status.value, 'data': data, 'output': output or [], 'message': 'ok'}


def _sd_version_json(version=TOOL_VERSION):
    return _collector_json({'version': version})


def _patch_tool_version(monkeypatch, version=TOOL_VERSION):
    import scylla_doctor
    monkeypatch.setattr(scylla_doctor.Doctor, "read_tool_version", staticmethod(lambda: version))


def test_analyze_cluster_no_vitals(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, 'argv', ['scylla_doctor_cluster.py', '--dir', str(tmp_path)])
    config = Configuration()
    with pytest.raises(ValueError, match="No detected vitals"):
        analyze_cluster(config)


def test_analyze_cluster_identical_vitals(monkeypatch, tmp_path):
    _patch_tool_version(monkeypatch)
    vitals_dir = tmp_path / "vitals"
    vitals_dir.mkdir()
    collector_json = {
        'SDVersionCollector': _sd_version_json(),
        'DummyCollector': _collector_json({'value': 42}),
    }
    for node in ('node1', 'node2'):
        with open(vitals_dir / f"{node}.vitals.json", 'w') as f:
            json.dump(collector_json, f)

    monkeypatch.setattr(
        sys,
        'argv',
        ['scylla_doctor_cluster.py', '--dir', str(vitals_dir)],
    )
    config = Configuration()

    def skip_analyze_vitals(*args, **kwargs):
        return None

    monkeypatch.setattr('scylla_doctor_cluster.analyze_vitals', skip_analyze_vitals)
    files, failures, warnings, inconsistencies = analyze_cluster(config)

    assert len(files) == 2
    assert failures == {}
    assert warnings == {}
    assert inconsistencies == {}


def _verbose_output_entry(value):
    # level 2 == Level.VERBOSE; stripped away before diffing
    return {'level': 2, 'type': 'Value of', 'name': 'verbose_entry', 'value': value}


def test_analyze_cluster_diff_uses_stripped_data(monkeypatch, tmp_path):
    """
    check_vitals() diffs *stripped* results: a difference living only in verbose output must NOT be
    reported as an inconsistency, while a difference in default-level data must be reported.
    """
    vitals_dir = tmp_path / "vitals"
    vitals_dir.mkdir()

    _patch_tool_version(monkeypatch)
    node1 = {
        'SDVersionCollector': _sd_version_json(),
        # differs only in verbose output -> stripped before diff -> no inconsistency
        'SwapCollector': _collector_json({'swap_total': '0'}, output=[_verbose_output_entry('aaa')]),
        # differs in default-level data -> inconsistency reported
        'PlainCollector': _collector_json({'x': '1'}),
    }
    node2 = {
        'SDVersionCollector': _sd_version_json(),
        'SwapCollector': _collector_json({'swap_total': '0'}, output=[_verbose_output_entry('bbb')]),
        'PlainCollector': _collector_json({'x': '2'}),
    }
    with open(vitals_dir / "node1.vitals.json", 'w') as f:
        json.dump(node1, f)
    with open(vitals_dir / "node2.vitals.json", 'w') as f:
        json.dump(node2, f)

    monkeypatch.setattr(sys, 'argv', ['scylla_doctor_cluster.py', '--dir', str(vitals_dir)])
    config = Configuration()
    # Isolate the diff behavior from the analyzer run (covered separately).
    monkeypatch.setattr('scylla_doctor_cluster.analyze_vitals', lambda *a, **k: None)

    _files, _failures, _warnings, inconsistencies = analyze_cluster(config)

    assert 'PlainCollector' in inconsistencies, "data-level difference should be reported"
    assert 'SwapCollector' not in inconsistencies, "verbose-only difference must be stripped before diffing"


def test_analyze_cluster_analyzes_in_memory_vitals(monkeypatch, tmp_path):
    """
    analyze_cluster must hand the already-decoded vitals to the analysis path (run_doctor(vitals=...))
    instead of re-reading the file (run_doctor(vitals_file=...)). This avoids the redundant second parse.
    """
    _patch_tool_version(monkeypatch)
    vitals_dir = tmp_path / "vitals"
    vitals_dir.mkdir()
    node = {
        'SDVersionCollector': _sd_version_json(),
        'DummyCollector': _collector_json({'value': 42}),
    }
    with open(vitals_dir / "node1.vitals.json", 'w') as f:
        json.dump(node, f)

    monkeypatch.setattr(sys, 'argv', ['scylla_doctor_cluster.py', '--dir', str(vitals_dir)])
    config = Configuration()

    captured = {}

    def fake_run_doctor(config, vitals=None, vitals_file=None, additional_args=None):
        captured['vitals'] = vitals
        captured['vitals_file'] = vitals_file

        class _Doctor:
            def print_results(self, format, file):
                file.write('{}')
        return _Doctor()

    monkeypatch.setattr('scylla_doctor_cluster.run_doctor', fake_run_doctor)
    analyze_cluster(config)

    assert captured['vitals_file'] is None, "analysis must not re-read the vitals file"
    assert captured['vitals'] is not None, "analysis must receive in-memory decoded vitals"
    assert 'DummyCollector' in captured['vitals']


def test_verify_cluster_vitals_versions_lists_all_mismatches(monkeypatch, tmp_path):
    """Mixed-version directories must name every file that does not match the tool version."""
    _patch_tool_version(monkeypatch, "1.5")
    vitals_dir = tmp_path / "vitals"
    vitals_dir.mkdir()
    for name, version in (("fileA", "1.4"), ("fileB", "1.4"), ("fileC", "1.5")):
        with open(vitals_dir / f"{name}.vitals.json", 'w') as f:
            json.dump({'SDVersionCollector': _sd_version_json(version)}, f)

    files = sorted(str(p) for p in vitals_dir.glob("*.vitals.json"))
    with pytest.raises(ValueError) as exc_info:
        verify_cluster_vitals_versions(files)

    message = str(exc_info.value)
    assert "analyzer: 1.5" in message
    assert "fileA.vitals.json (v1.4)" in message
    assert "fileB.vitals.json (v1.4)" in message
    assert "fileC.vitals.json" not in message
    assert "Re-collect the vitals" in message


def test_verify_cluster_vitals_versions_uniform_points_at_cluster_tool(monkeypatch, tmp_path):
    """When every file agrees, the cluster tool's Scylla Doctor is what has to change."""
    _patch_tool_version(monkeypatch, "1.5")
    vitals_dir = tmp_path / "vitals"
    vitals_dir.mkdir()
    for name in ("fileA", "fileB"):
        with open(vitals_dir / f"{name}.vitals.json", 'w') as f:
            json.dump({'SDVersionCollector': _sd_version_json("1.4")}, f)

    files = sorted(str(p) for p in vitals_dir.glob("*.vitals.json"))
    with pytest.raises(ValueError) as exc_info:
        verify_cluster_vitals_versions(files)

    message = str(exc_info.value)
    assert "All vitals were collected with Scylla Doctor 1.4" in message
    assert "--scylla-doctor-path" in message
    assert "Re-collect" not in message


def test_analyze_cluster_version_mismatch_skips_analysis(monkeypatch, tmp_path):
    _patch_tool_version(monkeypatch, "1.5")
    vitals_dir = tmp_path / "vitals"
    vitals_dir.mkdir()
    for name, version in (("fileA", "1.4"), ("fileB", "1.4"), ("fileC", "1.5")):
        with open(vitals_dir / f"{name}.vitals.json", 'w') as f:
            json.dump({'SDVersionCollector': _sd_version_json(version)}, f)

    monkeypatch.setattr(sys, 'argv', ['scylla_doctor_cluster.py', '--dir', str(vitals_dir)])
    config = Configuration()
    analyzed = []
    monkeypatch.setattr(
        'scylla_doctor_cluster.analyze_vitals',
        lambda *a, **k: analyzed.append(a),
    )

    with pytest.raises(ValueError, match=r"fileA\.vitals\.json \(v1\.4\).*fileB\.vitals\.json \(v1\.4\)"):
        analyze_cluster(config)
    assert analyzed == []


def test_verify_cluster_vitals_versions_continues_past_unreadable_file(monkeypatch, tmp_path):
    """A file with no SDVersionCollector data must not abort the scan of remaining files."""
    _patch_tool_version(monkeypatch, "1.5")
    vitals_dir = tmp_path / "vitals"
    vitals_dir.mkdir()
    with open(vitals_dir / "fileA.vitals.json", 'w') as f:
        json.dump({'SDVersionCollector': _sd_version_json("1.4")}, f)
    with open(vitals_dir / "fileB.vitals.json", 'w') as f:
        json.dump({}, f)

    files = sorted(str(p) for p in vitals_dir.glob("*.vitals.json"))
    with pytest.raises(ValueError) as exc_info:
        verify_cluster_vitals_versions(files)

    message = str(exc_info.value)
    assert "fileA.vitals.json (v1.4)" in message
    assert "fileB.vitals.json" in message


def test_verify_cluster_vitals_versions_ok_when_all_match(monkeypatch, tmp_path):
    _patch_tool_version(monkeypatch, "1.5")
    vitals_dir = tmp_path / "vitals"
    vitals_dir.mkdir()
    for name in ("fileA", "fileB"):
        with open(vitals_dir / f"{name}.vitals.json", 'w') as f:
            json.dump({'SDVersionCollector': _sd_version_json("1.5")}, f)

    files = sorted(str(p) for p in vitals_dir.glob("*.vitals.json"))
    verify_cluster_vitals_versions(files)
