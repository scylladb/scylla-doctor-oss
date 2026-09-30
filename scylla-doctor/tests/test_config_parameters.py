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

import inspect
import io
import json
import re
import sys

import pytest

import analyzers
import collectors
import scylla_doctor
from analyzers import RAMAnalyzer
from collectors import InfrastructureProviderCollector
from collectors_base import Collector
from common import ConfigParameter, ConfigValuesParser, DictView


def _components_with_config_parameters():
    for module in (collectors, analyzers):
        for _, cls in inspect.getmembers(module, predicate=inspect.isclass):
            if (not inspect.isabstract(cls) and issubclass(cls, ConfigValuesParser) and
                    cls.config_parameters_definitions()):
                yield cls


def test_config_parameters_include_run(doctor_factory):
    doctor = doctor_factory(collectors=None, analyzers=None)
    params = doctor.config_parameters('RAMAnalyzer')
    assert params['RAMAnalyzer']['run'].display_default() == 'unset (enabled)'


def test_config_parameters_component_specific_defaults(doctor_factory):
    doctor = doctor_factory(collectors=None, analyzers=None)
    params = doctor.config_parameters('ScyllaSSTablesAnalyzer')
    assert params['ScyllaSSTablesAnalyzer']['recommended_format'].default is None
    assert 'system.config sstable_format' in params['ScyllaSSTablesAnalyzer']['recommended_format'].default_description


def test_config_parameters_classmethod():
    assert 'timeout' in InfrastructureProviderCollector.config_parameters_definitions()
    timeout = InfrastructureProviderCollector.config_parameters_definitions()['timeout']
    assert timeout.default == '1'
    assert timeout.param_type is float
    assert timeout.unit == 'seconds'
    assert RAMAnalyzer.config_parameters_definitions()['ram_minimum_total'].default == '4194304'


def test_get_config_value_uses_definition_defaults():
    analyzer = RAMAnalyzer(DictView({'RAMAnalyzer': {}}))
    assert analyzer._get_config_value('ram_minimum_total') == 4194304
    assert analyzer._get_config_value('ram_minimum_per_lcore') == 524288


def test_get_config_value_comma_separated():
    analyzer = analyzers.PerftuneAnalyzer(DictView({
        'PerftuneAnalyzer': {'skip_files': ' /a , b '}
    }))
    assert analyzer._get_config_value('skip_files') == {'/a', 'b'}


def test_get_config_value_fallback():
    analyzer = analyzers.ScyllaSSTablesAnalyzer(DictView({'ScyllaSSTablesAnalyzer': {}}))
    assert analyzer._get_config_value('recommended_format', fallback='md') == 'md'


def test_config_parameters_list_all_components(doctor_factory):
    doctor = doctor_factory(collectors=None, analyzers=None)
    params = doctor.config_parameters()
    assert 'General' not in params
    assert {'run', 'ram_minimum_total'} <= set(params['RAMAnalyzer'])
    assert list(params['AIOMAXNRAnalyzer']) == ['run']
    assert set(params['ClockSourceCollector']) == {'include_output', 'run'}
    assert params['LSPCICollector']['include_output'].display_default() == 'yes'


def test_print_config_parameters_text(doctor_factory):
    doctor = doctor_factory(collectors=None, analyzers=None)
    output = io.StringIO()
    doctor.print_config_parameters('ScyllaSSTablesAnalyzer', file=output)
    text = output.getvalue()
    assert '[ScyllaSSTablesAnalyzer]' in text
    assert 'recommended_format (default: system.config sstable_format, then me when unset)' in text
    assert 'run (default: unset (enabled))' in text


def test_print_config_parameters_json(doctor_factory):
    doctor = doctor_factory(collectors=None, analyzers=None)
    output = io.StringIO()
    doctor.print_config_parameters('RAMAnalyzer', as_json=True, file=output)
    payload = json.loads(output.getvalue())
    assert payload['RAMAnalyzer']['ram_minimum_total']['default'] == '4194304'
    assert payload['RAMAnalyzer']['ram_minimum_total']['type'] == 'int'
    assert payload['RAMAnalyzer']['ram_minimum_total']['unit'] == 'KB'
    perftune = doctor.config_parameters('PerftuneAnalyzer')['PerftuneAnalyzer']['skip_files']
    assert perftune.runtime_type_name() == 'set[str]'
    assert payload['RAMAnalyzer']['run']['default_description'] == 'unset (enabled)'
    for param in payload['RAMAnalyzer'].values():
        assert set(param.keys()) == {'description', 'default', 'default_description', 'type', 'unit'}


def test_config_parameters_unknown_section(doctor_factory):
    doctor = doctor_factory(collectors=[], analyzers=[])
    with pytest.raises(ValueError, match='Unknown section'):
        doctor.config_parameters('NoSuchAnalyzer')


def test_main_list_parameters_unknown_section(capsys):
    old_argv = sys.argv
    try:
        sys.argv = ['scylla_doctor.py', '--list-parameters', 'NoSuchAnalyzer']
        with pytest.raises(SystemExit) as exc_info:
            scylla_doctor.main()
        assert exc_info.value.code == 1
        assert 'Unknown section' in capsys.readouterr().err
    finally:
        sys.argv = old_argv


def test_main_list_parameters_json(capsys):
    old_argv = sys.argv
    try:
        sys.argv = ['scylla_doctor.py', '--list-parameters', 'RAMAnalyzer', '--list-parameters-json']
        with pytest.raises(SystemExit) as exc_info:
            scylla_doctor.main()
        assert exc_info.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        assert payload['RAMAnalyzer']['ram_minimum_total']['default'] == '4194304'
    finally:
        sys.argv = old_argv


def test_main_list_parameters_json_without_list_flag(capsys):
    old_argv = sys.argv
    try:
        sys.argv = ['scylla_doctor.py', '--list-parameters-json']
        with pytest.raises(SystemExit) as exc_info:
            scylla_doctor.main()
        assert exc_info.value.code == 0
        payload = json.loads(capsys.readouterr().out)
        assert 'General' not in payload
        assert 'RAMAnalyzer' in payload
        assert 'AIOMAXNRAnalyzer' in payload
        assert 'ClockSourceCollector' in payload
    finally:
        sys.argv = old_argv


def test_config_parameters_collector_include_output_defaults(doctor_factory):
    doctor = doctor_factory(collectors=None, analyzers=None)
    params = doctor.config_parameters()
    assert params['ScyllaClusterSchemaDescriptionCollector']['include_output'].display_default() == 'yes'
    assert 'unset' in params['ClockSourceCollector']['include_output'].display_default()


def test_config_parameters_run_cannot_be_overridden():
    class BadRAMAnalyzer(RAMAnalyzer):
        @classmethod
        def config_parameters_definitions(cls):
            definitions = dict(RAMAnalyzer.config_parameters_definitions())
            definitions['run'] = ConfigParameter(description='accidental override')
            return definitions

    params = BadRAMAnalyzer(DictView({'RAMAnalyzer': {}})).config_parameters
    assert params['run'].description == 'Set to no/0/false/off to disable this component.'


def test_comma_separated_runtime_type_name():
    param = analyzers.PerftuneAnalyzer.config_parameters_definitions()['skip_files']
    assert param.runtime_type_name() == 'set[str]'


def _config_access_source(cls) -> str:
    source = inspect.getsource(cls._collect if issubclass(cls, Collector) else cls._analyze)
    if not issubclass(cls, Collector):
        for name, value in cls.__dict__.items():
            if name.startswith('_') and isinstance(value, property) and value.fget is not None:
                source += inspect.getsource(value.fget)
            elif name.startswith('_') and inspect.isfunction(value):
                source += inspect.getsource(value)
    return re.sub(r'\s+', ' ', source)


@pytest.mark.parametrize("cls", list(_components_with_config_parameters()))
def test_config_parameters_used_via_get_config_value(cls):
    source = _config_access_source(cls)
    for name in cls.config_parameters_definitions():
        if cls is analyzers.DriverVersionAnalyzer and name in {'minimum_version', 'latest_version'}:
            assert '_get_config_value(version_type' in source
            continue
        pattern = rf"_get_config_value\(\s*['\"]{re.escape(name)}['\"]"
        assert re.search(pattern, source), \
            f"{cls.__name__}.{name} must be read via _get_config_value() in runtime code"
