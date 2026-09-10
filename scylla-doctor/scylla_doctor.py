#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright (C) 2021-present ScyllaDB
#

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


###############################################################################
# Modules #####################################################################
###############################################################################
import argparse
import configparser
import enum
import inspect
import json
import os
import re
import sys
import zipfile

from typing import Dict, Optional, Tuple, Union

from common import DictView, Paths, AbortedException, ConfigParameter
from collectors_base import CollectorStatus, CollectorResult, Collector
from analyzers_base import AnalyzerStatus, Analyzer
from common import read_config_file

import collectors
from models.output_entry import Level

from utils import Executor, Formatter, memoize


###############################################################################
# Class discovery cache #######################################################
###############################################################################
@memoize
def _discover_classes() -> Tuple[Tuple, Tuple]:
    """Discover collector/analyzer classes once per process. Returns immutable tuples."""
    collectors_list = []
    for _, cls in inspect.getmembers(sys.modules[__name__], predicate=inspect.isclass):
        if not inspect.isabstract(cls) and issubclass(cls, Collector):
            collectors_list.append(cls)
    for _, cls in inspect.getmembers(sys.modules[collectors.__name__], predicate=inspect.isclass):
        if not inspect.isabstract(cls) and issubclass(cls, Collector):
            collectors_list.append(cls)

    analyzers_list = []
    try:
        import analyzers
        for _, cls in inspect.getmembers(analyzers, predicate=inspect.isclass):
            if not inspect.isabstract(cls) and issubclass(cls, Analyzer):
                analyzers_list.append(cls)
    except ModuleNotFoundError:
        pass

    return tuple(collectors_list), tuple(analyzers_list)


###############################################################################
# Class: Doctor ###############################################################
###############################################################################
class DoctorOutputFormat(enum.Enum):
    FULL = "full"
    SHORT = "short"
    JSON = "json"

    def __str__(self):
        return self.value


class Doctor:
    vitals: Dict[str, CollectorResult]
    collectors: Dict[str, Collector]
    analyzers: Dict[str, Analyzer]

    def __init__(self, environment) -> None:
        self.environment = environment
        self.vitals = dict()
        self.collectors = dict()
        self.analyzers = dict()

        collector_classes, analyzer_classes = _discover_classes()
        store_output = self.should_store_output()

        for cls in collector_classes:
            collector = cls(self.environment.configuration, self.environment.paths)
            collector.set_store_output(store_output)
            self.collectors[collector.id] = collector

        for cls in analyzer_classes:
            analyzer = cls(self.environment.configuration)
            self.analyzers[analyzer.id] = analyzer

    def should_store_output(self) -> bool:
        """Whether collectors retain Output entries in memory (print and/or save)."""
        args = self.environment.args
        return bool(args.verbose or args.detailed or self.include_output_in_vitals())

    def include_output_in_vitals(self) -> bool:
        """Global only: --include-output or [General] include_output."""
        if self.environment.args.include_output:
            return True
        val = self.environment.get_config_parameter('General', 'include_output')
        return bool(val and val.lower() in ("1", "yes", "true", "on"))

    def print_results(self, format=DoctorOutputFormat.FULL, file=None):
        """
        Print results on screen
        """

        if format == DoctorOutputFormat.JSON:
            print(json.dumps({
                name: {
                    'description': analyzer.name,
                    'status': analyzer.status.value,  # type: ignore
                    'message': analyzer.message
                }
                for name, analyzer in self.analyzers.items()}, indent=4), file=file)
            return

        if format == DoctorOutputFormat.SHORT:
            print("Scylla Doctor launched successfully", file=file)
            print(f"{len(self.collectors)} collectors launched", file=file)
            if self.environment.args.save_vitals:
                print(f"Vitals saved to {self.environment.args.save_vitals}", file=file)
            return

        formatter = Formatter()

        formatter.print_logo(file=file)
        formatter.print_table_header(file=file)

        level = Level.DEFAULT
        if self.environment.args.verbose:
            level = Level.VERBOSE
        elif self.environment.args.detailed:
            level = Level.DETAILED

        name_matcher = re.compile(self.environment.args.print_filter)

        formatter.print_table_checkup_header("Data collection", file=file)
        for name, collector in self.collectors.items():
            if not name_matcher.match(name) or name not in self.vitals:
                continue
            result = self.vitals[name]
            formatter.print_table_test_row(f"{name}: {collector.name}",
                                           result.status.name, result.message, file=file)
            for entry in result.output:
                if entry.level <= level:
                    formatter.print_output_entry(entry, file=file)

        analyzers_to_print = [
            (name, analyzer)
            for name, analyzer in self.analyzers.items()
            if name_matcher.match(name) and analyzer.executed
        ]
        if analyzers_to_print:
            formatter.print_table_checkup_header("Data analysis", file=file)
            for name, analyzer in analyzers_to_print:
                formatter.print_table_test_row(f"{name}: {analyzer.name}", analyzer.status.name, analyzer.message,
                                               file=file)

    def run_collectors(self):
        for collector in self.collectors.values():
            if self.environment.args.verbose:
                print(f"Running {collector.name}...")

            collector.collect(self.vitals, self.collectors)
            status = self.vitals[collector.id].status
            if status == CollectorStatus.FAILED:
                if self.environment.args.abort_on_first_error:
                    raise AbortedException(f'Collector {collector.id} failed')

    @staticmethod
    def read_vitals_version_from_json(vitals_json: dict) -> str:
        if 'SDVersionCollector' not in vitals_json:
            raise Exception("Vitals file does not contain SDVersionCollector data.")

        result = CollectorResult.decode(vitals_json['SDVersionCollector'])
        if result.status != CollectorStatus.PASSED:
            raise Exception(f"SDVersionCollector failed in vitals file: {result.message}")

        version = result.data.get('version')
        if not version:
            raise Exception("Vitals file does not contain a version value.")

        return version

    @staticmethod
    def read_vitals_file_version(file_name: str) -> str:
        with open(file_name, 'r') as f:
            vitals_json = json.load(f)

        return Doctor.read_vitals_version_from_json(vitals_json)

    def verify_vitals_version(self) -> None:
        if self.environment.args.ignore_vitals_version or not self.environment.args.load_vitals:
            return

        vitals_version = self.read_vitals_file_version(self.environment.args.load_vitals)
        self._verify_vitals_version(vitals_version)

    def verify_loaded_vitals_version(self, vitals: Dict[str, CollectorResult]) -> None:
        """
        Version check for the in-memory (analyze_vitals) path, mirroring verify_vitals_version() which
        reads the version straight from the vitals file. 'vitals' is the full, unfiltered decoded mapping.
        """
        if self.environment.args.ignore_vitals_version:
            return

        version_result = vitals.get('SDVersionCollector')
        if version_result is None:
            raise Exception("Vitals do not contain SDVersionCollector data.")
        if version_result.status != CollectorStatus.PASSED:
            raise Exception(f"SDVersionCollector failed in vitals: {version_result.message}")
        vitals_version = version_result.data.get('version')
        if not vitals_version:
            raise Exception("Vitals do not contain a version value.")

        self._verify_vitals_version(vitals_version)

    def _verify_vitals_version(self, vitals_version: str) -> None:
        tool_version = self.read_tool_version()
        if vitals_version == tool_version:
            return

        print(f"Version mismatch: collected: {vitals_version} analyzer: {tool_version}")
        print("Vitals version mismatch. Use a correct Scylla Doctor version.")
        sys.exit(1)

    def run_analyzers(self):
        for analyzer in self.analyzers.values():
            analyzer.analyze(self.vitals)
            if analyzer.status == AnalyzerStatus.FAILED:
                if self.environment.args.abort_on_first_error:
                    raise AbortedException

    def save_vitals(self, file_name="vitals.json"):
        with open(file_name, 'w') as f:
            json.dump(
                self.vitals,
                f,
                cls=CollectorResult.Encoder,
                include_output=self.include_output_in_vitals(),
            )

    def _should_load_collector(self, collector) -> bool:
        # If this specific collector is known and skipped - don't load its value from Vitals
        collector_instance = self.collectors.get(collector)
        return not (collector_instance and not collector_instance.run)

    def load_vitals(self, file_name="vitals.json"):
        with open(file_name, 'r') as f:
            vitals_json = json.load(f)
            for collector, result in vitals_json.items():
                if not self._should_load_collector(collector):
                    continue

                self.vitals[collector] = CollectorResult.decode(result)

    @staticmethod
    def read_tool_version() -> str:
        script_path = os.path.dirname(collectors.__file__)
        verfile_name = 'version'
        if zipfile.is_zipfile(script_path):
            try:
                with zipfile.ZipFile(script_path, 'r') as archive:
                    return archive.read(verfile_name).decode().strip()
            except Exception as e:
                raise Exception(f"Failed to read version data: {e}. Please, report!")

        buildversion = os.path.join(script_path, verfile_name)
        if os.path.isfile(buildversion):
            with open(buildversion) as f:
                return f.readline().strip()

        raise Exception("Couldn't find SD version file, did you run 'make version' ?")

    def set_vitals(self, vitals: Dict[str, CollectorResult]):
        """
        Populate vitals from an already-decoded, in-memory mapping instead of reading them from disk.
        Applies the same skip filtering as load_vitals. This lets callers that already hold decoded
        vitals (e.g. the cluster runner) reuse them for analysis without re-parsing the file.
        """
        for collector, result in vitals.items():
            if not self._should_load_collector(collector):
                continue

            self.vitals[collector] = result

    def analyze_vitals(self, vitals: Dict[str, CollectorResult]):
        """
        Run analyzers against pre-loaded, in-memory vitals, skipping the collection step entirely.
        This mirrors the load-vitals path of run(), including the vitals/tool version check.
        """
        self.vitals = dict()
        self.set_vitals(vitals)
        self.verify_loaded_vitals_version(vitals)
        try:
            self.run_analyzers()
        except AbortedException as e:
            print(f'Execution aborted: {str(e)}')

    @property
    def version(self) -> str:
        """
        Return the running Scylla Doctor version from the version file.
        """
        return self.read_tool_version()

    @staticmethod
    def general_config_parameters() -> Dict[str, ConfigParameter]:
        return {
            'include_output': ConfigParameter(
                description=(
                    'Set to 1/yes/true/on to include collector output arrays in --save-vitals JSON. '
                    'Also --include-output. Unset omits output to save space.'
                ),
                default_description='unset (omitted)',
            ),
        }

    def config_parameters(self, section: Optional[str] = None) -> Dict[str, Dict[str, ConfigParameter]]:
        """
        Return configuration parameters and defaults for collectors and analyzers.
        :param section: Optional component class name, or ``General``. When set, return only that section.
        """
        general = self.general_config_parameters()
        components: Dict[str, Union[Collector, Analyzer]] = {}

        for name in sorted(self.collectors.keys()):
            components[name] = self.collectors[name]
        for name in sorted(self.analyzers.keys()):
            components[name] = self.analyzers[name]

        if section is not None:
            if section == 'General':
                return {'General': general}
            if section not in components:
                raise ValueError(f"Unknown section: {section}")
            return {section: components[section].config_parameters}

        result: Dict[str, Dict[str, ConfigParameter]] = {'General': general}
        for name, component in components.items():
            if not type(component).config_parameters_definitions():
                continue
            result[name] = component.config_parameters
        return result

    def print_config_parameters(self,
                                section: Optional[str] = None,
                                as_json: bool = False,
                                file=None) -> None:
        parameters = self.config_parameters(section)

        if as_json:
            payload: Dict[str, Dict[str, Dict[str, Optional[str]]]] = {}
            for section_name, section_params in parameters.items():
                payload[section_name] = {}
                for param_name, param in section_params.items():
                    entry: Dict[str, Optional[str]] = {
                        'description': param.description,
                        'default': param.default,
                        'default_description': param.default_description,
                        'type': param.runtime_type_name(),
                        'unit': param.unit,
                    }
                    payload[section_name][param_name] = entry
            print(json.dumps(payload, indent=4), file=file)
            return

        for section_name, section_params in parameters.items():
            print(f"[{section_name}]", file=file)
            for param_name, param in section_params.items():
                print(f"  {param_name} (default: {param.display_default()})", file=file)
                print(f"    {param.description}", file=file)
            print(file=file)

    def run(self):
        self.vitals = dict()

        try:
            if self.environment.args.version:
                print(f"version: {self.version}")
                sys.exit(0)

            if self.environment.args.vitals_version:
                print(f"version: {self.read_vitals_file_version(self.environment.args.vitals_version)}")
                sys.exit(0)

            if not self.environment.args.load_vitals:
                self.run_collectors()
            else:
                self.load_vitals(self.environment.args.load_vitals)
                self.verify_vitals_version()

            if self.environment.args.save_vitals:
                self.save_vitals(self.environment.args.save_vitals)
            self.run_analyzers()
        except AbortedException as e:
            print(f'Execution aborted: {str(e)}')


################################################################################
# Main #########################################################################
################################################################################

###############################################################################
# Arguments and configurations ################################################
###############################################################################
# Functions
def section_option_value(tuple):
    try:
        section, option, value = tuple.split(',', 2)
        return section, option, value
    except Exception:
        raise argparse.ArgumentTypeError("value must be as: section_name,option_name,value_name")


class DoctorEnvironment:
    def __init__(self, args=None):
        self.load_arguments(args)
        self.load_configurations()
        self.init_paths()

    def load_arguments(self, args):
        self.__parser = argparse.ArgumentParser(description="Scylla Doctor",
                                                formatter_class=argparse.RawDescriptionHelpFormatter)
        self.__parser.add_argument("-aofe", "--abort-on-first-error", help="abort when the first error happens",
                                   action="store_true")
        self.__parser.add_argument("-cf", "--configuration-file", help="use a specific "
                                                                       "configuration file")
        group1 = self.__parser.add_mutually_exclusive_group()
        group1.add_argument("-d", "--detailed", help="show extra information "
                                                     "(if available)", action="store_true")
        group1.add_argument("-v", "--verbose", help="show all information gathered",
                            action="store_true")
        self.__parser.add_argument("-sov", "--section-option-value", action="append", type=section_option_value,
                                   default=[],
                                   help="set the section option value using SECTION_NAME,OPTION_NAME,VALUE_NAME")
        self.__parser.add_argument("-st", "--skip-test", action='append', help="skip test", default=[])

        self.__parser.add_argument('--save-vitals', nargs='?', default=None, const='vitals.json',
                                   help="After running collectors, store vitals in a file (vitals.json by default)")
        self.__parser.add_argument('--load-vitals', nargs='?', default=None, const='vitals.json',
                                   help="Instead of running Collectors, load vitals from file (vitals.json by default)")
        self.__parser.add_argument('--include-output', action='store_true',
                                   help="Include collector output arrays in --save-vitals JSON "
                                        "(omitted by default to save space; also [General] include_output)")
        self.__parser.add_argument('--output', default=DoctorOutputFormat.FULL, type=DoctorOutputFormat,
                                   choices=list(DoctorOutputFormat),
                                   help="Give out full human-readable report, short launch log, or machine-readable analyzers output for further processing")  # noqa: E501
        self.__parser.add_argument('--print-filter', default=".*",
                                   help="Regular expression filter to apply to Collectors and Analyzers names before printing. Print only those which name matches.")  # noqa: E501
        self.__parser.add_argument('--version', help="Print Scylla Doctor version and exit", action="store_true")
        self.__parser.add_argument('--list-parameters', nargs='?', const='', default=None, metavar='SECTION',
                                   help="Print configuration parameters and defaults. "
                                        "Optional SECTION limits output to General or one collector/analyzer.")
        self.__parser.add_argument('--list-parameters-json', action='store_true',
                                   help="Output --list-parameters as JSON (implies --list-parameters)")
        self.__parser.add_argument('--vitals-version', nargs='?', default=None, const='vitals.json',
                                   help="Print version stored in a vitals file (vitals.json by default) and exit")
        self.__parser.add_argument('--ignore-vitals-version', help="Skip vitals version compatibility check",
                                   action="store_true")

        self._build_epilog()

        self.args = self.__parser.parse_args(args)

    def _build_epilog(self):
        collector_classes, analyzer_classes = _discover_classes()
        self.__parser.epilog = "Collectors:\n"
        for cls in collector_classes:
            self.__parser.epilog += f"{cls.__name__} - " \
                                    f"{cls.__doc__ or cls({}, Paths({})).name or 'no description'}\n"
        if analyzer_classes:
            self.__parser.epilog += "\nAnalyzers:\n"
            for cls in analyzer_classes:
                s = getattr(cls, '_analyze')
                self.__parser.epilog += f"{cls.__name__} - {str(s.__doc__).strip()}\n"

    def load_configurations(self):
        """
        Load configurations from file
        """
        self.__configurations = configparser.ConfigParser()
        if self.args.configuration_file:
            self.__configurations = read_config_file(self.args.configuration_file)

        # Sanity check: validate command line and config file
        for skipped_test in self.args.skip_test:
            self.set_config_parameter(skipped_test, "run", "no")

        for test, option, value in self.args.section_option_value:
            self.set_config_parameter(test, option, value)

    @property
    def configuration(self):
        return DictView(self.__configurations)

    def get_config_parameter(self, section_name, parameter_name):
        """
        Get test's specific parameter
        """

        if self.__configurations.has_option(section_name, parameter_name):
            return self.__configurations[section_name][parameter_name]

        return None

    def set_config_parameter(self, section_name, parameter_name, parameter_value):
        """
        Set sections's specific parameter
        """

        if not parameter_value:
            raise Exception("Value cannot be empty")

        if section_name not in self.__configurations:
            self.__configurations[section_name] = {}

        self.__configurations[section_name][parameter_name] = parameter_value

    def get_config_section(self, section_name):
        if section_name not in self.__configurations:
            self.__configurations[section_name] = {}
        return self.__configurations[section_name]

    def init_paths(self):
        # Scylla default directories
        scylla_directory = self.get_config_parameter("DefaultPaths", "scylla_directory") or "/opt/scylladb"
        self.set_config_parameter("Paths", "scylla_directory", scylla_directory)

        scylla_directory_config = self.get_config_parameter("DefaultPaths", "scylla_directory_config") or "/etc/scylla"
        self.set_config_parameter("Paths", "scylla_directory_config", scylla_directory_config)

        scylla_directory_configs = self.get_config_parameter("DefaultPaths", "scylla_directory_configs") or "/etc/scylla.d"  # noqa: E501
        self.set_config_parameter("Paths", 'scylla_directory_configs', scylla_directory_configs)

        scylla_directory_var = self.get_config_parameter("DefaultPaths", "scylla_directory_var") or "/var/lib/scylla"
        self.set_config_parameter("Paths", "scylla_directory_var", scylla_directory_var)

        self.set_config_parameter("Paths", "scylla_directory_bin", scylla_directory + "/bin")
        self.set_config_parameter("Paths", "scylla_directory_scripts", scylla_directory + "/scripts")
        self.set_config_parameter("Paths", "scylla_file_config", scylla_directory_config + "/scylla.yaml")

        self.paths = Paths(self.__configurations)


def main():
    doctor_env = DoctorEnvironment()

    Executor.cql_config = doctor_env.get_config_section("CQL")
    Executor.paths = doctor_env.get_config_section("Paths")

    # Start Scylla Doctor
    doctor = Doctor(doctor_env)

    if doctor_env.args.list_parameters is not None or doctor_env.args.list_parameters_json:
        section = doctor_env.args.list_parameters or None
        try:
            doctor.print_config_parameters(section, as_json=doctor_env.args.list_parameters_json)
        except ValueError as e:
            print(str(e), file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    # Run checkups
    doctor.run()

    # Show results
    doctor.print_results(doctor_env.args.output)


if __name__ == '__main__':
    main()
