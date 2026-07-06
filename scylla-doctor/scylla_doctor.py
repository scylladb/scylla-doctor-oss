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
import re
import sys

from typing import Dict

from common import DictView, Paths, AbortedException
from collectors_base import CollectorStatus, CollectorResult, Collector
from analyzers_base import AnalyzerStatus, Analyzer
from common import read_config_file

import collectors
from models.output_entry import Level

from utils import Executor, Formatter


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

        # Detect and collect available Collectors instances
        for _, cls in inspect.getmembers(sys.modules[__name__], predicate=inspect.isclass):
            if not inspect.isabstract(cls) and issubclass(cls, Collector):
                collector = cls(self.environment.configuration, self.environment.paths)
                self.collectors[collector.id] = collector
        for _, cls in inspect.getmembers(sys.modules[collectors.__name__], predicate=inspect.isclass):
            if not inspect.isabstract(cls) and issubclass(cls, Collector):
                collector = cls(self.environment.configuration, self.environment.paths)
                self.collectors[collector.id] = collector

        # Try to load available Analyzer classes
        try:
            import analyzers
            for _, cls in inspect.getmembers(analyzers, predicate=inspect.isclass):
                if not inspect.isabstract(cls) and issubclass(cls, Analyzer):
                    analyzer = cls(self.environment.configuration)
                    self.analyzers[analyzer.id] = analyzer
        except ModuleNotFoundError:
            pass

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

        formatter.print_table_checkup_header("Data analysis", file=file)
        for name, analyzer in self.analyzers.items():
            if name_matcher.match(name) and analyzer.executed:
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

    def run_analyzers(self):
        # Verify that vitals and SD versions match before checking anything else
        vitals_version_verifier = self.analyzers.get('SDVersionAnalyzer')
        vitals_version_collector = self.collectors.get('SDVersionCollector')
        if (vitals_version_collector and vitals_version_collector.run and
                vitals_version_verifier and vitals_version_verifier.run):
            vitals_version_verifier.analyze(self.vitals)
            if vitals_version_verifier.status != AnalyzerStatus.PASSED:
                print(vitals_version_verifier.message)
                raise Exception("Vitals version mismatch. Use a correct Scylla Doctor version.")

        for analyzer in self.analyzers.values():
            analyzer.analyze(self.vitals)
            if analyzer.status == AnalyzerStatus.FAILED:
                if self.environment.args.abort_on_first_error:
                    raise AbortedException

    def save_vitals(self, file_name="vitals.json"):
        with open(file_name, 'w') as f:
            json.dump(self.vitals, f, cls=CollectorResult.Encoder)

    def load_vitals(self, file_name="vitals.json"):
        with open(file_name, 'r') as f:
            vitals_json = json.load(f)
            for collector, result in vitals_json.items():
                # If this specific collector is known and skipped - don't load its value from Vitals
                collector_instance = self.collectors.get(collector)
                if collector_instance and not collector_instance.run:
                    continue

                self.vitals[collector] = CollectorResult.decode(result)

    @property
    def version_collector_name(self) -> str:
        return "SDVersionCollector"

    @property
    def version(self) -> str:
        """
        Scylla Doctor version is one of the Vitals, and we use it to make sure that the tool version used to collect
        Vitals matches a version of the tool used to analyze them.
        Hence, we have a dedicated Collector that reads a version information from a 'version' file.
        :return: a version string
        """
        if self.version_collector_name not in self.collectors:
            raise Exception(f"{self.version_collector_name} is missing. Version can't be identified!")

        version_collector = self.collectors[self.version_collector_name]
        if version_collector.id not in self.vitals:
            version_collector.collect(self.vitals, self.collectors)

        if self.vitals[version_collector.id].status != CollectorStatus.PASSED:
            raise Exception(f"Collector {version_collector.id} failed. Version can't be read. "
                            f"Run 'make version' if a 'version' file is missing' and make sure "
                            f"{self.version_collector_name} is not disabled.")

        return self.vitals[version_collector.id].data['version']

    def run(self):
        self.vitals = dict()

        try:
            if self.environment.args.version:
                # Print a version string and exit
                print(f"version: {self.version}")
                sys.exit(0)

            if not self.environment.args.load_vitals:
                self.run_collectors()
            else:
                self.load_vitals(self.environment.args.load_vitals)

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
        self.__parser.add_argument('--output', default=DoctorOutputFormat.FULL, type=DoctorOutputFormat,
                                   choices=list(DoctorOutputFormat),
                                   help="Give out full human-readable report, short launch log, or machine-readable analyzers output for further processing")  # noqa: E501
        self.__parser.add_argument('--print-filter', default=".*",
                                   help="Regular expression filter to apply to Collectors and Analyzers names before printing. Print only those which name matches.")  # noqa: E501
        self.__parser.add_argument('--version', help="Print a version information", action="store_true")

        self.__parser.epilog = "Collectors:\n"
        # Detect and collect available Collectors instances
        for collector_source in [sys.modules[__name__], sys.modules[collectors.__name__]]:
            for _, cls in inspect.getmembers(collector_source, predicate=inspect.isclass):
                if not inspect.isabstract(cls) and issubclass(cls, Collector):
                    self.__parser.epilog += f"{cls.__name__} - " \
                                            f"{cls.__doc__ or cls({}, Paths({})).name or 'no description'}\n"

        # Try to load available Analyzer classes
        try:
            import analyzers
            self.__parser.epilog += "\nAnalyzers:\n"
            for _, cls in inspect.getmembers(analyzers, predicate=inspect.isclass):
                if not inspect.isabstract(cls) and issubclass(cls, Analyzer):
                    s = getattr(cls, '_analyze')
                    self.__parser.epilog += f"{cls.__name__} - {str(s.__doc__).strip()}\n"
        except ModuleNotFoundError:
            pass

        self.args = self.__parser.parse_args(args)

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

    # Run checkups
    doctor.run()

    # Show results
    doctor.print_results(doctor_env.args.output)


if __name__ == '__main__':
    main()
