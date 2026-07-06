#!/usr/bin/env python3
# Copyright (C) 2021-present ScyllaDB
#
# This file is part of Scylla Doctor.
#
# Scylla Doctor Cluster is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Scylla Doctor Cluster is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Scylla Doctor.  If not, see <http://www.gnu.org/licenses/>.
"""
Scylla Doctor for Scylla Cluster
"""

import argparse
import ast
import enum
import glob
import io
import json
import numbers
import os
import sys
import zipfile
from typing import List, Optional

from deepdiff import DeepDiff

from collections.abc import Iterable


class ConfigurationError(Exception):
    pass

class DoctorClusterOutputFormat(enum.Enum):
    TXT = "txt"
    JSON = "json"

    def __str__(self):
        return self.value


class Configuration:
    """
    Parse command line options and a configuration file if provided
    """
    def __init__(self):
        self.__skipped_analyzers = set()
        self.__excluded_from_diff_collectors = set()
        self.__max_normalised_diff_percent = 0
        self.__per_collector_config = {}
        self.__section_option_value_list = []
        self.__args = None

        self.__setup_command_line_parser()
        self.__set_scylla_doctor_path()
        self.__parse_config_file()
        self.__parse_command_line_args()

# Public methods
    @property
    def output_format(self) -> DoctorClusterOutputFormat:
        return self.__args.output

    @property
    def excluded_from_diff_collectors(self):
        return self.__excluded_from_diff_collectors

    @property
    def skipped_analyzers(self):
        return self.__skipped_analyzers

    @property
    def scylla_doctor_configuration_file_name(self):
        return self.__args.sd_config_file

    @property
    def max_normalised_diff_percent(self):
        return self.__max_normalised_diff_percent

    @property
    def path_to_vitals(self):
        """
        Directory where Vitals JSON files are located
        """
        if not self.__args.dir:
            raise ConfigurationError("Bad configuration: a vitals directory wasn't provided!")

        return self.__args.dir

    @property
    def section_option_value_list(self):
        return self.__section_option_value_list

    def collector_options(self, collector_name):
        return self.__per_collector_config.get(collector_name)

    def print_version(self) -> bool:
        return self.__args.version

# Private methods
    @staticmethod
    def __section_option_value(tuple_str):
        try:
            section, option, value = tuple_str.split(',', 2)
            return section, option, value
        except Exception as e:
            raise argparse.ArgumentTypeError(f"{e}: value must be as: section_name,option_name,[value_name]")

    def __setup_command_line_parser(self):
        ###############################################################################
        # Arguments ###################################################################
        ###############################################################################
        parser = argparse.ArgumentParser(description="Scylla Doctor Cluster")
        parser.add_argument("--dir", help="Folder with Scylla Doctor outputs from cluster nodes")
        parser.add_argument("--scylla-doctor-path", help="Folder with Scylla Doctor library")
        parser.add_argument("--config-file", help="Configuration file")
        parser.add_argument("--sd-config-file", help="Scylla Doctor configuration file")
        parser.add_argument("-sov", "--section-option-value", action="append",
                            type=Configuration.__section_option_value, default=[],
                            help="set the section option value using SECTION_NAME,OPTION_NAME,[VALUE]")
        parser.add_argument('--output', default=DoctorClusterOutputFormat.TXT,
                            type=DoctorClusterOutputFormat, choices=list(DoctorClusterOutputFormat),
                            help="Output format: 'txt' (human-readable) or 'json'. 'txt' is a default format")
        parser.add_argument('--version', help="Print a version information", action="store_true")

        self.__args = parser.parse_args()

    def __parse_command_line_args(self):
        self.__parse_section_option_value()

    def __parse_section_option_value(self):
        for section, option, value in self.__args.section_option_value:
            if section == self.__exclude_from_diff_section_name:
                self.__add_excluded_from_diff([option])
            elif section == self.__skip_test_section_name:
                self.__add_skipped_tests([option])
            elif section == self.__general_section_name:
                if option == self.__max_normalised_diff_percent_key and value:
                    self.__max_normalised_diff_percent = float(value)
            elif option in self.__supported_per_collector_options:
                # Per-collector sections

                value_to_set = None
                if value:
                    value_to_set = ast.literal_eval(value)

                self.__per_collector_config.setdefault(section, {})[option] = value_to_set
            else:
                # General section-option-value to be passed to Scylla Doctor
                self.__section_option_value_list.extend(["--section-option-value", ','.join([section, option, value])])

    def __set_scylla_doctor_path(self):
        """
        Add a Scylla Doctor modules location to a sys.path when appropriate:
          - If we are NOT executed as a self-contained archive - in this case Scylla Doctor modules are going to be
            packaged inside the archive.
          - If --scylla-doctor-path is provided use a given value.
          - Otherwise, use a <location of scylla_doctor_cluster.py>/../scylla-doctor as a Scylla Doctor modules
            location.
        """
        script_name = sys.argv[0]
        scylla_doctor_path = self.__args.scylla_doctor_path

        if not scylla_doctor_path and not zipfile.is_zipfile(script_name):
            scylla_doctor_path = os.path.join(os.path.dirname(os.path.realpath(script_name)), "../scylla-doctor")

        if scylla_doctor_path:
            sys.path.append(scylla_doctor_path)

    def __parse_config_file(self):
        # If configuration file name is not provided there is nothing to do here
        if not self.__args.config_file:
            return

        from common import read_config_file
        config = read_config_file(self.__args.config_file, allow_no_value=True)

        for s in config.sections():
            # Parse 'ExcludeFromDiff' section fields
            if s == self.__exclude_from_diff_section_name:
                self.__add_excluded_from_diff([it[0] for it in config.items(self.__exclude_from_diff_section_name)])

            # Parse 'SkipTest' section fields
            elif s == self.__skip_test_section_name:
                self.__add_skipped_tests([it[0] for it in config.items(self.__skip_test_section_name)])

            # Parse 'General' section fields
            elif s == self.__general_section_name:
                if config.has_option(s, self.__max_normalised_diff_percent_key):
                    self.__max_normalised_diff_percent = (
                        float(config.getfloat(s, self.__max_normalised_diff_percent_key)))

            # Parse per-collector configuration
            else:
                for o in config.options(s):
                    if o in self.__supported_per_collector_options:
                        val = config.get(s, o)
                        value_to_set = None
                        if val:
                            value_to_set = ast.literal_eval(val)

                        self.__per_collector_config.setdefault(s, {})[o] = value_to_set
                    else:
                        self.__section_option_value_list.extend(
                            ["--section-option-value", ','.join([s, o, config.get(s, o)])])

    def __add_excluded_from_diff(self, collectors_to_exclude: Iterable):
        """
        Append a list of Collectors that need to be excluded from diff calculation to a corresponding list.
        :param collectors_to_exclude: an iterable of Collectors names
        """
        self.__excluded_from_diff_collectors |= set(collectors_to_exclude)

    def __add_skipped_tests(self, analyzers_to_skip: Iterable):
        """
        Append a list of Analyzers that need to be skipped to a corresponding list.
        :param analyzers_to_skip: an iterable of Analyzers names
        """
        self.__skipped_analyzers |= set(analyzers_to_skip)

    @property
    def __general_section_name(self):
        return "General"

    @property
    def __exclude_from_diff_section_name(self):
        return "ExcludeFromDiff"

    @property
    def __skip_test_section_name(self):
        return "SkipTest"

    @property
    def __max_normalised_diff_percent_key(self):
        return "max_normalised_diff_percent"

    @property
    def __supported_per_collector_options(self):
        return ['mask']


###############################################################################
# Functions ###################################################################
###############################################################################
def remove_key(container, key):
    """
    Remove key occurrences from a dict on all levels.
    """
    if type(container) is dict:
        if key in container:
            del container[key]
        for v in container.values():
            remove_key(v, key)
    if type(container) is list:
        for v in container:
            remove_key(v, key)


def strip_similar(deep_diff, max_normalised_diff_percent=0):
    # throw away negligible differences between numeric values
    for k, v in list(deep_diff.items()):
        if k != "values_changed":
            continue
        for path, details in list(v.items()):
            new, old = details['new_value'], details['old_value']
            if isinstance(old, numbers.Number) \
                    and isinstance(old, numbers.Number) \
                    and abs((new - old) / (max(new, old))) < max_normalised_diff_percent / 100.:
                del v[path]
        if not v:
            del deep_diff[k]


def check_vitals(node, vitals, base_node, base_vitals, config: Configuration, failures, inconsistencies):
    """
    Search vitals for failed collectors and inconsistencies
    """
    from collectors_base import CollectorStatus, CollectorResult, Output
    from models.output_entry import OutputEntry

    custom_encoder = CollectorResult.Encoder()

    default_mapping = {
        OutputEntry: custom_encoder.default,
        Output: custom_encoder.default,
        CollectorStatus: custom_encoder.default,
    }

    for name, result in vitals.items():
        # look for failed collectors
        if result.status == CollectorStatus.FAILED:
            if name not in failures:
                failures[name] = {}
            if result.message not in failures[name]:
                failures[name][result.message] = []
            failures[name][result.message].append(node)

        if name not in config.excluded_from_diff_collectors:
            diff = json.loads(DeepDiff(result.strip(), base_vitals[name].strip(),
                                       get_deep_distance=True).to_json(default_mapping=default_mapping))
            strip_similar(diff, config.max_normalised_diff_percent)
            remove_key(diff, "deep_distance")
            if diff:
                if name not in inconsistencies:
                    inconsistencies[name] = []
                inconsistencies[name].append([base_node, node, diff])


def run_doctor(config: Configuration,
               vitals_file: Optional[str] = None,
               additional_args: Optional[List[str]] = None) -> "scylla_doctor.Doctor":
    """
    Run a Scylla Doctor instance with a given configuration.
    :param config: Configuration object with configuration file, command line options and environment variables
    :param vitals_file: Optional Vitals file that should be loaded and analyzed
    :param additional_args: Optional additional Scylla Doctor parameters
    :return: Doctor class object with the result of the Scylla Doctor execution
    """
    import scylla_doctor

    if additional_args is None:
        additional_args = []

    doctor_args = []
    if vitals_file:
        doctor_args.extend(["--load-vitals", vitals_file])

    for skipped_test in config.skipped_analyzers:
        doctor_args.extend(['--skip-test', skipped_test])

    if config.scylla_doctor_configuration_file_name:
        doctor_args.extend(["--configuration-file", config.scylla_doctor_configuration_file_name])

    doctor_args.extend(config.section_option_value_list)
    doctor_args.extend(additional_args)

    doctor_env = scylla_doctor.DoctorEnvironment(doctor_args)
    doctor = scylla_doctor.Doctor(doctor_env)
    doctor.run()

    return doctor


def analyze_file(file, node, config: Configuration, failures, warnings):
    """
    Run scylla doctor analyzers against vitals file. Look for failures and warnings
    """
    import scylla_doctor
    from analyzers_base import AnalyzerStatus

    doctor = run_doctor(config=config, vitals_file=file)
    with io.StringIO() as f:
        doctor.print_results(format=scylla_doctor.DoctorOutputFormat.JSON, file=f)
        analyzers = json.loads(f.getvalue())

        for name, result in analyzers.items():
            if result['status'] == AnalyzerStatus.FAILED.value:
                if name not in failures:
                    failures[name] = {}
                if result['message'] not in failures[name]:
                    failures[name][result['message']] = []
                failures[name][result['message']].append(node)

            if result['status'] == AnalyzerStatus.WARNING.value:
                if name not in warnings:
                    warnings[name] = {}
                if result['message'] not in warnings[name]:
                    warnings[name][result['message']] = []
                warnings[name][result['message']].append(node)


def analyze_cluster(config: Configuration):
    """
    Check vitals gathered from Scylla Cluster. Look for failed collectors and analyzers, warnings and inconsistencies
    """
    from collectors_base import CollectorResult

    failures = {}  # map of {'check_name': {'exact_failure_message': ['array_of_nodes_with_that_message']}}
    warnings = {}  # map of {'check_name': {'exact_warning_message': ['array_of_nodes_with_that_message']}}
    inconsistencies = {}  # array of tuples [(node1, node2, prettydiff_generated_by_jsondiff)]
    base_node, base_vitals = None, None
    files = sorted(glob.glob(f"{config.path_to_vitals}/*.vitals.json"))

    if not files:
        raise ValueError(f"No detected vitals in the specified directory '{config.path_to_vitals}'.\n"
                         f"Verify that the directory is correct, and that the files have the '.vitals.json' extension.")

    for file in files:
        node = os.path.basename(file).split('.vitals.json')[0]

        # search vitals for failed collectors and inconsistencies
        with open(file, 'r') as vitals_file:
            vitals = {}
            for k, v in json.load(vitals_file).items():
                extra_mask = None
                if config.collector_options(k):
                    extra_mask = config.collector_options(k).get('mask')
                vitals[k] = CollectorResult.decode(v, extra_mask=extra_mask)

            if not base_vitals:
                base_node, base_vitals = node, vitals
            check_vitals(node, vitals, base_node, base_vitals, config, failures, inconsistencies)

        analyze_file(file, node, config, failures, warnings)

    return files, failures, warnings, inconsistencies


def print_results(config: Configuration, vitals: List[str], failures, warnings, inconsistencies):
    if config.output_format == DoctorClusterOutputFormat.TXT:
        print_human_readable_results(vitals, failures, warnings, inconsistencies)
    else:  # JSON
        print_json_results(vitals, failures, warnings, inconsistencies)


def print_json_results(vitals: List[str], failures, warnings, inconsistencies):
    """
    Generate report in a JSON format.
    """

    res = {'vitals': vitals, 'failures': failures, 'warnings': warnings, 'inconsistencies': inconsistencies}
    print(json.dumps(res, indent=4))


def print_human_readable_results(vitals: List[str], failures, warnings, inconsistencies):
    """
    Generate human-readable report. Arrange info in the following order:
     - failed collectors and analyzers
     - warnings issued by analyzers
     - inconsistencies between nodes vitals
    """
    print(f"{len(vitals)} vitals, {len(failures)} failed, {len(warnings)} warnings, "
          f"{len(inconsistencies)} inconsistencies")

    print(f"\nFailed: {len(failures)} total")
    for name, data in failures.items():
        total_nodes = sum([len(nodes) for nodes in data.values()])
        print(f"{name}: {total_nodes} nodes")
        for message, nodes in data.items():
            print(f" - {message} ({nodes})")

    print(f"\nWarnings: {len(warnings)} total")
    for name, data in warnings.items():
        total_nodes = sum([len(nodes) for nodes in data
                          .values()])
        print(f"{name}: {total_nodes} nodes")
        for message, nodes in data.items():
            print(f" - {message} ({nodes})")

    print(f"\nInconsistencies: {len(inconsistencies)} total")
    for name, data in inconsistencies.items():
        print(f"{name}:")
        for message in data:
            print(f" - {message[0]} \n   {message[1]} \n{json.dumps(message[2], indent=4)}")

    print(f"\nVitals files: {len(vitals)} total")
    for vitals_file_name in vitals:
        print(f" - {vitals_file_name}")


def print_version(config: Configuration):
    run_doctor(config=config, additional_args=["--version"])


###############################################################################
# Entry point #################################################################
###############################################################################
def main():
    try:
        config = Configuration()
        if config.print_version():
            print_version(config)
            sys.exit(0)

        vitals, failures, warnings, inconsistencies = analyze_cluster(config)
        print_results(config, vitals, failures, warnings, inconsistencies)

        # exit code 1 if any problems were found with the report
        sys.exit(0 if sum([len(x) for x in [failures, warnings, inconsistencies]]) == 0 else 1)
    except Exception as e:
        sys.exit(f"{e}")


if __name__ == "__main__":
    main()

