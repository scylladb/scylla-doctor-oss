#!/usr/bin/env python3
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
import configparser
import dataclasses
import enum
import os

from typing import Any, Dict, Optional, Callable, Set, Type
from collections.abc import Mapping, Iterable

ENCODING = "UTF-8"

_CONFIG_VALUE_UNSET = object()


# Common static functions ################################
def read_config_file(config_file_name: str, allow_no_value=False) -> configparser.ConfigParser:
    """
    Try to parse a given configuration file.
    :param config_file_name: Configuration file name
    :param allow_no_value: See configparser.ConfigParser() allow_no_value parameter description
    :return: a ConfigParser object with the parsed configuration file content
    """
    try:
        configurations = configparser.ConfigParser(allow_no_value=allow_no_value)
        configurations.optionxform = lambda option: option  # type: ignore[assignment]
        if not os.path.isfile(config_file_name):
            raise FileNotFoundError(config_file_name)
        configurations.read(config_file_name)
        return configurations
    except configparser.DuplicateSectionError as cpe:
        raise Exception("Configuration file has the same section defined more than once") from cpe
    except configparser.DuplicateOptionError as cpe:
        raise Exception("Configuration file has an option defined more than once") from cpe
    except (configparser.MissingSectionHeaderError, configparser.ParsingError) as cpe:
        raise Exception("Configuration file seems to be broken") from cpe


class AbortedException(Exception):
    pass


class InvalidConfigurationException(Exception):
    pass


class NodePlatform(enum.Enum):
    CONTAINER = "container"
    VM = "virtual machine"
    BAREMETAL = "bare-metal"
    CLOUD = "cloud"


class GossipInfoInvariantValues(enum.IntEnum):
    """
    IDs of GossipInfo application_state entries that are supposed to have same values when collected on different nodes.
    """
    STATUS = 0,
    SCHEMA = 2,
    DC = 3,
    RACK = 4,
    RELEASE_VERSION = 5,
    NET_VERSION = 11,
    HOST_ID = 12,
    TOKENS = 13,              # Semicolon separated list
    SUPPORTED_FEATURES = 14,  # Coma separated list
    SCHEMA_TABLES_VERSION = 16,
    RPC_READY = 17,
    SHARD_COUNT = 19,
    IGNORE_MSB_BITS = 20,
    CDC_GENERATION_ID = 21,
    SNITCH_NAME = 22,


class DictView(Mapping):
    """
    Provides a best-effort read-only view on a dict.
    You can optionally specify a slice by passing a subset of keys that may be visible.
    """
    def __init__(self, source: Mapping, valid_keys: Optional[Iterable] = None):
        if not valid_keys:
            valid_keys = source.keys()

        self.__source = source
        self.__valid_keys = valid_keys

    def __getitem__(self, key):
        if key in self.__valid_keys and key in self.__source:
            return self.__source[key]
        else:
            raise KeyError(key)

    def __setitem__(self, key, value):
        raise Exception(f"Trying to alter read-only mapping for a key {key}")

    def __delitem__(self, key):
        raise Exception(f"Trying to alter read-only mapping for a key {key}")

    def __iter__(self):
        for key in self.__valid_keys:
            if key in self.__source:
                yield key

    def __len__(self):
        return len(set(self.__valid_keys) & set(self.__source.keys()))


class Paths(DictView):
    @property
    def section_name(self):
        return "Paths"

    def __init__(self, source):
        super().__init__(source[self.section_name] if self.section_name in source else {})


class HumanBytesUnitFormat(enum.IntEnum):
    """
    Human friendly format to print a bytes value.
    Enum values correspond to a divider to translate a value in kilobytes into a value corresponding to a specific
    format.
    """
    KiB = 1
    MiB = 1024
    GiB = 1024 * 1024
    TiB = 1024 * 1024 * 1024

    def __str__(self):
        return self.name

    @staticmethod
    def get_format_for_kib(value_in_kilobytes: int) -> "HumanBytesUnitFormat":
        """
        Select a human-friendly format for a value in kilobytes.
        :param value_in_kilobytes:
        :return: A format that would represent a given value as a number less or equal to 1024
        """
        if value_in_kilobytes < 1024:
            return HumanBytesUnitFormat.KiB
        elif value_in_kilobytes < 1024 * 1024:
            return HumanBytesUnitFormat.MiB
        elif value_in_kilobytes < 1024 * 1024 * 1024:
            return HumanBytesUnitFormat.GiB
        else:
            return HumanBytesUnitFormat.TiB

    def translate_kib(self, value_in_kilobytes: int) -> float:
        """
        :param value_in_kilobytes: value in kilobytes
        :return: a floating point value corresponding to a given value in kilobytes after the translation to a
                 corresponding format.
        """
        return value_in_kilobytes / self

    @staticmethod
    def default_float_formatter(float_value: float) -> str:
        return f"{float_value:.2f}"

    @staticmethod
    def get_differentiating_format_for_kib(value_in_kilobytes: int, other_value_in_kilobytes: int,
                                           float_formatter: Optional[Callable[[float], str]] = None) \
            -> "HumanBytesUnitFormat":
        """
        If a second parameter value is different from the first value then return a format
        that would produce a different printout with a given float_formatter or with a default formatter otherwise.

        :param value_in_kilobytes: First value in kilobytes
        :param other_value_in_kilobytes: Second value in kilobytes
        :param float_formatter: Optional function that takes a float and returns a formatted string. By default, print a
                                floating point value with 2 decimal places.
        :return: A selected unit format
        """
        unit_format = HumanBytesUnitFormat.get_format_for_kib(value_in_kilobytes)

        if other_value_in_kilobytes is None or other_value_in_kilobytes == value_in_kilobytes:
            return unit_format

        def format_float(x: float) -> str:
            if float_formatter:
                return float_formatter(x)
            return HumanBytesUnitFormat.default_float_formatter(x)

        # Reduce the coarseness of the format until printed values look differently
        formats = list(reversed(sorted(HumanBytesUnitFormat)))
        for current_format in formats[formats.index(unit_format):]:
            if (format_float(current_format.translate_kib(value_in_kilobytes)) !=
                    format_float(current_format.translate_kib(other_value_in_kilobytes))):
                return current_format

        return HumanBytesUnitFormat.KiB


if __name__ == '__main__':
    from scylla_doctor import Doctor, DoctorEnvironment

    doctor = Doctor(DoctorEnvironment())

    doctor.collectors = {
        'CPUSpecificationsCollector': doctor.collectors['CPUSpecificationsCollector']
    }
    doctor._Doctor__checkups = []  # type: ignore
    doctor.analyzers = {
        'CPUInstructionSetAnalyzer': doctor.analyzers['CPUInstructionSetAnalyzer']
    }
    doctor.run()

    # FOR DEMO PURPOSES
    print(doctor.collectors['CPUSpecificationsCollector'].result)
    print(doctor.analyzers['CPUInstructionSetAnalyzer'].status)
    print(doctor.analyzers['CPUInstructionSetAnalyzer'].message)
    print(doctor.vitals)

    doctor.print_results()


@dataclasses.dataclass(frozen=True)
class ConfigParameter:
    description: str
    default: Optional[str] = None
    default_description: Optional[str] = None
    param_type: Type[Any] = str
    unit: Optional[str] = None
    comma_separated: bool = False

    def display_default(self) -> str:
        if self.default is not None:
            value = self.default
        elif self.default_description is not None:
            value = self.default_description
        else:
            value = 'unset'
        if self.unit and self.default is not None:
            return f"{value} {self.unit}"
        return value

    def runtime_type_name(self) -> str:
        if self.comma_separated:
            return 'set[str]'
        return self.param_type.__name__


_RUN_CONFIG_PARAMETER = ConfigParameter(
    default_description='unset (enabled)',
    description='Set to no/0/false/off to disable this component.',
)


def _cast_config_parameter_value(raw: str, param: ConfigParameter) -> Any:
    if param.comma_separated:
        return {s.strip() for s in raw.split(',') if s.strip()}
    if param.param_type is int:
        return int(raw)
    if param.param_type is float:
        return float(raw)
    return raw


class ConfigValuesParser(abc.ABC):
    @property
    @abc.abstractmethod
    def config(self) -> DictView:
        """
        Should return a DictView object with configuration values for the current class.
        """
        pass

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        """
        Return component-specific configuration parameters and their defaults.
        The universal ``run`` parameter is added automatically.
        """
        return {}

    @property
    def config_parameters(self) -> Dict[str, ConfigParameter]:
        params = dict(type(self).config_parameters_definitions())
        params.pop('run', None)
        params['run'] = _RUN_CONFIG_PARAMETER
        return params

    def _config_raw_value(self, name: str) -> Optional[str]:
        if name not in self.config:
            return None
        value = self.config[name]
        return value if value != '' else None

    def _get_config_value(self, name: str, fallback: Any = _CONFIG_VALUE_UNSET) -> Any:
        """
        Resolve a declared configuration parameter using its metadata default and type.
        """
        definitions = type(self).config_parameters_definitions()
        if name not in definitions:
            raise KeyError(f"Undefined config parameter '{name}' for {type(self).__name__}")

        param = definitions[name]
        raw = self._config_raw_value(name)
        if raw is None:
            if param.default is not None:
                raw = param.default
            elif fallback is not _CONFIG_VALUE_UNSET:
                return fallback
            elif param.comma_separated:
                raw = ''
            else:
                return None

        return _cast_config_parameter_value(raw, param)

    def _parse_comma_separated_config(self, config_key_name: str) -> Set[str]:
        """
        Parses a comma-separated string into a set of stripped, non-empty items.

        This function takes a string where items are separated by commas, splits the
        string, removes any leading or trailing whitespace from each item, and
        ignores any empty strings in the resulting set. The returned set contains
        unique values.

        :param config_key_name: The name of the configuration key to retrieve and process.
        :return: A set containing unique, stripped, non-empty items from the input string.
        """
        if config_key_name in type(self).config_parameters_definitions():
            value = self._get_config_value(config_key_name)
            return value if value is not None else set()

        return {s.strip() for s in self.config.get(config_key_name, '').split(',') if s.strip()}
