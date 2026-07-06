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

import dataclasses
import enum
from typing import Any


class Level(enum.IntEnum):
    """Available levels to print collector outputs. """
    DEFAULT = 0
    DETAILED = 1
    VERBOSE = 2


class OutputEntryType(enum.Enum):
    STDOUT = "Command output"
    FILE = "File content"
    PARSED_FILE = "Parsed content of"
    API = "API output from"
    CQL = "CQL output of"
    VALUE = "Value of"


@dataclasses.dataclass
class OutputEntry:
    level: Level
    type: OutputEntryType
    name: str
    value: Any
    # for OutputEntryType.PARSED_FILE, set of sensitive keys,whose values need to be stripped from human-readable report
    mask: set = dataclasses.field(default_factory=set)
