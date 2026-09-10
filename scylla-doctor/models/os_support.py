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
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


class OSSupportMatrixError(ValueError):
    """Raised when the OS support matrix JSON cannot be parsed or is malformed."""


# os-release ID -> family name as published in the OS support matrix. An explicit
# mapping is deliberately preferred over fuzzy name matching; extend it when the
# matrix adds a distribution whose os-release ID does not equal its family name.
DISTRO_ID_TO_FAMILY = {
    'centos': 'Rocky / CentOS / RHEL',
    'rhel': 'Rocky / CentOS / RHEL',
    'rocky': 'Rocky / CentOS / RHEL',
    'amzn': 'Amazon Linux',
}


def _parse_family_map(families: Dict[str, List[str]], loc: str) -> List["SupportedOS"]:
    """Validate a mapping of OS family name -> list of version strings and build SupportedOS entries."""
    result: List["SupportedOS"] = []
    for family, versions in families.items():
        if not isinstance(family, str) or not family:
            raise OSSupportMatrixError(f"OS support matrix {loc} has a non-string OS family name")
        if not isinstance(versions, list) or not all(isinstance(v, str) for v in versions):
            raise OSSupportMatrixError(
                f"OS support matrix {loc}: family {family!r} is not a list of version strings")
        result.append(SupportedOS(family, list(versions)))
    return result


@dataclass
class SupportedOS:
    """A supported OS distribution: its family name and the list of supported version strings.

    A version string may carry a '*' suffix meaning 'supported with restrictions'
    (for example '24.04*' for Enterprise 2024.1).
    """

    # Family name as published in the matrix, e.g. 'Ubuntu' or 'Rocky / CentOS / RHEL'.
    name: str
    versions: List[str]

    def matches_distro(self, distro: str) -> bool:
        """Return True if `distro` refers to this family.

        :param distro: the host's os-release ID, e.g. 'ubuntu' or 'rhel'
        :return: True if `distro` maps to this family via :data:`DISTRO_ID_TO_FAMILY`,
                 or (for IDs not in the mapping) equals the family name ignoring case.
        """
        family = DISTRO_ID_TO_FAMILY.get(distro.lower(), distro)
        return family.lower() == self.name.lower()

    def restriction_for(self, version: str, version_minor: str) -> Optional[bool]:
        """Report how the host OS version is listed for this family.

        :param version: the host's OS major version, e.g. '22'
        :param version_minor: the host's full OS version string, e.g. '22.04'
        :return: True if listed with restrictions ('*' suffix), False if listed
                 without, or None if the host's version is not in this family's list.
        """
        tokens = {t for t in (version_minor, version) if t}
        tokens |= {t.split('.')[0] for t in list(tokens) if '.' in t}
        for listed in self.versions:
            if listed.rstrip('*') in tokens:
                return listed.endswith('*')
        return None


@dataclass
class ScyllaVersionSupport:
    """One 'ScyllaDB Versions' row: a release label and the OS families that release supports."""

    # Release label as published in the matrix, e.g. 'ScyllaDB 2025.1' or 'Enterprise 2024.2'.
    version: str
    supported_os: List[SupportedOS]

    @staticmethod
    def _release_key(version: str) -> Optional[Tuple[int, int]]:
        """Extract the major.minor release key from a version string, e.g. 'ScyllaDB 2025.1' -> (2025, 1)."""
        match = re.search(r'(\d+)\.(\d+)', version)
        if not match:
            return None
        return int(match.group(1)), int(match.group(2))

    def matches_major(self, scylla_version: str) -> bool:
        """Return True if this release row matches the major.minor of `scylla_version`.

        :param scylla_version: the version reported by `scylla --version`,
            e.g. '2025.1.4' or '2024.1.9-0.20240612.abcdef' — anything with a
            leading major.minor pair.
        :return: True if the first major.minor found in `scylla_version` equals this
            row's. The edition is irrelevant: a version number is unique, so only
            major.minor is compared.
        """
        key = ScyllaVersionSupport._release_key(scylla_version)
        return key is not None and ScyllaVersionSupport._release_key(self.version) == key

    def match_os(self, distro: str, version: str, version_minor: str) -> Optional[bool]:
        """Report how `distro version_minor` is supported by this release.

        :param distro: the host's os-release ID or name, e.g. 'ubuntu'
        :param version: the host's OS major version, e.g. '22'
        :param version_minor: the host's full OS version string, e.g. '22.04'
        :return: True/False/None as in :meth:`SupportedOS.restriction_for`, or None if
                 `distro` is not a family this release supports.
        """
        for family in self.supported_os:
            if family.matches_distro(distro):
                return family.restriction_for(version, version_minor)
        return None


@dataclass
class OSSupportMatrix:
    """The ScyllaDB OS support matrix.

    Holds the general list of supported distributions (the top-level 'Linux Distributions'
    element) and, per release, the distributions and versions that release supports
    (the 'ScyllaDB Versions' list).
    """

    distributions: List[SupportedOS]
    versions: List[ScyllaVersionSupport]

    @classmethod
    def from_json(cls, payload: str, source: str) -> "OSSupportMatrix":
        try:
            matrix = json.loads(payload)
        except (json.JSONDecodeError, TypeError) as e:
            raise OSSupportMatrixError(f"Failed to parse OS support matrix from {source}") from e
        if not isinstance(matrix, dict):
            raise OSSupportMatrixError(f"OS support matrix from {source} is not an object")

        raw_distributions = matrix.get('Linux Distributions')
        if raw_distributions is None:
            raw_distributions = {}
        if not isinstance(raw_distributions, dict):
            raise OSSupportMatrixError(f"OS support matrix {source} 'Linux Distributions' is not an object")
        distributions = _parse_family_map(raw_distributions, f"{source} top-level")

        raw_versions = matrix.get('ScyllaDB Versions')
        if not isinstance(raw_versions, list):
            raise OSSupportMatrixError(f"OS support matrix from {source} is missing 'ScyllaDB Versions'")
        versions = [cls._parse_version_entry(raw, source, i) for i, raw in enumerate(raw_versions)]
        return cls(distributions, versions)

    @staticmethod
    def _parse_version_entry(raw: object, source: str, index: int) -> ScyllaVersionSupport:
        loc = f"{source} entry {index}"
        if not isinstance(raw, dict):
            raise OSSupportMatrixError(f"OS support matrix {loc} is not an object")
        version = raw.get('version')
        if not isinstance(version, str) or not version:
            raise OSSupportMatrixError(f"OS support matrix {loc} is missing a version string")
        supported_os = raw.get('supported_OS')
        if not isinstance(supported_os, dict):
            raise OSSupportMatrixError(f"OS support matrix {loc} ({version}) has invalid supported_OS")
        families = _parse_family_map(supported_os, f"{loc} ({version})")
        return ScyllaVersionSupport(version, families)

    def find_version_entry(self, scylla_version: str) -> Optional[ScyllaVersionSupport]:
        """Find the matrix row for a running Scylla version.

        :param scylla_version: the version reported by `scylla --version`,
            e.g. '2025.1.4' — see :meth:`ScyllaVersionSupport.matches_major`.
        :return: the release row whose major.minor matches, or None if the
            matrix has no entry for that release.
        """
        for version in self.versions:
            if version.matches_major(scylla_version):
                return version
        return None
