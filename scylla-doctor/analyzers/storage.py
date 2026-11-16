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

import itertools
import re

from typing import Dict, Set, Iterable

from analyzers_base import Analyzer, AnalyzerStatus
from common import HumanBytesUnitFormat, ConfigParameter, DictView


class DiskPerformanceExceededAnalyzer(Analyzer):
    # Counters reported by the AWS Nitro NVMe devices: the accumulated time (microseconds) IO demand exceeded the
    # volume or the instance performance limits. Both instance store and EBS devices report them, with slightly
    # different key names depending on the nvme-cli version, hence a suffix match.
    _EXCEEDED_KEY_SUFFIXES = ("performance_exceeded_iops", "performance_exceeded_tp")

    @property
    def name(self) -> str:
        return "Disk performance limits exceeded"

    @property
    def __collector(self) -> str:
        return "NitroDetailedStatsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'threshold': ConfigParameter(
                default='0',
                param_type=int,
                unit='microseconds',
                description='Accumulated time the IO demand may exceed a disk or an instance performance limit '
                            'before a warning is issued.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that the IO demand has not exceeded the disk or the instance performance limits.
        """
        threshold = self._get_config_value('threshold')
        devices = vitals[self.__collector].data['devices']

        counters = [(device, counter, value)
                    for device, stats in sorted(devices.items())
                    for counter, value in sorted(stats.items())
                    if counter.endswith(self._EXCEEDED_KEY_SUFFIXES)]
        if not counters:
            # An unexpected nvme-cli output shape must not be reported as PASSED without checking anything.
            self.status = AnalyzerStatus.SKIPPED
            self.message = "No 'performance exceeded' counters found in the Nitro NVMe statistics"
            return

        exceeded = [f"{device}: {counter}={value} microseconds"
                    for device, counter, value in counters if value > threshold]

        if exceeded:
            self.status = AnalyzerStatus.WARNING
            self.message = (f"IO demand has exceeded the performance limits since the instance has started: "
                            f"{', '.join(exceeded)}. Check the Scylla IO scheduler configuration "
                            f"(io_properties.yaml) and the disk provisioning.")
            return

        self.status = AnalyzerStatus.PASSED
        self.message = f"No performance limits were exceeded on {len(devices)} NVMe device(s)"


class RAIDSetupAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "RAID Setup"

    @property
    def __collector_raid(self) -> str:
        return "RAIDSetupCollector"

    @property
    def __collector_storage(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_raid, self.__collector_storage}

    @staticmethod
    def _block_device_basename(name: str) -> str:
        nvme = re.match(r'^(nvme\d+n\d+)(?:p\d+)?$', name)
        if nvme:
            return nvme.group(1)
        return re.sub(r'\d+$', '', name)

    @classmethod
    def _device_matches_member(cls, device: str, member: str) -> bool:
        # Exact match, or whole-disk ↔ its partition (sda↔sda1, nvme0n1↔nvme0n1p1).
        # Sibling partitions (sda1↔sda12) must not match.
        if device == member:
            return True
        return cls._block_device_basename(member) == device or cls._block_device_basename(device) == member

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that if any data-related directory is mounted on an SW RAID assembly it is of a RAID0 kind.
        """
        arrays = vitals[self.__collector_raid].data['arrays']

        messages = []
        for dir, dir_stats in vitals[self.__collector_storage].data.items():
            for dir_stat in dir_stats.values():
                # union nvme and non-nvme devices
                devices = set(itertools.chain.from_iterable(dir_stat['devices'].values()))

                raid_device = None
                raid_mode = None

                for device in devices:
                    matches = [(name, info) for name, info in arrays.items()
                               if any(self._device_matches_member(device, m) for m in info.get('members', []))]

                    if matches:
                        if len(matches) > 1:
                            self.status = AnalyzerStatus.WARNING
                            self.message = f"Funny RAID configuration detected for {dir}"
                            return
                        else:
                            raid_device, info = matches[0]
                            level = info.get('level')
                            raid_mode = level.upper() if level else None

                if raid_mode not in [None, "RAID0"]:
                    self.status = AnalyzerStatus.WARNING
                    self.message = f"RAID mode {raid_mode} detected for {dir}, it is not recommended"
                    return

                if not raid_device or not raid_mode:
                    messages.append(f"{dir}: No RAID")
                else:
                    messages.append(f"{dir}: {raid_mode}")

        self.message = ",".join(messages)
        self.status = AnalyzerStatus.PASSED


class ScyllaSSTablesAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Scylla SSTables"

    @property
    def __sstables_collector(self) -> str:
        return "ScyllaSSTablesCollector"

    @property
    def __system_config_collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__sstables_collector, self.__system_config_collector}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'recommended_format': ConfigParameter(
                default_description='system.config sstable_format, then me when unset',
                description='Expected SSTable format as a regex matched at the start of each sstable name '
                            '(e.g. md|me). Overrides auto-detected sstable_format when set.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that sstables are stored in recommended format
        """
        scylla_config = vitals[self.__system_config_collector].data
        sstable_format = self._get_config_value(
            "recommended_format",
            fallback=scylla_config.get('sstable_format', {}).get('value', 'me'))
        # re.match anchors every alternative at the stem start, so no wrapping group (it would break leading
        # inline flags such as '(?i)').
        try:
            format_re = re.compile(sstable_format)
        except re.error as e:
            self.status = AnalyzerStatus.FAILED
            self.message = f"recommended_format '{sstable_format}' is not a valid regular expression: {e}"
            return

        sstables = list(self.__sstable_stems(vitals))
        if len(sstables) == 0:
            self.status = AnalyzerStatus.PASSED
            self.message = "No SSTables found"
        elif any(not format_re.match(sstable) for sstable in sstables):
            self.status = AnalyzerStatus.WARNING
            self.message = f"SSTable format is not '{sstable_format}' (recommended)"
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = f"SSTable format is '{sstable_format}'"

    def __sstable_stems(self, vitals: DictView) -> Iterable[str]:
        # Ref https://github.com/scylladb/scylladb/blob/master/docs/dev/sstables-directory-structure.md
        sstables_re = re.compile(r".*(((Data|Index|Filter|CompressionInfo|Summary|Statistics|CRC|Scylla)\.db)|"
                                 r"(Digest\.(crc32|adler32|sha1))|"
                                 r"TOC\.txt)$")

        # ScyllaSSTablesCollector stores {directory: {stem: [suffix, ...]}}. The stem carries the format, but only
        # the suffix says whether the entry is an sstable at all: pending_delete/sstables-<min>-<max>.log splits on
        # '-' too and must not be checked against the format.
        for stems in vitals[self.__sstables_collector].data['sstables'].values():
            for stem, suffixes in stems.items():
                if any(sstables_re.match(suffix) for suffix in suffixes):
                    yield stem


class StorageRAMRatioAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Storage/RAM ratio"

    @property
    def __collector_ram(self) -> str:
        return "RAMCollector"

    @property
    def __collector_storage(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_ram, self.__collector_storage}

    @classmethod
    def config_parameters_definitions(cls) -> Dict[str, ConfigParameter]:
        return {
            'ratio': ConfigParameter(
                default='105',
                param_type=int,
                description='Maximum recommended storage-to-RAM ratio.',
            ),
        }

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that Storage/RAM ratio is lower than recommended value.
        """
        recommended_ratio = self._get_config_value('ratio')
        total_storage = sum([dir_stats['storage_size_kb'] for dir_stats
                             in vitals[self.__collector_storage].data['data_file_directories'].values()])
        total_ram = vitals[self.__collector_ram].data['total']

        if not total_storage:
            self.status = AnalyzerStatus.FAILED
            self.message = "Cannot determine the ratio between storage/RAM"
            return

        detected_ratio = int(total_storage / total_ram)
        if detected_ratio <= recommended_ratio:
            self.status = AnalyzerStatus.PASSED
            self.message = f"Storage/RAM ratio ({str(detected_ratio)}:1) is lower than recommended ({str(recommended_ratio)}:1)"  # noqa: E501
        else:
            self.status = AnalyzerStatus.WARNING
            self.message = f"Storage/RAM ratio ({str(detected_ratio)}:1) is higher than recommended ({str(recommended_ratio)}:1)"  # noqa: E501


class StorageTypeAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Storage configuration"

    @property
    def __collector(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that all data-related directories settle on local NVME disks (storage detected as
        network-attached, such as AWS EBS, counts as non-NVMe).
        """
        data_dirs = vitals[self.__collector].data['data_file_directories'].values()

        # A network-attached volume (e.g. AWS EBS) is named nvme* on AWS Nitro but gives none of the
        # latency guarantees of a local NVMe, so it is counted on the non-NVMe side here.
        nvme_devices_count = 0
        non_nvme_devices_count = 0
        network_backed_count = 0
        for dir_stats in data_dirs:
            devices = dir_stats['devices']
            network_backed = set(devices.get('network_backed', []))
            nvme_devices_count += len(set(devices['nvme']) - network_backed)
            non_nvme_devices_count += len(set(devices['non_nvme']) | (set(devices['nvme']) & network_backed))
            network_backed_count += len(network_backed)

        if not nvme_devices_count and not non_nvme_devices_count:
            self.status = AnalyzerStatus.FAILED
            self.message = "Storage type cannot be determined"
            return

        if nvme_devices_count and non_nvme_devices_count:
            self.status = AnalyzerStatus.WARNING
            disk_type = "NVME + non-NVME"
        elif non_nvme_devices_count:
            self.status = AnalyzerStatus.WARNING
            disk_type = "non-NVME"
        else:
            self.status = AnalyzerStatus.PASSED
            disk_type = "NVME"

        if network_backed_count:
            disk_type += ", incl. network-attached storage (e.g. AWS EBS)"

        storage_size = sum([dir_stats['storage_size_kb'] for dir_stats in data_dirs])
        storage_unit = HumanBytesUnitFormat.get_format_for_kib(storage_size)
        self.message = (f"{self.format_float(storage_unit.translate_kib(storage_size))} {storage_unit} "
                        f"detected ({disk_type})")


class UnusedNVMeDevicesAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "Unused NVMe devices"

    @property
    def __collector(self) -> str:
        return "NVMeDevicesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Warn if there are NVMe devices that are not mounted and not used by an active SW RAID.
        """
        data = vitals[self.__collector].data
        nvme_devices = data['nvme_devices']
        unused_devices = data['unused_nvme_devices']

        if not nvme_devices:
            self.status = AnalyzerStatus.PASSED
            self.message = "No NVMe devices detected"
            return

        if unused_devices:
            self.status = AnalyzerStatus.WARNING
            self.message = f"Unused NVMe device(s) detected: {', '.join(unused_devices)}"
            return

        self.status = AnalyzerStatus.PASSED
        self.message = f"All {len(nvme_devices)} NVMe device(s) are in use"


class XFSAnalyzer(Analyzer):
    @property
    def name(self) -> str:
        return "XFS setup"

    @property
    def _collector(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self._collector}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that data-related directories reside on XFS.
        """
        for dirs in vitals[self._collector].data.values():
            for dir_stats in dirs.values():
                if dir_stats['filesystem'] != "xfs":
                    self.status = AnalyzerStatus.WARNING
                    self.message = "XFS setup was not done"
                    return
        self.status = AnalyzerStatus.PASSED
        self.message = "XFS setup was done"
