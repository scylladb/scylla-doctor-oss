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

import glob
import json
import os
import re
import shutil

from typing import Dict, Optional, Set, List, Iterable, Union, Sequence

from common import DictView
from collectors_base import CollectorStatus, Collector
from models.output_entry import OutputEntryType, Level

from utils import Executor, running_in_container


class NVMeDevicesCollector(Collector):
    _NVME_DISK_NAME_RE = re.compile(r'^nvme\d+n\d+$')

    @property
    def name(self) -> str:
        return "NVMe devices"

    @property
    def __collector_raid(self) -> str:
        return "RAIDSetupCollector"

    @property
    def __collector_provider(self) -> str:
        return "InfrastructureProviderCollector"

    @property
    def skip_in_container(self) -> Optional[str]:
        return ("mountpoints come from the container's mount namespace, so host NVMe disks not mounted into the "
                "container would look unused")

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_raid, self.__collector_provider}

    @classmethod
    def _list_nvme_disks(cls) -> List[str]:
        if not os.path.isdir('/sys/block'):
            return []
        return sorted(name for name in os.listdir('/sys/block') if cls._NVME_DISK_NAME_RE.match(name))

    @staticmethod
    def _block_device_basename(source: str) -> str:
        name = os.path.basename(source)
        nvme_namespace = re.match(r'^(nvme\d+n\d+)(?:p\d+)?$', name)
        if nvme_namespace:
            return nvme_namespace.group(1)
        return re.sub(r'\d+$', '', name)

    @classmethod
    def _root_block_device_name(cls) -> Optional[str]:
        output = Executor.run_command('findmnt -n -o SOURCE /', check=False)
        if output.returncode != 0 or not output.stdout.strip():
            return None
        return cls._block_device_basename(output.stdout.strip())

    def _applicable_nvme_disks(self, vitals: DictView, nvme_disks: List[str]) -> List[str]:
        if vitals[self.__collector_provider].data.get('provider') != 'AWS':
            return nvme_disks

        root_device = self._root_block_device_name()
        if not root_device:
            return nvme_disks

        return [disk for disk in nvme_disks if disk != root_device]

    @staticmethod
    def _active_raid_nvme_members(raid_data: Dict) -> Set[str]:
        return {
            match.group(1)
            for array in raid_data['arrays'].values() if array.get('state') == 'active'
            for member in array.get('members', [])
            for match in [re.match(r'(nvme\d+n\d+)', member)] if match
        }

    def _mounted_nvme_disks(self, nvme_disks: Set[str]) -> Optional[Set[str]]:
        mounted = set()
        for disk in sorted(nvme_disks):
            command = f"lsblk -rno MOUNTPOINT /dev/{disk}"
            output = Executor.run_command(command, check=False)
            if output.returncode != 0:
                self.status = CollectorStatus.FAILED
                self._message = f"Failed to run {command}: {output.stderr.strip()}"
                return None
            self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
            if any(line.strip() for line in output.stdout.splitlines()):
                mounted.add(disk)
        return mounted

    def _collect(self, vitals: DictView) -> None:
        nvme_disks = self._applicable_nvme_disks(vitals, self._list_nvme_disks())
        raid_data = vitals[self.__collector_raid].data

        nvme_disk_set = set(nvme_disks)
        mounted = self._mounted_nvme_disks(nvme_disk_set)
        if mounted is None:
            return

        used = mounted | self._active_raid_nvme_members(raid_data)
        used &= nvme_disk_set

        self._data = {
            'nvme_devices': nvme_disks,
            'used_nvme_devices': sorted(used),
            'unused_nvme_devices': sorted(nvme_disk_set - used),
        }
        self.status = CollectorStatus.PASSED


class NitroDetailedStatsCollector(Collector):
    """
    Collect detailed NVMe performance statistics (`nvme amzn stats --details`) from AWS Nitro-based instances.

    Statistics are collected only for the NVMe devices used by Scylla, as already discovered by
    NVMeDevicesCollector. This requires the `nvme-cli` `amzn` plugin to implement the `stats`
    sub-command, which is not installed by default, is not available in every `nvme-cli` build and
    needs root privileges. `nvme amzn stats --help` is probed first: a missing `stats` sub-command results in
    a SKIPPED status, while a failure of a supported `stats` command for a device results in a FAILED status.
    """

    @property
    def name(self) -> str:
        return "AWS Nitro detailed NVMe statistics"

    @property
    def privileged(self) -> bool:
        # `nvme amzn stats` reads controller log pages and requires root privileges
        return True

    @property
    def __collector_nvme(self) -> str:
        return "NVMeDevicesCollector"

    @property
    def __collector_provider(self) -> str:
        return "InfrastructureProviderCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_nvme, self.__collector_provider}

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Statistics are per-node cumulative counters and histograms, therefore they always differ between
        nodes - exclude from drifts checking.
        """
        return ["devices"]

    def _collect(self, vitals: DictView) -> None:
        if vitals[self.__collector_provider].data.get('provider') != 'AWS':
            self.status = CollectorStatus.SKIPPED
            self._message = "Detailed NVMe performance statistics are available on AWS Nitro instances only"
            return

        if not shutil.which('nvme'):
            self.status = CollectorStatus.SKIPPED
            self._message = "'nvme' utility (nvme-cli package) is not installed, " \
                            "skipping Nitro detailed NVMe statistics"
            return

        # Only the data disks in active use are relevant to Scylla's IO workload. NVMeDevicesCollector
        # already drops the AWS root EBS volume (the OS volume) from 'used_nvme_devices'.
        used_nvme = vitals[self.__collector_nvme].data.get('used_nvme_devices', [])
        if not used_nvme:
            self.status = CollectorStatus.SKIPPED
            self._message = "No NVMe devices are used by Scylla, nothing to collect"
            return

        # The `amzn` plugin is not always built in, and when it is, it doesn't always implement `stats`
        # (e.g. nvme-cli 1.16 on Ubuntu only has `id-ctrl` and `version`). An unknown sub-command makes
        # `nvme` print the plugin's sub-command list instead of the `stats` options, so the presence of the
        # `--output-format` option that is relied upon below is what tells `stats` is supported. The exit
        # code is no indication: nvme-cli 1.x exits non-zero after printing the help of a supported command.
        stats_help_command = "nvme amzn stats --help"
        stats_help = Executor.run_command(stats_help_command, check=False)
        self._output.put(OutputEntryType.STDOUT, stats_help_command, stats_help.stdout, level=Level.VERBOSE)
        if "--output-format" not in stats_help.stdout:
            self.status = CollectorStatus.SKIPPED
            self._message = "The installed nvme-cli does not support 'nvme amzn stats' ('nvme amzn stats --help' " \
                            "does not list its options), skipping Nitro detailed NVMe statistics"
            return

        # `--details` (latency histograms) was added to nvme-cli after `stats` itself.
        details_option = " --details" if "--details" in stats_help.stdout else ""

        devices = {}
        errors = []
        for disk in used_nvme:
            # JSON output only: nvme-cli builds without JSON support print a human readable report instead,
            # which is reported as a device error below.
            command = f"nvme amzn stats{details_option} /dev/{disk} --output-format=json"
            output = Executor.run_command(command, check=False)
            self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
            if output.returncode != 0:
                errors.append(f"{disk}: {output.stdout.strip()}")
                continue
            # Executor merges stderr into stdout: decode the JSON object only, skipping any warning around it
            # (e.g. libnvme complaining about a missing /etc/nvme/hostnqn).
            try:
                devices[disk] = json.JSONDecoder().raw_decode(output.stdout, output.stdout.index('{'))[0]
            except ValueError:
                errors.append(f"{disk}: output is not JSON")

        self._data = {'devices': devices}
        if errors:
            self.status = CollectorStatus.FAILED
            self._message = f"'nvme amzn stats{details_option}' failed for NVMe devices used by Scylla: " \
                            f"{'; '.join(errors)}"
            return

        self.status = CollectorStatus.PASSED


class RAIDSetupCollector(Collector):
    # md0 : active raid0 nvme0n2[1] nvme0n1[0]
    # md1 : active (auto-read-only) raid1 sda1[0] sdb1[1]
    # md2 : inactive sda1[0](S) sdb1[1](S)
    # Numeric mdN names only: Scylla nodes use kernel-assigned /dev/mdN, not mdadm --name arrays.
    _ARRAY_LINE_RE = re.compile(r'^(?P<name>md\d+)\s*:\s+(?P<state>\S+)(?:\s+\([^)]*\))?\s*(?P<rest>.*)$')
    _MEMBER_RE = re.compile(r'^([^\s\[\]]+)\[\d+\](?:\([^)]*\))?$')

    @property
    def name(self) -> str:
        return "RAID Setup"

    @classmethod
    def _parse_mdstat(cls, content: List[str]) -> Dict:
        """
        Parse /proc/mdstat into a structured dict so cluster drift comparison is stable.

        Member device order in the raw file can differ across nodes with the same RAID layout;
        sorting members (and other lists) makes the collector data comparable.
        """
        personalities: List[str] = []
        arrays: Dict[str, Dict] = {}
        unused_devices: List[str] = []

        for raw_line in content:
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith('Personalities'):
                personalities = re.findall(r'\[([^\]]+)\]', line.split(':', 1)[1] if ':' in line else '')
                continue

            if line.startswith('unused devices:'):
                # Kernel/mdadm separate multiple unused devices with whitespace, not commas.
                unused_value = line.split(':', 1)[1].strip()
                if unused_value and unused_value != '<none>':
                    unused_devices = sorted(unused_value.split())
                continue

            array_match = cls._ARRAY_LINE_RE.match(line)
            if not array_match:
                continue

            # First non-member token (if any) is the personality/level, e.g. "raid0", "linear";
            # inactive arrays list only members and have no level token.
            tokens = (array_match.group('rest') or '').split()
            level = tokens.pop(0) if tokens and not cls._MEMBER_RE.match(tokens[0]) else None
            members = sorted(match.group(1) for match in (cls._MEMBER_RE.match(t) for t in tokens) if match)
            arrays[array_match.group('name')] = {
                'state': array_match.group('state'),
                'level': level,
                'members': members,
            }

        return {
            'personalities': sorted(personalities),
            'arrays': {name: arrays[name] for name in sorted(arrays)},
            'unused_devices': unused_devices,
        }

    def _collect(self, vitals: DictView) -> None:
        filename = "/proc/mdstat"

        # /proc/mdstat is only present when the md (software RAID) kernel module is available. Its absence
        # means software RAID is not in use on this node, which is not an error - skip instead of failing.
        try:
            content = Executor.read_file_content(filename)
        except FileNotFoundError:
            self.status = CollectorStatus.SKIPPED
            self._message = f"{filename} is not present, software RAID is not configured"
            return

        if not content:
            self.status = CollectorStatus.FAILED
            self._message = f"Cannot read {filename}"
            return

        self._data = self._parse_mdstat(content)
        self._output.put(OutputEntryType.FILE, filename, content, level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED


class ScyllaSSTablesCollector(Collector):
    """
    Every file under scylla_directory_var/data. Names with '-' are sstable components, nested as
    data.sstables[directory][stem] = [suffix, ...] with stem/suffix = basename.rpartition('-'), so a directory and a
    stem are written once per sstable instead of once per component (~8x smaller vitals). Names without '-'
    (manifest.json, schema.cql) go to data.other_files[directory] = [basename, ...]. Sorted at every level.
    """

    @property
    def name(self) -> str:
        return "Scylla sstables"

    def _collect(self, vitals: DictView) -> None:
        data_glob = os.path.join(self._paths['scylla_directory_var'], "data/**/*")
        files = [file for file in glob.glob(data_glob, recursive=True) if not os.path.isdir(file)]
        sstables: Dict[str, Dict[str, List[str]]] = {}
        other_files: Dict[str, List[str]] = {}
        for file in files:
            directory, basename = os.path.split(file)
            stem, dash, suffix = basename.rpartition('-')
            if dash:
                sstables.setdefault(directory, {}).setdefault(stem, []).append(suffix)
            else:
                other_files.setdefault(directory, []).append(basename)
        self._data['sstables'] = {directory: {stem: sorted(suffixes) for stem, suffixes in sorted(stems.items())}
                                  for directory, stems in sorted(sstables.items())}
        self._data['other_files'] = {directory: sorted(names) for directory, names in sorted(other_files.items())}
        # Dump the nested data rather than the flat paths so --include-output keeps the same size saving,
        # one line per directory so -v stays readable in a terminal or pager.
        lines = [f"{directory}: {json.dumps(entries)}"
                 for key in ('sstables', 'other_files') for directory, entries in self._data[key].items()]
        self._output.put(OutputEntryType.VALUE, f"All {len(files)} files in {data_glob}",
                         "\n".join(lines), level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ['*']


class StorageConfigurationCollector(Collector):
    # perftune.py exits with e.g. "[Errno 2] No such file or directory: '/dev/vda4'" when the /dev node is missing.
    _MISSING_DEV_NODE_RE = re.compile(r"No such file or directory: ['\"]?/dev/")

    @property
    def name(self) -> str:
        return "Storage configuration"

    @staticmethod
    def _is_network_backed(device: str) -> bool:
        # AWS Nitro instances expose EBS volumes as nvme* devices, see
        # https://docs.aws.amazon.com/ebs/latest/userguide/nvme-ebs-volumes.html
        disk = re.sub(r'p\d+$', '', device)
        try:
            model = Executor.read_file_content(f"/sys/block/{disk}/device/model")[0]
        except (OSError, IndexError):
            return False
        return "elastic block store" in model.lower()

    @property
    def __collector_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_config}

    def _collect(self, vitals: DictView) -> None:
        # One of the things we are going to collect are mount options for each data directory of our interest.
        # A typical 'mount' line looks as follows:
        #
        # /dev/nvme0n1 on /var/lib/systemd/coredump type xfs (rw,noatime,attr2,inode64,logbufs=8,logbsize=32k,noquota)
        #
        # Mount options are at the end between '(' and ')'
        # Let's find everything between '(' and ')' then...
        mount_options_expr = re.compile(r'.*\((.*)\).*')

        # Cache all mount lines
        mount_lines = []
        command = "mount"
        output = Executor.run_command(command)
        if output:
            mount_lines = output.stdout.split("\n")
            self._output.put(OutputEntryType.STDOUT, "mount", output.stdout, level=Level.VERBOSE)

        scylla_config = vitals[self.__collector_config].data
        scylla_workdir = scylla_config['workdir,W']['value'] or self._paths['scylla_directory_var']
        dirs = {
            'data_file_directories': scylla_config['data_file_directories']['value'] or [os.path.join(scylla_workdir, 'data')],  # noqa: E501
            'commitlog_directories': [scylla_config['commitlog_directory']['value'] or os.path.join(scylla_workdir, 'commitlog')],  # noqa: E501
            'hints_directories': [scylla_config['hints_directory']['value'] or os.path.join(scylla_workdir, 'hints')],  # noqa: E501
            'view_hints_directories': [scylla_config['view_hints_directory']['value'] or os.path.join(scylla_workdir, 'view_hints')],  # noqa: E501
        }

        for dir, paths in dirs.items():
            self._data[dir] = {}
            for path in paths:
                # detect disks
                command = "{}/perftune.py --dir {} --tune disks --dry-run" \
                    .format(self._paths["scylla_directory_scripts"], path)
                output = Executor.run_command(command, check=False)
                if output.returncode != 0 or not output.stdout:
                    # perftune.py stats the /dev node behind the directory to find its disk. An unprivileged
                    # container has a private /dev without block device nodes, so that one failure is a skip there;
                    # any other perftune error is reported the same way as on a host. Directories collected so far
                    # stay in the data, as before: consumers such as the PS vitals summary read their sizes.
                    error = (output.stderr + output.stdout).strip()
                    if running_in_container() and self._MISSING_DEV_NODE_RE.search(error):
                        self.status = CollectorStatus.SKIPPED
                        self._message = ("Block device nodes behind the Scylla directories are not visible from this "
                                         f"container: {error}")
                        return
                    self.status = CollectorStatus.FAILED
                    self._message = f"Failed to run {command}: {error}"
                    return
                self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

                nvme = Executor.search_string("Setting NVMe disks", output.stdout.split("\n"))
                nvme_devices = sorted(set(nvme[0].split(":")[1].strip()[:-3].split(", ")) if nvme else set())

                non_nvme = Executor.search_string("Setting non-NVMe disks", output.stdout.split("\n"))
                non_nvme_devices = sorted(set(non_nvme[0].split(":")[1].strip()[:-3].split(", ")) if non_nvme else set())  # noqa: E501

                # 'nvme'/'non_nvme' above are perftune's name-based split and say nothing about where
                # a device physically lives. 'network_backed' is an independent locality axis over both
                # lists: it names the devices we could positively identify as network-attached (today only
                # AWS EBS, which Nitro exposes as nvme*). It is best-effort - not being listed is not proof
                # of local storage, e.g. an NVMe-over-fabrics target is indistinguishable here.
                network_backed_devices = sorted(device for device in nvme_devices + non_nvme_devices
                                                if self._is_network_backed(device))

                # Check storage filesystem and size
                command = "df -T {}".format(path)
                output = Executor.run_command(command)
                self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

                filesystem: Optional[str] = None
                mountpoint: Optional[str] = None
                if output:
                    path_info = output.stdout.split("\n")[1].split()
                    filesystem = path_info[1].lower()
                    mountpoint = path_info[6]

                mount_options: List[str] = []
                if mountpoint:
                    mpoint_expr = re.compile(rf'\s+{mountpoint}\s+')
                    for scylla_mount_line in filter(lambda ln: mpoint_expr.search(ln) is not None, mount_lines):
                        # Theoretically there may be no mount options
                        opts = mount_options_expr.match(scylla_mount_line)
                        if opts:
                            mount_options = opts.group(1).split(",")

                storage_stats = os.statvfs(path)
                storage_size_kb = storage_stats.f_frsize * storage_stats.f_blocks / 1024
                free_storage_size_kb = storage_stats.f_frsize * storage_stats.f_bfree / 1024

                self._data[dir][path] = {
                    'devices': {
                        'nvme': nvme_devices,
                        'non_nvme': non_nvme_devices,
                        'network_backed': network_backed_devices
                    },
                    'filesystem': filesystem,
                    'mountpoint': mountpoint,
                    'mount_options': mount_options,
                    'storage_size_kb': storage_size_kb,
                    'free_storage_size_kb': free_storage_size_kb
                }
        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        # No need to compare free storage size between nodes
        return [("*", "*", "free_storage_size_kb")]
