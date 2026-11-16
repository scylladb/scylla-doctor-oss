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

import argparse
import glob
import json
import os
import re
import yaml

from typing import Dict, Optional, Set, Iterable, Union, Sequence

from common import DictView
from collectors_base import CollectorStatus, Collector, ScyllaConfigurationCollector
from models.output_entry import OutputEntryType, Level

from utils import Executor, running_in_container


class CPUSetCollector(Collector):
    @property
    def name(self) -> str:
        return "cpuset setup"

    @property
    def __collector(self) -> str:
        return "ScyllaExtraConfigurationFilesCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        cpuset_content = vitals[self.__collector].data['files'].get('cpuset.conf', {})
        cpuset = cpuset_content.get('CPUSET')

        if not cpuset_content or not cpuset:
            self.status = CollectorStatus.SKIPPED
            self._message = "cpuset setup was not done"
            return

        parser = argparse.ArgumentParser()
        parser.add_argument("--cpuset")
        cpuset_list = parser.parse_known_args(cpuset.split(' '))[0].cpuset
        if cpuset_list is None:
            self.status = CollectorStatus.SKIPPED
            self._message = "cpuset setup was not performed using Scylla tools: '--cpuset' is not used in CPUSET"
            return

        hwloc_calc_cmd = f"{self._paths['scylla_directory']}/bin/hwloc-calc"

        # cpuset_list = re.sub(r'^--cpuset (.+)$', r'\1', cpuset).strip()
        hwloc_cmd = f"{hwloc_calc_cmd}" + " -p --pi {}". \
            format(" ".join(['PU:{}'.format(c) for c in cpuset_list.split(",")])).strip("\n")
        cpusetconf_mask = Executor.run_command(hwloc_cmd).stdout

        self._output.put(OutputEntryType.STDOUT, hwloc_cmd, cpusetconf_mask, Level.VERBOSE)

        options_file = f"{self._paths['scylla_directory_configs']}/perftune.yaml"
        if not os.path.isfile(options_file):
            self.status = CollectorStatus.FAILED
            self._message = "perftune.yaml is not found"
            return

        perftune_file = f"{self._paths['scylla_directory_scripts']}/perftune.py"
        command = f"{perftune_file} --get-cpu-mask --options-file {options_file}"
        perftune_mask = Executor.run_command(command).stdout

        self._output.put(OutputEntryType.STDOUT, command, perftune_mask, Level.VERBOSE)

        # calculate bitwise-and intersection between cpusetconf and perftune masks
        hwloc_cmd = f"{hwloc_calc_cmd} --restrict {cpusetconf_mask} {perftune_mask} --intersect PU -p"
        cpusetconf_intersect_perftune_list = Executor.run_command(hwloc_cmd).stdout

        self._output.put(OutputEntryType.STDOUT, hwloc_cmd, cpusetconf_intersect_perftune_list, Level.VERBOSE)

        hwloc_cmd = f"{hwloc_calc_cmd}" + " -p --pi {}". \
            format(" ".join(['PU:{}'.format(c) for c in cpusetconf_intersect_perftune_list.split(",")]))
        cpusetconf_intersect_perftune_mask = Executor.run_command(hwloc_cmd).stdout

        self._output.put(OutputEntryType.STDOUT, hwloc_cmd, cpusetconf_intersect_perftune_mask, Level.VERBOSE)

        self._data = {
            'cpusetconf_mask': cpusetconf_mask,
            'perftune_mask': perftune_mask,
            'cpusetconf_intersect_perftune_mask': cpusetconf_intersect_perftune_mask
        }
        self.status = CollectorStatus.PASSED


class PerftuneSystemConfigurationCollector(Collector):
    @property
    def name(self) -> str:
        return "System configuration suggested by perftune.py"

    @property
    def __storage_collector(self) -> str:
        return "StorageConfigurationCollector"

    @property
    def __hypervisor_type_collector(self) -> str:
        return "HypervisorTypeCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__storage_collector, self.__hypervisor_type_collector}

    def __get_nvme_smp_affinity_files(self, dir_data: Dict, perftune_file: str) -> Set[str]:
        """
        :param dir_data: Data of StorageConfigurationCollector
        :param perftune_file: path to a perftune.py
        :return: Names of NVMe disks smp_affinity files.
        """
        nvme_devs = set()
        for dirs in dir_data.values():
            for one_dir in dirs.values():
                nvme_devs |= set(one_dir['devices']['nvme'])

        # If there are no NVMe disks - return
        if not nvme_devs:
            return set()

        dev_command = ' '.join([f"--dev {d}" for d in nvme_devs])
        command = f"{perftune_file} --tune disks {dev_command} --dry-run"
        output = Executor.run_command(command)
        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

        smp_affinity_lines = Executor.search_string(r"smp_affinity", output.stdout.split("\n"))
        # strings like "echo 00000001 > proc/irq/41/smp_affinity"
        return set([smp_affinity_line.split(maxsplit=3)[3] for smp_affinity_line in smp_affinity_lines])

    def _collect(self, vitals: DictView) -> None:
        options_file = f"{self._paths['scylla_directory_configs']}/perftune.yaml"
        if not os.path.isfile(options_file):
            # perftune.yaml is written by scylla_setup on the host; a container only has one when the image or an
            # operator ships it, so its absence is not a failure there.
            if running_in_container():
                self.status = CollectorStatus.SKIPPED
                self._message = "perftune.yaml is not available from this container"
                return
            self.status = CollectorStatus.FAILED
            self._message = "perftune.yaml is not found"
            return

        dir_data = vitals[self.__storage_collector].data
        scylla_dirs = set().union(*[[d for d in dirs.keys()] for dirs in dir_data.values()])

        dir_command = " ".join([f"--dir {dir}" for dir in scylla_dirs])
        perftune_file = f"{self._paths['scylla_directory_scripts']}/perftune.py"
        command = f"{perftune_file} --tune disks {dir_command} --dry-run --options-file {options_file}"
        output = Executor.run_command(command)

        if not output or output.returncode != 0:
            self.status = CollectorStatus.FAILED
            self._message = f"'{options_file}' contains invalid values"
            return

        self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

        # If we are running on any platform but Xen VM let's filter out NVMe cards IRQs' smp_affinity files because
        # kernel is not going to allow perftune.py to change their content.
        smp_affinity_files_to_skip = set()
        if vitals[self.__hypervisor_type_collector].data['hypervisor'] != 'xen':
            smp_affinity_files_to_skip = self.__get_nvme_smp_affinity_files(dir_data, perftune_file)

        self._data = {
            'perftune': {
                'files': {},
                'sysctl': {}
            },
            'files': {},
            'sysctl': {}
        }

        files_affected = Executor.search_string(r"^echo(\s+\S+\s*)+>", output.stdout.split("\n"))
        for file_affected in files_affected:
            # strings like "echo 00000001 > proc/irq/41/smp_affinity"
            # or "echo 493986 658648 987971 > /proc/sys/net/ipv4/tcp_mem"
            echo_value, file = file_affected.split(">", maxsplit=1)
            # echo_value is always "echo <token(s)>" because the regex requires \s+\S+ before '>',
            # so split(maxsplit=1)[1] is guaranteed to exist.
            value = echo_value.split(maxsplit=1)[1].strip()
            file = file.strip()
            if file not in smp_affinity_files_to_skip:
                try:
                    file_value = Executor.read_file_content(file)[0].strip("\n") if os.path.isfile(file) else None
                    if file_value is not None:
                        self._output.put(OutputEntryType.FILE, file, [f"{file_value}\n"], level=Level.VERBOSE)
                    self._data['perftune']['files'][file] = value
                    self._data['files'][file] = file_value
                # Reading a sysfs file can fail for at least two reasons: 'perftune.py --dry-run' may list
                # Rx/Tx queue files that vanish once the queue count is reduced, or a sysfs file
                # may exist but be inaccessible due to permissions or kernel restrictions.
                except (OSError, FileNotFoundError, PermissionError, IndexError) as e:
                    self._output.put(OutputEntryType.STDOUT, f"cat {file}", f"{e}",
                                     level=Level.VERBOSE)

        params_affected = Executor.search_string("^sysctl -w", output.stdout.split("\n"))
        for param_affected in params_affected:
            # strings like "sysctl -w net.core.rps_sock_flow_entries=32768"
            name, value = param_affected.split(maxsplit=2)[2].split('=', maxsplit=1)
            cmd = "sysctl " + name
            # Output is a string like "net.core.rps_sock_flow_entries = 0"
            current_value = Executor.run_command(cmd).stdout.split("\n")[0].split(maxsplit=2)[2]
            self._output.put(OutputEntryType.STDOUT, cmd, current_value, level=Level.VERBOSE)
            self._data['perftune']['sysctl'][name] = value
            self._data['sysctl'][name] = current_value

        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ['*']


class PerftuneYamlDefaultCollector(Collector):
    @property
    def name(self) -> str:
        return "Default content of perftune.yaml, generated by perftune.py"

    @property
    def __collector_systemwide(self) -> str:
        return "ScyllaSystemConfigurationFilesCollector"

    @property
    def skip_in_container(self) -> Optional[str]:
        return "perftune.py tunes the host, so defaults computed inside a container would not apply to it"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_systemwide}

    def _collect(self, vitals: DictView) -> None:
        scylla_server_config = vitals[self.__collector_systemwide].data['files'].get('scylla-server')

        if not scylla_server_config:
            self.status = CollectorStatus.FAILED
            self._message = "`scylla-server` config not found"
            return

        pt_parameters = ""

        nic = scylla_server_config.get('IFNAME', 'eth0')
        pt_parameters += f'--tune net --nic {nic}'

        if scylla_server_config.get('SET_CLOCKSOURCE', '').lower() == "yes":
            pt_parameters += ' --tune system --tune-clock'

        if scylla_server_config.get('DISABLE_WRITEBACK_CACHE', '').lower() == "yes":
            pt_parameters += ' --write-back-cache=false'

        perftune_py_path = os.path.join(self._paths['scylla_directory_scripts'], 'perftune.py')
        command = f"{perftune_py_path} {pt_parameters} --dump-options-file"
        perftune_output = Executor.run_command(command)

        if not perftune_output or perftune_output.returncode != 0:
            self.status = CollectorStatus.FAILED
            self._message = "perftune.py execution failed"
            if perftune_output:
                self._message += f": {perftune_output.stdout}"
            return

        self._output.put(OutputEntryType.STDOUT, command, perftune_output.stdout, level=Level.VERBOSE)

        command = f"{perftune_py_path} {pt_parameters} --get-cpu-mask"
        perftune_cpu_mask = Executor.run_command(command)
        self._output.put(OutputEntryType.STDOUT, command, perftune_cpu_mask.stdout, level=Level.VERBOSE)

        self._data = {
            'perftune.yaml': Executor.sort_dictionary(yaml.load(perftune_output.stdout, Loader=yaml.FullLoader)),
            'cpu_mask': perftune_cpu_mask.stdout
        }
        self.status = CollectorStatus.PASSED


class ScyllaExtraConfigurationFilesCollector(ScyllaConfigurationCollector):

    @property
    def name(self) -> str:
        return "Extra configuration files"

    @property
    def __identical_files(self) -> Set[str]:
        return {"cpuset.conf", "dev-mode.conf", "io_properties.yaml"}

    def _collect(self, vitals: DictView) -> None:
        dir = self._paths['scylla_directory_configs']
        if not os.path.isdir(dir):
            self.status = CollectorStatus.FAILED
            self._message = f"Scylla config directory {dir} is not found"
            return

        self._data['files'] = dict()
        all_extra_files = sorted(glob.glob(dir + "/*"))
        self._output.put(OutputEntryType.VALUE, f"Files in {dir}", f"{json.dumps(all_extra_files, indent=4)}",
                         level=Level.VERBOSE)
        for config_file in all_extra_files:
            if os.path.isdir(config_file):
                continue

            config_file_ext = os.path.splitext(config_file)[1].strip('.')
            # scylla-server.service reads every *.conf here as an environment file: it may hold AWS credentials or
            # flags such as --ldap-bind-passwd.
            parsed_file = self._redact_credentials(Executor.parse_config_file_to_dict(config_file, config_file_ext))
            filename = os.path.basename(config_file)
            self._data['files'][filename] = parsed_file

            # these files must be identical between all nodes, so we put them into detailed output for strict comparison
            if filename in self.__identical_files:
                self._output.put(OutputEntryType.PARSED_FILE, filename, parsed_file, level=Level.DETAILED)
            elif parsed_file:
                self._output.put(OutputEntryType.PARSED_FILE, filename, parsed_file, level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED


class SeastarCPUMapCollector(Collector):
    """
    Collect the output of 'seastar-cpu-map.sh -n scylla' and the shard to CPU mapping parsed out of it
    """
    @property
    def name(self) -> str:
        return "seastar-cpu-map.sh -n scylla"

    def _collect(self, vitals: DictView) -> None:
        # seastar-cpu-map.sh finds scylla with pgrep and reads each shard's CPU affinity with taskset. Its own output
        # does not say when one is missing, so check both up front.
        if not self._require_tools('pgrep', 'taskset'):
            return

        short_command = "seastar-cpu-map.sh -n scylla"
        full_command = f"{self._paths['scylla_directory_scripts']}/{short_command}"
        output = Executor.run_command(full_command)
        self._output.put(OutputEntryType.STDOUT, short_command, output.stdout, level=Level.VERBOSE)

        # seastar-cpu-map.sh prints a line per shard, e.g. "shard: 0, cpu: 0" or "shard: 0, cpu: 0,16"
        shard_cpu_map = {shard: cpu
                         for shard, cpu in re.findall(r"^shard:\s*(\d+),\s*cpu:\s*(\S+)",
                                                      output.stdout, re.MULTILINE)}
        if not shard_cpu_map:
            self.status = CollectorStatus.FAILED
            self._message = f"No shard to CPU mapping could be parsed out of '{short_command}' output"
            return

        self._data = {'shard_cpu_map': shard_cpu_map}
        self._output.put(OutputEntryType.VALUE, "shard to CPU mapping",
                         ", ".join(f"shard {shard}: CPU {cpu}"
                                   for shard, cpu in sorted(shard_cpu_map.items(), key=lambda item: int(item[0]))),
                         level=Level.DETAILED)
        self.status = CollectorStatus.PASSED
