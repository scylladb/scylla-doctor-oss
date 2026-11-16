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
import ipaddress
import pathlib
import socket

from typing import Set, Iterable, Union, Sequence

from common import DictView
from collectors_base import CollectorStatus, Collector, PERMISSION_REFUSED_RE
from models.output_entry import OutputEntryType, Level

from utils import Executor, running_in_container


class FirewallRulesCollector(Collector):
    @property
    def include_output_default(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "Gather firewall rules"

    @property
    def privileged(self) -> bool:
        return True

    def _collect(self, vitals: DictView) -> None:
        command = "iptables -L -v"
        rules = Executor.run_command(command, check=False)
        if rules.returncode == 0:
            self.status = CollectorStatus.PASSED
            self._output.put(OutputEntryType.STDOUT, command, rules.stdout, level=Level.VERBOSE)
            # iptables lists the network namespace it runs in: the node's with --network host, the container's own
            # otherwise. Both apply to bridged traffic, so keep the listing and say what it is.
            if running_in_container():
                self._message = "Rules of this container's network namespace, which are the node's only with " \
                                "--network host"
            return

        # iptables needs CAP_NET_ADMIN over the network namespace it runs in; unprivileged Docker and Podman drop
        # that capability by default ("Permission denied (you must be root)", exit 4). Try first, skip only a
        # refused container; other errors (missing table, nft/legacy mismatch) stay FAILED.
        if running_in_container() and PERMISSION_REFUSED_RE.search(rules.stderr):
            self.status = CollectorStatus.SKIPPED
            self._message = "Firewall rules not collected: iptables needs CAP_NET_ADMIN, which this container lacks " \
                            f"(run it with --cap-add NET_ADMIN): {rules.stderr.strip()}"
            return

        self.status = CollectorStatus.FAILED
        self._message = f"`iptables` call failed. Please check it: `{command}`: {rules.stderr.strip()}"


class IPAddressesCollector(Collector):
    @property
    def include_output_default(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "Network interface controller addresses"

    @property
    def __collector(self):
        return "NICsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        for nic in vitals[self.__collector].data['nics']:
            command = f"ip addr show {nic}"
            content = Executor.run_command(command)
            self._output.put(OutputEntryType.STDOUT, command, content.stdout, level=Level.VERBOSE)

        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ['*']


class IPRoutesCollector(Collector):
    @property
    def name(self) -> str:
        return "IP routing"

    @property
    def __collector(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        addresses = {
            vitals[self.__collector].data['listen_address']['value'],
            vitals[self.__collector].data['broadcast_address']['value'],
            vitals[self.__collector].data['rpc_address']['value'],
            vitals[self.__collector].data['broadcast_rpc_address']['value'],
            vitals[self.__collector].data['api_address']['value']
        }

        for address in addresses:
            if address:
                ip_addr = ipaddress.ip_address(address if address != "localhost" else "127.0.0.1")
                if not ip_addr.is_loopback:
                    cmd = f"ip {'-6' if isinstance(ip_addr, ipaddress.IPv6Address) else ''} route show match {address}"
                    self._data[address] = Executor.run_command(cmd).stdout
                    self._output.put(OutputEntryType.STDOUT, cmd, self._data[address], level=Level.VERBOSE)
        self.status = CollectorStatus.PASSED

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ['*']


class NICsCollector(Collector):
    @property
    def name(self) -> str:
        return "Gather all available NICs"

    @property
    def __default_skip_nics(self) -> Set[str]:
        # Loopback and virtual/tunnel interfaces that do not support ethtool (e.g. exit 75 "No data available").
        return {'lo', 'erspan0', 'gre0', 'gretap0', 'sit0', 'ip6tnl0'}

    def _collect(self, vitals: DictView) -> None:
        if not self._require_tools('ethtool'):
            return

        skip_nics = self.__default_skip_nics | self._parse_comma_separated_config('skip_nics')

        self._data['nics'] = dict()
        for nic_path in sorted(glob.glob("/sys/class/net/*")):
            nic_pathlib_path = pathlib.Path(nic_path)

            # NICs are represented by symlinks in /sys/class/net/. Let's skip everything other than symlinks.
            if not nic_pathlib_path.is_symlink():
                continue

            nic = nic_pathlib_path.name

            if nic in skip_nics:
                continue

            command_i = f"ethtool -i {nic}"
            output_i = Executor.run_command(command_i)
            self._output.put(OutputEntryType.STDOUT, command_i, output_i.stdout, level=Level.VERBOSE)

            command = f"ethtool {nic}"
            output = Executor.run_command(command)
            self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)

            driver, speed = None, None
            if output_i:
                driver_line = Executor.search_string(r"^driver: ", output_i.stdout.split("\n"))
                driver = driver_line[0].split()[1] if driver_line else None

            if output:
                speed_line = Executor.search_string(r"Speed:", output.stdout.split("\n"))
                if speed_line:
                    speed_str = speed_line[0].split()[1]
                    speed = None if speed_str == "Unknown!" else int(speed_str.replace('Mb/s', ''))

            self._data['nics'][nic] = {
                'driver': driver,
                'speed': speed
            }

        self.status = CollectorStatus.PASSED

    @property
    def legacy_data(self) -> dict:
        return {
            'specs': {
                'network': self._data
            }
        }

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        Exclude this Collector from drifts checking due to false alarms.
        """
        return ['*']


class ScyllaSeedsCollector(Collector):
    @property
    def name(self) -> str:
        return "Scylla seeds"

    @property
    def __collector(self) -> str:
        return "ScyllaConfigurationFileCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector}

    def _collect(self, vitals: DictView) -> None:
        scylla_config = vitals[self.__collector].data
        seed_provider = scylla_config.get('seed_provider')
        if not seed_provider:
            self.status = CollectorStatus.FAILED
            self._message = "'seed_provider' was not set"
            return

        try:
            detected_seeds = seed_provider[0]['parameters'][0]['seeds'].split(",")
        except Exception:
            self.status = CollectorStatus.FAILED
            self._message = "Malformed of scylla.yaml file: 'seeds' field is not properly defined!"
            return

        use_ssl = scylla_config.get('server_encryption_options', {}).get('internode_encryption', 'none') != 'none'
        rpc_port = scylla_config['ssl_storage_port'] if use_ssl else scylla_config['storage_port']

        for seed in detected_seeds:
            seed = seed.strip()
            if not seed:
                continue
            host = seed[1:-1] if seed.startswith('[') and seed.endswith(']') else seed
            self._data[seed] = self.__connect_seed(host, rpc_port)
        self.status = CollectorStatus.PASSED

    @staticmethod
    def __connect_seed(host: str, port: int) -> int:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return 0
        except socket.gaierror:
            return -1
        except OSError as e:
            return e.errno if e.errno is not None else -1


class TCPConnectionsCollector(Collector):
    @property
    def include_output_default(self) -> bool:
        return True

    @property
    def name(self) -> str:
        return "TCP connections"

    def _collect(self, vitals: DictView) -> None:
        command = "ss --all --tcp"
        output = Executor.run_command(command)
        if not output or not output.stdout:
            self.status = CollectorStatus.FAILED
            self._message = "'ss' usage failed"
        else:
            self._output.put(OutputEntryType.STDOUT, command, output.stdout, level=Level.VERBOSE)
            self.status = CollectorStatus.PASSED
