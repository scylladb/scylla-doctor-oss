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

from common import DictView, Paths, ConfigValuesParser, ConfigParameter
from models.output_entry import OutputEntry, OutputEntryType, Level
from typing import Any, Dict, List, Optional, Set, Sequence, Tuple, Union, Iterable, Type, Generic, TypeVar
import abc
import dataclasses
import enum
import json
import os
import pathlib
import re
import shutil
from utils import Executor, running_in_container


# How dmesg and iptables report a missing capability, as opposed to any other failure.
PERMISSION_REFUSED_RE = re.compile(r"Operation not permitted|Permission denied|you must be root")


class UnableToReadScyllaRestApi(Exception):
    pass


class UnsupportedRestApiEndpoint(Exception):
    pass


class Output:
    """Collector diagnostic/verbose entries. When disabled, put() is a no-op (no memory retained)."""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.output: List[OutputEntry] = []

    def put(self, type: OutputEntryType, name: str, value, level: Level = Level.DEFAULT):
        if not self.enabled:
            return

        # validate values
        if type in (OutputEntryType.STDOUT, OutputEntryType.API, OutputEntryType.VALUE):
            if not isinstance(value, str):
                raise TypeError(f"Values should be strings for {type.name}")
        elif type == OutputEntryType.CQL:
            if not (isinstance(value, str) or isinstance(value, list)):
                raise TypeError(f"Values should be strings or lists for {type.name}")
        elif type == OutputEntryType.PARSED_FILE:
            if not isinstance(value, dict):
                raise TypeError(f"Values should be dictionaries for {type.name}")
        elif type == OutputEntryType.FILE:
            if not isinstance(value, list):
                raise TypeError(f"Values should be lists for {type.name}")

        self.output.append(OutputEntry(level, type, name, value))

    def __iter__(self):
        return iter(self.output)

    def __len__(self):
        return len(self.output)


class CollectorStatus(enum.Enum):
    PASSED = 0
    FAILED = 1
    SKIPPED = 2

    def __bool__(self):
        raise NotImplementedError(
            f"Implicit cast to boolean is not allowed. Use explicit comparison to {self.__class__.__name__} values instead.")  # noqa: E501


@dataclasses.dataclass(frozen=True)
class CollectorResult:
    status: CollectorStatus
    data: Dict[str, Any]
    output: Output
    message: str
    # Mask can include a data key to be filtered or an iterable that represents
    # a "path" to a key to be filtered when data is a nested dictionary.
    #
    # For example:
    #
    # If data has data['k1']['k2'] and data['k3'] to filter both these values
    # a mask can be as follows:
    #
    # mask = [('k1', 'k2'), 'k3']
    #
    # If a mask key value equals '*' it matches any key.
    # Note that [('*','*','*')] mask is not equal to [('*', '*')] or to ['*'].
    #
    # [('*','*','*')] is going to delete all keys of a 3-levels deep nested dictionaries.
    #
    # For example if
    # data = {
    #         "k0" : { "k2" : "6" },
    #         "k1" : { "k2" : {"k2" : "3",
    #                          "k4" : "4"},
    #                  "k3":  {"k2": "3",
    #                          "k3": "4"}
    #                  },
    #         "k3" : {},
    #         "k2" : "4",
    #         }
    # Filtering with [('*','*','*')] will result in
    # data = {
    #         "k0": { "k2": "6" },
    #         "k1": { "k2": {},
    #                 "k3": {}
    #               },
    #         "k3": {},
    #         "k2": "4"
    # }
    mask: Sequence[Union[str, Iterable]] = dataclasses.field(default_factory=list)

    @property
    def skip_reason(self) -> str:
        """
        The message without the "Required ... was skipped: " prefixes of dependency chains, so that dependents repeat
        only the root reasons instead of the whole chains.
        """
        return re.sub(r"Required \S+ Collector was skipped: ", "", self.message or "")

    class Encoder(json.JSONEncoder):
        def __init__(self, *, include_output: bool = True, **kwargs):
            super().__init__(**kwargs)
            self.include_output = include_output

        def default(self, o):
            if isinstance(o, CollectorResult):
                return o.as_dict(self.include_output)
            if isinstance(o, enum.Enum):
                return o.value
            if isinstance(o, OutputEntry):
                return {
                    'level': o.level.value,
                    'type': o.type.value,
                    'name': o.name,
                    'value': o.value
                }
            if isinstance(o, Output):
                return o.output
            if hasattr(o, "__dict__"):
                return o.__dict__
            if isinstance(o, set):
                return list(o)
            return json.JSONEncoder.default(self, o)

    @staticmethod
    def decode(json_obj: Dict, extra_mask: Optional[Sequence[Union[str, Iterable]]] = None) -> "CollectorResult":
        """
        Sample json, generated by CollectorResult.Encoder:
        {
            "status": 0,
            "data": {...},
            "output": [{
                    "level": 1,
                    "type": "Command output",
                    "name": "dpkg -l",
                    "value": "..."
                }],
            "message": "Data collected"
        }
        ``output`` is optional (omitted by default in --save-vitals); missing means empty.
        """
        try:
            for key in ['status', 'message', 'data']:
                if key not in json_obj:
                    raise ValueError(f"{key} is missing")
            output_list = json_obj.get('output', [])
            if type(output_list) is not list:
                raise ValueError("Invalid output")
            output = Output()
            for output_entry in output_list:
                for key in ['type', 'name', 'value', 'level']:
                    if key not in output_entry:
                        raise ValueError(f"{key} is missing in output")
                output.put(
                    OutputEntryType(output_entry['type']),
                    output_entry['name'],
                    output_entry['value'],
                    level=Level(output_entry['level'])
                )
            return CollectorResult(
                status=CollectorStatus(json_obj['status']),
                data=json_obj['data'],
                output=output,
                message=json_obj['message'],
                mask=json_obj.get('mask', []) + (list(extra_mask) if extra_mask is not None else [])
            )
        except Exception as e:
            raise ValueError(f"Cannot parse to CollectorResult: {str(e)}, {str(json_obj)}")

    def as_dict(self, include_output: bool = True) -> dict:
        """Plain dict for JSON encoding; ``output`` dropped unless requested (see Doctor.save_vitals)."""
        d = {f.name: getattr(self, f.name) for f in dataclasses.fields(self)}
        if not include_output:
            d.pop('output', None)
        return d

    @staticmethod
    def any_key_mask():
        return "*"

    def strip(self):
        """
        Remove all info that is not relevant for strict comparison - verbose outputs, masked keys, etc.
        """

        # strip verbose-level output and higher
        self.output.output = [entry for entry in self.output.output if entry.level < Level.VERBOSE]

        # strip `masked` keys from data
        for key in self.mask:
            if isinstance(key, str):
                # if we have a '*' in mask keys - we need to filter out all keys
                if key == self.any_key_mask():
                    self.data.clear()
                    return self

                if key in self.data:
                    del self.data[key]
            elif isinstance(key, Iterable):
                self.__filter_nested_key(key_path=key)

        return self

    def __filter_nested_key(self, key_path: Iterable) -> None:
        """
        Filter out a nested map entry given a "path" to it.
        If a specific item in the "path" is '*' it matches any key at the corresponding level.
        :param key_path: an iterable that represents a keys "path" to the entry to be filtered
        """
        mask_list = list(key_path)
        # Sanity: empty mask
        if not mask_list:
            return

        CollectorResult.do_filter_nested_key(self.data, mask_list)

    @staticmethod
    def do_filter_nested_key(m: Any, mask_list: List[str]) -> None:
        # Recursion stop conditions:

        # Not a dictionary
        if not isinstance(m, dict):
            return

        # Empty dictionary
        if not m:
            return

        mask_key = mask_list[0]
        # Last item in the mask
        if len(mask_list) == 1:
            # '*' mask - delete the whole value
            if mask_key == CollectorResult.any_key_mask():
                m.clear()
            elif mask_key in m:
                del m[mask_key]

            return

        # So m is a not empty dict and mask_list has more than one item: let's dive into recursion
        new_mask_list = mask_list[1:]

        # (..., '*', ...) case: let's filter every value in m
        if mask_key == CollectorResult.any_key_mask():
            for k, v in m.items():
                CollectorResult.do_filter_nested_key(v, new_mask_list)
        # specific key case
        elif mask_key in m:
            CollectorResult.do_filter_nested_key(m[mask_key], new_mask_list)
        # "no match" branch - break recursion
        else:
            return


class Collector(ConfigValuesParser, abc.ABC):
    """Collectors are meant to gather information from the host and store it in vitals for further analysis"""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Human-readable name. Must be specified. """
        pass

    @property
    def privileged(self) -> bool:
        """Set to True if the test requires root privileges to succeed. """
        return False

    @property
    def skip_in_container(self) -> Optional[str]:
        """
        Why this Collector is skipped inside a container, or None if it runs there. Collectors that read host state a
        container usually cannot see return a reason, and the base class puts it in the skip message.
        """
        return None

    @property
    def depends_on(self) -> Set[str]:
        """Set of other Collectors id's, that must be launched before-hands"""
        return set()

    @property
    def mask(self) -> Sequence[Union[str, Iterable]]:
        """
        List of keys that should be stripped from Collector result.data before comparing different results

        Mask can include a data key to be filtered or an iterable that represents
        a "path" to a key to be filtered when data is a nested dictionary.

        For example:

        If data has data['k1']['k2'] and data['k3'] to filter both these values
        a mask can be as follows:

        mask = [('k1', 'k2'), 'k3']
        """
        return []

    _status: Optional[CollectorStatus]
    _data: Union[Dict[str, Any], Any]
    _output: Output
    _message: str

    def __init__(self, configuration: DictView, paths: Paths):
        self._status = None
        self._data = dict()
        self._output = Output()
        self._message = self.__default_message

        self._config = configuration.get(self.id, {})
        self._paths = paths

    @property
    def include_output_default(self) -> bool:
        """
        Override to return True on collectors whose useful payload lives in `output` (raw command text that has no
        structured `data` counterpart): their output is then retained and saved in vitals even without the global
        --include-output.
        """
        return False

    @property
    def include_output(self) -> bool:
        """
        Per-collector opt-in to keep `output` in --save-vitals; OR-ed with the global --include-output, so `no` only
        matters when the global switch is off. `[<Collector>] include_output` overrides the class default.
        :raise ValueError: on a value outside the documented yes/no sets, so a typo cannot silently drop a payload.
        """
        raw = self.config.get('include_output', '').strip().lower()
        if not raw:
            return self.include_output_default
        if raw in ("1", "yes", "true", "on"):
            return True
        if raw in ("0", "no", "false", "off"):
            return False
        raise ValueError(f"[{self.id}] include_output: invalid value '{raw}', expected yes/no")

    @property
    def config_parameters(self) -> Dict[str, ConfigParameter]:
        params = super().config_parameters
        params['include_output'] = ConfigParameter(
            description='Set to 1/yes/true/on to keep this collector\'s `output` in --save-vitals even without the '
                        'global --include-output; no/0/false/off omits it unless the global switch is on.',
            default_description='yes' if self.include_output_default else 'unset (omitted unless --include-output)',
        )
        return params

    def set_store_output(self, enabled: bool) -> None:
        """Collector-wide: whether put() retains diagnostic entries."""
        self._output.enabled = enabled

    @property
    def config(self) -> DictView:
        return self._config

    @property
    def __default_message(self) -> str:
        return "Data collected"

    @property
    def output(self) -> Output:
        return self._output

    @property
    def id(self) -> str:
        return self.__class__.__name__

    @property
    def config_run_parameter(self):
        return "run"

    @property
    def config_run_skip_values(self):
        return ["0", "no", "false", "off"]

    @property
    def run(self):
        return self.config.get(self.config_run_parameter, '').lower() not in self.config_run_skip_values

    @property
    def status(self) -> CollectorStatus:
        if not self.executed:
            raise AttributeError(f"Status is empty, probably {self.id} was never executed")
        return self._status  # type: ignore[return-value]

    @status.setter
    def status(self, value: CollectorStatus):
        if not isinstance(value, CollectorStatus):
            cls = __class__  # type: ignore[name-defined]
            raise TypeError(f"{cls}.status must be an instance of {cls}.Status enum")
        self._status = value

    @property
    def executed(self) -> bool:
        return self._status is not None

    def has_required_privileges(self) -> bool:
        return not self.privileged or os.getuid() == 0

    def _require_tools(self, *tools: str) -> bool:
        """
        Check that every tool is on PATH. A missing tool is a packaging gap on this node or image, not a finding
        about the node, so the Collector is SKIPPED and names the missing tools; it never FAILS for this.
        :return: True when all tools are available; otherwise status and message are set and False is returned.
        """
        missing = [tool for tool in tools if not shutil.which(tool)]
        if not missing:
            return True
        self.status = CollectorStatus.SKIPPED
        self._message = f"{', '.join(repr(tool) for tool in missing)} not installed"
        return False

    def collect(self, vitals: Dict[str, CollectorResult], available_collectors: Dict[str, Any]) -> None:
        return self._collect_recursive(vitals, available_collectors)

    def _collect_recursive(self,
                           vitals: Dict[str, CollectorResult],
                           available_collectors: Dict[str, Any],
                           dependency_chain: Optional[Set[str]] = None) -> None:
        if dependency_chain is None:
            dependency_chain = set()

        name = self.__class__.__name__
        if name in dependency_chain:
            raise RecursionError(f"Endless dependency cycle detected for {name}")
        dependency_chain.add(name)

        if self.id in vitals:
            return

        if not self.run:
            self.status = CollectorStatus.SKIPPED
            self._message = "Disabled in configuration"
            vitals[self.id] = self.result
            return

        if not self.has_required_privileges():
            self.status = CollectorStatus.SKIPPED
            self._message = "Insufficient privileges, please run as root"
            vitals[self.id] = self.result
            return

        container_skip_reason = self.skip_in_container
        if container_skip_reason is not None and running_in_container():
            self.status = CollectorStatus.SKIPPED
            self._message = f"Not available for containers: {container_skip_reason}"
            vitals[self.id] = self.result
            return

        available_collectors_names = set(available_collectors.keys())
        if not self.depends_on.issubset(available_collectors_names):
            missing_deps = self.depends_on - available_collectors_names
            raise Exception(f"Dependencies are not available for {self.__class__.__name__}: {missing_deps}")

        error_messages = []
        dependency_failed = False
        dependency_skipped = False
        for dep in self.depends_on:
            if dep not in vitals:
                available_collectors[dep]._collect_recursive(vitals, available_collectors,
                                                             dependency_chain=dependency_chain)

            if vitals[dep].status == CollectorStatus.FAILED:
                dependency_failed = True
                error_messages.append(f"Required {dep} Collector has not run successfully")
            elif vitals[dep].status == CollectorStatus.SKIPPED:
                dependency_skipped = True
                error_messages.append(f"Required {dep} Collector was skipped: {vitals[dep].skip_reason}")

        # If any dependency was skipped - skip the current Collector as well, even if any other dependency failed.
        # Skipped status means that either the user disabled the dependency in configuration, or the HW/SW state doesn't
        # allow to run it (e.g. insufficient privileges, missing files, etc.).
        # In this case the current Collector should be skipped as well, because it effectively means that same reasons
        # don't allow it to be executed too.
        # Otherwise, if any dependency failed - fail the current Collector as well.
        if dependency_skipped:
            self.status = CollectorStatus.SKIPPED
            self._message = ", ".join(error_messages)
            vitals[self.id] = self.result
            return
        elif dependency_failed:
            self.status = CollectorStatus.FAILED
            self._message = ", ".join(error_messages)
            vitals[self.id] = self.result
            return

        try:
            self._collect(DictView(vitals, self.depends_on))
        except Exception as e:
            # If a 'status' has already been set - do not override it unless it's 'PASSED'.
            # We want to prevent from a Collector being marked as 'SUCCESS' if it raised an exception.
            # We bypass public 'status' getter here to avoid unnecessary sanity checks.
            if self._status is None or self._status == CollectorStatus.PASSED:
                # subprocess raises FileNotFoundError with the bare command name; a missing file carries a path.
                # This assumes collectors open files by absolute path: a relative one would look like a command.
                if isinstance(e, FileNotFoundError) and isinstance(e.filename, str) and os.sep not in e.filename:
                    # Same rule as _require_tools: a tool that is not installed is skipped, not a failure.
                    self.status = CollectorStatus.SKIPPED
                    self.message = f"'{e.filename}' not installed"  # type: ignore[attr-defined]
                    vitals[self.id] = self.result
                    return
                self.status = CollectorStatus.FAILED

            self.message = f"Unexpected exception: {str(e)}"
        vitals[self.id] = self.result

    @abc.abstractmethod
    def _collect(self, vitals: DictView) -> None:
        """
        Should store in self._data some new information for further analysis.
        In case of errors should store some quick hint for the user in self._message
        Only vitals gathered by Collectors specified in depends_on will be passed as input.
        Any additional information (e. g. for debugging purposes) should be stored in self._output
        """
        pass

    @property
    def result(self) -> CollectorResult:
        return CollectorResult(self.status, self._data, self._output, self._message, self.mask)

    @property
    def message(self) -> str:
        return self._message

    @message.setter
    def message(self, msg: str) -> None:
        self._message = msg


class ScyllaConfigurationCollector(Collector, abc.ABC):
    """
    Base of the collectors reading Scylla's configuration: scylla.yaml, the sysconfig files, the /etc/scylla.d drop-ins
    and system.config. Credentials never reach the vitals or the verbose output (DOCTOR-130): a subclass passes what
    it read through _redact_credentials(), which keeps the structure and replaces each credential with redacted_value.
    """

    @property
    def secret_keys(self) -> Set[str]:
        """
        Configuration keys holding a credential, matched case-insensitively at any depth: the AWS keys of kms_hosts
        and the AWS environment variables of an environment file (object_storage_endpoints takes its credentials from
        them, not from keys of its own), and the azure_hosts client secret. A key ending in one of
        secret_key_suffixes is one too.
        """
        return {'aws_access_key_id', 'aws_secret_access_key', 'aws_session_token', 'azure_client_secret'}

    @property
    def secret_key_suffixes(self) -> Tuple[str, ...]:
        """
        How the other credential keys end: the kmip_hosts password, ldap_bind_passwd, auth_superuser_salted_password,
        the keystore_password of a scylla.yaml copied from Cassandra, the keyStorePassword JMX flag.
        """
        return ('password', 'passwd')

    @property
    def redacted_value(self) -> str:
        return '<redacted>'

    def _redact_credentials(self, config: Any) -> Any:
        """
        Return a copy of config with every credential redacted: the entries of a dict at any depth, and the values of
        secret keys and flags inside a string (see _redact_credentials_in_text).
        """
        if isinstance(config, dict):
            return {key: self._redact_credentials_in_entry(key, value) for key, value in config.items()}
        if isinstance(config, list):
            return [self._redact_credentials(value) for value in config]
        if isinstance(config, str):
            return self._redact_credentials_in_text(config)
        return config

    def _redact_credentials_in_entry(self, key: Any, value: Any) -> Any:
        """
        The value a configuration entry keeps: redacted_value for a set secret key, otherwise the value with any
        credential inside it redacted.

        :param key: the entry's key: a configuration parameter, environment variable or flag name, matched
                    case-insensitively against secret_keys and secret_key_suffixes when it is a string.
        :param value: the entry's value as parsed: a string, a nested dict or list, or None when unset.
        """
        # The last word of the key: an environment file line `export AWS_SECRET_ACCESS_KEY=x` reaches here with the
        # key `export AWS_SECRET_ACCESS_KEY`.
        name = key.split()[-1].lower() if isinstance(key, str) and key.strip() else None
        is_secret_key = name is not None and (name in self.secret_keys or name.endswith(self.secret_key_suffixes))
        # An unset secret stays as it is (None, or how YAML spells it when loaded as strings, in any case), so
        # analyzers can still tell the credential is not configured.
        unset = value is None or (isinstance(value, str) and value.lower() in ('', "''", '""', 'null', '~'))
        if is_secret_key and not unset:
            return self.redacted_value
        return self._redact_credentials(value)

    def _redact_credentials_in_text(self, text: str) -> str:
        """
        Replace the value of every secret key or flag in text, in both forms it comes in:
        - a flag or an environment variable, `--ldap-bind-passwd=x` in SCYLLA_ARGS or `AWS_SECRET_ACCESS_KEY=x`: a
          quoted value goes whole; a bare one up to the next flag, as the sysconfig parser removes double quotes;
        - a key in JSON or flow-style YAML, `"aws_access_key_id": "x"`, also inside a JSON string such as the one
          system.config prints for object_storage_endpoints (`\"aws_access_key_id\": \"x\"`, with two backslashes
          once cqlsh COPY has doubled them): a quoted value goes whole, escaped quotes included; a bare one, spaces
          included, up to the next comma, closing bracket or end of line.
        An unset value (null, ~, empty quotes) stays, as in _redact_credentials_in_entry.
        """
        names = (r'(?:' + '|'.join(k.replace('_', '[_-]') for k in sorted(self.secret_keys)) +
                 r'|[\w.-]*(?:' + '|'.join(self.secret_key_suffixes) + r'))\b')
        key = r'\b' + names
        # Only a flag takes its value after a space: prose such as `change the password for x` is kept.
        flag = r'(?<![\w.-])--?' + names
        # Empty quotes escaped with up to two backslashes too: an unset value in JSON inside a JSON string.
        unset = r'(?!(?:null|~|\\{0,2}"\\{0,2}"|\'\')(?:[\s,}\]\\]|$))'
        quoted = r'"(?:\\.|[^"\\])+"|\'(?:\'\'|[^\'])+\''
        # A JSON string inside a JSON string: its quotes carry one backslash as Scylla prints it, two once cqlsh COPY
        # (behind read_cql_table) has doubled every backslash; inside it a backslash carries twice as many and a quote
        # three times as many backslashes as its quotes.
        escaped = (r'\\"(?:\\{4}|\\{3}"|\\{2}[^"\\]|[^"\\])+\\"'
                   r'|\\{2}"(?:\\{8}|\\{6}"|\\{4}[^"\\]|[^"\\])+\\{2}"')
        # After `=` the value may start with `--` (`--ldap-bind-passwd=--x`); after a space, `--` is the next flag.
        # A bare value stops before a word starting with `-`, so a JVM flag after it (`-Dfoo=bar`) is kept: the rest
        # of a bare value with such a word in it (`--ldap-bind-passwd a -b`) is not redacted. A bare value stays on its
        # line, so the lines after it in a multi-line value are kept. It does not stop at a comma: a password may hold
        # one, so `key=value` in a comma-separated mapping loses the rest of the line (over-redaction, never a leak).
        space = r'[^\S\n]'
        text = re.sub(rf'({key}{space}*=(?:{space}+(?!--))?|{flag}{space}+(?!--)){unset}'
                      rf'(?:{quoted}|\S+(?:{space}+(?!-)\S+)*)',
                      rf'\g<1>{self.redacted_value}', text, flags=re.IGNORECASE)
        bare = r'[^\s,}\]"\']+(?:[^\S\n]+[^\s,}\]"\']+)*'
        return re.sub(rf'({key}(?:\\{{0,2}}["\'])?\s*:\s*){unset}(?:{escaped}|\\?(?:{quoted})|{bare})',
                      rf'\g<1>{self.redacted_value}', text, flags=re.IGNORECASE)


class ScyllaRestApiAwareCollector(Collector, abc.ABC):
    """
    Base class for Collectors that need to read data from Scylla REST API.
    """

    def _read_scylla_rest_api(self, endpoint: str, api_address: str, api_port: int,
                              endpoint_parameters: Optional[str] = None, timeout: int = 2) -> Any:
        """
        Read Scylla REST API endpoint
        :param endpoint: REST API endpoint path, e.g. "/system/some_endpoint"
        :param api_address: REST API address
        :param api_port: REST API port
        :param endpoint_parameters: Optional endpoint parameters to append to the endpoint URL.
                                    This URL suffix is not part of the endpoint API definition and is not checked for
                                    support.
                                    It can be used to add query parameters, e.g. "?param1=value1&param2=value2" or
                                    whatever the endpoint syntax supports.
        :param timeout: Timeout in seconds
        :return: A dictionary with the parsed JSON response
        :raise UnableToReadScyllaRestApi: if unable to read the Scylla REST API
        :raise UnsupportedRestApiEndpoint: if the given endpoint is not supported
        :raise ValueError: if the output format of the swagger endpoint is unexpected or if the endpoint format is
                           invalid
        """
        def __error(message: str, collector_status: CollectorStatus, exception_type: Type) -> None:
            self.status = collector_status
            raise exception_type(message)

        endpoint_parsed = pathlib.PurePosixPath(endpoint)
        endpoint_parts = endpoint_parsed.parts

        if not endpoint_parsed.root:
            __error(f"Invalid endpoint: {endpoint}. Endpoint must be an absolute path starting with '/'",
                    CollectorStatus.FAILED, ValueError)

        # Endpoint can not be "/"
        if len(endpoint_parts) == 1:
            __error(f"Invalid endpoint: {endpoint}", CollectorStatus.FAILED, ValueError)

        endpoint_base = pathlib.PurePosixPath(endpoint_parts[0]) / endpoint_parts[1]

        def rest_endpoint_is_supported(swagger_endpoint: str, endpoint_to_check: str) -> bool:
            """
            Scylla supported REST API endpoints query URLs return a swagger-like JSON objects that have an "apis" field
            with a list of dictionaries with a "path" field with a supported endpoint name.

            For example:

            {
              "apiVersion": "0.0.1",
              "swaggerVersion": "1.2",
              "apis": [
                {
                  "path": "/system",
                  "description": "The system related API"
                },
                {
                  "path": "/error_injection",
                  "description": "The error injection API"
                },
                ...
              ]
            }

            This function checks if a given endpoint is supported by the Scylla REST API.

            :param swagger_endpoint: Scylla REST API endpoint that returns a swagger-like JSON object with a list of
                                     supported endpoints
            :param endpoint_to_check: REST API endpoint to check if supported
            :return: True if supported, False otherwise
            :raise UnableToReadScyllaRestApi: if unable to read the Scylla REST API
            :raise ValueError: if the output format of the swagger endpoint is unexpected or if the endpoint format is
                               invalid
            """
            url = f'http://{api_address}:{api_port}/{swagger_endpoint.strip("/")}/'
            read_url_value = Executor.get_url_content(url, timeout=timeout)
            if read_url_value is None:
                __error(f"Unable to read Scylla REST API: {url}", CollectorStatus.FAILED, UnableToReadScyllaRestApi)

            supported_endpoints = json.loads(read_url_value).get("apis")  # type: ignore[arg-type]
            if not supported_endpoints:
                __error(f"Unexpected output format of {url} endpoint: 'apis' field is missing",
                        CollectorStatus.FAILED, ValueError)

            return any(supported_api_item.get("path") == str(endpoint_to_check) for
                       supported_api_item in supported_endpoints)

        # Check if a given REST API base endpoint is supported.
        # Reading from /api-doc/ endpoint returns a swagger-like JSON with a list of supported endpoints like this:
        if not rest_endpoint_is_supported("/api-doc/", str(endpoint_base)):
            __error(f"Unsupported REST API endpoint base: {endpoint_base}",
                    CollectorStatus.SKIPPED, UnsupportedRestApiEndpoint)

        # Check if a given REST API full endpoint is supported
        if not rest_endpoint_is_supported(f"/api-doc/{endpoint_parts[1]}/", endpoint):
            __error(f"Unsupported REST API endpoint: {endpoint}", CollectorStatus.SKIPPED,
                    UnsupportedRestApiEndpoint)

        # Read the endpoint content
        url = f'http://{api_address}:{api_port}{endpoint}'
        if endpoint_parameters:
            url += f'{endpoint_parameters}'
        read_url_value = Executor.get_url_content(url, timeout=timeout)
        if read_url_value is None:
            __error(f"Unable to read Scylla REST API: {url}", CollectorStatus.FAILED, UnableToReadScyllaRestApi)

        parsed = json.loads(read_url_value)  # type: ignore[arg-type]
        self.output.put(OutputEntryType.API, url, json.dumps(parsed, indent=4), level=Level.VERBOSE)

        return parsed


T = TypeVar("T")


class ScyllaSimplePerTableRestApiCollector(ScyllaRestApiAwareCollector, Generic[T], abc.ABC):
    """
    Base class for Scylla REST API collectors that collect per-table information
    where the endpoint returns a simple value (int, float, etc.).
    The specific endpoint is defined in the subclass.
    The collected data is a nested dictionary mapping keyspace names to table names to the collected value.
    E.g.:
    {
        "keyspace1": {
            "table1": value1,
            "table2": value2,
            ...
        },
        "keyspace2": {
            "table3": value3,
            ...
        },
        ...
    }

    The REST API endpoint is expected to be of the form: /<endpoint>/{keyspace}:{table}
    """
    @property
    @abc.abstractmethod
    def _endpoint(self) -> str:
        pass

    @abc.abstractmethod
    def _endpoint_value_converter(self, value: str) -> T:
        pass

    @property
    def __collector_tables_description(self) -> str:
        return "ScyllaClusterTablesDescriptionCollector"

    @property
    def __collector_scylla_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_tables_description, self.__collector_scylla_config}

    def _collect(self, vitals: DictView) -> None:
        api_address = vitals[self.__collector_scylla_config].data['api_address']['value']
        api_port = int(vitals[self.__collector_scylla_config].data['api_port']['value'])

        tables_endpoint_info: Dict[str, Dict[str, T]] = {}
        tables_description_info = vitals[self.__collector_tables_description].data
        for keyspace, tables in tables_description_info.items():
            for table in tables:
                response_json = self._read_scylla_rest_api(endpoint=self._endpoint,
                                                           endpoint_parameters=f"/{keyspace}:{table}",
                                                           api_address=api_address, api_port=api_port)
                tables_endpoint_info.setdefault(keyspace, {})[table] = self._endpoint_value_converter(response_json)

        self._data = tables_endpoint_info
        self.status = CollectorStatus.PASSED
