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
import csv
import enum
import functools
import glob
import inspect
import json
import os
import pathlib
import re
import shutil
import socket
import yaml

import shlex
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from typing import Dict, Optional, List, Union, Tuple, Any

from common import Authenticator
from models.output_entry import OutputEntry

###############################################################################
# Global Constants and Variables Declaration ##################################
###############################################################################
# Encoding
ENCODING = "UTF-8"


###############################################################################
# Utils
###############################################################################

# https://stackoverflow.com/questions/1988804/what-is-memoization-and-how-can-i-use-it-in-python
# can be replaced with functools.cache once Scylla node python environment gets upgraded to python3.9 or above
def memoize(function):
    memo = {}
    sig = inspect.signature(function)

    @functools.wraps(function)
    def wrapper(*args, **kwargs):
        # Bind all positional and keyword args to their parameter names so that
        # f(1, 0, 0) and f(timeout=1, retries=0, retry_interval=0) share the same cache entry.
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        key = tuple(bound.arguments.items())

        if key not in memo:
            memo[key] = function(*args, **kwargs)

        return memo[key]

    return wrapper


###############################################################################
# Classes: Main ###############################################################
###############################################################################
class RestEndpointOutputFormatError(Exception):
    pass


class RestEndpointReadError(Exception):
    pass


class SystemConfigurationError(Exception):
    pass


class CloudProvider(abc.ABC):
    """
    Base cloud provider
    """

    snitch = "GossipingPropertyFileSnitch"

    class CPUPlatform(enum.Enum):
        INTEL_CASCADE_LAKE = "Intel Cascade Lake"
        INTEL_ICE_LAKE = "Intel Ice Lake"
        INTEL_BROADWELL = "Intel Broadwell"
        AMD_EPIC_NAPLES = "AMD EPIC Naples"

    @property
    def name(self) -> str:
        """
        Provider name
        """
        raise NotImplementedError()

    def __init__(self, timeout=2, retries=3, retry_interval=2):
        self.timeout = timeout
        self.retries = retries
        self.retry_interval = retry_interval

    @property
    @abc.abstractmethod
    def belonging(self) -> bool:
        """
        Determine if the instance belongs to the cloud provider
        """
        pass

    def gather_instance_data(self, url, headers=None, check=True):
        """
        Gather data from the instance
        """

        return Executor.get_url_content(url, headers=headers,
                                        timeout=self.timeout, retries=self.retries,
                                        retry_interval=self.retry_interval, check=check)

    @property
    def scheduled_maintenance_events(self) -> Optional[List[Dict]]:
        """
        :return: In case there is a scheduled maintenance event a dictionary with relevant information is returned.
        If there is no scheduled maintenance event, return [].
        NOTE: If we cannot detect any scheduled maintenance events for the cloud provider, as in it is unsupported
        via instance metadata service, then we return None.

        :raises RestEndpointReadError: If there is a problem reading the cloud provider metadata endpoint for scheduled
                                       maintenance events.
        :raises RestEndpointOutputFormatError: If the output format of the scheduled maintenance events endpoint is
                                               different from the expected one.
        """
        return None

    @staticmethod
    def nic_mac_address(nic):
        """
        Get NIC's MAC
        """

        with open(f'/sys/class/net/{nic}/address') as mac:
            return mac.read().strip()

    @property
    def instance_type(self) -> Optional[str]:
        """
        Return instance type

        Return values:
         - String -> Instance type
         - None -> Instance type cannot be gathered
        """
        return None

    @property
    def cpu_platform(self) -> Optional[str]:
        """
        :return: CPU platform description, e.g. "Intel Ice Lake"
        """
        return None

    def get_extra(self, **kwargs) -> Optional[Dict]:
        """
        Return some provider-specific extra information
        """
        raise NotImplementedError()

    def read_metadata(self, url_path: str, api_version: Optional[str] = None) -> str:
        """
        Read metadata from the cloud provider's metadata service.
        :param url_path: metadata endpoint suffix, e.g. "instance" for Azure or "instance/machine-type" for GCP.
        :param api_version: metadata API version, if applicable for the cloud provider.
                            For example, Azure has different API versions for different metadata endpoints.
        :return: returned string from the metadata service for a given endpoint. The format of the returned string
                 may differ between different cloud providers and endpoints, e.g. it can be a JSON string or a
                 plain string.
        :raises UrlReadFailedException: In case of any error during reading the metadata, e.g. due to an unsupported
                                        endpoint or API version, or due to a network issue, a UrlReadFailedException
                                        message includes the URL and code if applicable.
        :raises NotImplementedError: In case reading metadata for a given cloud provider is not implemented.
        """
        raise NotImplementedError()

    def _read_json_metadata_endpoint(self, metadata_endpoint_suffix: str, api_version: Optional[str] = None) -> Any:
        """
        Helper method to read a metadata endpoint that is expected to return a JSON output.
        :param metadata_endpoint_suffix: The suffix of the metadata endpoint URL that comes after the base URL.
        :param api_version: API version to use when reading the metadata endpoint, if applicable for the cloud provider.
        :return: a parsed JSON object with the metadata endpoint output
        :raises RestEndpointOutputFormatError: If the output format of the metadata endpoint is not a valid JSON.
        :raises RestEndpointReadError: If there is a problem reading the metadata endpoint.
        :raises UrlReadFailedException: If the metadata URL is not reachable
        """
        try:
            rest_result = self.read_metadata(url_path=metadata_endpoint_suffix, api_version=api_version)
        except UrlReadFailedException:
            raise
        except Exception as ex:
            raise RestEndpointReadError(f"Error while reading metadata endpoint {metadata_endpoint_suffix} using api "
                                        f"version {api_version}: {ex}")

        try:
            return json.loads(rest_result)
        except Exception as ex:
            raise RestEndpointOutputFormatError(f"Error while parsing metadata endpoint {metadata_endpoint_suffix} "
                                                f"output - we expected JSON, returned '{rest_result}', "
                                                f"parsing error: {ex}")


class CloudProviderAE(CloudProvider):
    """
    Cloud provider: Microsoft Azure
    """

    __INSTANCE_DATA_BASE_URL = "http://169.254.169.254/metadata/"
    __INSTANCE_DATA_HEADERS = {'Metadata': 'true'}
    __INSTANCE_DATA_API_VERSION = "2021-02-01"

    @property
    def name(self) -> str:
        return "AZURE"

    def __init__(self, timeout=2, retries=3, retry_interval=2):
        super().__init__(timeout, retries, retry_interval)

    @property
    def belonging(self) -> bool:
        """
        Check if the instance belongs to Azure
        Return values:
         - True -> Instance belongs to Azure
         - False -> Instance does not belong to Azure
        """

        # Check if the internal URL is reachable
        request = super()\
            .gather_instance_data(self.__INSTANCE_DATA_BASE_URL +
                                  "instance?api-version=" +
                                  self.__INSTANCE_DATA_API_VERSION,
                                  headers=self.__INSTANCE_DATA_HEADERS, check=False)

        if not request:
            return False
        else:
            return True

    @property
    @memoize
    def instance_type(self) -> Optional[str]:
        """
        Return instance type

        Return values:
         - String -> Instance type
        """
        metadata = json.loads(self.read_metadata("instance"))

        return metadata['compute']['vmSize']

    @property
    @memoize
    def cpu_platform(self) -> Optional[str]:
        lsv2_pattern = re.compile(r"Standard_L\d+s_v2")
        lsv3_pattern = re.compile(r"Standard_L\d+s_v3")
        if lsv2_pattern.match(self.instance_type):
            return CloudProvider.CPUPlatform.AMD_EPIC_NAPLES.value
        elif lsv3_pattern.match(self.instance_type):
            return CloudProvider.CPUPlatform.INTEL_ICE_LAKE.value
        else:
            return None

    @property
    def scheduled_maintenance_events(self) -> List[Dict]:
        """
        Retrieves upcoming maintenance event.

        https://learn.microsoft.com/en-us/azure/virtual-machines/windows/scheduled-events

        This uses a different versioned API than e.g. querying instance information.
        """
        # Example: curl -H Metadata:true http://169.254.169.254/metadata/scheduledevents?api-version=2020-07-01
        metadata_endpoint_suffix = "scheduledevents"
        api_version = "2020-07-01"
        events_key = "Events"
        scheduled_maintenance_event = self._read_json_metadata_endpoint(
            metadata_endpoint_suffix=metadata_endpoint_suffix, api_version=api_version)

        if (not isinstance(scheduled_maintenance_event, dict) or events_key not in scheduled_maintenance_event or
                not isinstance(scheduled_maintenance_event[events_key], list) or
                any(not isinstance(event, dict) for event in scheduled_maintenance_event[events_key])):
            raise RestEndpointOutputFormatError(f"Unexpected format of Azure metadata endpoint "
                                                f"{metadata_endpoint_suffix} and api_version {api_version} output - "
                                                f"we expected a dictionary with an "
                                                f"'{events_key}' key containing a list of dictionaries, "
                                                f"returned '{scheduled_maintenance_event}'")

        return scheduled_maintenance_event[events_key]

    def read_metadata(self, url_path, api_version: Optional[str] = None) -> str:
        """
        Read metadata
        :param url_path: URL path (e.g. instance, scheduledevents)
        The path that comes after the base URL and "/metadata/"
        :param api_version: API version
        """
        if not api_version:
            api_version = self.__INSTANCE_DATA_API_VERSION

        metadata = super().gather_instance_data(
                              self.__INSTANCE_DATA_BASE_URL +
                              url_path +
                              "?api-version=" + api_version,
                              headers=self.__INSTANCE_DATA_HEADERS)

        return metadata


class CloudProviderAN(CloudProvider):
    """
    Cloud provider: Aliyun
    """

    __INSTANCE_DATA_BASE_URL = "http://100.100.100.200/latest/"

    @property
    def name(self) -> str:
        return "AN"

    def __init__(self, timeout=2, retries=3, retry_interval=2):
        super().__init__(timeout, retries, retry_interval)

    @property
    def belonging(self) -> bool:
        """
        Check if the instance belongs to AN

        Return values:
         - True -> Instance belongs to AN
         - False -> Instance does not belong to AN
        """

        # Check if the internal URL is reachable
        request = super().gather_instance_data(self.__INSTANCE_DATA_BASE_URL
                                               + "meta-data/instance-id",
                                               check=False)
        if not request:
            return False
        else:
            return True


class CloudProviderAWS(CloudProvider):
    """
    Cloud provider: Amazon Web Services
    """

    __INSTANCE_DATA_BASE_URL = "http://169.254.169.254/latest/"

    @property
    def name(self) -> str:
        return "AWS"

    def __init__(self, timeout=2, retries=3, retry_interval=2):
        super().__init__(timeout, retries, retry_interval)

    @staticmethod
    def __imdsv2_token_ttl_header(timeout_seconds: int = 2) -> Dict[str, int]:
        """
        Get the header required to request an IMDSv2 token with a specified TTL (time to live) in seconds.
        :param timeout_seconds: The TTL for the IMDSv2 token in seconds. This value should be set considering the total
                                time it may take to perform the metadata queries using the token, including retries and
                                retry intervals, to avoid token expiration during the process.
                                A small time buffer can also be added to ensure the token does not expire during
                                retries.
        :return: A dictionary containing the header for requesting an IMDSv2 token with the specified TTL.
        """
        return {'X-aws-ec2-metadata-token-ttl-seconds': timeout_seconds}

    @staticmethod
    def __imdsv2_request_header(token: str) -> Dict[str, str]:
        """
        Get the header required to use an IMDSv2 token when querying the instance metadata service.
        :param token: The IMDSv2 token to be included in the header for querying the instance metadata service.
        :return: A dictionary containing the header for using the IMDSv2 token when querying the instance metadata
                 service.
        """
        return {'X-aws-ec2-metadata-token': token}

    @property
    @memoize
    def __requires_imdsv2(self) -> bool:
        """
        Check if the instance requires using IMDSv2 by trying to query the instance metadata service without a token
        and checking if the error code is 401 Unauthorized, which indicates that IMDSv2 is required.

        :raises UrlReadFailedException: If there is an error other than 401 Unauthorized when trying to query the
                                        metadata service.
        :return: True if IMDSv2 is required, False otherwise.
        """
        try:
            # Try to query the instance metadata service without a token
            Executor.get_url_content(self.__INSTANCE_DATA_BASE_URL + "meta-data/ami-id", check=True, retries=0,
                                     timeout=self.timeout)
            return False
        except UrlReadFailedException as ex:
            if ex.code == 401:
                return True
            else:
                raise

    def gather_instance_data(self, url, headers=None, check=True) -> Optional[str]:
        """
        Gather data from the instance metadata service, using IMDSv2 if required by the instance configuration.

        :param url: URL to query the instance metadata service, including the base URL and the suffix
                    (e.g. "meta-data/instance-type").
        :param headers: HTTP headers to use when querying the instance metadata service. If not provided, no headers
                        will be used.
        :param check: If True, an exception will be raised if both IMDSv1 and IMDSv2 fail to return the instance data.
                      If False, None will be returned in such a case.
        :return: The instance data returned by the instance metadata service for a given URL suffix.
        :raises UrlReadFailedException: If both IMDSv1 and IMDSv2 fail to return the instance data and check is True.
                                        The exception message will include the URL and the error code if applicable.
        """
        # Shortcut for cases when we are not running on AWS
        try:
            requires_imdsv2 = self.__requires_imdsv2
        except UrlReadFailedException:
            if check:
                raise
            else:
                return None

        if not requires_imdsv2:
            # IMDSv1:
            # curl http://169.254.169.254/latest/meta-data/...
            return Executor.get_url_content(url, headers=headers, timeout=self.timeout, retries=self.retries,
                                            retry_interval=self.retry_interval, check=check)
        else:
            try:
                # IMDSv2:
                # TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: <token TTL in seconds>"`  # noqa E501
                # curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/...

                # Adding a small time buffer to ensure the token does not expire during retries
                token_ttl_seconds = int((self.timeout + self.retry_interval) * (self.retries + 1) + 5)
                token = Executor.get_url_content(self.__INSTANCE_DATA_BASE_URL + "api/token",
                                                 headers=self.__imdsv2_token_ttl_header(token_ttl_seconds),
                                                 timeout=self.timeout,
                                                 retries=self.retries, retry_interval=self.retry_interval, check=True,
                                                 method=HttpRequestMethod.PUT)
                final_headers = self.__imdsv2_request_header(token)  # type: ignore[arg-type]
                if headers:
                    final_headers.update(headers)
                return Executor.get_url_content(url, headers=final_headers, timeout=self.timeout, retries=self.retries,
                                                retry_interval=self.retry_interval, check=check)
            except UrlReadFailedException:
                if check:
                    raise
                else:
                    return None

    @property
    def belonging(self) -> bool:
        """
        Check if the instance belongs to AWS

        Return values:
         - True -> Instance belongs to AWS
         - False -> Instance does not belong to AWS
        """

        # Check if the internal URL is reachable
        request = self.gather_instance_data(self.__INSTANCE_DATA_BASE_URL + "meta-data/ami-id",
                                            check=False)

        if not request:
            return False
        else:
            return True

    def get_extra(self, **kwargs) -> Optional[Dict]:
        nics = kwargs['nics']
        return {
            'enhanced_networking_driver_support': self.enhanced_networking_driver_support(nics),
            'enhanced_networking_nic_type': self.enhanced_networking_nic_type(),
            'vpc_enabled_from_nics': self.vpc_enabled_from_nics(nics)
        }

    def enhanced_networking_driver_support(self, nics):
        """
         Return if any detected NIC has support for enhanced networking

         Return values:
          - True -> NIC's driver supports enhanced networking
          - False -> NIC's driver does not support enhanced networking
         """

        # Check if detected driver belongs to an enhanced networking NIC
        for nic in nics:
            if nics[nic]['driver'] == self.enhanced_networking_nic_type():
                return True

        return False

    def enhanced_networking_nic_type(self):
        """
        Return enhanced networking NIC type

        Return values:
         - String -> Enhanced networking NIC type
         - None -> Instance enhanced networking NIC type cannot be gathered
        """

        instances_class_list = {
            'a1': {'*': "ena"},
            'c3': {'*': "ixgbevf"},
            'c4': {'*': "ixgbevf"},
            'c5': {'*': "ena"},
            'c5a': {'*': "ena"},
            'c5d': {'*': "ena"},
            'c5n': {'*': "ena"},
            'c6g': {'*': "ena"},
            'c6gd': {'*': "ena"},
            'd2': {'*': "ixgbevf"},
            'f1': {'*': "ena"},
            'g3': {'*': "ena"},
            'g4': {'*': "ena"},
            'h1': {'*': "ena"},
            'i2': {'*': "ixgbevf"},
            'i3': {'*': "ena"},
            'i3en': {'*': "ena"},
            'i4i': {'*': "ena"},
            'i7i': {'*': "ena"},
            'i7ie': {'*': "ena"},
            'i8g': {'*': "ena"},
            'i8ge': {'*': "ena"},
            'inf1': {'*': "ena"},
            'r3': {'*': "ixgbevf"},
            'm4': {'16xlarge': "ena", '*': "ixgbevf"},
            'm5': {'*': "ena"},
            'm5a': {'*': "ena"},
            'm5ad': {'*': "ena"},
            'm5d': {'*': "ena"},
            'm5dn': {'*': "ena"},
            'm5n': {'*': "ena"},
            'm6g': {'*': "ena"},
            'm6gd': {'*': "ena"},
            'p2': {'*': "ena"},
            'p3': {'*': "ena"},
            'r4': {'*': "ena"},
            'r5': {'*': "ena"},
            'r5a': {'*': "ena"},
            'r5ad': {'*': "ena"},
            'r5b': {'*': "ena"},
            'r5d': {'*': "ena"},
            'r5dn': {'*': "ena"},
            'r5n': {'*': "ena"},
            'r6g': {'*': "ena"},
            'r6gd': {'*': "ena"},
            't3': {'*': "ena"},
            't3a': {'*': "ena"},
            't4g': {'*': "ena"},
            'u-6tb1': {'*': "ena"},
            'u-9tb1': {'*': "ena"},
            'u-12tb1': {'*': "ena"},
            'u-18tn1': {'*': "ena"},
            'u-24tb1': {'*': "ena"},
            'x1': {'*': "ena"},
            'x1e': {'*': "ena"},
            'x2gd': {'*': "ena"},
            'z1d': {'*': "ena"}
        }
        instance_class = self.instance_class
        if instance_class in instances_class_list:
            if instances_class_list[instance_class].get(self.instance_size):
                return instances_class_list[instance_class][self.instance_size]
            else:
                return instances_class_list[instance_class]['*']

        return None

    @property
    @memoize
    def instance_class(self) -> str:
        """
         Return instance class

         Return values:
          - String -> Instance class
         """

        return self.instance_type.split(".")[0]

    @property
    @memoize
    def instance_size(self) -> str:
        """
         Return instance size

         Return values:
          - String -> Instance size
         """

        return self.instance_type.split(".")[1]

    @property
    @memoize
    def instance_type(self) -> str:
        """
        Return instance type

        Return values:
         - String -> Instance type
        """
        return self.read_metadata("instance-type")

    @property
    def scheduled_maintenance_events(self) -> List[Dict]:
        """
        Retrieves upcoming maintenance event.

        https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/viewing_scheduled_events.html
        """
        # Example: curl http://169.254.169.254/latest/meta-data/events/maintenance/scheduled
        metadata_endpoint_suffix = "events/maintenance/scheduled"
        scheduled_maintenance_events = self._read_json_metadata_endpoint(metadata_endpoint_suffix)

        # Filter for events with State == 'active'
        if (not isinstance(scheduled_maintenance_events, list) or
                any(not isinstance(event, dict) for event in scheduled_maintenance_events)):
            raise RestEndpointOutputFormatError(f"Unexpected format of AWS metadata endpoint "
                                                f"{metadata_endpoint_suffix} output - we expected a list of "
                                                f"dictionaries, returned '{scheduled_maintenance_events}'")

        return [event for event in scheduled_maintenance_events if event.get("State") == "active"]

    def read_metadata(self, url_path, api_version: Optional[str] = None) -> str:
        """
        Read metadata
        :param url_path: metadata endpoint suffix (e.g. "instance-type").
        :param api_version: unused for AWS; present for interface compatibility.
        """
        return self.gather_instance_data(CloudProviderAWS.__INSTANCE_DATA_BASE_URL + "meta-data/" + url_path)  # type: ignore[return-value] # noqa E501

    def vpc_enabled_from_nics(self, nics):
        """
        Check if VPC ID is present in any of detected NIC

        Return values:
         - True -> VPC ID found
         - False -> VPC ID not found
        """

        if not nics:
            return False

        for nic in nics:
            current_mac = CloudProviderAWS.nic_mac_address(nic)
            if not current_mac:
                continue

            current_vpc = self.read_metadata("network/interfaces/macs/" + current_mac)
            if not current_vpc:
                continue

            return True

        return False

    @property
    @memoize
    def cpu_platform(self) -> Optional[str]:
        if self.instance_type == "i3.metal":
            return CloudProvider.CPUPlatform.INTEL_BROADWELL.value
        elif self.instance_class == "i4i":
            return CloudProvider.CPUPlatform.INTEL_ICE_LAKE.value
        else:
            return None


class CloudProviderDO(CloudProvider):
    """
    Cloud provider: Digital Ocean
    """

    __INSTANCE_DATA_BASE_URL = "http://169.254.169.254/"

    @property
    def name(self) -> str:
        return "DO"

    def __init__(self, timeout=2, retries=3, retry_interval=2):
        super().__init__(timeout, retries, retry_interval)

    @property
    def belonging(self) -> bool:
        """
        Check if the instance belongs to DO

        Return values:
         - True -> Instance belongs to DO
         - False -> Instance does not belong to DO
        """

        # Check if the internal URL is reachable
        request = super().gather_instance_data(self.__INSTANCE_DATA_BASE_URL + "metadata/v1/", check=False)
        if not request:
            return False
        else:
            return True


class CloudProviderGCP(CloudProvider):
    """
    Cloud provider: Google Cloud Platform
    """

    __INSTANCE_DATA_BASE_URL = "http://metadata.google.internal/"
    __INSTANCE_DATA_HEADERS = {'Metadata-Flavor': 'Google'}

    @property
    def name(self) -> str:
        return "GCP"

    def __init__(self, timeout=2, retries=3, retry_interval=2):
        super().__init__(timeout, retries, retry_interval)

    @property
    def belonging(self) -> bool:
        """
        Check if the instance belongs to GCP

        Return values:
         - True -> Instance belongs to GCP
         - False -> Instance does not belong to GCP
        """

        # Check if the internal URL is reachable
        request = super()\
            .gather_instance_data(self.__INSTANCE_DATA_BASE_URL
                                  + "computeMetadata/v1/project/",
                                  headers=self.__INSTANCE_DATA_HEADERS,
                                  check=False)

        if not request:
            return False
        else:
            return True

    @property
    @memoize
    def instance_type(self):
        """
        Return instance type

        Return values:
         - String -> Instance type
         - None -> Instance type cannot be gathered
        """
        return self.read_metadata("instance/machine-type").split("/")[-1]

    @property
    @memoize
    def cpu_platform(self) -> Optional[str]:
        """
        :return: Standardized CPU Platform name for known platforms and the platform name from the GCP metadata for
        unknown ones.
        """
        cpu_platform_value = self.read_metadata("instance/cpu-platform")
        if cpu_platform_value == "Intel Ice Lake":
            return CloudProvider.CPUPlatform.INTEL_ICE_LAKE.value
        elif cpu_platform_value == "Intel Cascade Lake":
            return CloudProvider.CPUPlatform.INTEL_CASCADE_LAKE.value
        else:
            return cpu_platform_value

    @property
    def scheduled_maintenance_events(self) -> Optional[List[Dict]]:
        """
        Retrieves upcoming maintenance event if possible.
        There are limitations where this only can be retrieved for specific instance types (e.g. z3)
        The maintenance operation may be pending or already ongoing. Hence, when no events are detected,
        we return None as this may be due to API limitations.

        https://cloud.google.com/compute/docs/instances/monitor-plan-host-maintenance-event
        """
        # Example: curl -H "Metadata-Flavor: Google" \
        #          http://metadata.google.internal/computeMetadata/v1/instance/upcoming-maintenance?alt=json
        metadata_endpoint_suffix = "instance/upcoming-maintenance?alt=json"
        try:
            scheduled_maintenance_event = self._read_json_metadata_endpoint(metadata_endpoint_suffix)
        except UrlReadFailedException as ex:
            # If endpoint is not found, it may be due to the fact that the instance type does not support maintenance
            # events. In such a case, we return None to differentiate from the case where there are no maintenance
            # events at the moment, but the endpoint is supported and reachable.
            # It's also noticed that despite the official documentation in case there are no upcoming maintenance
            # events, a 503 HTTP code is returned with Service Unavailable.
            if ex.code != 404:
                return []
            else:
                return None

        if isinstance(scheduled_maintenance_event, dict) and scheduled_maintenance_event.get("error"):
            return []
        # Check for "NONE" string which indicates that maintenance event are not supported for the instance type.
        # This an undocumented behavior but has been observed in practice.
        elif isinstance(scheduled_maintenance_event, str) and scheduled_maintenance_event == "NONE":
            return None
        elif not isinstance(scheduled_maintenance_event, dict):
            # Let's not require a specific dictionary format since the corresponding GCE doc page itself has an
            # "upcoming notification event is presented in a manner similar to the following..." phrase.
            # Hence, the only thing we should probably safely assume is that the maintenance event is going to be
            # represented by a dictionary.
            raise RestEndpointOutputFormatError(f"Unexpected format of GCP metadata endpoint "
                                                f"{metadata_endpoint_suffix} output - we expected a dictionary or a "
                                                f"string 'NONE', returned '{scheduled_maintenance_event}'")
        else:
            return [scheduled_maintenance_event]

    def read_metadata(self, url_path, api_version: Optional[str] = None) -> str:
        """
        Read metadata
        :param url_path: metadata endpoint suffix (e.g. "instance/machine-type").
        :param api_version: unused for GCP; present for interface compatibility.
        """
        return super()\
            .gather_instance_data(self.__INSTANCE_DATA_BASE_URL +
                                  "computeMetadata/v1/" + url_path,
                                  headers=self.__INSTANCE_DATA_HEADERS)


class CloudProviderOCI(CloudProvider):
    """
    Cloud provider: Oracle Cloud Infrastructure
    """

    __INSTANCE_DATA_BASE_URL = "http://169.254.169.254/opc/v2/"
    __INSTANCE_DATA_HEADERS = {'Authorization': 'Bearer Oracle'}

    @property
    def name(self) -> str:
        return "OCI"

    def __init__(self, timeout=2, retries=3, retry_interval=2):
        super().__init__(timeout, retries, retry_interval)

    @property
    def belonging(self) -> bool:
        """
        Check if the instance belongs to OCI

        Return values:
         - True -> Instance belongs to OCI
         - False -> Instance does not belong to OCI
        """

        # Check if the internal URL is reachable
        request = super()\
            .gather_instance_data(self.__INSTANCE_DATA_BASE_URL + "instance/",
                                  headers=self.__INSTANCE_DATA_HEADERS,
                                  check=False)
        if not request:
            return False
        else:
            return True

    @property
    @memoize
    def instance_type(self) -> Optional[str]:
        """
        Return instance shape from OCI IMDS (e.g. VM.DenseIO.E5.Flex).
        """
        metadata = json.loads(self.read_metadata("instance/"))
        return metadata.get("shape")

    def read_metadata(self, url_path, api_version: Optional[str] = None) -> str:
        """
        Read metadata
        :param url_path: metadata endpoint suffix (e.g. "instance/").
        :param api_version: unused for OCI; present for interface compatibility.
        """
        return super().gather_instance_data(
            self.__INSTANCE_DATA_BASE_URL + url_path,
            headers=self.__INSTANCE_DATA_HEADERS)


class CloudProviderOS(CloudProvider):
    """
    Cloud provider: Open Stack
    """

    __INSTANCE_DATA_BASE_URL = "http://169.254.169.254/"

    @property
    def name(self) -> str:
        return "OS"

    def __init__(self, timeout=2, retries=3, retry_interval=2):
        super().__init__(timeout, retries, retry_interval)

    @property
    def belonging(self) -> bool:
        """
        Check if the instance belongs to OS

        Return values:
         - True -> Instance belongs to OS
         - False -> Instance does not belong to OS
        """

        # Check if the internal URL is reachable
        request = super().gather_instance_data(self.__INSTANCE_DATA_BASE_URL
                                               + "openstack",
                                               check=False)
        if not request:
            return False
        else:
            return True


class CqlFailedException(Exception):
    pass


class UrlReadFailedException(Exception):
    def __init__(self, message: str, code=None) -> None:
        super().__init__(message)
        self.code = code


# We define our own HttpRequestMethod enum with a few currently used HTTP methods.
# There are a lot more (around 30) that are supported in general.
# If we need to use more HTTP methods in the future, we can easily add them to this enum.
class HttpRequestMethod(enum.Enum):
    GET = "GET"
    PUT = "PUT"


class Executor:
    """Static class. """

    cql_config: Dict = {}
    paths: Dict = {}

    __cqlsh_ssl_functioning = None

    @classmethod
    def set_cqlsh_ssl_functioning(cls, cqlsh_ssl_functioning: bool) -> None:
        """
        Set the cqlsh SSL functioning state: if Client-Server SSL is enabled in Scylla Configuration but cqlsh is not
        configured to use it, we will try to use cqlsh without SSL.

        Note: this method is not expected to be called more than once during the whole Doctor's execution.

        :param cqlsh_ssl_functioning: True if cqlsh SSL is functioning, False otherwise
        """
        cls.__cqlsh_ssl_functioning = cqlsh_ssl_functioning

    @classmethod
    def cqlsh_ssl_functioning(cls) -> Optional[bool]:
        return cls.__cqlsh_ssl_functioning

    @staticmethod
    def use_ssl_values():
        return ["1", "yes", "true", "on"]

    @staticmethod
    def cqlsh(query, scylla_config, user: Optional[str] = None, password: Optional[str] = None):
        """
        Execute a query using cqlsh

        :param query: CQL query to execute
        :param scylla_config: Scylla configuration (from scylla.yaml)
        :param user: Optional CQL username override. When authentication is required and this is
                     omitted, falls back to CQL config / default ``cassandra``.
        :param password: Optional CQL password override. When authentication is required and this is
                         omitted, falls back to CQL config / default ``cassandra``.

        Return values:
         - CompletedProcess instance -> No error
         - None -> An error occurred
        """

        address = Executor.cql_config.get('rpc_address') or scylla_config['rpc_address']
        command_args = [f"{Executor.paths['scylla_directory']}/share/cassandra/bin/cqlsh", address]
        if Executor.cql_config.get('native_transport_port'):
            command_args += [Executor.cql_config.get('native_transport_port')]
        command_args += ["-e", query]
        credentials_args = []

        # Explicit user/password overrides always attach credentials, even when the
        # authenticator isn't recognized as requiring them (e.g. a credential probe).
        if user is not None or password is not None or Executor.cqlsh_authentication_required(scylla_config):
            resolved_user = user if user is not None else (Executor.cql_config.get("user") or "cassandra")
            resolved_password = password if password is not None else (
                Executor.cql_config.get("password") or "cassandra")
            credentials_args = ["-u", resolved_user, "-p", resolved_password]

        def do_execute_command(cmd_args: List[str], cred_args: List[str]):
            """
            :param cmd_args: Shell command args to execute e.g. ["cqlsh", "localhost", "-e", "SELECT * FROM TABLE"]
            These arguments get joined together in a shell-safe manner.
            :param cred_args: Credentials arguments e.g. ["-u", "user", "-p", "password"]
            :raise CqlFailedException: In case of the cqlsh attempts timed out, and retries failed, we
            throw a CqlFailedException with the original command variable information.
            This variable should not feature any credential information.
            """
            # Execute the query. Wait up to 300 seconds.
            # Due to https://github.com/scylladb/scylla-enterprise/issues/5335 we can't implement a proper solution,
            # which would be reading the number of rows first and then setting the timeout to a corresponding value
            # taking into account how many pages need to be read.
            # In the meantime, let's just bump the total timeout to 5 minutes until the issue above is resolved.
            # Try for 3 times - cqlsh sometimes hangs (for unknown reason).
            full_command = shlex.join(cmd_args + cred_args)

            max_attempts = 3
            timeout = 300
            for i in range(1, max_attempts+1):
                try:
                    output = Executor.run_command(full_command, shell=True, timeout=timeout, check=False)

                    if output is not None and output.returncode == 0:
                        return output
                except subprocess.TimeoutExpired:
                    if i == max_attempts:
                        # We throw a new CqlFailedException that does not feature credentials.
                        # We raise from None to supress Exception chaining, as it may feature
                        # the credentials that were used to run the command.
                        raise CqlFailedException(f"Command: {shlex.join(cmd_args)}, "
                                                 f"was attempted with {max_attempts} tries, "
                                                 f"and a timeout of {timeout} seconds.") from None
                    else:
                        pass

            return None

        # Check if client-node SSL is enabled and a special cqlsh option is required
        if Executor.cqlsh_ssl_enabled(scylla_config):
            res = do_execute_command(command_args + ["--ssl"], credentials_args)

            # If cqlsh worked with SSL in the past - simply return the result, no need to fallback.
            # If the command failed, it wasn't due to an SSL related cqlsh configuration issue.
            if Executor.cqlsh_ssl_functioning():
                return res

            # If SSL failed, store this fact in the Executor state and try without SSL
            if res is None and Executor.cqlsh_ssl_functioning() is None:
                # Note that after this line we will never attempt cqlsh with SSL because Executor.cqlsh_ssl_enabled()
                # will always return False from then on.
                Executor.set_cqlsh_ssl_functioning(False)
                return do_execute_command(command_args, credentials_args)

            Executor.set_cqlsh_ssl_functioning(True)
            return res
        else:
            return do_execute_command(command_args, credentials_args)

    @staticmethod
    def read_cql_table_command(table_name: str, columns: Optional[List[str]] = None, delimiter: str = ';', ) -> str:
        """
        Returns the command used to read a CQL table.
        :param table_name: Name of a table to read
        :param delimiter: Delimiter used to separate values.
        :param columns: Optional list of column names to read
        :return: CQL command to read a table for a given delimiter and optionally set of columns.
        """
        if columns:
            command = f"COPY {table_name} ({','.join(columns)}) TO STDOUT WITH DELIMITER='{delimiter}' AND HEADER=TRUE"
        else:
            command = f"COPY {table_name} TO STDOUT WITH DELIMITER='{delimiter}' AND HEADER=TRUE"

        return command

    @staticmethod
    def read_cql_table(scylla_config, table_name: str, columns: Optional[List[str]] = None,
                       max_rows: int = -1) \
            -> Tuple[str, List[Dict[str, str]]]:
        """
        Read the content (full scan) of given columns from a given table.

        Note that this is a full scan, hence this function is not meant to read tables with a lot of rows.
        We are using cqlsh for CQL reads only in order to not require Python CQL driver installation.
        However, if one needs to read large CQL tables in the future, we should switch using a Python CQL driver
        directly (and require its installation) and read data using paging according to all best practices.

        :param scylla_config: Scylla's configuration
        :param table_name: Name of a table to read
        :param columns: Optional list of column names to read
        :param max_rows: Optional maximum number of rows to return - if not provided or is less than 0,
                         all rows will be returned.
        :return: A tuple of issued CQL query and a list of parsed non-empty rows: each row is presented as a non-empty
                 dict of corresponding column names and values (strings)
        :raise CqlFailedException: in case the corresponding CQL command fails
        """
        delimiter = ';'
        command = Executor.read_cql_table_command(table_name, columns, delimiter)
        output = Executor.cqlsh(command, scylla_config)

        # Output check
        if output is None:
            raise CqlFailedException(f"{command} failed")

        # Parse the table dump and map each row its column values to the respective column names.
        table_copy = list(csv.reader(output.stdout.split("\n"), delimiter=delimiter, escapechar='\\'))
        if max_rows >= 0:
            table_copy = table_copy[:max_rows + 1]  # +1 to include the header row

        table_column_names = table_copy[0]
        table_rows = []

        for row_values in table_copy[1:]:
            if len(row_values) == 0:
                continue

            if len(row_values) != len(table_column_names):
                raise ValueError(f"Invalid row: {row_values} - number of columns {table_column_names} "
                                 "doesn't match the number of values")

            row = dict(zip(table_column_names, row_values))
            table_rows.append(row)

        return command, table_rows

    @staticmethod
    def cqlsh_authentication_required(scylla_config):
        """
        Check if authentication is required to use cqlsh

        Return values:
         - True -> Authentication is required
         - False -> Authentication is not required
        """

        return Authenticator.parse(scylla_config.get('authenticator')).requires_password_for_cqlsh

    @staticmethod
    def cqlsh_ssl_enabled(scylla_config):
        """
        Check if client-node SSL is enabled in Scylla configuration.

        Return values:
         - True -> SSL is enabled
         - False -> SSL is not enabled
        """
        # If local SSL is not functioning, don't even try to use it
        if Executor.cqlsh_ssl_functioning() is False:
            return False

        client_encryption_config = scylla_config.get('client_encryption_options')
        # User provided configuration should always override configuration from scylla.yaml
        if Executor.cql_config.get('use_ssl'):
            if Executor.cql_config.get('use_ssl').lower() in Executor.use_ssl_values():
                client_encryption_config = {'enabled': True}
            else:
                client_encryption_config = {'enabled': False}

        if not client_encryption_config:
            return False

        if client_encryption_config.get('enabled') in [True, 'true', 'True', '1']:
            return True

        return False

    @staticmethod
    def generate_output_filename(path=None, prefix="", suffix="", extension=""):
        """
        Generate a time-based file name.

        When ``path`` is omitted, the system temporary directory is used so files are not written next to
        the scylla-doctor binary (for example /usr/bin when installed as a system package).

        Return value: String
        """

        if path is None:
            path = tempfile.gettempdir()

        filename = pathlib.PurePosixPath(path).joinpath(f'{prefix}{time.strftime("%Y%m%d%H%M%S")}{suffix}{extension}')

        return f'{filename}'

    @staticmethod
    def get_url_content(url, headers=None, timeout=2,
                        retries=3, retry_interval=2, check=False,
                        method: HttpRequestMethod = HttpRequestMethod.GET) -> Optional[str]:
        """
        Get content from URL

        :param url: URL to get content from
        :param headers: HTTP headers to provide with a URL request
        :param timeout: amount of seconds to wait for a server response
        :param retries: number of retries
        :param retry_interval: amount of delay in seconds between retries
        :param check: raise an UrlReadFailedException exception if case of a failure
        :param method: HTTP method to use, e.g. "HEAD", "GET", "POST".
        :return: Content returned by the server, None if URL error or the connection can't be established and
                 check == False
        :raises UrlReadFailedException: if couldn't read the provided URL after given number of retried attempts and
                check == True
        """
        context = ssl._create_unverified_context()
        sslHandler = urllib.request.HTTPSHandler(context=context)
        proxy_handler = urllib.request.ProxyHandler({})
        opener = urllib.request.build_opener(proxy_handler,
                                             sslHandler)
        urllib.request.install_opener(opener)
        request = urllib.request.Request(url, headers=headers or {}, method=method.value)
        retry_count = 0

        while True:
            try:
                output = opener.open(request, timeout=timeout)

            except (urllib.error.HTTPError, urllib.error.URLError, socket.error) as ex:
                time.sleep(retry_interval)
                retry_count += 1

                if retry_count >= retries:
                    if not check:
                        return None
                    else:
                        code = None
                        if isinstance(ex, urllib.error.HTTPError):
                            code = ex.code
                        raise UrlReadFailedException(f"{url} failed after {retries} retries", code=code)

                continue

            return output.read().decode(ENCODING)

    @staticmethod
    def sort_dictionary(dictionary: Dict, deep_sort=True) -> Dict:
        """
        Sort a dictionary alphabetically
        :param dictionary: A dictionary to sort
        :param deep_sort: Perform a deep dictionary sort
        """
        def deep_sort_func(obj: Union[Dict, List]) -> Union[Dict, List]:
            """
            Recursive dictionary sorting

            Based on a solution from https://stackoverflow.com/a/59218649/7513465

            :param obj: Object to sort. Can be a dict or a list.
            :return: Sorted dictionary
            """
            if isinstance(obj, dict):
                obj = dict(sorted(obj.items()))
                for k, v in obj.items():
                    if isinstance(v, dict) or isinstance(v, list):
                        obj[k] = deep_sort_func(v)

            if isinstance(obj, list):
                for i, v in enumerate(obj):
                    if isinstance(v, dict) or isinstance(v, list):
                        obj[i] = deep_sort_func(v)
                obj = sorted(obj, key=lambda x: json.dumps(x))

            return obj

        if not isinstance(dictionary, dict):
            raise Exception("Trying to sort a non-dictionary object")

        if not dictionary:
            return {}

        if not deep_sort:
            return dict(sorted(dictionary.items()))

        return dict(deep_sort_func(dictionary))

    @staticmethod
    def parse_config_file_to_dict(source_file, file_type="", deep_sort=True, no_yaml_values_parsing=False):
        """
        Read 'source_file' content

        :param source_file: Source file name
        :param file_type: Type of file. 'json' for JSON, 'yaml' for YAML, 'conf', 'ini', 'cfg' or '' for an INI file.
        :param deep_sort: Perform a deep dictionary sort
        :param no_yaml_values_parsing: Don't perform a YAML values parsing - leave them as strings

        Return values:
         - Dictionary -> Dictionary containing data parsed
         - None -> Any error trying to parsing the file
        """

        try:
            with open(source_file, 'r', encoding=ENCODING) as parsed_file:
                if file_type == "json":
                    try:
                        return Executor.sort_dictionary(json.load(parsed_file), deep_sort=deep_sort)
                    except json.JSONDecodeError:
                        return None
                elif file_type == "yaml" or file_type == "yml":
                    try:
                        if no_yaml_values_parsing:
                            return Executor.sort_dictionary(yaml.load(parsed_file, Loader=yaml.BaseLoader),
                                                            deep_sort=deep_sort)
                        else:
                            return Executor.sort_dictionary(yaml.load(parsed_file, Loader=yaml.FullLoader),
                                                            deep_sort=deep_sort)
                    except yaml.YAMLError:
                        return None
                elif file_type in ("", "conf", "cfg", "ini"):
                    parsed_content = configparser.ConfigParser()
                    parsed_content.optionxform = lambda option: option

                    try:
                        default_section_name = "DEFAULT"
                        file_content = f"[{default_section_name}]\n" + parsed_file.read()
                        parsed_content.read_string(file_content)
                        dictionary = {}

                        for section in [default_section_name] + parsed_content.sections():
                            # Store "[DEFAULT]" section values flat
                            section_dict_ref = dictionary
                            if section != default_section_name:
                                section_key = f"[{section}]"
                                dictionary[section_key] = {}
                                section_dict_ref = dictionary[section_key]

                            for option, value in parsed_content.items(section):
                                section_dict_ref[option] = value.replace('"', '')

                        return Executor.sort_dictionary(dictionary, deep_sort=deep_sort)
                    except (configparser.ParsingError,
                            configparser.DuplicateOptionError,
                            configparser.DuplicateSectionError):
                        return None
                else:
                    return None
        except OSError:
            return None

    @staticmethod
    def read_file_content(source_file: str) -> List[str]:
        """
        Read 'source_file' content, return a list of it's lines
        """

        if not os.path.isfile(source_file):
            raise FileNotFoundError(source_file)

        with open(source_file, encoding=ENCODING) as file:
            return file.readlines()

    @staticmethod
    def run_command(command: str, shell: bool = False, output_file: Optional[str] = None,
                    output_file_compression: bool = False, timeout: Optional[int] = None,
                    check: bool = True) -> (
            subprocess.CompletedProcess):
        """
        Run a 'command'

        :param command: a string with a command to be executed
        :param shell: When 'True' run a ``command`` in a shell
        :param output_file: optional path; ``command`` stdout is written here
        :param output_file_compression: when True, gztar ``output_file`` beside it (basename-only members), then
            delete it if the archive was created successfully.
        :param timeout: timeout in seconds to wait for a ``command``'s completion.
        :param check: When 'True' raise a subprocess.CalledProcessError if the ``command`` fails.
        :return: subprocess.CompletedProcess object

        :raise subprocess.CalledProcessError: if an error happened during the execution of a ``command``.
        :raise subprocess.TimeoutExpired: if a ``timeout`` is set but the command hasn't completed after ``timeout``
                                          seconds.
        """
        def run(command=command, shell=shell, stdout=subprocess.PIPE):
            if not shell:
                command = command.split()

            return subprocess.run(command, universal_newlines=True,
                                  check=check, shell=shell, encoding=ENCODING,
                                  stdout=stdout, stderr=stdout, timeout=timeout)

        if output_file is not None:
            with open(output_file, 'w', encoding=ENCODING) as destination_file:
                res = run(command=command, shell=shell, stdout=destination_file)

            if output_file_compression:
                output_path = pathlib.Path(output_file)
                try:
                    shutil.make_archive(str(output_path.with_suffix('')), 'gztar',
                                        str(output_path.parent), output_path.name)
                except OSError:
                    pass
                else:
                    try:
                        os.remove(output_file)
                    except OSError:
                        pass

        else:
            res = run(command=command, shell=shell)

        return res

    @staticmethod
    def search_string(pattern: str, lines: List[str], flags: int = 0) -> List[str]:
        """
        Scan through 'lines' array of strings looking for all matches
        where the regular expression 'pattern' produces one
        """

        return list(filter(lambda line: re.compile(pattern, flags).search(line), lines))

    @staticmethod
    def search_string_in_file(pattern, source_file):
        """
        Scan through 'source_file' looking for the first match
        where the regular expression 'pattern' produces one

        Return values:
         - String list containing each whole line -> Match
         - None -> No match
        """

        lines = []

        with open(source_file, encoding=ENCODING) as file:
            while True:
                line = file.readline()
                if re.search(pattern, line):
                    lines.append(line)
                if not line:
                    break

        if len(lines) == 0:
            return None
        else:
            return lines


class Formatter:
    # Table columns, alignment and width
    __TABLE = (
        {'title': "Checkup", 'align': "<", 'width': 100},
        {'title': "Status", 'align': "<", 'width': 15},
        {'title': "Information", 'align': "<", 'width': 50}
    )

    @staticmethod
    def print_logo(file=None):
        """
        Print logo
        """

        print(r" __            _ _            ___           _             ", file=file)
        print(r"/ _\ ___ _   _| | | __ _     /   \___   ___| |_ ___  _ __ ", file=file)
        print(r"\ \ / __| | | | | |/ _` |   / /\ / _ \ / __| __/ _ \| '__|", file=file)
        print(r"_\ \ (__| |_| | | | (_| |  / /_// (_) | (__| || (_) | |   ", file=file)
        print(r"\__/\___|\__, |_|_|\__,_| /___,' \___/ \___|\__\___/|_|   ", file=file)
        print(r"         |___/                                            ", file=file)

    def print_table_checkup_header(self, name, file=None):
        """
        Print checkup
        """

        table = self.__TABLE[0]

        print(f"+ {name: {table['align']}{table['width'] - 2}}", file=file)

    def print_table_header(self, file=None):
        """
        Print table header
        """

        separator_length = 0

        # Print each defined column
        for column, _ in enumerate(self.__TABLE):
            print("{:{}{}}".format(self.__TABLE[column]['title'],
                                   self.__TABLE[column]['align'],
                                   self.__TABLE[column]['width']), end="", file=file)
            separator_length += self.__TABLE[column]['width']

        print(file=file)  # New line
        print("=" * separator_length, file=file)  # Print a separator line

    def print_table_test_row(self, name, status, message, file=None):
        """
        Print test
        """

        table = self.__TABLE

        print(f"  - {name: {table[0]['align']}{table[0]['width'] - 4}}", end="", file=file)
        print(f"{status: {table[1]['align']}{table[1]['width']}}", end="", file=file)
        print(f"{message: {table[2]['align']}{table[2]['width']}}\n", end="", file=file)

    def print_output_entry(self, entry: OutputEntry, file=None):

        header = f"    [ <BEGIN> {entry.type.value}: '{entry.name}' ]"
        footer = f"    [ <END> {entry.type.value}: '{entry.name}' ]\n"

        print(header, file=file)
        if not entry.value:
            print(footer, file=file)
            return

        # Print output content
        if isinstance(entry.value, str):
            for line in entry.value.strip("\n").split("\n"):
                print(f"      {line}", file=file)
        elif isinstance(entry.value, list):
            for line in entry.value:
                if isinstance(line, str):
                    line = line.strip("\n")
                print(f"      {line}", file=file)
        elif isinstance(entry.value, dict):
            for key, value in entry.value.items():
                if key in entry.mask:
                    value = "**SKIPPED**"

                print(f"      {key}: {json.dumps(value, indent=4)}", file=file)

        print(footer, file=file)


class InfrastructureProvider:
    """
    Infrastructure provider
    """

    def identify(self, timeout, retries, retry_interval) -> Optional[CloudProvider]:
        """
        Check to which cloud provider the instance belongs to

        Return values:
         - CloudProviderX instance -> A cloud provider was found
         - None -> Unknown cloud provider or on-premise
        """

        cloud_providers = [
            CloudProviderAWS(timeout, retries, retry_interval),
            CloudProviderGCP(timeout, retries, retry_interval),
            CloudProviderAE(timeout, retries, retry_interval),
            CloudProviderOCI(timeout, retries, retry_interval),
            CloudProviderOS(timeout, retries, retry_interval),
            CloudProviderDO(timeout, retries, retry_interval),
            CloudProviderAN(timeout, retries, retry_interval)
        ]

        # Check each available cloud provider
        for cloud_provider in cloud_providers:
            if cloud_provider.belonging:
                return cloud_provider

        return None


class ServiceManager:

    class Interface(enum.Enum):
        SYSTEMD = "systemd"
        SUPERVISORD = "supervisord"

    class SystemdServiceMode(enum.Enum):
        SYSTEM = enum.auto()
        PER_USER = enum.auto()
        NOT_EXISTS = enum.auto()

    interface: Optional[Interface]

    @staticmethod
    def detect_interface() -> Optional[Interface]:
        detected = None
        if shutil.which("supervisorctl"):
            detected = ServiceManager.Interface.SUPERVISORD
        elif shutil.which("systemctl"):
            detected = ServiceManager.Interface.SYSTEMD
        return detected

    def __init__(self):
        self.interface = ServiceManager.detect_interface()

    @property
    def __scylla_server_service_names(self):
        return ["scylla-server", "scylla"]

    def __get_systemd_service_mode(self, service_name: str) -> SystemdServiceMode:
        assert self.interface == ServiceManager.Interface.SYSTEMD
        is_system = False
        is_per_user = False
        try:
            Executor.run_command("systemctl cat " + service_name)
            is_system = True
        except Exception:
            pass

        try:
            Executor.run_command("systemctl --user cat " + service_name)
            is_per_user = True
        except Exception:
            pass

        if is_system and is_per_user:
            raise SystemConfigurationError(f"Service {service_name} exists both as a system and a per-user service, "
                                           f"which is not expected")
        elif is_system:
            return ServiceManager.SystemdServiceMode.SYSTEM
        elif is_per_user:
            return ServiceManager.SystemdServiceMode.PER_USER
        else:
            return ServiceManager.SystemdServiceMode.NOT_EXISTS

    def __service_systemctl_command(self, service_name: str) -> Optional[str]:
        assert self.interface == ServiceManager.Interface.SYSTEMD
        service_privileged_state = self.__get_systemd_service_mode(service_name)
        if service_privileged_state == ServiceManager.SystemdServiceMode.SYSTEM:
            return "systemctl"
        elif service_privileged_state == ServiceManager.SystemdServiceMode.PER_USER:
            return "systemctl --user"
        else:
            return None

    def service_autostarts(self, service_name: str) -> bool:
        if self.interface == ServiceManager.Interface.SYSTEMD:
            systemd_command = self.__service_systemctl_command(service_name)
            if not systemd_command:
                return False
            output = Executor.run_command(f"{systemd_command} is-enabled " + service_name, check=False)
            return output is not None and output.returncode == 0
        elif self.interface == ServiceManager.Interface.SUPERVISORD:
            supervisord_config_path = "/etc/supervisord.conf.d/"

            if os.path.isdir(supervisord_config_path):
                glob_path = supervisord_config_path + "*"
                for config_file in sorted(glob.glob(glob_path)):
                    service_tag = ":" + service_name + "]"
                    if Executor.search_string_in_file(service_tag, config_file):
                        return True
                return False

        return False

    def service_environment(self, service_name: str) -> Optional[str]:
        if self.interface == ServiceManager.Interface.SYSTEMD:
            systemd_command = self.__service_systemctl_command(service_name)
            if not systemd_command:
                return None
            output = Executor.run_command(f"{systemd_command} --no-pager show " + service_name, check=False)
            if output is not None and output.returncode == 0:
                return output.stdout.strip("\n")
        elif self.interface == ServiceManager.Interface.SUPERVISORD:
            raise NotImplementedError("One can't get a service environment variables from supervisord since "
                                      "supervisord doesn't support this functionality")

        return None

    def service_exists(self, service_name: str) -> bool:
        if self.interface == ServiceManager.Interface.SYSTEMD:
            return self.__get_systemd_service_mode(service_name) != ServiceManager.SystemdServiceMode.NOT_EXISTS
        elif self.interface == ServiceManager.Interface.SUPERVISORD:
            return self.service_active(service_name)
        return False

    def service_active(self, service_name: str) -> bool:
        if self.interface == ServiceManager.Interface.SYSTEMD:
            systemd_command = self.__service_systemctl_command(service_name)
            if not systemd_command:
                return False
            output = Executor.run_command(f"{systemd_command} is-active " + service_name, check=False)
            return output is not None and output.returncode == 0
        elif self.interface == ServiceManager.Interface.SUPERVISORD:
            output = Executor.run_command("supervisorctl status " + service_name, check=False)
            return output is not None and output.returncode == 0 and re.search("RUNNING", output.stdout) is not None
        return False

    @property
    def scylla_server_service_active(self) -> bool:
        """
        :return: True if scylla server service is active
        """
        return any([self.service_active(service) for service in self.__scylla_server_service_names])
