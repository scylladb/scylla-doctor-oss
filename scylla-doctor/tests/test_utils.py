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

import shlex
import subprocess
import json
from unittest.mock import Mock, patch
import pytest
from utils import Executor, CqlFailedException, UrlReadFailedException, RestEndpointReadError, CloudProvider, \
    SystemConfigurationError
from utils import CloudProviderGCP, CloudProviderAWS, CloudProviderAE, RestEndpointOutputFormatError, ServiceManager


def cqlsh_command():
    return f"{Executor.paths['scylla_directory']}/share/cassandra/bin/cqlsh"


class TestExecutorCqlsh:
    """Test cases for Executor.cqlsh method"""

    @pytest.mark.parametrize("config,expected", [
        ({'authenticator': 'PasswordAuthenticator'}, True),
        ({'authenticator': 'com.scylladb.auth.TransitionalAuthenticator'}, True),
        ({'authenticator': 'AllowAllAuthenticator'}, False),
        ({'authenticator': 'UnknownAuthenticator'}, False),
        ({}, False),
    ])
    def test_cqlsh_authentication_required(self, config, expected):
        """Test authentication required check with various authenticator configurations"""
        assert Executor.cqlsh_authentication_required(config) is expected

    @patch('utils.Executor.run_command')
    @patch('utils.Executor.cqlsh_authentication_required')
    def test_cqlsh_basic_query_success(self, mock_auth_required, mock_run_command):
        """Test successful cqlsh execution without authentication"""
        # Setup
        mock_auth_required.return_value = False
        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = "Test output"
        mock_run_command.return_value = mock_result
        rpc_address = "127.0.0.1"
        basic_scylla_config = {'rpc_address': rpc_address}
        Executor.paths = {'scylla_directory': '/some/path'}

        # Execute
        cql_query = "SELECT * FROM test_table"
        result = Executor.cqlsh(cql_query, basic_scylla_config)

        # Verify
        assert result is not None
        assert result.returncode == 0
        assert result.stdout == "Test output"

        expected_command = shlex.join([cqlsh_command(), rpc_address, "-e", cql_query])

        mock_run_command.assert_called_once_with(
            expected_command,
            shell=True,
            timeout=300,
            check=False
        )

    @patch('utils.Executor.run_command')
    @patch('utils.Executor.cqlsh_authentication_required')
    def test_cqlsh_different_rpc_addresses_in_config_file(self, mock_auth_required, mock_run_command):
        """Test cqlsh with different RPC addresses in the configuration file"""
        # Setup
        mock_auth_required.return_value = False
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run_command.return_value = mock_result
        Executor.paths = {'scylla_directory': '/some/path'}

        test_configs = [
            {'rpc_address': 'localhost'},
            {'rpc_address': '::1'},  # IPv6
            {'rpc_address': 'scylla-node.example.com'},  # Hostname
        ]

        cql_query = "SELECT * FROM test"

        for config in test_configs:
            # Execute
            result = Executor.cqlsh(cql_query, config)

            # Verify
            assert result is not None
            expected_command = shlex.join([cqlsh_command(), config['rpc_address'], "-e", cql_query])
            mock_run_command.assert_called_with(
                expected_command,
                shell=True,
                timeout=300,
                check=False
            )

    @patch('utils.Executor.run_command')
    @patch('utils.Executor.cqlsh_authentication_required')
    def test_cqlsh_configured_via_command_line_no_ssl_section_in_config_file(self,
                                                                             mock_auth_required, mock_run_command):
        """
        Test cqlsh with different RPC addresses provided via command line and SSL configuration is not present in the
        config file.
        The command line options should take precedence over the config file values.
        The SSL option should be included in the command line if they are included in either command line or in the
        config file.
        The RPC address from the command line should be used regardless of the config file value.
        """
        # Setup
        mock_auth_required.return_value = False
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run_command.return_value = mock_result

        config_file_content_no_ssl = {'rpc_address': 'wrong_address'}
        Executor.cql_config = {'rpc_address': 'good_address', 'native_transport_port': '1234', 'use_ssl': 'yes'}
        Executor.paths = {'scylla_directory': '/some/path'}
        cql_query = "SELECT * FROM test"

        # Execute when config file doesn't have SSL configuration
        result = Executor.cqlsh(cql_query, config_file_content_no_ssl)

        # Verify
        assert result is not None
        expected_command = shlex.join([cqlsh_command(), Executor.cql_config['rpc_address'],
                                       Executor.cql_config['native_transport_port'],
                                       "-e", cql_query, "--ssl"])
        mock_run_command.assert_called_with(
            expected_command,
            shell=True,
            timeout=300,
            check=False
        )

    @patch('utils.Executor.run_command')
    @patch('utils.Executor.cqlsh_authentication_required')
    def test_cqlsh_configured_via_command_line_ssl_section_in_config_file(self, mock_auth_required, mock_run_command):
        """
        Test cqlsh with different RPC addresses provided via command line and SSL configuration in the config file.
        The command line options should take precedence over the config file values.
        The SSL option should be included in the command line if they are included in either command line or in the
        config file.
        The RPC address from the command line should be used regardless of the config file value.
        """
        # Setup
        mock_auth_required.return_value = False
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run_command.return_value = mock_result
        Executor.paths = {'scylla_directory': '/some/path'}

        config_file_content_with_ssl = {'client_encryption_options': {'enabled': False}, 'rpc_address': 'wrong_address'}
        Executor.cql_config = {'rpc_address': 'good_address', 'native_transport_port': '1234', 'use_ssl': 'yes'}
        cql_query = "SELECT * FROM test"

        # Execute when config file has SSL configuration - make sure command line options are used
        result = Executor.cqlsh(cql_query, config_file_content_with_ssl)

        # Verify
        assert result is not None
        expected_command = shlex.join([cqlsh_command(), Executor.cql_config['rpc_address'],
                                       Executor.cql_config['native_transport_port'],
                                       "-e", cql_query, "--ssl"])
        mock_run_command.assert_called_with(
            expected_command,
            shell=True,
            timeout=300,
            check=False
        )

    @patch('utils.Executor.run_command')
    @patch('utils.Executor.cqlsh_authentication_required')
    def test_cqlsh_configured_via_command_line_ssl_disabled(self, mock_auth_required, mock_run_command):
        """
        Test cqlsh with different RPC addresses provided via command line and SSL not enabled in either the command line
        or the config file.
        The command line options should take precedence over the config file values.
        The SSL option should be included in the command line if they are included in either command line or in the
        config file.
        The RPC address from the command line should be used regardless of the config file value.
        """
        # Setup
        mock_auth_required.return_value = False
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run_command.return_value = mock_result
        Executor.paths = {'scylla_directory': '/some/path'}

        config_file_content_with_ssl = {'rpc_address': 'wrong_address'}
        Executor.cql_config = {'rpc_address': 'good_address', 'native_transport_port': '1234'}
        cql_query = "SELECT * FROM test"

        # Execute when config file has SSL configuration - make sure command line options are used
        result = Executor.cqlsh(cql_query, config_file_content_with_ssl)

        # Verify
        assert result is not None
        expected_command = shlex.join([cqlsh_command(), Executor.cql_config['rpc_address'],
                                       Executor.cql_config['native_transport_port'],
                                       "-e", cql_query])
        mock_run_command.assert_called_with(
            expected_command,
            shell=True,
            timeout=300,
            check=False
        )

    @pytest.mark.parametrize("user,password,expected_command", [
        # Test user with space, and password with shell metacharacters
        ("test user", "pass$word;echo$(id)",
         lambda: shlex.join([cqlsh_command(), "192.168.1.10", "-e", "SELECT * FROM test",
                             "-u", "test user", "-p", "pass$word;echo$(id)"])),
        # Test user with quote, and password with backslashes
        ("special'_admin", "pass\\word\\123",
         lambda: shlex.join([cqlsh_command(), "192.168.1.10", "-e", "SELECT * FROM test",
                             "-u", "special'_admin", "-p", "pass\\word\\123"])),
        # Test password with mixed special characters
        ("test", "p@$$w0rd! & 'test' \"value\"",
         lambda: shlex.join([cqlsh_command(), "192.168.1.10", "-e", "SELECT * FROM test",
                             "-u", "test", "-p", "p@$$w0rd! & 'test' \"value\""])),
    ])
    @patch('utils.Executor.run_command')
    @patch('utils.Executor.cqlsh_authentication_required')
    def test_cqlsh_credential_escaping(self, mock_auth_required, mock_run_command,
                                       user, password, expected_command):
        """Test cqlsh command construction with proper escaping of usernames and passwords."""
        # Setup
        mock_auth_required.return_value = True
        Executor.cql_config = {'user': user, 'password': password}
        auth_scylla_config = {'rpc_address': '192.168.1.10', 'authenticator': 'PasswordAuthenticator'}
        mock_result = Mock()
        mock_result.returncode = 0
        mock_run_command.return_value = mock_result
        Executor.paths = {'scylla_directory': '/some/path'}

        # Execute
        result = Executor.cqlsh("SELECT * FROM test", auth_scylla_config)

        # Verify successful execution and proper command construction
        assert result is not None
        mock_run_command.assert_called_once_with(
            expected_command(),
            shell=True,
            timeout=300,
            check=False
        )

    @patch('utils.Executor.run_command')
    def test_cqlsh_timeout_exception_handling_and_retries(self, mock_run_command):
        """Test cqlsh retries time-outs 3 times and raises CqlFailedException with correct message"""
        # Simulate TimeoutExpired for each call
        cql_query = "SELECT * FROM test"
        rpc_address = "192.168.1.10"
        command = shlex.join(["cqlsh", rpc_address, "-e", cql_query])

        mock_run_command.side_effect = subprocess.TimeoutExpired(cmd=command, timeout=300)
        basic_scylla_config = {'rpc_address': rpc_address}
        Executor.paths = {'scylla_directory': '/some/path'}

        with pytest.raises(CqlFailedException) as exc_info:
            Executor.cqlsh(cql_query, basic_scylla_config)

        # Verify run_command was called 3 times
        assert mock_run_command.call_count == 3

        # Check the exception message
        assert "was attempted with 3 tries, and a timeout of 300 seconds" in str(exc_info.value)
        assert cql_query in str(exc_info.value) or "cqlsh" in str(exc_info.value)

    @pytest.mark.parametrize("user,password", [
        ("test user", "pass$word;echo$(id)"),
        ("special'_admin", "pass\\word\\123"),
        ("testuser", "p@$$w0rd! & 'test' \"value\""),
    ])
    @patch('utils.Executor.run_command')
    @patch('utils.Executor.cqlsh_authentication_required')
    def test_cqlsh_exception_features_no_credentials(self, mock_auth_required, mock_run_command, user, password):
        """Test that username and password are not present in CqlFailedException after all retries."""
        mock_auth_required.return_value = True
        Executor.cql_config = {'user': user, 'password': password}
        Executor.paths = {'scylla_directory': '/some/path'}
        auth_scylla_config = {'rpc_address': '192.168.1.10', 'authenticator': 'PasswordAuthenticator'}
        cql_query = "SELECT * FROM test"
        # Build the command as it would be constructed
        command = shlex.join([
            cqlsh_command(), "192.168.1.10", "-e", cql_query,
            "-u", user, "-p", password
        ])
        # Simulate TimeoutExpired for each call
        mock_run_command.side_effect = subprocess.TimeoutExpired(cmd=command, timeout=300)

        with pytest.raises(CqlFailedException) as exc_info:
            Executor.cqlsh(cql_query, auth_scylla_config)

        # The error message should not contain the raw username or password
        error_msg = str(exc_info.value)
        assert user not in error_msg
        assert password not in error_msg


class ConcreteCloudProvider(CloudProvider):
    """Minimal concrete subclass of CloudProvider for testing the base-class behaviour."""

    @property
    def belonging(self) -> bool:
        return False


class TestCloudProvider:
    @pytest.fixture
    def provider(self):
        return ConcreteCloudProvider()

    def test_instance_type_returns_none_by_default(self, provider):
        """Base CloudProvider.instance_type must return None (not implemented)"""
        assert provider.instance_type is None

    def test_cpu_platform_returns_none_by_default(self, provider):
        """Base CloudProvider.cpu_platform must return None (not implemented)"""
        assert provider.cpu_platform is None

    def test_scheduled_maintenance_events_returns_none_by_default(self, provider):
        """Base CloudProvider.scheduled_maintenance_events must return None"""
        assert provider.scheduled_maintenance_events is None

    def test_read_json_metadata_endpoint_uses_instance_values(self, provider):
        """_read_json_metadata_endpoint must use instance-level timeout/retries/retry_interval via read_metadata"""
        with patch.object(provider, 'read_metadata', return_value='{}') as mock_read:
            provider._read_json_metadata_endpoint("some/endpoint")
            mock_read.assert_called_once_with(url_path="some/endpoint", api_version=None)

    def test_scheduled_maintenance_event_bad_url(self, provider):
        """
        Verify that UrlReadFailedException is re-raised by scheduled_maintenance_events
        """
        with patch.object(provider, 'read_metadata', side_effect=UrlReadFailedException("URL retries failed")):
            try:
                _ = provider._read_json_metadata_endpoint("fake_url", "fake_api_version")
            except UrlReadFailedException as ex:
                assert str(ex) == "URL retries failed"

    def test_scheduled_maintenance_event_bad_result_format(self, provider):
        """
        Verify that RestEndpointOutputFormatError is raised when the output format is not a valid JSON object.
        """
        rest_return = '{ "error": "no notifications '
        api_path = "fake_url"
        api_version = "fake_api_version"
        with patch.object(provider, 'read_metadata', return_value=rest_return):
            with pytest.raises(RestEndpointOutputFormatError) as exc_info:
                _ = provider._read_json_metadata_endpoint(metadata_endpoint_suffix=api_path, api_version=api_version)
                assert (f"Error while parsing metadata endpoint {api_path} output - we expected JSON, returned "
                        f"'{rest_return}', parsing error") in str(exc_info.value)

    def test_scheduled_maintenance_event_unexpected_exception(self, provider):
        # Simulate UrlReadFailedException when no upcoming event
        exception_text = "Something bad happened"
        api_path = "fake_url"
        api_version = "fake_api_version"
        with patch.object(provider, 'read_metadata', side_effect=Exception(exception_text)):
            with pytest.raises(RestEndpointReadError) as exc_info:
                _ = provider._read_json_metadata_endpoint(metadata_endpoint_suffix=api_path, api_version=api_version)
                assert (f"Error while reading metadata endpoint {api_path} using api version {api_version}: "
                        f"{exception_text}") in str(exc_info.value)


class TestCloudProviderGCP:
    @pytest.fixture
    def provider(self):
        return CloudProviderGCP()

    def test_instance_type(self, provider):
        """instance_type strips the full resource path and returns only the machine type name"""
        with patch.object(provider, 'read_metadata',
                          return_value='projects/123456/machineTypes/n2-standard-8'):
            result = provider.instance_type
            assert result == "n2-standard-8"

    def test_instance_type_calls_read_metadata(self, provider):
        """instance_type must call read_metadata with the correct endpoint"""
        with patch.object(provider, 'read_metadata', return_value='zones/us/machineTypes/n2-standard-4') as mock_read:
            result_kw = provider.instance_type
            result_pos = provider.instance_type
            assert result_kw == result_pos
            mock_read.assert_called_once()  # second call served from cache

    def test_instance_type_memoized(self, provider):
        """Repeated access to instance_type must use the cache"""
        with patch.object(provider, 'read_metadata', return_value='zones/us/machineTypes/n2-standard-4') as mock_read:
            result1 = provider.instance_type
            result2 = provider.instance_type
            assert result1 == result2
            mock_read.assert_called_once()  # second access served from cache

    @pytest.mark.parametrize("raw_platform,expected", [
        ("Intel Ice Lake",     "Intel Ice Lake"),
        ("Intel Cascade Lake", "Intel Cascade Lake"),
        ("AMD Rome",           "AMD Rome"),          # unknown → returned as-is
    ])
    def test_cpu_platform(self, provider, raw_platform, expected):
        with patch.object(provider, 'read_metadata', return_value=raw_platform):
            result = provider.cpu_platform
            assert result == expected

    def test_cpu_platform_calls_read_metadata(self, provider):
        """cpu_platform must call read_metadata with the correct endpoint"""
        with patch.object(provider, 'read_metadata', return_value='Intel Ice Lake') as mock_read:
            provider.cpu_platform
            mock_read.assert_called_once_with("instance/cpu-platform")

    def test_scheduled_maintenance_event_pending(self, provider):
        # Simulate a pending maintenance event
        event_json = json.dumps({
            "can_reschedule": True,
            "latest_window_start_time": "2025-09-10T09:28:16+00:00",
            "maintenance_status": "PENDING",
            "start_time_window": {"earliest": "2025-09-10T09:28:15+00:00", "latest": "2025-09-10T13:28:15+00:00"},
            "type": "SCHEDULED",
            "window_end_time": "2025-09-10T13:28:15+00:00",
            "window_start_time": "2025-09-10T09:28:15+00:00"
        })
        with patch.object(provider, 'read_metadata', return_value=event_json):
            event = provider.scheduled_maintenance_events.pop()
            assert event["maintenance_status"] == "PENDING"
            assert event["type"] == "SCHEDULED"

    def test_scheduled_maintenance_event_unsupported_url(self, provider):
        # Simulate UrlReadFailedException when no upcoming event
        with patch.object(provider, 'read_metadata',
                          side_effect=UrlReadFailedException("URL retries failed", code=404)):
            events = provider.scheduled_maintenance_events
            assert events is None

    def test_scheduled_maintenance_event_url_overloaded(self, provider):
        # Simulate UrlReadFailedException when no upcoming event
        with patch.object(provider, 'read_metadata',
                          side_effect=UrlReadFailedException("URL retries failed", code=503)):
            events = provider.scheduled_maintenance_events
            assert events == []

    def test_scheduled_maintenance_event_NONE_string(self, provider):
        # Simulate a response of "NONE" when Maintenance Events are not supported
        with patch.object(provider, 'read_metadata', return_value='"NONE"'):
            events = provider.scheduled_maintenance_events
            assert events is None

    def test_scheduled_maintenance_event_no_events(self, provider):
        with patch.object(provider, 'read_metadata',
                          return_value='{ "error": "no notifications have been received yet, try again later" }'):
            events = provider.scheduled_maintenance_events
            assert events == []

    def test_scheduled_maintenance_event_unexpected_format(self, provider):
        # Simulate invalid GCP API response format
        metadata_endpoint_suffix = "instance/upcoming-maintenance?alt=json"
        bad_api_response = '[ "some event" ]'

        with patch.object(provider, 'read_metadata', return_value=bad_api_response):
            with pytest.raises(RestEndpointOutputFormatError) as exc_info:
                _ = provider.scheduled_maintenance_events
                assert (f"Unexpected format of GCP metadata endpoint {metadata_endpoint_suffix} output - we expected "
                        f"a dictionary or a string 'NONE', returned "
                        f"'{json.loads(bad_api_response)}'") == str(exc_info.value)


class TestCloudProviderAWS:
    @pytest.fixture
    def provider(self):
        return CloudProviderAWS()

    def test_instance_type(self, provider):
        with patch.object(provider, 'read_metadata', return_value='i3.xlarge'):
            assert provider.instance_type == "i3.xlarge"

    def test_instance_type_calls_read_metadata(self, provider):
        with patch.object(provider, 'read_metadata', return_value='i3.xlarge') as mock_read:
            provider.instance_type
            mock_read.assert_called_once_with("instance-type")

    def test_instance_class(self, provider):
        with patch.object(provider, 'read_metadata', return_value='i3.xlarge'):
            assert provider.instance_class == "i3"

    def test_instance_size(self, provider):
        with patch.object(provider, 'read_metadata', return_value='i3.xlarge'):
            assert provider.instance_size == "xlarge"

    @pytest.mark.parametrize("instance_type,expected", [
        ("i3.metal",   "Intel Broadwell"),
        ("i4i.xlarge", "Intel Ice Lake"),
        ("i3.xlarge",  None),
    ])
    def test_cpu_platform(self, provider, instance_type, expected):
        with patch.object(provider, 'read_metadata', return_value=instance_type):
            result = provider.cpu_platform
            assert result == expected

    @pytest.mark.parametrize("instance_type,expected_nic_type", [
        ("i3.xlarge",       "ena"),
        ("i3en.xlarge",     "ena"),
        ("i4i.xlarge",      "ena"),
        ("i7i.xlarge",      "ena"),
        ("i7ie.xlarge",     "ena"),
        ("i8g.xlarge",      "ena"),
        ("i8ge.xlarge",     "ena"),
        ("c3.xlarge",       "ixgbevf"),
        ("m4.16xlarge",     "ena"),
        ("m4.xlarge",       "ixgbevf"),
        ("z1d.xlarge",      "ena"),
    ])
    def test_enhanced_networking_nic_type(self, provider, instance_type, expected_nic_type):
        with patch.object(provider, 'read_metadata', return_value=instance_type):
            result = provider.enhanced_networking_nic_type()
            assert result == expected_nic_type

    def test_enhanced_networking_nic_type_unknown_instance_class(self, provider):
        """Returns None for unknown instance classes"""
        with patch.object(provider, 'read_metadata', return_value='x99.xlarge'):
            result = provider.enhanced_networking_nic_type()
            assert result is None

    def test_enhanced_networking_driver_support_true(self, provider):
        """Returns True when a NIC's driver matches the expected enhanced networking type"""
        with patch.object(provider, 'read_metadata', return_value='i3.xlarge'):  # → ena
            nics = {'eth0': {'driver': 'ena'}, 'eth1': {'driver': 'virtio'}}
            assert provider.enhanced_networking_driver_support(nics) is True

    def test_enhanced_networking_driver_support_false(self, provider):
        """Returns False when no NIC driver matches"""
        with patch.object(provider, 'read_metadata', return_value='i3.xlarge'):  # → ena
            nics = {'eth0': {'driver': 'virtio'}}
            assert provider.enhanced_networking_driver_support(nics) is False

    def test_enhanced_networking_driver_support_empty_nics(self, provider):
        """Returns False for an empty NICs dict"""
        with patch.object(provider, 'read_metadata', return_value='i3.xlarge'):
            assert provider.enhanced_networking_driver_support({}) is False

    def test_vpc_enabled_from_nics_no_nics(self, provider):
        """Returns False immediately when the NIC list is empty"""
        assert provider.vpc_enabled_from_nics([]) is False

    def test_vpc_enabled_from_nics_vpc_found(self, provider):
        """Returns True when VPC metadata is found for a NIC's MAC address"""
        with patch.object(CloudProviderAWS, 'nic_mac_address', return_value='0a:11:22:33:44:55'), \
             patch.object(provider, 'read_metadata', return_value='vpc-0abc1234'):
            result = provider.vpc_enabled_from_nics(['eth0'])
            assert result is True

    def test_vpc_enabled_from_nics_no_vpc(self, provider):
        """Returns False when VPC metadata is empty/None for all NICs"""
        with patch.object(CloudProviderAWS, 'nic_mac_address', return_value='0a:11:22:33:44:55'), \
             patch.object(provider, 'read_metadata', return_value=''):
            result = provider.vpc_enabled_from_nics(['eth0'])
            assert result is False

    def test_get_extra(self, provider):
        """get_extra composes enhanced networking and VPC results"""
        nics = {'eth0': {'driver': 'ena'}}
        with patch.object(provider, 'enhanced_networking_driver_support', return_value=True) as mock_en_drv, \
             patch.object(provider, 'enhanced_networking_nic_type', return_value='ena') as mock_en_type, \
             patch.object(provider, 'vpc_enabled_from_nics', return_value=True) as mock_vpc:
            result = provider.get_extra(nics=nics)
            assert result == {
                'enhanced_networking_driver_support': True,
                'enhanced_networking_nic_type': 'ena',
                'vpc_enabled_from_nics': True,
            }
            mock_en_drv.assert_called_once_with(nics)
            mock_en_type.assert_called_once_with()
            mock_vpc.assert_called_once_with(nics)

    def test_scheduled_maintenance_event_aws_pending(self, provider):
        # Simulate AWS scheduled maintenance events
        events_json = json.dumps([
            {
                "NotBefore": "20 Jan 2025 10:00:15 GMT",
                "Code": "system-reboot",
                "Description": "[Canceled] scheduled reboot",
                "EventId": "instance-event-asd121298asa",
                "NotAfter": "20 Jan 2025 10:22:25 GMT",
                "State": "completed"
            },
            {
                "NotBefore": "20 Jan 2025 11:00:15 GMT",
                "Code": "system-reboot",
                "Description": "[Active] scheduled reboot",
                "EventId": "instance-event-asdsad9182918",
                "NotAfter": "20 Jan 2025 11:22:25 GMT",
                "State": "active"
            }
        ])
        with patch.object(provider, 'read_metadata', return_value=events_json):
            events = provider.scheduled_maintenance_events
            assert events is not None
            assert isinstance(events, list)
            assert len(events) == 1
            assert events[0]["State"] == "active"
            assert events[0]["Description"] == "[Active] scheduled reboot"

    def test_scheduled_maintenance_event_aws_none(self, provider):
        # Simulate no upcoming event (empty list)
        no_event_json = json.dumps([])
        with patch.object(provider, 'read_metadata', return_value=no_event_json):
            events = provider.scheduled_maintenance_events
            assert events == []

    def test_scheduled_maintenance_event_unexpected_result_format(self, provider):
        # Simulate invalid AWS API response format (not a list)
        metadata_endpoint_suffix = "events/maintenance/scheduled"
        bad_api_responses = [
            '{}',  # Not a list
            json.dumps([{3: 4}, 1])  # List contains non-dict
        ]
        for bad_api_response in bad_api_responses:
            with patch.object(provider, 'read_metadata', return_value=bad_api_response):
                with pytest.raises(RestEndpointOutputFormatError) as exc_info:
                    _ = provider.scheduled_maintenance_events
                    assert (f"Unexpected format of AWS metadata endpoint {metadata_endpoint_suffix} output - "
                            f"we expected a list of dictionaries, returned "
                            f"'{json.loads(bad_api_response)}'") == str(exc_info.value)


class TestCloudProviderAzure:
    @pytest.fixture
    def provider(self):
        return CloudProviderAE()

    def test_instance_type(self, provider):
        """instance_type parses vmSize from the instance JSON"""
        metadata = json.dumps({"compute": {"vmSize": "Standard_L8s_v3"}})
        with patch.object(provider, 'read_metadata', return_value=metadata):
            result = provider.instance_type
            assert result == "Standard_L8s_v3"

    def test_instance_type_calls_read_metadata(self, provider):
        """instance_type must call read_metadata with the correct endpoint"""
        metadata = json.dumps({"compute": {"vmSize": "Standard_L8s_v3"}})
        with patch.object(provider, 'read_metadata', return_value=metadata) as mock_read:
            provider.instance_type
            mock_read.assert_called_once_with("instance")

    @pytest.mark.parametrize("vm_size,expected", [
        ("Standard_L8s_v2",  "AMD EPIC Naples"),
        ("Standard_L32s_v2", "AMD EPIC Naples"),
        ("Standard_L8s_v3",  "Intel Ice Lake"),
        ("Standard_D8s_v3",  None),   # not an LSv2/LSv3 — unknown
    ])
    def test_cpu_platform(self, provider, vm_size, expected):
        metadata = json.dumps({"compute": {"vmSize": vm_size}})
        with patch.object(provider, 'read_metadata', return_value=metadata):
            result = provider.cpu_platform
            assert result == expected

    def test_scheduled_maintenance_event_azure_none(self, provider):
        # Simulate Azure IMDS response with no events
        response_json = json.dumps({
            "DocumentIncarnation": "1",
            "Events": []
        })
        with patch.object(provider, 'read_metadata', return_value=response_json):
            events = provider.scheduled_maintenance_events
            assert events == []

    def test_scheduled_maintenance_event_azure_pending(self, provider):
        # Simulate Azure IMDS response with one scheduled event
        response_json = json.dumps({
            "DocumentIncarnation": "1",
            "Events": [
                {
                    "EventId": "event-123",
                    "EventType": "Reboot",
                    "ResourceType": "VirtualMachine",
                    "Resources": ["test-vm-1"],
                    "EventStatus": "Scheduled",
                    "NotBefore": "Mon, 07 Apr 2025 10:26:58 GMT",
                    "Description": "Platform maintenance",
                    "EventSource": "Platform",
                    "DurationInSeconds": 600
                }
            ]
        })
        with patch.object(provider, 'read_metadata', return_value=response_json):
            events = provider.scheduled_maintenance_events
            assert isinstance(events, list)
            assert len(events) == 1
            event = events[0]
            assert event["EventType"] == "Reboot"
            assert event["EventStatus"] == "Scheduled"
            assert event["Description"] == "Platform maintenance"

    def test_scheduled_maintenance_event_unexpected_result_format(self, provider):
        # Simulate invalid Azure API response format (not a list)
        metadata_endpoint_suffix = "scheduledevents"
        api_version = "2020-07-01"
        bad_api_responses = [
            '{}',  # Not a list
            json.dumps({"DocumentIncarnation": "1"}),  # Missing 'Events' key
            json.dumps({"DocumentIncarnation": "1", "Events": {}}),  # 'Events' is not a list
            json.dumps({"DocumentIncarnation": "1", "Events": ["not a dict"]}),  # 'Events' list contains non-dict
        ]

        for bad_api_response in bad_api_responses:
            with patch.object(provider, 'read_metadata', return_value=bad_api_response):
                with pytest.raises(RestEndpointOutputFormatError) as exc_info:
                    _ = provider.scheduled_maintenance_events
                    assert (f"Unexpected format of Azure metadata endpoint "
                            f"{metadata_endpoint_suffix} and api_version {api_version} output - "
                            f"we expected a dictionary with an "
                            f"'Events' key containing a list of dictionaries, "
                            f"returned '{json.loads(bad_api_response)}'") == str(exc_info.value)


class TestServiceManager:
    """Test cases for ServiceManager class"""

    @pytest.fixture
    def service_manager(self):
        return ServiceManager()

    @patch('utils.shutil.which')
    def test_detect_interface_supervisord(self, mock_which):
        """Test detection of supervisord interface"""
        mock_which.side_effect = lambda cmd: cmd == 'supervisorctl'
        interface = ServiceManager.detect_interface()
        assert interface == ServiceManager.Interface.SUPERVISORD

    @patch('utils.shutil.which')
    def test_detect_interface_systemd(self, mock_which):
        """Test detection of systemd interface"""
        mock_which.side_effect = lambda cmd: cmd == 'systemctl'
        interface = ServiceManager.detect_interface()
        assert interface == ServiceManager.Interface.SYSTEMD

    @patch('utils.shutil.which')
    def test_detect_interface_none(self, mock_which):
        """Test no interface detected"""
        mock_which.return_value = None
        interface = ServiceManager.detect_interface()
        assert interface is None

    @patch('utils.ServiceManager.detect_interface', return_value=ServiceManager.Interface.SYSTEMD)
    def test_init_systemd(self, mock_detect):
        """Test initialization with systemd interface"""
        sm = ServiceManager()
        assert sm.interface == ServiceManager.Interface.SYSTEMD

    @patch('utils.ServiceManager.detect_interface', return_value=ServiceManager.Interface.SUPERVISORD)
    def test_init_supervisord(self, mock_detect):
        """Test initialization with supervisord interface"""
        sm = ServiceManager()
        assert sm.interface == ServiceManager.Interface.SUPERVISORD

    def test_scylla_server_service_names(self, service_manager):
        """Test scylla server service names property"""
        assert service_manager._ServiceManager__scylla_server_service_names == ["scylla-server", "scylla"]

    @patch('utils.Executor.run_command')
    def test_is_systemd_service_is_system(self, mock_run_command, service_manager):
        """Test checking if systemd service is in a system mode"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_run_command.side_effect = [Mock(returncode=0), Exception("System mode")]

        result = service_manager._ServiceManager__get_systemd_service_mode("test-service")
        assert result == ServiceManager.SystemdServiceMode.SYSTEM
        mock_run_command.assert_any_call("systemctl cat test-service")
        mock_run_command.assert_any_call("systemctl --user cat test-service")

    @patch('utils.Executor.run_command')
    def test_is_systemd_service_is_per_user(self, mock_run_command, service_manager):
        """Test checking if systemd service is in a per-user mode"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_run_command.side_effect = [Exception("Per-user mode"), Mock(returncode=0)]

        result = service_manager._ServiceManager__get_systemd_service_mode("test-service")
        assert result == ServiceManager.SystemdServiceMode.PER_USER
        mock_run_command.assert_any_call("systemctl cat test-service")
        mock_run_command.assert_any_call("systemctl --user cat test-service")

    @patch('utils.Executor.run_command')
    def test_is_systemd_service_exists_both_as_system_and_as_per_user(self, mock_run_command, service_manager):
        """
        Test checking if systemd service defined both in system and per-user mode - SystemConfigurationError
        should be raised in this case.
        """
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_run_command.side_effect = Mock(returncode=0)

        with pytest.raises(SystemConfigurationError) as exc_info:
            service_manager._ServiceManager__get_systemd_service_mode("test-service")
            assert ("Service test-service is defined both as a system and a per-user service, which is not a valid "
                    "configuration") in str(exc_info.value)

        mock_run_command.assert_any_call("systemctl cat test-service")
        mock_run_command.assert_any_call("systemctl --user cat test-service")

    @patch('utils.Executor.run_command')
    def test_is_systemd_service_not_exists(self, mock_run_command, service_manager):
        """Test checking if systemd service does not exist"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_run_command.side_effect = Exception("Not found")

        result = service_manager._ServiceManager__get_systemd_service_mode("test-service")
        assert result == ServiceManager.SystemdServiceMode.NOT_EXISTS

    @patch('utils.Executor.run_command')
    def test_service_systemctl_system_command(self, mock_run_command, service_manager):
        """Test getting systemctl command for a system mode service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_run_command.side_effect = [Mock(returncode=0), Exception("System mode")]

        command = service_manager._ServiceManager__service_systemctl_command("test-service")
        assert command == "systemctl"

    @patch('utils.Executor.run_command')
    def test_service_systemctl_command_per_user(self, mock_run_command, service_manager):
        """Test getting systemctl command for per-user mode service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_run_command.side_effect = [Exception("Per-user mode"), Mock(returncode=0)]

        command = service_manager._ServiceManager__service_systemctl_command("test-service")
        assert command == "systemctl --user"

    @patch('utils.Executor.run_command')
    def test_service_systemctl_command_none(self, mock_run_command, service_manager):
        """Test getting systemctl command for non-existent service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_run_command.side_effect = Exception()

        command = service_manager._ServiceManager__service_systemctl_command("test-service")
        assert command is None

    @patch('utils.Executor.run_command')
    def test_service_autostarts_systemd_enabled(self, mock_run_command, service_manager):
        """Test service autostarts for enabled systemd service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_result = Mock(returncode=0)
        mock_run_command.return_value = mock_result

        with patch.object(service_manager, '_ServiceManager__service_systemctl_command', return_value="systemctl"):
            result = service_manager.service_autostarts("test-service")
            assert result is True

    @patch('utils.Executor.run_command')
    def test_service_autostarts_systemd_disabled(self, mock_run_command, service_manager):
        """Test service autostarts for disabled systemd service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_result = Mock(returncode=1)
        mock_run_command.return_value = mock_result

        with patch.object(service_manager, '_ServiceManager__service_systemctl_command', return_value="systemctl"):
            result = service_manager.service_autostarts("test-service")
            assert result is False

    @patch('utils.os.path.isdir', return_value=True)
    @patch('utils.glob.glob')
    @patch('utils.Executor.search_string_in_file')
    def test_service_autostarts_supervisord_true(self, mock_search, mock_glob, mock_isdir, service_manager):
        """Test service autostarts for supervisord service that exists"""
        service_manager.interface = ServiceManager.Interface.SUPERVISORD
        mock_glob.return_value = ["/etc/supervisord.conf.d/test.conf"]
        mock_search.return_value = ["[program:test-service]"]

        result = service_manager.service_autostarts("test-service")
        assert result is True

    @patch('utils.os.path.isdir', return_value=True)
    @patch('utils.glob.glob')
    @patch('utils.Executor.search_string_in_file')
    def test_service_autostarts_supervisord_false(self, mock_search, mock_glob, mock_isdir, service_manager):
        """Test service autostarts for supervisord service that does not exist"""
        service_manager.interface = ServiceManager.Interface.SUPERVISORD
        mock_glob.return_value = ["/etc/supervisord.conf.d/test.conf"]
        mock_search.return_value = None

        result = service_manager.service_autostarts("test-service")
        assert result is False

    @patch('utils.os.path.isdir', return_value=False)
    def test_service_autostarts_supervisord_no_dir(self, mock_isdir, service_manager):
        """Test service autostarts for supervisord when config dir does not exist"""
        service_manager.interface = ServiceManager.Interface.SUPERVISORD

        result = service_manager.service_autostarts("test-service")
        assert result is False

    @patch('utils.Executor.run_command')
    def test_service_environment_systemd(self, mock_run_command, service_manager):
        """Test service environment for systemd service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_result = Mock(returncode=0, stdout="Environment=KEY=VALUE\n")
        mock_run_command.return_value = mock_result

        with patch.object(service_manager, '_ServiceManager__service_systemctl_command', return_value="systemctl"):
            result = service_manager.service_environment("test-service")
            assert result == "Environment=KEY=VALUE"

    def test_service_environment_supervisord(self, service_manager):
        """Test service environment for supervisord service (not implemented)"""
        service_manager.interface = ServiceManager.Interface.SUPERVISORD

        with pytest.raises(NotImplementedError):
            service_manager.service_environment("test-service")

    @patch('utils.Executor.run_command')
    def test_service_exists_systemd_exists(self, mock_run_command, service_manager):
        """Test service exists for existing systemd service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD

        for mocking_system_mode in [[Mock(returncode=0), Exception("System mode")],
                                    [Exception("Per-user mode"), Mock(returncode=0)]]:
            mock_run_command.side_effect = mocking_system_mode
            result = service_manager.service_exists("test-service")
            assert result is True

    @patch('utils.Executor.run_command')
    def test_service_exists_systemd_not_exists(self, mock_run_command, service_manager):
        """Test service exists for non-existing systemd service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_run_command.side_effect = Exception("Does not exist")
        result = service_manager.service_exists("test-service")
        assert result is False

    def test_service_exists_supervisord(self, service_manager):
        """Test service exists for supervisord service"""
        service_manager.interface = ServiceManager.Interface.SUPERVISORD

        with patch.object(service_manager, 'service_active', return_value=True):
            result = service_manager.service_exists("test-service")
            assert result is True

    @patch('utils.Executor.run_command')
    def test_service_active_systemd_active(self, mock_run_command, service_manager):
        """Test service active for active systemd service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_result = Mock(returncode=0)
        mock_run_command.return_value = mock_result

        with patch.object(service_manager, '_ServiceManager__service_systemctl_command', return_value="systemctl"):
            result = service_manager.service_active("test-service")
            assert result is True

    @patch('utils.Executor.run_command')
    def test_service_active_systemd_inactive(self, mock_run_command, service_manager):
        """Test service active for inactive systemd service"""
        service_manager.interface = ServiceManager.Interface.SYSTEMD
        mock_result = Mock(returncode=1)
        mock_run_command.return_value = mock_result

        with patch.object(service_manager, '_ServiceManager__service_systemctl_command', return_value="systemctl"):
            result = service_manager.service_active("test-service")
            assert result is False

    @patch('utils.Executor.run_command')
    def test_service_active_supervisord_running(self, mock_run_command, service_manager):
        """Test service active for running supervisord service"""
        service_manager.interface = ServiceManager.Interface.SUPERVISORD
        mock_result = Mock(returncode=0, stdout="test-service RUNNING")
        mock_run_command.return_value = mock_result

        result = service_manager.service_active("test-service")
        assert result is True

    def test_scylla_server_service_active_true(self, service_manager):
        """Test scylla server service active when one is active"""
        with patch.object(service_manager, 'service_active', side_effect=[True, False]):
            result = service_manager.scylla_server_service_active
            assert result is True

    def test_scylla_server_service_active_false(self, service_manager):
        """Test scylla server service active when none are active"""
        with patch.object(service_manager, 'service_active', return_value=False):
            result = service_manager.scylla_server_service_active
            assert result is False


class TestReadCqlTable:
    """Test cases for Executor.read_cql_table with max_rows parameter"""

    # A minimal cqlsh CSV dump: header + 5 data rows
    _ROWS = 5
    _STDOUT = "col_a;col_b\n" + "\n".join(f"val_a{i};val_b{i}" for i in range(_ROWS)) + "\n"

    def _make_cqlsh_result(self, stdout: str) -> Mock:
        result = Mock()
        result.returncode = 0
        result.stdout = stdout
        return result

    @patch('utils.Executor.cqlsh')
    def test_no_max_rows_returns_all_rows(self, mock_cqlsh):
        mock_cqlsh.return_value = self._make_cqlsh_result(self._STDOUT)
        _, rows = Executor.read_cql_table({}, "test.table")
        assert len(rows) == self._ROWS

    @patch('utils.Executor.cqlsh')
    def test_max_rows_limits_result(self, mock_cqlsh):
        mock_cqlsh.return_value = self._make_cqlsh_result(self._STDOUT)
        _, rows = Executor.read_cql_table({}, "test.table", max_rows=2)
        assert len(rows) == 2
        assert rows[0] == {'col_a': 'val_a0', 'col_b': 'val_b0'}
        assert rows[1] == {'col_a': 'val_a1', 'col_b': 'val_b1'}

    @patch('utils.Executor.cqlsh')
    def test_max_rows_larger_than_table_returns_all_rows(self, mock_cqlsh):
        mock_cqlsh.return_value = self._make_cqlsh_result(self._STDOUT)
        _, rows = Executor.read_cql_table({}, "test.table", max_rows=100)
        assert len(rows) == self._ROWS

    @patch('utils.Executor.cqlsh')
    def test_max_rows_zero_returns_no_rows(self, mock_cqlsh):
        mock_cqlsh.return_value = self._make_cqlsh_result(self._STDOUT)
        _, rows = Executor.read_cql_table({}, "test.table", max_rows=0)
        assert len(rows) == 0

    @patch('utils.Executor.cqlsh')
    def test_max_rows_one_returns_single_row(self, mock_cqlsh):
        mock_cqlsh.return_value = self._make_cqlsh_result(self._STDOUT)
        _, rows = Executor.read_cql_table({}, "test.table", max_rows=1)
        assert len(rows) == 1
        assert rows[0] == {'col_a': 'val_a0', 'col_b': 'val_b0'}
