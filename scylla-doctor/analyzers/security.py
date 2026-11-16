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

from typing import Set

from analyzers_base import Analyzer, AnalyzerStatus
from common import DictView, Authenticator


class AuthenticationAnalyzer(Analyzer):
    """
    Verify authentication best practices: authentication enabled, and default cassandra/cassandra absent.
    """

    __DEFAULT_ROLE = 'cassandra'

    @property
    def name(self) -> str:
        return "Authentication best practices"

    @property
    def __collector_config(self) -> str:
        return "SystemConfigCollector"

    @property
    def __collector_roles(self) -> str:
        return "RolesCollector"

    @property
    def __collector_default_credentials(self) -> str:
        return "DefaultCredentialsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__collector_config, self.__collector_roles, self.__collector_default_credentials}

    def _analyze(self, vitals: DictView) -> None:
        """
        Check that authentication is enabled and the default cassandra/cassandra credentials are not present.
        """
        # Effective in-memory authenticator from system.config, not the on-disk yaml: the option
        # can also be given on the command line, in which case the yaml would be misleading.
        authenticator_raw = (vitals[self.__collector_config].data.get('authenticator') or {}).get('value')
        if not authenticator_raw:
            self.status = AnalyzerStatus.FAILED
            self.message = ("The 'authenticator' parameter is missing from system.config, "
                            "authentication cannot be verified")
            return

        authenticator = Authenticator.parse(authenticator_raw)
        roles = vitals[self.__collector_roles].data
        default_credentials_check = vitals[self.__collector_default_credentials].data

        if authenticator is Authenticator.ALLOW_ALL:
            auth_status, auth_msg = (
                AnalyzerStatus.FAILED,
                f"Authentication is disabled (authenticator is '{authenticator_raw}')",
            )
        elif authenticator is Authenticator.TRANSITIONAL:
            recommended = ', '.join(a.value for a in Authenticator.recommended())
            auth_status, auth_msg = (
                AnalyzerStatus.WARNING,
                f"Authentication is transitional (authenticator is '{authenticator_raw}'); "
                f"prefer a non-transitional authenticator ({recommended})",
            )
        elif authenticator is Authenticator.UNKNOWN:
            auth_status, auth_msg = (
                AnalyzerStatus.FAILED,
                f"Unrecognized authenticator '{authenticator_raw}'",
            )
        else:
            auth_status, auth_msg = (
                AnalyzerStatus.PASSED,
                f"Authentication is enabled (authenticator is '{authenticator_raw}')",
            )

        # Successful login with cassandra/cassandra already implies the default role exists, so
        # report one finding instead of two near-identical failures.
        default_role_present = any(row.get('role') == self.__DEFAULT_ROLE for row in roles)
        default_user_login = default_credentials_check.get('default_user_login')
        if default_user_login == 'allowed':
            role_status, role_msg = (
                AnalyzerStatus.FAILED,
                f"Default user '{self.__DEFAULT_ROLE}' can still log in with password "
                f"'{self.__DEFAULT_ROLE}'; create a custom superuser and drop the default role",
            )
        elif default_role_present:
            role_status, role_msg = (
                AnalyzerStatus.FAILED,
                f"Default role '{self.__DEFAULT_ROLE}' is still present; create a custom superuser and drop it",
            )
        else:
            role_status, role_msg = (
                AnalyzerStatus.PASSED,
                f"Default role '{self.__DEFAULT_ROLE}' is not present",
            )

        self.status = AnalyzerStatus.combine([auth_status, role_status])
        self.message = f"{auth_msg}; {role_msg}"


class BrokenRolePermissionsAnalyzer(Analyzer):
    """
    Verify that there are no 'null' permissions in the 'roles' table..
    """
    @property
    def name(self) -> str:
        return "Verify non-null permissions in the 'roles' table"

    @property
    def __roles_permissions_collector(self) -> str:
        return "RolePermissionsCollector"

    @property
    def depends_on(self) -> Set[str]:
        return {self.__roles_permissions_collector}

    def _analyze(self, vitals: DictView) -> None:
        permissions = vitals[self.__roles_permissions_collector].data
        errors = []
        for permission in permissions:
            # If permissions have a null value, it will be presented as an empty string in the Collector's data
            if permission.get('permissions', '') == '':
                self.status = AnalyzerStatus.FAILED
                errors.append(f"Role '{permission.get('role')}' has a null permission for "
                              f"resource '{permission.get('resource')}'")

        if errors:
            self.status = AnalyzerStatus.FAILED
            self.message = " ; ".join(errors)
        else:
            self.status = AnalyzerStatus.PASSED
            self.message = "No null permissions in the 'roles' table."
