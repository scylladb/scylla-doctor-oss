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

import operator
import socket
import ssl
import urllib.error
import urllib.request

from typing import Tuple, Optional


class InvalidVersionFormat(Exception):
    def __init__(self, raw_version: str):
        super().__init__(f"Unexpected version format: \"{raw_version}\"")


def sanitize_version(raw_version_string: str) -> Tuple[int, int, int]:
    """
     Convert raw_version to X.Y.Z format

     Return value: X,Y,Z
     """

    raw_version = raw_version_string.split(".")

    def try_parse_int(value):
        for part in value.split('-'):
            if part.isdigit():
                return int(part)
        raise Exception()

    try:
        if len(raw_version) >= 3:
            return try_parse_int(raw_version[0]), try_parse_int(raw_version[1]), try_parse_int(raw_version[2])
        elif len(raw_version) == 2:
            return try_parse_int(raw_version[0]), try_parse_int(raw_version[1]), 0
        elif len(raw_version) == 1:
            return try_parse_int(raw_version[0]), 0, 0
        else:
            return 0, 0, 0
    except Exception:
        raise InvalidVersionFormat(raw_version_string)


def compare_versions(raw_version_a: str, raw_version_b: str, comparison_operator: str) -> bool:
    """Compares 'version_a' against 'version_b' using 'comparison_operator'"""

    operators = {
        '>': operator.gt,
        '<': operator.lt,
        '>=': operator.ge,
        '<=': operator.le,
        '==': operator.eq
    }

    # Validate comparison operator
    if comparison_operator not in operators:
        raise TypeError('Invalid comparison operator')

    # 'Version A' and 'Version B' sanitization
    version_a = sanitize_version(raw_version_a)
    version_b = sanitize_version(raw_version_b)

    # Digit by digit comparison
    for index in range(0, 3):
        if version_a[index] == version_b[index]:
            continue
        if operators[comparison_operator](version_a[index], version_b[index]):
            return True
        else:
            return False

    if comparison_operator in ('==', '>=', '<='):
        return True

    return False


def get_url_content(url: str, timeout: int = 3) -> Optional[str]:
    """
    :param url: URL endpoint to GET.
    :param timeout: Timeout in seconds.
    :return: Returns the response body or None in case of an error.
    """
    context = ssl._create_unverified_context()
    sslHandler = urllib.request.HTTPSHandler(context=context)
    proxy_handler = urllib.request.ProxyHandler({})
    opener = urllib.request.build_opener(proxy_handler,
                                         sslHandler)
    urllib.request.install_opener(opener)

    try:
        req = urllib.request.Request(url)
        output = opener.open(req, timeout=timeout)
    except (urllib.error.URLError, socket.error):
        return None

    return output.read().decode("UTF-8")
