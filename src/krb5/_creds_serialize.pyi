# Copyright: (c) 2021 Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import typing

from krb5._context import Context
from krb5._creds import Creds

def marshal_credentials(
    context: Context,
    creds: Creds
) -> bytes:
    """Marshal credentials"""
