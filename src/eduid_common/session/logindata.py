#
# Copyright (c) 2013, 2014, 2016 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

import pprint
from datetime import datetime
from html import escape, unescape
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional
from urllib.parse import urlencode

from eduid_common.session.namespaces import SessionNSBase
from eduid_common.authn.idp_saml import IdP_SAMLRequest
from eduid_userdb.credentials import Credential


@dataclass
class ExternalMfaData(object):
    """
    Data about a successful external authentication as a multi factor.
    """
    issuer: str
    authn_context: str
    timestamp: datetime

    def to_session_dict(self):
        return asdict(self)

    @classmethod
    def from_session_dict(cls, data: Dict):
        return cls(**data)


@dataclass
class SSOLoginData(SessionNSBase):
    """
    Class to hold data about an ongoing login process - i.e. data relating to a
    particular IdP visitor in the process of logging in, but not yet fully logged in.

    :param key: Unique reference for this instance.
    :param SAMLRequest: SAML request.
    :param binding: SAML binding
    :param RelayState: This is an opaque string generated by a SAML SP that must be
                        sent to the SP when the authentication is finished and the
                        user redirected to the SP.
    :param FailCount: The number of failed login attempts. Used to show an alert
                      message to the user to make them aware of the reason they got
                      back to the IdP login page.
    """
    key: str
    SAMLRequest: str
    binding: str
    RelayState: str = ''
    FailCount: int = 0

    # saml request object
    saml_req: IdP_SAMLRequest = field(init=False)

    # query string
    query_string: str = field(init=False)

    mfa_action_creds: Dict[Credential, datetime] = field(default_factory=dict, init=False)
    mfa_action_external: Optional[ExternalMfaData] = field(default=None, init=False)

    def __post_init__(self):
        self.key = escape(self.key, quote=True)
        self.RelayState = escape(self.RelayState, quote=True)
        self.SAMLRequest = escape(self.SAMLRequest, quote=True)
        self.binding = escape(self.binding, quote=True)
        qs = {
            'SAMLRequest': self.SAMLRequest,
            'RelayState': self.RelayState
        }
        self.query_string = urlencode(qs)

    def to_dict(self):
        return {'key': unescape(self.key),
                'SAMLRequest': unescape(self.SAMLRequest),  # backwards compat
                'RelayState': unescape(self.RelayState),
                'binding': unescape(self.binding),  # backwards compat
                'FailCount': self.FailCount,
                }

    @classmethod
    def from_dict(cls, data):
        key = escape(data['key'])
        SAMLRequest = escape(data['SAMLRequest'])
        binding = escape(data['binding'])
        RelayState = escape(data['RelayState'])
        FailCount = data['FailCount']
        return cls(key, SAMLRequest, binding, RelayState, FailCount)

    def __str__(self):
        data = self.to_dict()
        if 'SAMLRequest' in data:
            data['SAMLRequest length'] = len(data['SAMLRequest'])
            del data['SAMLRequest']
        return pprint.pformat(data)
