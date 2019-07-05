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
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import urlencode

from eduid_common.session.namespaces import SessionNSBase
from eduid_common.authn.idp_authn import ExternalMfaData
from eduid_common.authn.idp_saml import IdP_SAMLRequest
from eduid_userdb.credentials import Credential


@dataclass
class SSOLoginData(SessionNSBase):
    """
    Class to hold data about an ongoing login process - i.e. data relating to a
    particular IdP visitor in the process of logging in, but not yet fully logged in.

    :param key: Unique reference for this instance.
    :param saml_req: Parsed SAML request.
    :param RelayState: This is an opaque string generated by a SAML SP that must be
                        sent to the SP when the authentication is finished and the
                        user redirected to the SP.
    :param FailCount: The number of failed login attempts. Used to show an alert
                      message to the user to make them aware of the reason they got
                      back to the IdP login page.
    """
    key: str
    saml_req: IdP_SAMLRequest
    RelayState: str = ''
    FailCount: int = 0

    # The SAML request in transport encoding (base 64)
    SAMLRequest: str = field(init=False)
    # binding this request was received with
    binding: str = field(init=False)
    # query string
    query_string: str = field(init=False)

    mfa_action_creds: Dict[Credential, datetime] = field(default_factory=dict, init=False)
    mfa_action_external: Optional[ExternalMfaData] = field(default=None, init=False)

    def __post_init__(self):
        self.key = escape(self.key, quote=True)
        self.RelayState = escape(self.RelayState, quote=True)
        self.SAMLRequest = escape(self.saml_req.request, quote=True)
        self.binding = escape(self.saml_req.binding, quote=True)
        qs = {
            'SAMLRequest': self.SAMLRequest,
            'RelayState': self.RelayState
        }
        self.query_string = urlencode(qs)

    def to_dict(self):
        return {'key': unescape(self.key),
                'req_info': self.saml_req,
                'SAMLRequest': self.saml_req.request,  # backwards compat
                'RelayState': unescape(self.RelayState),
                'binding': self.saml_req.binding,  # backwards compat
                'FailCount': self.FailCount,
                }

    @classmethod
    def from_dict(cls, data):
        key = escape(data['key'])
        saml_req = data['req_info']
        RelayState = escape(data['RelayState'])
        FailCount = data['FailCount']
        return cls(key, saml_req, RelayState, FailCount)

    def __str__(self):
        data = self.to_dict()
        if 'SAMLRequest' in data:
            data['SAMLRequest length'] = len(data['SAMLRequest'])
            del data['SAMLRequest']
        return pprint.pformat(data)