# -*- coding: utf-8 -*-

# From https://stackoverflow.com/a/39757388
# The TYPE_CHECKING constant is always False at runtime, so the import won't be evaluated, but mypy
# (and other type-checking tools) will evaluate the contents of that block.
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from eduid_common.session.logindata import ExternalMfaData

from abc import ABC
from copy import deepcopy
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum, unique
from typing import Optional, Dict
from eduid_userdb.credentials import Credential


__author__ = 'ft'


class SessionNSBase(ABC):

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        return cls(**_data)


@unique
class LoginApplication(Enum):
    idp = 'idp'
    authn = 'authn'
    signup = 'signup'


@dataclass()
class Common(SessionNSBase):
    eppn: Optional[str] = None
    is_logged_in: bool = False
    login_source: Optional[LoginApplication] = None

    def to_dict(self):
        res = asdict(self)
        if res.get('login_source') is not None:
            res['login_source'] = res['login_source'].value
        return res

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        if _data.get('login_source') is not None:
            _data['login_source'] = LoginApplication(_data['login_source'])
        return cls(**_data)


@dataclass()
class SamlRequestInfo:
    saml_request: str
    relay_state: str
    binding: str


@dataclass()
class SamlIdp(SessionNSBase):
    requests: Dict[str, SamlRequestInfo] = field(default_factory=dict)


@dataclass()
class LoginRequest:
    expires_at: datetime
    return_endpoint_url: str
    require_mfa: bool = False


@dataclass()
class LoginResponse:
    expires_at: datetime
    sso_session_id: str
    #credentials_used: list = field(default_factory=list)  XXX: For later?
    mfa_action_creds: Dict[Credential, datetime] = field(default_factory=dict, init=False)
    mfa_action_external: Optional[ExternalMfaData] = field(default=None, init=False)


@dataclass()
class Login(SessionNSBase):
    requests: Dict[str, LoginRequest] = field(default_factory=dict)
    responses: Dict[str, LoginResponse] = field(default_factory=dict)


@dataclass()
class MfaAction(SessionNSBase):
    success: bool = False
    issuer: Optional[str] = None
    authn_instant: Optional[str] = None
    authn_context: Optional[str] = None


@dataclass()
class TimestampedNS(SessionNSBase):
    ts: Optional[datetime] = None

    def to_dict(self):
        res = super(TimestampedNS, self).to_dict()
        if res.get('ts') is not None:
            res['ts'] = str(int(res['ts'].timestamp()))
        return res

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        if _data.get('ts') is not None:
            _data['ts'] = datetime.fromtimestamp(int(_data['ts']))
        return cls(**_data)


@dataclass()
class Signup(TimestampedNS):
    """"""

@dataclass()
class Actions(TimestampedNS):
    session: Optional[str] = None
