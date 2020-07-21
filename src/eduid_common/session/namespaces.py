# -*- coding: utf-8 -*-

from abc import ABC
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum, unique
from typing import Optional

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
class SamlRequestInfo(SessionNSBase):
    saml_request: str
    relay_state: str
    binding: str


@dataclass()
class SamlIdp(SessionNSBase):
    requests: Dict[str, SamlRequestInfo] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        for key, request in _data.get('requests', {}).items():
            _data['requests'][key] = SamlRequestInfo.from_dict(request)
        return cls(**_data)


@dataclass()
class ExpiringData(SessionNSBase):
    expires_at: datetime

    def __post_init__(self):
        if isinstance(self.expires_at, str):
            self.expires_at = datetime.fromisoformat(self.expires_at)


@dataclass()
class LoginRequest(ExpiringData):
    return_endpoint_url: str
    require_mfa: bool = False
    force_authn: bool = False
    verified_credentials: List[SessionAuthnData] = field(default_factory=list)
    eppn: Optional[str] = None
    sso_session_public_id: Optional[str] = None


@dataclass()
class SessionAuthnData:
    cred_id: str
    authn_ts: datetime
    issuer: Optional[str] = None
    authn_context: Optional[str] = None

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        if data.get('authn_ts') and not isinstance(data.get('authn_ts'), datetime):
            _data['authn_ts'] = datetime.fromisoformat(_data['authn_ts'])
        return cls(**_data)


@dataclass()
class LoginResponse(ExpiringData):
    public_sso_session_id: str
    credentials_used: List[SessionAuthnData] = field(default_factory=list)
    mfa_action_external: Optional[ExternalMfaData] = field(default=None)

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        _data['credentials_used'] = []
        for item in data.get('credentials_used'):
            _data['credentials_used'].append(SessionAuthnData.from_dict(item))
        return cls(**_data)


@dataclass()
class Login(SessionNSBase):
    requests: Dict[str, LoginRequest] = field(default_factory=dict)
    responses: Dict[str, LoginResponse] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data):
        _data = deepcopy(data)  # do not modify callers data
        for key, request in _data.get('requests', {}).items():
            _data['requests'][key] = LoginRequest.from_dict(request)
        for key, response in _data.get('responses', {}).items():
            _data['responses'][key] = LoginResponse.from_dict(response)
        return cls(**_data)


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
            _data['ts'] = datetime.isoformat(_data['ts'])
        return cls(**_data)


@dataclass
class ResetPasswordNS(SessionNSBase):
    generated_password_hash: Optional[str] = None
    # XXX the keys below are not in use yet. They are set in eduid-common,
    # in a way that the security app understands. Once the (reset|change)
    # password views are removed from the security app, we will be able to
    # start using them. The session key reauthn-for-chpass is in the same
    # situation.
    extrasec_u2f_challenge: Optional[str] = None
    extrasec_webauthn_state: Optional[str] = None


@dataclass()
class Signup(TimestampedNS):
    email_verification_code: Optional[str] = None


@dataclass()
class Actions(TimestampedNS):
    session: Optional[str] = None
