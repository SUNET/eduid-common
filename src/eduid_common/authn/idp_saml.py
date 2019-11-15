import warnings

import six
import logging
from dataclasses import dataclass
from typing import Mapping, NewType, Optional, AnyStr
from hashlib import sha1

from eduid_common.authn import utils
import saml2.server
from saml2.s_utils import UnknownPrincipal, UnknownSystemEntity, UnravelError, UnsupportedBinding, BadRequest
from saml2.saml import Issuer
from saml2.samlp import RequestedAuthnContext
from saml2.sigver import verify_redirect_signature

ResponseArgs = NewType('ResponseArgs', dict)

# TODO: Rename to logger when remove from function/method args
module_logger = logging.getLogger(__name__)


def gen_key(something: AnyStr) -> str:
    """
    Generate a unique (not strictly guaranteed) key based on `something'.

    :param something: object
    :return:
    """
    if isinstance(something, six.binary_type):
        return sha1(something).hexdigest()
    return sha1(something.encode('UTF-8')).hexdigest()


@dataclass
class AuthnInfo(object):
    """ Information about what AuthnContextClass etc. to put in SAML Authn responses."""

    class_ref: str
    authn_attributes: dict  # these are added to the user attributes
    instant: Optional[int] = None


class IdP_SAMLRequest(object):

    def __init__(self, request: str, binding: str, idp: saml2.server.Server, logger: Optional[logging.Logger],
                 debug: bool):
        self._request = request
        self._binding = binding
        self._relay_state: Optional[str] = None
        self._idp = idp
        self._logger = logger
        self._debug = debug

        if self._logger is not None:
            warnings.warn(
                "logger argument deprecated",
                DeprecationWarning
            )

        try:
            self._req_info = idp.parse_authn_request(request, binding)
        except UnravelError as exc:
            module_logger.info(f'Failed parsing SAML request ({len(request)} bytes)')
            module_logger.debug(f'Failed parsing SAML request:\n{request}\nException {exc}')
            raise

        if not self._req_info:
            # Either there was no request, or pysaml2 found it to be unacceptable.
            # For example, the IssueInstant might have been out of bounds.
            module_logger.debug('No valid SAMLRequest returned by pysaml2')
            raise ValueError('No valid SAMLRequest returned by pysaml2')

        # Only perform expensive parse/pretty-print if debugging
        if debug:
            xmlstr = utils.maybe_xml_to_string(self._req_info.message)
            module_logger.debug(f'Decoded SAMLRequest into AuthnRequest {repr(self._req_info.message)}:\n\n{xmlstr}\n\n')

    @property
    def binding(self):
        return self._binding

    def verify_signature(self, sig_alg: str, signature: str) -> bool:
        info = {'SigAlg': sig_alg,
                'Signature': signature,
                'SAMLRequest': self.request,
                }
        _certs = self._idp.metadata.certs(self.sp_entity_id, 'any', 'signing')
        verified_ok = False
        # Make sure at least one certificate verifies the signature
        for cert in _certs:
            if verify_redirect_signature(info, cert):
                verified_ok = True
                break
        if not verified_ok:
            _key = gen_key(info['SAMLRequest'])
            module_logger.info('{!s}: SAML request signature verification failure'.format(_key))
        return verified_ok

    @property
    def request(self) -> str:
        """The original SAMLRequest XML string."""
        return self._request

    @property
    def raw_requested_authn_context(self) -> Optional[RequestedAuthnContext]:
        return self._req_info.message.requested_authn_context

    def get_requested_authn_context(self) -> Optional[str]:
        """
        SAML requested authn context.

        TODO: Don't just return the first one, but the most relevant somehow.
        """
        if self.raw_requested_authn_context:
            return self.raw_requested_authn_context.authn_context_class_ref[0].text
        return None

    @property
    def raw_sp_entity_id(self) -> Issuer:
        return self._req_info.message.issuer

    @property
    def sp_entity_id(self) -> str:
        """The entity ID of the service provider as a string."""
        return self.raw_sp_entity_id.text

    @property
    def force_authn(self) -> Optional[bool]:
        return self._req_info.message.force_authn

    @property
    def request_id(self) -> str:
        return self._req_info.message.id

    @property
    def sp_entity_attributes(self) -> Mapping:
        """Return the entity attributes for the SP that made the request from the metadata."""
        try:
            return self._idp.metadata.entity_attributes(self.sp_entity_id)
        except KeyError:
            return {}

    @property
    def relay_state(self) -> Optional[str]:
        return self._relay_state

    @relay_state.setter
    def relay_state(self, value: Optional[str]):
        self._relay_state = value

    def get_response_args(self, bad_request=None, key: str = None) -> ResponseArgs:
        if bad_request is not None:
            warnings.warn(
                "bad_request argument deprecated",
                DeprecationWarning
            )
        if not key:
            raise TypeError(f'argument key can not be {type(key)}')
        try:
            resp_args = self._idp.response_args(self._req_info.message)

            # not sure if we need to call pick_binding again (already done in response_args()),
            # but it is what we've always done
            binding_out, destination = self._idp.pick_binding('assertion_consumer_service', entity_id=self.sp_entity_id)
            module_logger.debug(f'Binding: {binding_out}, destination: {destination}')

            resp_args['binding_out'] = binding_out
            resp_args['destination'] = destination
        except UnknownPrincipal as excp:
            module_logger.info(f'{key}: Unknown service provider: {excp}')
            raise BadRequest("Don't know the SP that referred you here")
        except UnsupportedBinding as excp:
            module_logger.info(f'{key}: Unsupported SAML binding: {excp}')
            raise BadRequest("Don't know how to reply to the SP that referred you here")
        except UnknownSystemEntity as exc:
            # TODO: Validate refactoring didn't move this exception handling to the wrong place.
            #       Used to be in an exception handler in _redirect_or_post around perform_login().
            module_logger.info(f'{key}: Service provider not known: {exc}')
            raise BadRequest('SAML_UNKNOWN_SP')

        return ResponseArgs(resp_args)

    def make_saml_response(self, attributes: Mapping, userid: str, response_authn: AuthnInfo, resp_args: ResponseArgs):
        # Create pysaml2 dict with the authn information
        authn = dict(class_ref = response_authn.class_ref,
                     authn_instant = response_authn.instant,
                     )
        saml_response = self._idp.create_authn_response(attributes, userid = userid,
                                                        authn = authn, sign_response = True,
                                                        **resp_args)
        return saml_response

    def apply_binding(self, resp_args: ResponseArgs, relay_state: str, saml_response: str):
        """ Create the Javascript self-posting form that will take the user back to the SP
        with a SAMLResponse.
        """
        binding_out = resp_args.get('binding_out')
        destination = resp_args.get('destination')
        module_logger.debug('Applying binding_out {!r}, destination {!r}, relay_state {!r}'.format(
            binding_out, destination, relay_state))
        http_args = self._idp.apply_binding(binding_out, str(saml_response), destination,
                                            relay_state, response = True)
        return http_args


def parse_saml_request(request_params: Mapping, binding: str, idp: saml2.server.Server,
                       logger: Optional[logging.Logger], debug: bool = False,
                       verify_request_signatures: bool = True) -> IdP_SAMLRequest:
    """
    Parse a SAMLRequest (base64 encoded) into an AuthnRequest instance.
    If the SAMLRequest is signed, the signature is validated.
    BadRequest raised on failure.
    """
    if logger is not None:
        warnings.warn(
            "logger argument deprecated",
            DeprecationWarning
        )
    try:
        saml_req = IdP_SAMLRequest(request_params['SAMLRequest'], binding, idp, logger, debug=debug)
    except UnravelError as e:
        module_logger.error(f'{e}: No valid SAMLRequest found')
        raise BadRequest('No valid SAMLRequest found')
    except ValueError as e:
        module_logger.error(f'{e}: No valid SAMLRequest found')
        raise BadRequest('No valid SAMLRequest found')
    
    if request_params.get('RelayState'):
        saml_req.relay_state = request_params.get('RelayState')

    if request_params.get('SigAlg') and request_params.get('Signature'):  # Signed request
        if verify_request_signatures:
            if not saml_req.verify_signature(request_params['SigAlg'], request_params['Signature']):
                module_logger.error('SAML request signature verification failure')
                raise BadRequest('SAML request signature verification failure')
        else:
            module_logger.debug('Ignoring existing request signature, verify_request_signature is False')
    else:
        # XXX check if metadata says request should be signed ???
        # Leif says requests are typically not signed, and that verifying signatures
        # on SAML requests is considered a possible DoS attack vector, so it is typically
        # not done.
        module_logger.debug('No signature in SAMLRequest')

    return saml_req
