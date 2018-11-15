# -*- coding: utf-8 -*-

import re
import six
from uuid import uuid4
from flask import current_app, session

from eduid_userdb.exceptions import UserDBValueError, EduIDUserDBError
from eduid_userdb.exceptions import UserDoesNotExist, MultipleUsersReturned
from eduid_common.api.exceptions import ApiException

from six.moves.urllib_parse import urlparse


def get_unique_hash():
    return six.text_type(uuid4())


def get_short_hash(entropy=10):
    return uuid4().hex[:entropy]


def update_modified_ts(user):
    """
    When loading a user from the central userdb, the modified_ts has to be
    loaded from the private userdb (since it is not propagated to 'attributes'
    by the eduid-am worker).

    This need should go away once there is a global version number on the user document.

    :param user: User object from the central userdb
    :type user: eduid_userdb.User

    :return: None
    """
    try:
        userid = user.user_id
    except UserDBValueError:
        current_app.logger.debug("User {!s} has no id, setting modified_ts to None".format(user))
        user.modified_ts = None
        return
    
    private_user = current_app.private_userdb.get_user_by_id(userid, raise_on_missing=False)
    if private_user is None:
        current_app.logger.debug("User {!s} not found in {!s}, "
                                 "setting modified_ts to None".format(user, current_app.private_userdb))
        user.modified_ts = None
        return

    if private_user.modified_ts is None:
        private_user.modified_ts = True  # use current time
        current_app.logger.debug("Updating user {!s} with new modified_ts: {!s}".format(
            private_user, private_user.modified_ts))
        current_app.private_userdb.save(private_user, check_sync = False)

    user.modified_ts = private_user.modified_ts
    current_app.logger.debug("Updating {!s} with modified_ts from central userdb user {!s}: {!s}".format(
        user, private_user, private_user.modified_ts))


def get_user():
    """
    :return: Central userdb user
    :rtype: eduid_userdb.user.User
    """
    eppn = session.get('user_eppn', None)
    if not eppn:
        raise ApiException('Not authorized', status_code=401)
    try:
        # Get user from central database
        return current_app.central_userdb.get_user_by_eppn(eppn, raise_on_missing=True)
    except UserDoesNotExist as e:
        current_app.logger.error('Could not find user in central database.')
        current_app.logger.error(e)
        raise ApiException('Not authorized', status_code=401)
    except MultipleUsersReturned as e:
        current_app.logger.error('Found multiple users in central database.')
        current_app.logger.error(e)
        raise ApiException('Not authorized', status_code=401)


def save_and_sync_user(user):
    """
    Save (new) user object to the private userdb and propagate the changes to the central user db.

    May raise UserOutOfSync exception

    :param user: the modified user
    :type user: current_app.private_userdb.UserClass
    """
    if not isinstance(user, current_app.private_userdb.UserClass):
        raise EduIDUserDBError('user is not of type {}'.format(current_app.private_userdb.UserClass))
    current_app.private_userdb.save(user)
    return current_app.am_relay.request_user_sync(user)


def urlappend(base, path):
    """
    :param base: Base url
    :type base: six.string_types
    :param path: Path to join to base
    :type path: six.string_types
    :return: Joined url
    :rtype: six.string_types

    Used instead of urlparse.urljoin to append path to base in an obvious way.

    >>> urlappend('https://test.com/base-path', 'my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path/', 'my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path/', '/my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path', '/my-path')
    'https://test.com/base-path/my-path'
    >>> urlappend('https://test.com/base-path', '/my-path/')
    'https://test.com/base-path/my-path/'
    """
    path = path.lstrip('/')
    if not base.endswith('/'):
        base = '{!s}/'.format(base)
    return '{!s}{!s}'.format(base, path)


def get_flux_type(req, suffix):
    """
    :param req: flask request
    :type req: flask.request
    :param suffix: SUCCESS|FAIL|?
    :type suffix: str|unicode
    :return: Flux type
    :rtype: str|unicode
    """
    method = req.method
    blueprint = req.blueprint
    # Remove APPLICATION_ROOT from request url rule
    # XXX: There must be a better way to get the internal path info
    app_root = current_app.config['APPLICATION_ROOT']
    if app_root is None:
        app_root = ''
    url_rule = req.url_rule.rule.replace(app_root, '')
    url_rule = url_rule.replace('/', ' ').replace('-', ' ')
    url_rule = re.sub(r'<.+?>', '', url_rule)
    flux_type = '_'.join('{!s} {!s} {!s} {!s}'.format(method, blueprint, url_rule, suffix).split()).upper()
    return flux_type


def init_template_functions(app):

    @app.template_global()
    def static_url_for(f):
        return urlappend(current_app.config['EDUID_STATIC_URL'], f)

    return app


def verify_relay_state(relay_state, safe_default='/'):
    """
    :param relay_state: Next url
    :param safe_default: The default if relay state is found unsafe

    :type safe_default: six.string_types
    :type relay_state: six.string_types

    :return: Safe relay state
    :rtype: six.string_types
    """
    if relay_state is not None:
        current_app.logger.debug('Checking if relay state {} is safe'.format(relay_state))
        url_scheme = current_app.config['PREFERRED_URL_SCHEME']
        safe_domain = current_app.config['SAFE_RELAY_DOMAIN']
        parsed_relay_state = urlparse(relay_state)

        # If relay state is only a path
        if (not parsed_relay_state.scheme and not parsed_relay_state.netloc) and parsed_relay_state.path:
            return relay_state

        # If schema matches PREFERRED_URL_SCHEME and fqdn ends with dot SAFE_RELAY_DOMAIN or equals SAFE_RELAY_DOMAIN
        if parsed_relay_state.scheme == url_scheme:
            if parsed_relay_state.netloc.endswith('.' + safe_domain) or parsed_relay_state.netloc == safe_domain:
                return relay_state

        # Unsafe relay state found
        current_app.logger.warning('Caught unsafe relay state: {}. '
                                   'Using safe relay state: {}.'.format(relay_state, safe_default))
    return safe_default
