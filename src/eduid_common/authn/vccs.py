#
# Copyright (c) 2015 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

import json

from datetime import datetime
from bson import ObjectId

import vccs_client

import logging
log = logging.getLogger(__name__)


def get_vccs_client(vccs_url):
    """
    Instantiate a VCCS client.
    :param vccs_url: VCCS authentication backend URL
    :type vccs_url: string
    :return: vccs client
    :rtype: VCCSClient
    """
    return vccs_client.VCCSClient(
        base_url=vccs_url,
    )


def check_password(vccs_url, password, user, vccs=None):
    """ Try to validate a user provided password.

    Returns False or a dict with data about the credential that validated.

    :param vccs_url: URL to VCCS authentication backend
    :param password: plaintext password
    :param user: user dict
    :param vccs: optional vccs client instance

    :type vccs_url: string
    :type password: string
    :type user: dict
    :type vccs: None or VCCSClient
    :rtype: bool or dict
    """
    if vccs is None:
        vccs = get_vccs_client(vccs_url)
    passwords = user.get_passwords()
    for password_dict in passwords:
        password_id = password_dict['id']
        factor = vccs_client.VCCSPasswordFactor(
            password,
            credential_id=str(password_id),
            salt=password_dict['salt'],
        )
        user_ids = [str(user.get_id()), user.get_mail()]
        if password_dict.get('user_id_hint') is not None:
            user_ids.insert(0, password_dict.get('user_id_hint'))
        try:
            for user_id in user_ids:
                if vccs.authenticate(user_id, [factor]):
                    password_dict['user_id_hint'] = user_id
                    return password_dict
        except Exception as e:
            log.info('Password check failed due to exception:  ' + str(e))
    return False


def add_credentials(vccs_url, old_password, new_password, user):
    """
    Add a new password to a user. Revokes the old one, if one is given.

    Returns True on success.

    :param vccs_url: URL to VCCS authentication backend
    :param old_password: plaintext current password
    :param new_password: plaintext new password
    :param user: user object

    :type vccs_url: string
    :type old_password: string
    :type user: User
    :rtype: bool
    """
    password_id = ObjectId()
    vccs = get_vccs_client(vccs_url)
    new_factor = vccs_client.VCCSPasswordFactor(new_password,
                                                credential_id=str(password_id))

    passwords = user.get_passwords()
    old_factor = None
    # remember if an old password was supplied or not, without keeping it in
    # memory longer than we have to
    old_password_supplied = bool(old_password)
    if passwords and old_password:
        # Find the old credential to revoke
        old_password = check_password(vccs_url, old_password, user, vccs=vccs)
        if not old_password:
            return False
        old_factor = vccs_client.VCCSRevokeFactor(
            str(old_password['id']),
            'changing password',
            reference='action.chpasswd',
        )

    if not vccs.add_credentials(str(user.get_id()), [new_factor]):
        log.warning("Failed adding password credential "
                    "{!r} for user {!r}".format(
                        new_factor.credential_id, user.get_id()))
        return False  # something failed
    log.debug("Added password credential {!s} for user {!s}".format(
        new_factor.credential_id, user.get_id()))

    if old_factor:
        # Use the user_id_hint inserted by check_password() until we know all
        # credentials use str(user['_id']) as user_id.
        vccs.revoke_credentials(old_password['user_id_hint'], [old_factor])
        passwords = [x for x in passwords if x['id'] != checked_password['id']]
        log.debug("Revoked old credential {!s} (user {!s})".format(
            old_factor.credential_id, user.get_id()))

    elif not old_password_supplied:
        # TODO: Revoke all current credentials on password reset for now
        revoked = []
        for password in passwords:
            revoked.append(vccs_client.VCCSRevokeFactor(str(password['id']),
                                                        'reset password',
                                                        reference='action.chpasswd'))
            log.debug("Revoked old credential (password reset) "
                      "{!s} (user {!s})".format(
                          password['id'], user.get_id()))
        if revoked:
            try:
                vccs.revoke_credentials(str(user.get_id()), revoked)
            except vccs_client.VCCSClientHTTPError:
                # Password already revoked
                # TODO: vccs backend should be changed to return something more informative than
                # TODO: VCCSClientHTTPError when the credential is already revoked or just return success.
                pass
        del passwords[:]

    passwords.append({
        'id': password_id,
        'salt': new_factor.salt,
        'source': 'dashboard',
        'created_ts': datetime.now(),
    })
    user.set_passwords(passwords)

    return True


def revoke_all_credentials(vccs_url, user):
    vccs = get_vccs_client(vccs_url)
    passwords = user.get_passwords()
    to_revoke = []
    for passwd_dict in passwords:
        credential_id = str(passwd_dict['id'])
        factor = vccs_client.VCCSRevokeFactor(
            credential_id,
            'subscriber requested termination',
            reference='dashboard'
        )
        log.debug("Revoked old credential (account termination)"
                  " {!s} (user {!s})".format(
                      credential_id, user.get_id()))
        to_revoke.append(factor)
    userid = str(user.get_id())
    vccs.revoke_credentials(userid, to_revoke)
