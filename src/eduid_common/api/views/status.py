# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
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

from __future__ import absolute_import

from flask import jsonify
from flask import Blueprint, current_app, request, abort
import redis

from eduid_common.session.session import get_redis_pool


status_views = Blueprint('status', __name__, url_prefix='')


def _check_mongo():
    db = current_app.central_userdb
    try:
        c = db.db_count()
        if c > 0:
            return True
        current_app.logger.debug('Mongodb health check failed: db count == {!r}'.format(c))
    except Exception as exc:
        current_app.logger.debug('Mongodb health check failed: {}'.format(exc))
        return False
    else:
        db.close()
        return False

def _check_redis():
    pool = get_redis_pool(current_app.config)
    client = redis.StrictRedis(connection_pool=pool)
    try:
        pong = client.ping()
    except Exception as exc:
        current_app.logger.debug('Redis health check failed: {}'.format(exc))
        return False
    else:
        if pong == 'PONG':
            return True
        current_app.logger.debug('Redis health check failed: response == {!r}'.format(pong))
    return False


@status_views.route('/healthy', methods=['GET'])
def smoke_test():
    res = {'status': 'STATUS_FAIL'}
    if not _check_mongo():
        res['reason'] = 'mongodb check failed'
    elif not _check_redis():
        res['reason'] = 'redis check failed'
    else:
        res['status'] = 'STATUS_OK'
        res['reason'] = 'Databases tested OK'
    return jsonify(res)


@status_views.route('/sanity-check', methods=['GET'])
def sanity_check():
    pass
