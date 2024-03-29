# -*- coding: utf-8 -*-

import logging

import eduid_am

from eduid_userdb import User
from eduid_userdb.exceptions import LockedIdentityViolation

from eduid_common.api.exceptions import AmTaskFailed
from eduid_common.config.base import AmConfigMixin

__author__ = 'lundberg'

logger = logging.getLogger(__name__)


class AmRelay(object):
    def __init__(self, config: AmConfigMixin):
        """
        :param config: celery config
        :param relay_for: Name of application to relay for
        """
        self.relay_for = f'eduid_{config.app_name}'
        if config.am_relay_for_override is not None:
            self.relay_for = config.am_relay_for_override

        eduid_am.init_app(config.celery)
        # these have to be imported _after_ eduid_am.init_app()
        from eduid_am.tasks import pong, update_attributes_keep_result

        self._update_attrs = update_attributes_keep_result
        self._pong = pong

    def request_user_sync(self, user: User, timeout: int = 25) -> bool:
        """
        Use Celery to ask eduid-am worker to propagate changes from our
        private UserDB into the central UserDB.

        :param user: User object
        :param timeout: Max wait time for task to finish

        :return: True if successful
        """
        # XXX: Do we need to check for acceptable_user_types?
        try:
            user_id = str(user.user_id)
        except (AttributeError, ValueError) as e:
            logger.error(f'Bad user_id in sync request: {e}')
            raise ValueError('Missing user_id. Can only propagate changes for eduid_userdb.User users.')

        logger.debug(f"Asking Attribute Manager to sync user {user}")
        rtask = self._update_attrs.delay(self.relay_for, user_id)
        try:
            result = rtask.get(timeout=timeout)
            logger.debug(f'Attribute Manager sync result: {result} for user {user}')
            return result
        except LockedIdentityViolation as e:
            rtask.forget()
            raise e
        except Exception as e:
            rtask.forget()
            logger.exception(f'Failed Attribute Manager sync request for user {user}')
            raise AmTaskFailed(f'request_user_sync task failed: {e}')

    def ping(self, timeout: int = 1) -> str:
        """
        Check if this application is able to reach an AM worker.
        :return: Result of celery Task.get
        """
        rtask = self._pong.apply_async(kwargs={'app_name': self.relay_for})
        try:
            return rtask.get(timeout=timeout)
        except Exception as e:
            rtask.forget()
            raise AmTaskFailed(f'ping task failed: {repr(e)}')
