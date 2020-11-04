# -*- coding: utf-8 -*-

from __future__ import annotations

import logging
import logging.config
import time
from os import environ
from pprint import PrettyPrinter
from typing import TYPE_CHECKING, Sequence

from eduid_common.config.exceptions import BadConfiguration
from eduid_common.session import session

# From https://stackoverflow.com/a/39757388
# The TYPE_CHECKING constant is always False at runtime, so the import won't be evaluated, but mypy
# (and other type-checking tools) will evaluate the contents of that block.
if TYPE_CHECKING:
    from eduid_common.api.app import EduIDBaseApp


__author__ = 'lundberg'

"""
Adds the following entries to logging context:
system_hostname - Set with environment variable SYSTEM_HOSTNAME
app_name - Flask app name
eppn - Available if a user session is initiated
"""

DEFAULT_FORMAT = '{asctime} | {levelname:7} | {hostname} | {eppn:9} | {name:35} | {module:10} | {message}'


# Default to RFC3339/ISO 8601 with tz
class EduidFormatter(logging.Formatter):
    def formatTime(self, record: logging.LogRecord, datefmt=None) -> str:
        # self.converter seems incorrectly typed as a two-argument method (Callable[[Optional[float]], struct_time])
        ct = self.converter(record.created)  # type: ignore
        if datefmt:
            s = time.strftime(datefmt, ct)
        else:
            t = time.strftime('%Y-%m-%dT%H:%M:%S', ct)
            tz = time.strftime('%z', ct)  # Can evaluate to empty string
            if tz:
                tz = '{0}:{1}'.format(tz[:3], tz[3:])  # Need colon to follow the rfc/iso
            s = '{}.{:03.0f}{}'.format(t, record.msecs, tz)
        return s


class DebugTimeFilter(logging.Filter):
    """ A filter to add record.debugTime which is time since the logger was initialised in a fixed format """

    def filter(self, record: logging.LogRecord) -> bool:
        _seconds = record.relativeCreated / 1000
        record.__setattr__('debugTime', f'{_seconds:.3f}s')  # use setattr to prevent mypy unhappiness
        return True


class AppFilter(logging.Filter):
    def __init__(self, app_name):
        super().__init__()
        self.app_name = app_name

    def filter(self, record: logging.LogRecord) -> bool:
        # use setattr to prevent mypy unhappiness
        record.__setattr__(
            'system_hostname', environ.get('SYSTEM_HOSTNAME', '')
        )  # Underlying hosts name for containers
        record.__setattr__('hostname', environ.get('HOSTNAME', ''))  # Actual hostname or container id
        record.__setattr__('app_name', self.app_name)
        return True


class UserFilter(logging.Filter):
    def __init__(self, debug_eppns: Sequence[str]):
        super().__init__()
        self.debug_eppns = debug_eppns

    def filter(self, record: logging.LogRecord) -> bool:
        eppn = ''
        if session:
            eppn = session.get('user_eppn', '')
        record.__setattr__('eppn', eppn)  # use setattr to prevent mypy unhappiness
        if record.levelno == logging.DEBUG:
            # If debug_eppns is not empty, we filter debug messages here and only allow them
            # (return True) if the eppn found in the session above is present in the debug_eppns list.
            if self.debug_eppns and eppn not in self.debug_eppns:
                # debug_eppns is not empty, but the eppn is not present in it
                return False
        return True


class RequireDebugTrue(logging.Filter):
    def __init__(self, app_debug: bool):
        super().__init__()
        self.app_debug = app_debug

    def filter(self, record: logging.LogRecord) -> bool:
        return self.app_debug


class RequireDebugFalse(logging.Filter):
    def __init__(self, app_debug: bool):
        super().__init__()
        self.app_debug = app_debug

    def filter(self, record: logging.LogRecord) -> bool:
        return not self.app_debug


def merge_config(base_config: dict, new_config: dict) -> dict:
    def merge(node, key, value):
        if isinstance(value, dict):
            for item in value:
                try:
                    merge(node[key], item, value[item])
                except KeyError:
                    # No such key in base_config, just set it
                    node[key] = value
        else:
            node[key] = value

    for k, v in new_config.items():
        merge(base_config, k, v)
    return base_config


def init_logging(app: EduIDBaseApp) -> None:
    """
    Init logging using dictConfig.

    Will look for the following settings keys:
    LOG_LEVEL
    LOG_FORMAT (optional)

    Merges optional dictConfig from settings before initializing.
    """
    try:
        local_context = {
            'level': app.config.setdefault('log_level', 'INFO'),
            'format': app.config.setdefault('log_format', DEFAULT_FORMAT),
            'app_name': app.name,
            'app_debug': app.debug,
            'debug_eppns': app.config.debug_eppns,
        }
    except (KeyError, AttributeError) as e:
        raise BadConfiguration(message=f'Could not initialize logging local_context. {type(e).__name__}: {e}')

    if app.debug:
        # Flask expects to be able to debug log in debug mode
        local_context['level'] = 'DEBUG'

    settings_config = app.config.logging_config
    base_config = {
        'version': 1,
        'disable_existing_loggers': False,
        # Local variables
        'local_context': local_context,
        'formatters': {
            'default': {
                '()': 'eduid_common.api.logging.EduidFormatter',
                'fmt': 'cfg://local_context.format',
                'style': '{',
            },
        },
        'filters': {
            'app_filter': {'()': 'eduid_common.api.logging.AppFilter', 'app_name': 'cfg://local_context.app_name',},
            'user_filter': {
                '()': 'eduid_common.api.logging.UserFilter',
                'debug_eppns': 'cfg://local_context.debug_eppns',
            },
            'require_debug_true': {
                '()': 'eduid_common.api.logging.RequireDebugTrue',
                'app_debug': 'cfg://local_context.app_debug',
            },
            'require_debug_false': {
                '()': 'eduid_common.api.logging.RequireDebugFalse',
                'app_debug': 'cfg://local_context.app_debug',
            },
            'debugtime_filter': {'()': 'eduid_common.api.logging.DebugTimeFilter',},
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'cfg://local_context.level',
                'formatter': 'default',
                'filters': ['app_filter', 'user_filter', 'debugtime_filter'],
            },
        },
        'root': {'handlers': ['console'], 'level': 'cfg://local_context.level',},
    }
    logging_config = merge_config(base_config, settings_config)
    logging.config.dictConfig(logging_config)
    if app.debug:
        pp = PrettyPrinter()
        app.logger.debug(f'Logging config:\n{pp.pformat(logging_config)}')
    app.logger.info('Logging configured')
    return None
