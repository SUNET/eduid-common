# -*- coding: utf-8 -*-

from eduid_common.api.schemas.base import EduidSchema
from marshmallow import fields

__author__ = 'lundberg'


class NinSchema(EduidSchema):
    number = fields.String(required=True)
    verified = fields.Boolean(required=True)
    primary = fields.Boolean(required=True)
