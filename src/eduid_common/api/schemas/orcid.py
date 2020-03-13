# -*- coding: utf-8 -*-

from eduid_common.api.schemas.base import EduidSchema
from marshmallow import fields

__author__ = 'lundberg'


class OrcidSchema(EduidSchema):
    id = fields.String()
    name = fields.String()
    given_name = fields.String()
    family_name = fields.String()
