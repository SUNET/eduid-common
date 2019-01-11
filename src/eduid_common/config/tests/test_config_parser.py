# -*- coding: utf-8 -*-

import os
import unittest
import pkg_resources

from eduid_common.config.parsers import ConfigParser
from eduid_common.config.parsers.ini import IniConfigParser
from eduid_common.config.parsers.etcd import EtcdConfigParser

__author__ = 'lundberg'


class TestEtcdParser(unittest.TestCase):

    def tearDown(self):
        os.environ.clear()

    def test_IniConfigParser(self):
        os.environ.setdefault('EDUID_INI_FILE_NAME', '/path/to/a/file.ini')
        parser = ConfigParser()
        self.assertIsInstance(parser, IniConfigParser)

    def test_EtcdConfigParser(self):
        os.environ.setdefault('EDUID_CONFIG_NS', '/test/ns/')
        parser = ConfigParser()
        self.assertIsInstance(parser, EtcdConfigParser)

    def test_loading_non_usascii(self):
        data_dir = pkg_resources.resource_filename(__name__, 'data')
        config_file = os.path.join(data_dir, 'eduid_msg.ini')
        parser = IniConfigParser(config_file)
        settings = parser.read_configuration()
        self.assertTrue(settings['MM_DEFAULT_SUBJECT'].startswith('Meddelande'))
