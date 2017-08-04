# -*- coding: utf-8 -*-

import json
import re

from opinel.utils.fs import read_ip_ranges

from AWSScout2.utils import format_service_name

ip_ranges_from_args = 'ip-ranges-from-args'

re_aws_account_id = re.compile(r'_AWS_ACCOUNT_ID_')
re_ip_ranges_from_file = re.compile(r'_IP_RANGES_FROM_FILE_\((.*?)\)')
re_ip_ranges_from_local_file = re.compile(r'_IP_RANGES_FROM_LOCAL_FILE`_\((.*?)\)')

testcases = [
    {
        'name': 'aws_account_id',
        'regex': re_aws_account_id
    },
    {
        'name': 'ip_ranges_from_file',
        'regex': re_ip_ranges_from_file
    },
    {
        'name': 'ip_ranges_from_local_file',
        'regex': re_ip_ranges_from_local_file
    }
]

class Rule(object):

    def __init__(self, filename, rule_type, enabled, level, arg_values):
        self.filename = filename
        self.rule_type = rule_type
        self.enabled = bool(enabled)
        self.level = level
        self.args = arg_values


    def set_definition(self, rule_definitions, attributes = [], ip_ranges = [], params = {}):
        """
        Update every attribute of the rule by setting the argument values as necessary

        :param parameterized_input:
        :param arg_values:
        :param convert:
        :return:
        """
        string_definition = rule_definitions[self.filename].string_definition
        parameters = re.findall(r'(_ARG_([a-zA-Z0-9]+)_)', string_definition)
        for param in parameters:
            index = int(param[1])
            string_definition = string_definition.replace(param[0], self.args[index])
        definition = json.loads(string_definition)
        # Set special values (IP ranges, AWS account ID, ...)
        if len(attributes):
          for condition in definition['conditions']:
            if type(condition) != list or len(condition) == 1 or type(condition[2]) == list:
                continue
            for testcase in testcases:
                result = testcase['regex'].match(condition[2])
                if result and (testcase['name'] == 'ip_ranges_from_file' or testcase['name'] == 'ip_ranges_from_local_file'):
                    filename = result.groups()[0]
                    if filename == ip_ranges_from_args:
                        prefixes = []
                        for filename in ip_ranges:
                            prefixes += read_ip_ranges(filename, local_file = True, ip_only = True)
                        condition[2] = prefixes
                    else:
                        local_file = True if testcase['name'] == 'ip_ranges_from_local_file' else False
                        condition[2] = read_ip_ranges(filename, local_file = local_file, ip_only = True)
                    break
                else:
                    condition[2] = testcase['regex']
                    break

        if len(attributes) == 0:
            attributes = [attr for attr in definition]
        for attr in attributes:
            if attr in definition:
                setattr(self, attr, definition[attr])
        if hasattr(self, 'path'):
            self.service = format_service_name(self.path.split('.')[0])
        if not hasattr(self, 'key'):
            setattr(self, 'key', self.filename)
        setattr(self, 'key', self.key.replace('.json', ''))
