#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json
import os
import subprocess
import sys

ROOT_DIR = os.path.abspath(os.path.dirname(__file__))
REPORT_DIR = os.path.abspath(os.path.join(ROOT_DIR, './scout2-report'))
CODA_DIR = os.path.abspath(os.path.join(ROOT_DIR, './coda'))
EXCEPTIONS_FILE = os.path.abspath(os.path.join(CODA_DIR, './exceptions.json'))
WHITELIST_FILE = os.path.abspath(os.path.join(CODA_DIR, './whitelisted_ips.json'))
SCOUT2_TOOL = os.path.abspath(os.path.join(ROOT_DIR, './scout2.py'))
SCOUT2_REPORT_FILE = os.path.abspath(os.path.join(REPORT_DIR, './inc-awsconfig/aws_config.js'))
SCOUT2_COMMAND = [
    SCOUT2_TOOL,
    '--force',
    '--no-browser',
    '--report-dir',
    REPORT_DIR,
    '--exceptions',
    EXCEPTIONS_FILE,
    '--ip-ranges',
    WHITELIST_FILE,
]


def main():
    # Generate a fresh report
    print('Running {}'.format(' '.join(SCOUT2_COMMAND)))
    subprocess.check_call(SCOUT2_COMMAND)

    # Read the resulting report
    with open(SCOUT2_REPORT_FILE) as result_file:
        result_content = result_file.readlines()
    
    # Parse it into a python-friendly dict, skipping the first line.
    report = json.loads(''.join(result_content[1:]))
    
    print('REPORT ANALYSIS')
    print('---------------------------------------------------------')
    finding_count = 0
    for serviceName, serviceDetail in report['services'].items():
        for findingName, findingDetail in serviceDetail['findings'].items():
            flagged_count = findingDetail['flagged_items']
            if flagged_count > 0:
                finding_count += flagged_count
                print('{}: {} found {} issues.'.format(serviceName, findingName, flagged_count))
    print('---------------------------------------------------------')
    if finding_count > 0:
        print('ERROR: Found {} total unexpected issues'.format(finding_count))
    else:
        print('No issues found')
    sys.exit(finding_count)


if __name__ == "__main__":
    main()