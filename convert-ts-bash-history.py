#!/usr/bin/env python3
"""

    Author: Jim Clausing <jclausing@isc.sans.edu>

    Date: 2025-09-26
    Version: 0.9.1

    This script takes 1 or more filenames of .bash_history files
    and returns a | separated list with 
        <filename>|<datetime>|<command>
    where <datetime> is ISO-8601 date and time if timestamps were
    recorded in the history file and NA, if not

    usage: convert-ts-bash-history.py file [file ...]

"""

__description__ = ('Program to convert .bash_history files to | separated list with ISO-8601 timestamps')
__author__ = 'Jim Clausing'
__version__ = '0.9.1'
__date__ = '2025-09-26'

import argparse
import sys
import re
import os
from datetime import datetime

def parse_bash_history(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    
    results = []
    timestamp = None
    time_regex = re.compile(r'^#(\d+)$')

    for line in lines:
        line = line.rstrip('\n')
        match = time_regex.match(line)
        if match:
            timestamp = int(match.group(1))
        else:
            if timestamp is not None:
                iso_time = datetime.fromtimestamp(timestamp).isoformat()
                results.append(f"{filename}|{iso_time}|{line}")
                timestamp = None
            else:
                results.append(f"{filename}|NA|{line}")
    return results

if __name__ == '__main__':
    parser = argparse.ArgumentParser(usage=' ' + os.path.basename(__file__) + ' FILENAME [FILENAME ...]\n' + __description__)
    parser.add_argument('filenames', metavar='FILENAME', nargs='+',
                        help='path to .bash_history file(s) to convert')
    parser.add_argument('-V', '--version', action='version', help='print version number',
                        version='%(prog)s v' + __version__)
    args = parser.parse_args()
    for filename in args.filenames:
        for entry in parse_bash_history(filename):
            print(entry)
