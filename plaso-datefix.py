#!/usr/bin/env python
#
# Massage plaso l2tcsv output to use ISO-8601(-ish) datetimestamp
# 
# Author: Jim Clausing
# Date: 2019-10-08
# Version: 0.4.1

from __future__ import print_function
import sys
import argparse
import fileinput
#import csv

__version_info__ = (0,4,0)
__version__ = ".".join(map(str, __version_info__))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Massage plaso l2tcsv output to use ISO-8601(-ish) datetimestamp')
    parser.add_argument("files", metavar='FILE', nargs='*', help='files to manipulate, if empty, use stdin')
    parser.add_argument('-V','--version', action='version', help='print version number', 
            version='%(prog)s v' + __version__)
    args = parser.parse_args()

    for lines in fileinput.input(files=args.files if len(args.files) > 0 else
            ('-', )):
        line = lines.rstrip('\n').split(',')
        date = line[0]
        if date == 'date':
            print ('datestamp,'+','.join(line[3:]))
            continue
        time = line[1]
        tz = line[2]
        rest = ','.join(line[3:])
        parts = date.split('/')
        datestamp = parts[2]+'-'+parts[0]+'-'+parts[1]+'T'+time+' '+tz
        print (datestamp+','+rest)
