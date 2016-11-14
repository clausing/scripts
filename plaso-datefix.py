#!/usr/bin/env python
#
# Massage plaso l2tcsv output to use ISO-8601(-ish) datetimestamp, I really prefer the mactime -y output
# 
# Author: Jim Clausing
# Date: 2016-11-14
# Version: 0.1
#

import sys
import argparse
import fileinput
import csv

__version_info__ = (0,1,0)
__version__ = ".".join(map(str, __version_info__))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("files", metavar='FILE', nargs='*', help='files to manipulate, if empty, use stdin')
    parser.add_argument('-V','--version', action='version', help='print version number',
                        version='%(prog)s v' + __version__)
    args = parser.parse_args()

    for line in csv.reader(fileinput.input(files=args.files if len(args.files) > 0 else
                    ('-', ))):
        date = line[0]
        if date == 'date':
            print 'datestamp,'+','.join(line[3:])
            continue
        time = line[1]
        tz = line[2]
        rest = ','.join(line[3:])
        parts = date.split('/')
        datestamp = parts[2]+'-'+parts[1]+'-'+parts[0]+'T'+time+' '+tz
        print datestamp+','+rest
