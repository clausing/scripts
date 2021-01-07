#!/usr/bin/env python3
#
# Description: parse.exe wasn't cutting it for me and wasn't doing much, so
# I figured I'd replace it with a python script
#
# Author: Jim Clausing
# Date: 2021-01-07
#

import sys
import os
import argparse
from datetime import *
from time import *
import contextlib
import codecs
import chardet

__version_info__ = (0, 1, 1)
__version__ = ".".join(map(str, __version_info__))


@contextlib.contextmanager
def smart_open(filename=None):
    # KAPE made the TLN file a UTF-16-LE file, this detects that and sets encoding accordingly
    if filename and filename != "-":
        fh = open(filename, "r")
        rawdata = open(filename, "rb").read()
        result = chardet.detect(rawdata)
        charenc = result["encoding"]
        fh.close()
        fh = open(filename, "r", encoding=charenc)
    else:
        fh = sys.stdin

    try:
        yield fh
    finally:
        if fh is not sys.stdin:
            fh.close()


def parse_line(line):
    line = line.rstrip()
    i = line.find(",")
    if i <= 0:
        l = line.split("|")
        l[0] = datetime.utcfromtimestamp(int(l[0])).strftime("%Y-%m-%d %H:%M:%S")
        print(",".join(l))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse/Transform TLN files")
    parser.add_argument("files", metavar="FILE", nargs="*", default="-", help="TLN file")

    args = parser.parse_args()

    for path in args.files:
        with smart_open(path) as f:
            for line in f:
                parse_line(line)

    sys.exit(0)
