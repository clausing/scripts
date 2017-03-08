#!/usr/bin/env python
#
# Rewrite of my perl sigs script in python.
# Calculate hashes of files
# 
# Author: Jim Clausing
# Date: 2017-03-08
# Version: 1.1.1

import sys
import os
import argparse
import hashlib
if sys.version_info < (3, 6):
    import sha3
import base64

__version_info__ = (1,2,0)
__version__ = ".".join(map(str, __version_info__))

def hash_file(fname):
    global md5, sha1, sha256, sha3, sha512
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    sha3 = hashlib.sha3_384()
    sha512 = hashlib.sha512()
    with open(fname, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            if (args.md5 or args.all):
                md5.update(block)
            if (args.sha1 or args.all):
                sha1.update(block)
            if (args.sha256 or args.all):
                sha256.update(block)
            if (args.sha3 or args.all):
                sha3.update(block)
            if (args.sha512 or args.all):
                sha512.update(block)

def print_hashes(fname):
    if hashcnt == 1:
        if args.md5:
            print md5.hexdigest()+'\t'+fname
        elif args.sha1:
            print sha1.hexdigest()+'\t'+fname
        elif args.sha256:
            print sha256.hexdigest()+'\t'+fname
        elif args.sha3:
            print sha3.hexdigest()+'\t'+fname
        elif args.sha512:
            print base64.b64encode(sha512.digest())+'\t'+fname
    else:
        print fname+":"
        if args.md5 or args.all:
            print '  MD5:  '+md5.hexdigest()
        if args.sha1 or args.all:
            print '  SHA1: '+sha1.hexdigest()
        if args.sha256 or args.all:
            print '  SHA256: '+sha256.hexdigest()
        if args.sha512 or args.all:
            print '  SHA512: '+base64.b64encode(sha512.digest())
        if args.sha3 or args.all:
            print '  SHA3-384: '+sha3.hexdigest()

def count_hashes():
    global hashcnt
    hashcnt = 0
    if (args.all):
        hashcnt = 5
    if (args.md5):
        hashcnt += 1
    if (args.sha1):
        hashcnt += 1
    if (args.sha256):
        hashcnt += 1
    if (args.sha3):
        hashcnt += 1
    if (args.sha512):
        hashcnt += 1

if __name__ == '__main__':
# define switches and commandline arguments
    parser = argparse.ArgumentParser(description='Calculate hashes')
    parser.add_argument("files", metavar='FILE', nargs='+', help='files to hash')
    parser.add_argument('-V','--version', action='version', help='print version number', 
            version='%(prog)s v' + __version__)
    parser.add_argument('-r','--recursive', action='store_true', help='recursive mode. All subdirectories are traversed')
    parser.add_argument('-a','--all', action='store_true', 
            help='All (MD5, SHA1, SHA256, SHA512, and SHA3-384), default if no other options chosen',
            default='true')
    parser.add_argument('-m','--md5', action='store_true', help='MD5 signature (md5sum equivalent output)')
    parser.add_argument('-s','--sha1', action='store_true', help='SHA1 signature (sha1sum equivalent output)')
    parser.add_argument('-2','--sha256', action='store_true', 
            help='SHA2 (aka SHA2-256) signature (sha256sum equivalent output)')
    parser.add_argument('-3','--sha3', action='store_true', help='SHA3-384 signature')
    parser.add_argument('-5','--sha512', action='store_true', 
            help='SHA512 (aka SHA2-512) signature (note: base64 encoded rather than hex)')
    parser.add_argument('-f','--fullpath', action='store_true', help='print full path rather than relative')
    args = parser.parse_args()

# if any hash switches are specified turn -a off
    if (args.md5 or args.sha1 or args.sha256 or args.sha3 or args.sha512):
        args.all = False 

# count whether a non-zero number of hashes are specified (affects output format)
    count_hashes()

# process commandline arguments
    for path in args.files:
        if os.path.isdir(os.path.abspath(path)) and args.recursive:
            if args.fullpath:
                path = os.path.abspath(path)
            for root, directories, filenames in os.walk(path):
                for filename in filenames: 
                    fname = os.path.join(root,filename)
                    if os.path.isfile(fname):
                        hash_file(fname)
                        print_hashes(fname)
        else:
            if os.path.isfile(path):
                hash_file(path)
                print_hashes(path)

    sys.exit(0)
