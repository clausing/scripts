#!/usr/bin/env python
#
# Author: Jim Clausing
# Date: 2017-08-30
# Desc: rewrite of the sleithkit mac-robber in Python
# Unlinke the TSK version, this one actually includes the MD5 and the inode number
# though i still return a 0 in the MD5 column for non-regular files
# 

import os
import argparse
import hashlib
from stat import *

__version_info__ = (1,0,0)
__version__ = ".".join(map(str, __version_info__))

def mode_to_string(mode):
    lookup = ['---','--x','-w-','-wx','r--','r-x','rw-','rwx']
    if S_ISDIR(mode):
        mode_str = 'd'
    elif S_ISCHR(mode):
        mode_str = 'c'
    elif S_ISBLK(mode):
        mode_str = 'b'
    elif S_ISREG(mode):
        mode_str = '-'
    elif S_ISFIFO(mode):
        mode_str = 'p'
    elif S_ISLNK(mode):
        mode_str = 'l'
    elif S_ISSOCK:
        mode_str = 's'
    own_mode = lookup[(mode & 0700)>>6]
    if mode & 04000:
        if mode & 0100:
            own_mode = own_mode.replace('x','s')
        else:
            own_mode = own_mode.replace('-$','S')
    mode_str = mode_str + own_mode
    grp_mode = lookup[(mode & 070)>>3]
    if mode & 02000:
        if mode & 010:
            grp_mode = grp_mode.replace('x','s')
        else:
            grp_mode = grp_mode.replace('-$','S')
    mode_str = mode_str + own_mode
    oth_mode = lookup[(mode & 07)]
    if mode & 01000:
        if mode & 01:
            oth_mode = oth_mode.replace('x','t')
        else:
            oth_mode = oth_mode.replace('-$','T')
    mode_str = mode_str + oth_mode
    return mode_str

def process_item(dirpath,item):
    md5 = hashlib.md5()
    fname = os.path.join(dirpath,item)
    if os.path.islink(fname):
        status = os.lstat(fname)
        filename = fname + ' -> ' + os.readlink(fname)
    else:
        status = os.stat(fname)
        filename = fname
    if S_ISREG(status.st_mode):
        with open(fname, "rb") as f:
            for block in iter(lambda: f.read(65536), b""):
                md5.update(block)
        md5str = md5.hexdigest()
    else:
        md5str = "0"
    #mode = oct(S_IMODE(status.st_mode))
    mode = mode_to_string(status.st_mode)
    mtime = status.st_mtime
    atime = status.st_atime
    ctime = status.st_mtime
    btime = 0
    size = status.st_size
    uid = status.st_uid
    gid = status.st_gid
    inode = status.st_ino
    return md5str+'|'+filename+'|'+str(inode)+'|'+mode+'|'+str(uid)+'|'+str(gid)+'|'+str(size)+'|'+str(atime)+'|'+str(mtime)+'|'+str(ctime)+'|'+str(btime)
    

parser = argparse.ArgumentParser(description='collect data on files')
parser.add_argument('directories', metavar='DIRS', nargs='+', help='directories to traverse')
parser.add_argument('-m','--prefix', help='prefix string')
parser.add_argument('-V','--version',  action='version', help='print version number',
                    version='%(prog)s v' + __version__)

args = parser.parse_args()

for directory in args.directories:
    for dirpath,dirs,files in os.walk(directory):
        for directory in dirs:
            print process_item(dirpath,directory)
        for filename in files:
            print process_item(dirpath,filename)
