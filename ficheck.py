#!/usr/bin/env python3
"""

    Author: Jim Clausing <jclausing@isc.sans.edu>

    Date: 2025-09-28
    Version: 0.9.1

    Perform file integrity check on Unix/Linux systems

    Based loosely on the fcheck Perl script by Michael A. Gumienny

    
    usage: ficheck.py [-h] [-c CONFIG] [-u] [-V] [-r]

    File integrity check.

    options:
      -h, --help            show this help message and exit
      -c CONFIG, --config CONFIG
                            Configuration file.
      -s SIZE, --size SIZE  max size of file to hash (default = 50M)
      -u, --update          update database
      -V, --version         print version number
      -r, --report          produce a report

"""

import csv
#import configparser
import os
import errno
import sys
from pathlib import Path
import argparse
import hashlib
import socket
import itertools
import shutil
from datetime import datetime,timezone
# pylint: disable=wildcard-import,unused-wildcard-import
from stat import *
# pylint: enable=wildcard-import
from time import strftime, localtime

# pylint: disable=invalid-name
try:
    import statx
except (ImportError, ModuleNotFoundError):
    have_statx = False
else:
    have_statx = True

__version_info__ = (0, 9, 1)
__version__ = ".".join(map(str, __version_info__))
new_db_file_path = "/run/ficheck.db.new"
old_db_file_path = "/var/lib/ficheck/ficheck.db"
report_file_path = "/run/ficheck.txt"
changes = 0
total_changes = 0
hostname = socket.gethostname()

# pylint: disable=too-many-locals,too-many-branches,too-many-statements,too-many-arguments,line-too-long
def write_file(filepath, inode, perms, links, uid, gid, size, ctime, mtime, btime, file_hash):
    """Write entry to new db file"""

    # Append the new user data
    # pylint: disable=redefined-outer-name
    with open(new_db_file_path, 'a', newline='', encoding='utf8') as file:
        writer = csv.writer(file, delimiter='&')
        writer.writerow([filepath, inode, perms, links, uid, gid, size, ctime, mtime, btime, file_hash])

def compare_files(file1_path, file2_path):
    """Compare new and old dbs"""
    global changes
    global total_changes

    if not args.report:
        return
    def get_next_line(reader):
        """Skip malformed lines and return valid entries"""
        try:
            while True:
                line = next(reader)
                return line
        except StopIteration:
            return None

    with open(file1_path, 'r', encoding='utf8') as f1, open(file2_path, 'r', encoding='utf8') as f2:
        reader1 = csv.reader(f1, delimiter='&')
        reader2 = csv.reader(f2, delimiter='&')

        line1 = get_next_line(reader1)
        line2 = get_next_line(reader2)

        print (f'Configuration on {hostname} is {args.config}', file = report)
        print ('============================================================', file = report)
        print (file = report)
        while line1:
            if line1[0][0:2] == '# ':
                line1 = get_next_line(reader1)
            else:
                break
        while line2:
            if line2[0][0:2] == '# ':
                line2 = get_next_line(reader2)
            else:
                break

        while line1 and line2:
            key1, key2 = line1[0], line2[0]
            if key1 == key2 and len(line1) == len(line2):
                if len(line1) == 1:
                    if 'BEGIN' in key1:
                        total_changes += changes
                        if changes == 0 and key1.split(' ')[2].split('-')[0] != '/':
                            print (" passed...", file = report)

                        changes = 0
                        # Print current directory
                        my_root = key1.split(' ')[2].split('-')[0]
                        print (file = report)
                        print (f"PROGRESS: Current directory: {my_root}", file = report)
                        print ("STATUS: ",end='', file = report)
                        line1 = get_next_line(reader1)
                        line2 = get_next_line(reader2)
                    elif 'END' in key1:
                        line1 = get_next_line(reader1)
                        line2 = get_next_line(reader2)
                    continue

                # Check fields 2-11 (indexes 1-10)
                differences = []
                for idx in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]:
                    if line1[idx] != line2[idx]:
                        differences.append( (idx, line1[idx], line2[idx]) )

                if line1[10] == 'Dir' and len(differences) == 2:
                    differences = []
                if differences:
                    changes += 1
                    print (file = report)
                    print (f"        WARNING: [{hostname}] {key1}", file = report)
                    print ("        [", end='', file = report)
                    num_diff = len(differences)
                    for idx, val1, val2 in differences:
                        if idx == 1:
                            print (f"Inodes: {val1} - {val2}", end='', file = report)
                        elif idx == 2:
                            print (f"Perms: {val1} - {val2}", end='', file = report)
                        elif idx == 3:
                            print (f"Links: {val1} - {val2}", end='', file = report)
                        elif idx == 4:
                            print (f"Uid: {val1} - {val2}", end='', file = report)
                        elif idx == 5:
                            print (f"Gid: {val1} - {val2}", end='', file = report)
                        elif idx == 6:
                            print (f"Size: {val1} - {val2}", end='', file = report)
                        elif idx == 7:
                            time1 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(val1)))
                            time2 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(val2)))
                            print (f"Ctime: {time1} - {time2}", end='', file = report)
                        elif idx == 8:
                            time1 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(val1)))
                            time2 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(val2)))
                            print (f"Mtime: {time1} - {time2}", end='', file = report)
                        elif idx == 9:
                            time1 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(val1)))
                            time2 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(val2)))
                            print (f"Btime: {time1} - {time2}", end='', file = report)
                        elif idx == 10:
                            if not os.path.islink(key1):
                                print (f"Hashes: {val1} - {val2}", end='', file = report)
                            else:
                                print (f"Hashes: SYMLINK:{val1} - SYMLINK:{val2}", end='', file = report)
                        if num_diff > 1:
                            print (", ", end='', file = report)
                            num_diff -= 1
                        else:
                            print ("]", file = report)

                line1 = get_next_line(reader1)
                line2 = get_next_line(reader2)
            elif (key1 < key2 and len(line1) == 11) or len(line1) > len(line2):
                changes += 1
                time3 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(line1[9])))
                print (file = report)
                print (f"        DELETION: [{hostname}] {key1}", file = report)
                # pylint: disable=consider-using-f-string
                print ("        {:<10} {:<12} {:<8} {:<8} {:<8} {:<15} {:<20}".format('Inode','Permissions','NLink','UID','GID','Size','Created On'),
                        file = report)
                print ("        {:<10} {:<12} {:<8} {:<8} {:<8} {:<15} {:<20}".format(line1[1],line1[2],line1[3],line1[4],line1[5],line1[6],time3),
                        file = report)
                line1 = get_next_line(reader1)
            else:
                changes += 1
                if len(line2) == 1:
                    if 'BEGIN' in key2:
                        total_changes += changes
                        # Print current directory
                        my_root = line2[0].split(' ')[2].split('-')[0]
                        print (file = report)
                        print (f"PROGRESS: Current directory: {my_root}", file = report)
                        print ("STATUS: ",end='', file = report)
                        line2 = get_next_line(reader2)
                        line2 = get_next_line(reader2)
                        changes = 0
                        if line2:
                            key2 = line2[0]
                    elif 'END' in key2:
                        line2 = get_next_line(reader2)
                        if line2:
                            key2 = line2[0]
                    continue
                time3 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(line2[9])))
                print (file = report)
                print (f"        ADDITION: [{hostname}] {key2}", file = report)
                # pylint: disable=consider-using-f-string
                print ("        {:<10} {:<12} {:<8} {:<8} {:<8} {:<15} {:<20}".format('Inode','Permissions','NLink','UID','GID','Size','Created On'),
                        file = report)
                print ("        {:<10} {:<12} {:<8} {:<8} {:<8} {:<15} {:<20}".format(line2[1],line2[2],line2[3],line2[4],line2[5],line2[6],time3),
                        file = report)
                line2 = get_next_line(reader2)

        # Process remaining lines in either file
        while line1:
            changes += 1
            if len(line1) == 1:
                if 'BEGIN' in line1[0]:
                    total_changes += changes
                    # Print current directory
                    my_root = line1[0].split(' ')[2].split('-')[0]
                    print (file = report)
                    print (f"PROGRESS: Current directory: {my_root}", file = report)
                    print ("STATUS: ",end='', file = report)
                    line1 = get_next_line(reader1)
                    changes = 0
                    if line1:
                        key1 = line1[0]
                elif 'END' in line1[0]:
                    line1 = get_next_line(reader1)
                    if line1:
                        key1 = line1[0]
                continue
            time3 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(line1[9])))
            print (file = report)
            print (f"        DELETION: [{hostname}] {key1}", file = report)
            # pylint: disable=consider-using-f-string
            print ("        {:<10} {:<12} {:>8} {:>8} {:>8} {:>15} {:<20}".format('Inode','Permissions','NLink','UID','GID','Size','Created On'),
                    file = report)
            print ("        {:<10} {:<12} {:>8} {:>8} {:>8} {:>15} {:<20}".format(line1[1],line1[2],line1[3],line1[4],line1[5],line1[6],time3),
                    file = report)
            line1 = get_next_line(reader1)

        while line2:
            changes += 1
            if len(line2) == 1:
                if 'BEGIN' in line2[0]:
                    total_changes += changes
                    # Print current directory
                    my_root = line2[0].split(' ')[2].split('-')[0]
                    print (file = report)
                    print (f"PROGRESS: Current directory: {my_root}", file = report)
                    print ("STATUS: ",end='', file = report)
                    line2 = get_next_line(reader2)
                    changes = 0
                    if line1:
                        key1 = line1[0]
                elif 'END' in line2[0]:
                    line2 = get_next_line(reader2)
                    if line1:
                        key1 = line1[0]
                continue
            time3 = strftime('%Y-%m-%d %H:%M:%S', localtime(int(line2[9])))
            print (file = report)
            print (f"        ADDITION: [{hostname}] {key2}", file = report)
            # pylint: disable=consider-using-f-string
            print ("        {:<10} {:<12} {:>8} {:>8} {:>8} {:>15} {:<20}".format('Inode','Permissions','NLink','UID','GID','Size','Created On'),
                    file = report)
            print ("        {:<10} {:<12} {:>8} {:>8} {:>8} {:>15} {:<20}".format(line2[1],line2[2],line2[3],line2[4],line2[5],line2[6],time3),
                    file = report)
            line2 = get_next_line(reader2)

        if changes == 0:
            print (" passed...", file = report)
            print (file = report)

    total_changes += changes

def mode_to_string(mode):
    """convert numeric file permissions to human-readable string"""

    lookup = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"]
    if S_ISDIR(mode):
        mode_str = "d"
    elif S_ISCHR(mode):
        mode_str = "c"
    elif S_ISBLK(mode):
        mode_str = "b"
    elif S_ISREG(mode):
        mode_str = "-"
    elif S_ISFIFO(mode):
        mode_str = "p"
    elif S_ISLNK(mode):
        mode_str = "l"
    elif S_ISSOCK(mode):
        mode_str = "s"
    own_mode = lookup[(mode & 0o700) >> 6]
    if mode & 0o4000:
        if mode & 0o100:
            own_mode = own_mode.replace("x", "s")
        else:
            own_mode = own_mode[:1] + "S"
    mode_str = mode_str + own_mode
    grp_mode = lookup[(mode & 0o70) >> 3]
    if mode & 0o2000:
        if mode & 0o10:
            grp_mode = grp_mode.replace("x", "s")
        else:
            grp_mode = grp_mode[:1] + "S"
    mode_str = mode_str + own_mode
    oth_mode = lookup[(mode & 0o7)]
    if mode & 0o1000:
        if mode & 0o1:
            oth_mode = oth_mode.replace("x", "t")
        else:
            oth_mode = oth_mode[:1] + "T"
    mode_str = mode_str + oth_mode
    return mode_str

def process_entry(fname):
    """Gather info about file (or directory) to add to db"""

    sha256 = hashlib.sha256()
    try:
        if os.path.islink(fname):
            status = os.lstat(fname)
        else:
            status = os.stat(fname)
    except IOError:
        return
    fname_out = fname
    try:
        if status.st_size == 0:
            sha256str = "0"
        elif os.path.isdir(fname):
            sha256str = "Dir"
        elif S_ISBLK(status.st_mode) or S_ISCHR(status.st_mode) or S_ISFIFO(status.st_mode):
            sha256str= "Device"
        elif os.path.islink(fname):
            sha256.update(os.readlink(fname).encode())
            sha256str = sha256.hexdigest()
        elif status.st_size > 0 and os.path.isfile(fname):
            with open(fname, "rb") as f:
                if status.st_size > args.size:
                    sha256str = "0"
                else:
                    for block in iter(lambda: f.read(65536), b""):
                        sha256.update(block)
                    sha256str = sha256.hexdigest()
        else:
            sha256str = "0"
    except IOError:
        sha256str = "0"
    mode = mode_to_string(status.st_mode)
    # pylint: disable=consider-using-f-string
    mtime = "{:10.0f}".format(status.st_mtime)
    #atime = "{:10.0f}".format(status.st_atime)
    ctime = "{:10.0f}".format(status.st_ctime)
    if have_statx:
        try:
            btime = "{:10.0f}".format(statx.statx(fname).btime)
        except TypeError:
            btime = 0
    else:
        btime = 0
    size = status.st_size
    uid = status.st_uid
    gid = status.st_gid
    inode = status.st_ino
    links = status.st_nlink
    write_file(fname_out, inode, mode, links, uid, gid, size, ctime, mtime, btime, sha256str)

def walk_directory_tree(dirs, paths):
    """Walk through the directories configured in config file"""

    for root_dir in dirs:

        # pylint: disable=redefined-outer-name
        with open(new_db_file_path, "a", encoding='utf8') as db:
            print (f"#-----------------BEGIN DIRECTORY {root_dir}--------------------", file=db)

        for dirpath, dirnames, filenames in os.walk(root_dir):
            dirnames.sort()
            filenames.sort()
            # Skip directories specified in skip_paths
            if root_dir == "/":
                filenames = filenames + dirnames
                del dirnames[:]
            dirnames[:] = [d for d in dirnames if os.path.abspath(os.path.join(dirpath, d)) not in paths]

            # Create entry for file that isn't skipped
            for filename in itertools.chain(dirnames,filenames):
                file_path = os.path.abspath(os.path.join(dirpath, filename))
                if file_path not in paths:
                    process_entry(file_path)

    with open(new_db_file_path, "a", encoding='utf8') as db:
        print ("#-----------------END DIRECTORIES--------------------", file=db)

def parse_config_file(config_file):
    """Pare config file"""

    my_root_dirs = []
    my_skip_paths = []
    if not os.path.exists(config_file):
        print (f"{os.strerror(errno.ENOENT)}: {config_file}")
        sys.exit(255)
    with open(config_file, 'r', encoding='utf8') as file:
        for line in file:
            line = line.strip()
            if not line or '=' not in line or line[0] == '#':
                continue
            key, value = map(str.strip, line.split('=', 1))
            if key.lower() == 'directory':
                my_root_dirs.append(os.path.abspath(value))
            elif key.lower() == 'exclusion':
                my_skip_paths.append(os.path.abspath(value))
    return my_root_dirs, my_skip_paths

def move_file(file1, file2):
    """If update switch passed, move new db into old db location"""

    parts = os.path.split(file1)
    Path(parts[0]).mkdir(parents=True, exist_ok=True)
    if os.path.isfile(file1):
        os.remove(file1)
    shutil.move(file2, file1)

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="File integrity check.")
    parser.add_argument(
        '-c',
        '--config',
        help="Configuration file.",
        required=False,
        default="/etc/ficheck/ficheck.cfg"
    )
    parser.add_argument(
        '-s',
        '--size',
        metavar="SIZE", 
        type=int, 
        help="max size of file to hash (default = 500000000 (500M))",
        default=500000000
    )
    parser.add_argument(
        '-u',
        '--update',
        action="store_true",
        help="update database",
        default=False
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        help="print version number",
        # pylint: disable=consider-using-f-string
        version="%(prog)s v{version}".format(version=__version__)
    )
    parser.add_argument(
        '-r',
        '--report',
        action='store_true',
        default=False,
        help="produce a report"
    )

    args = parser.parse_args()

    root_dirs = []
    skip_paths = []

    if args.config:
        config_root_dirs, config_skip_paths = parse_config_file(args.config)
        root_dirs.extend(config_root_dirs)
        skip_paths.extend(config_skip_paths)
        skip_paths.extend(['/proc/','/sys/'])

    if args.report:
        report = open(report_file_path, 'w', encoding='utf')

    with open(new_db_file_path, 'w+', newline='', encoding='utf8') as db:
        writer = csv.writer(db, delimiter='&')
    with open(new_db_file_path, "a", encoding='utf8') as db:
        if os.name == "posix":
            sys_info = os.uname()
        curr_time = datetime.now(timezone.utc).isoformat()
        print (f"# - - Host     {hostname}", file=db)
        print (f"# - - OS       {sys_info.sysname} {sys_info.release}", file=db)
        print (f"# - - Creation {curr_time}", file=db)
        print (f"# - - Uname    {sys_info.sysname} {hostname} {sys_info.release} {sys_info.version} {sys_info.machine}", file=db)
        print ("# - - Ficheck by Jim Clausing, ideas freely stolen from FCheck perl script by Michael A. Gumienny", file=db)

    if not os.path.exists(old_db_file_path):
        if args.update:
            args.report = False

    # Convert skip paths to absolute paths for consistency
    skip_paths = [os.path.abspath(p) for p in skip_paths]

    walk_directory_tree(root_dirs, skip_paths)

    compare_files(old_db_file_path, new_db_file_path)

    if args.update:
        move_file(old_db_file_path, new_db_file_path)
    else:
        os.remove(new_db_file_path)

    if args.report:
        report.close()
        if total_changes > 0:
            report = open(report_file_path, 'r', encoding='utf8')
            print (report.read())
            report.close()
            os.remove(report_file_path)
            sys.exit(1)
        else:
            os.remove(report_file_path)
