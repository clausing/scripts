#!/usr/bin/env python3
#
# Author: Jim Clausing
#

import os
import subprocess
import argparse
import shutil
import sys

__version_info__ = (0, 1, 0)
__version__ = ".".join(map(str, __version_info__))

def check_lsattr_exists():
    if not shutil.which('lsattr'):
        print("Error: 'lsattr' command not found. Please ensure it is installed and available in your PATH.")
        sys.exit(1)

def is_immutable(file_path):
    try:
        # Run the lsattr command and capture the output
        result = subprocess.run(['lsattr', file_path], capture_output=True, text=True, check=True)
        # The immutable attribute is represented by an 'i'
        return 'i' in result.stdout.split()[0]
    except subprocess.CalledProcessError:
        # If lsattr fails, we assume the file is not immutable
        return False

def search_immutable_files(directory, recursive, follow_symlinks):
    immutable_files = []
    if recursive:
        for root, _, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                if is_immutable(file_path):
                    immutable_files.append(file_path)
    else:
        for item in os.listdir(directory):
            file_path = os.path.join(directory, item)
            if os.path.isfile(file_path) or (follow_symlinks and os.path.islink(file_path)):
                if is_immutable(file_path):
                    immutable_files.append(file_path)
    return immutable_files

def main():
    check_lsattr_exists()

    parser = argparse.ArgumentParser(description="Search for immutable files.")
    parser.add_argument('paths', metavar='PATH', type=str, nargs='+', help='Path to file or directory')
    parser.add_argument('-r', '--recursive', action='store_true', help='Recursively search directories')
    parser.add_argument('-f', '--fullpath', action='store_true', help='Print full path rather than relative')
    parser.add_argument('-l', '--follow-symlinks', action='store_true', help='Follow symbolic links')
    args = parser.parse_args()

    immutable_files = []

    for path in args.paths:
        if args.fullpath:
            path = os.path.abspath(path)
        if os.path.isfile(path) or (args.follow_symlinks and os.path.islink(path)):
            if is_immutable(path):
                immutable_files.append(path)
        elif os.path.isdir(path):
            immutable_files.extend(search_immutable_files(path, args.recursive, args.follow_symlinks))
        else:
            print(f"Path '{path}' is neither a file nor a directory.")

    if immutable_files:
        for file in immutable_files:
            print(file)

if __name__ == "__main__":
    main()
