#!/bin/bash
#
# Name: debian-pkgs.sh
# Desc: Enumerate installed packages on Debian/Ubuntu systems
#
# Date: 2024-03-19
# Version: 1.0
#

OPTIND=1

PREFIX=''

while getopts "h?p:" opt; do
        case "$opt" in
                p) PREFIX="$OPTARG"
                        ;;
                h|\?)
                        echo "Usage: $(basename $0) [-p path/prefix]"
                        exit 0
                        ;;
        esac
done

cd ${PREFIX}/
fgrep -qi debian etc/os-release
if [ $? -eq 1 ]; then
        echo "Not a debian/ubuntu family system"
        exit 1
fi
egrep '^(Package:|Version:)' var/lib/dpkg/status | awk '{print $2}' | while read a ; do read b ; echo $a $b ; done
