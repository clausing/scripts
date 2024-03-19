#!/bin/bash
#
# Name: redhat-pkgs.sh
# Desc: Enumerate installed packages on a RHEL system
#
# Author: Jim Clausing
# Date: 2024-03-19
# Version: 1.0

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
fgrep -qi redhat etc/os-release
if [ $? -eq 1 ]; then
        echo "Not a redhat family system"
        exit 1
fi
for i in var/lib/yum/yumdb/*/* ; do basename $i | cut -d\- -f2- ; done
