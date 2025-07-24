#!/bin/bash
#
# Name: linux-pkgs.sh
# Desc: Enumerate installed packages on a RHEL/CentOS/Fedora/Debian/Ubuntu system
#
# Author: Jim Clausing
# Date: 2024-03-24
# Version: 1.0

OPTIND=1

PREFIX=''

while getopts "h?p:" opt; do
        case "$opt" in
                p) PREFIX="$OPTARG"
                        ;;
                h|\?)
                        echo "Usage: $(basename $0) [-p path/prefix] 
	
	-p path/prefix		mount point for the image (default will look at running system)
"
                        exit 0
                        ;;
        esac
done

cd ${PREFIX}/
if [ -d var/lib/dnf ] ; then
	echo "select name,version,release from rpm" | sqlite3 var/lib/dnf/history.sqlite | sed -e 's/|/-/g'
elif [ -d var/lib/yum/yumdb ] ; then
	for i in var/lib/yum/yumdb/*/* ; do basename $i | cut -d\- -f2- ; done
elif [ -d var/lib/dpkg ] ; then
	egrep '^(Package:|Version:)' var/lib/dpkg/status | awk '{print $2}' | while read a ; do read b ; echo "$a-$b" ; done
elif [ -d var/lib/rpm ] ; then
        rpm -q -a 
else
	echo "I don't recognize this distro"
	echo "I currently only handle distros that use dpkg/apt, yum, or dnf"
	exit 1
fi
