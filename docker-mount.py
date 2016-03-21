#!/usr/bin/env python
#
#  Title: 	docker-mount.py
#  Author:	Jim Clausing
#  Date:	2016-03-21
#  Version:	0.1
#
#  Purpose:	Allow the mounting of the AUFS layered/union filesystem from
#		a docker container to be mounted (read-only) for the purposes
#		of forensic examination
#

from sys import *
import os
import argparse
from subprocess import call

parser = argparse.ArgumentParser(prog='docker-mount', description='Mount docker AUFS filesystem for forensic examination')
parser.add_argument('container', help='container id (long hex string)')
parser.add_argument('mntpnt', help='mount point where read-only filesystem will be mounted')
#parser.add_argument('--verbose','-v', action='store_true', help='verbose',)
parser.add_argument('--root','-r', help='root of filesystem', default='')  # e.g., /mnt/image
parser.add_argument('--path','-p', help='path to docker files', default='/var/lib/docker')

args=parser.parse_args()

dockerpath=args.root+args.path+'/aufs/layers'
os.chdir(dockerpath)

layers = open(args.container).read().split('\n')
layers = layers[:-1]
layers.insert(0,args.container)

elements = [args.root+args.path+'/aufs/diff/'+s for s in layers]

f=":".join(elements)

call("/bin/mount"+" -t aufs -r -o br:"+f+" none "+args.mntpnt, shell=True)
