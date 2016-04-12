#!/usr/bin/env python
#
#  Title: 	docker-mount.py
#  Author:	Jim Clausing
#  Date:	2016-03-21
#  Version:	0.2
#
#  Purpose:	Allow the mounting of the AUFS layered/union filesystem from
#		a docker container to be mounted (read-only) for the purposes
#		of forensic examination
#

from sys import *
import os
import argparse
from subprocess import call
import json

__version_info__ = (0,2)
__version__ = ".".join(map(str, __version_info__))

parser = argparse.ArgumentParser(prog='docker-mount', description='Mount docker AUFS filesystem for forensic examination')
parser.add_argument('container', help='container id (long hex string)')
parser.add_argument('mntpnt', help='mount point where read-only filesystem will be mounted')
#parser.add_argument('--verbose','-v', action='store_true', help='verbose',)
parser.add_argument('--version','-V', action='version', help='print version number', version='%(prog)s v' + __version__)
parser.add_argument('--root','-r', help='root of filesystem (should include trailing /)', default='')  # e.g., /mnt/image
parser.add_argument('--path','-p', help='path to docker files', default='/var/lib/docker')

args=parser.parse_args()

dockerroot = args.root+args.path
config1 = dockerroot + '/containers/' + args.container + '/config.json'
config2 = dockerroot + '/containers/' + args.container + '/config.v2.json'
if (os.path.isfile(config1)):
    dockerversion = 1
elif (os.path.isfile(config2)):
    dockerversion = 2
else:
    raise Exception('Unknown docker version or invalid container id, check and try again')

dockerpath=args.root+args.path+'/aufs/layers'
if (dockerversion == 1):
    layerid = args.container
else:
    layerid = open(args.root + args.path + '/image/aufs/layerdb/mounts/' + args.container + '/mount-id').read()
# image/aufs/layerdb/mounts/516ae11fdca97f3228dac2dea2413c6d34a444e24b1d8b2a47cd54fbca091905/mount-id
    
os.chdir(dockerpath)

layers = open(layerid).read().split('\n')
layers = layers[:-1]
layers.insert(0,layerid)

elements = [args.root+args.path+'/aufs/diff/'+s for s in layers]

f=":".join(elements)

call(["/bin/mount","-t","aufs","-r","-o","br:"+f,"none",args.mntpnt], shell=False)
