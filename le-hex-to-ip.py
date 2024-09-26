#!/usr/bin/env python3

__description__ = "Program to convert little-endian hex (as found in /proc/<pid>/net/tcp[6], etc.) to IPv4 or IPv6 addresses"
__author__ = 'Jim Clausing'
__version__ = '1.3.0'
__date__ = '2024-09-26'

import os
import struct
import socket
import argparse
import fileinput

def ipconvert(hexstr):
    if len(hexstr) == 8:
        addr_long = int(hexstr, 16)
        return (socket.inet_ntop(socket.AF_INET,struct.pack("<L", addr_long)) )
    elif len(hexstr) == 32:
        out = []
        outstr = ''
        for i in range(0, len(hexstr), 8):
            outstr += struct.pack("<L", int(hexstr[i:i+8],16)).hex()
        return (socket.inet_ntop(socket.AF_INET6,bytes.fromhex(outstr)))

def main():
    
    parser = argparse.ArgumentParser(usage='usage: ' + os.path.basename(__file__) + ' hexstring\n' + __description__)
    parser.add_argument("hexstring", metavar='HEXSTRING', nargs='*', default='-', help='hexstrings to convert, if none, take from stdin')
    parser.add_argument('-V','--version', action='version', help='print version number', 
                        version='%(prog)s v' + __version__)
    args = parser.parse_args()

    for hexstr in args.hexstring:
        try:
            if hexstr.index(':'):
                strings = hexstr.split(':')
                hexstr = ipconvert(strings[0])
                print (hexstr+':'+str(int(strings[1],16)))
        except ValueError:
            hexstr = ipconvert(hexstr)
            print (hexstr)


if __name__ == '__main__':
    main()
