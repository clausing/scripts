#!/usr/bin/env python3

__description__ = "Program to convert little-endian hex (as found in /proc/<pid>/net/tcp[6], etc.) to IPv4 or IPv6 addresses"
__author__ = 'Jim Clausing'
__version__ = '1.2.0'
__date__ = '2024-03-19'

import os
import struct
import socket
import argparse

def main():
    
    parser = argparse.ArgumentParser(usage='usage: ' + os.path.basename(__file__) + ' hexstring\n' + __description__)
    parser.add_argument("hexstring", metavar='HEXSTRING', nargs='+', help='hexstrings to convert')
    parser.add_argument('-V','--version', action='version', help='print version number', 
                        version='%(prog)s v' + __version__)
    args = parser.parse_args()

    for hexstr in args.hexstring:
        if len(hexstr) == 8:
            addr_long = int(hexstr, 16)
            print (socket.inet_ntop(socket.AF_INET,struct.pack("<L", addr_long)) )
        elif len(hexstr) == 32:
            out = []
            outstr = ''
            for i in range(0, len(hexstr), 8):
                outstr += struct.pack("<L", int(hexstr[i:i+8],16)).hex()
            print (socket.inet_ntop(socket.AF_INET6,bytes.fromhex(outstr)))
                


if __name__ == '__main__':
    main()
