#!/usr/bin/env python3
"""
	Name: mail_stuff.py
    Author: Jim Clausing <jclausing@isc.sans.edu>
    Version: 1.0.1
    Desc:   A script to send e-mail if there is any text fed to the script
            It can take several arguments -s for subject and -u if the body is UTF-8
            and -V for version info
"""

import argparse
import subprocess
import sys

__version_info__ = (1, 0, 1)
__version__ = ".".join(map(str, __version_info__))

def main():
    parser = argparse.ArgumentParser(description='Send email via mailx with optional subject and UTF-8 encoding.')
    parser.add_argument('-u', action='store_true', help='Add UTF-8 Content-Type header')
    parser.add_argument('-s', metavar='SUBJECT', help='Email subject')
    parser.add_argument('recipients', nargs='*', help='Email recipients')
    parser.add_argument("-V", "--version", action="version", help="print version number",
        version="%(prog)s v{version}".format(version=__version__)
    )
    args = parser.parse_args()

    if not args.recipients:
        sys.exit(11)  

    msg = sys.stdin.read()
    if not msg.strip():
        return  # No message exit silently

    cmd = ['/usr/bin/mailx']
    
    # Add Content-Type header if -u is set
    if args.u:
        cmd.extend(['-a', 'Content-Type: text/plain; charset=UTF-8'])

    # Add subject if provided
    if args.s:
        cmd.extend(['-s', args.s])

    # Add recipients
    cmd.extend(args.recipients)

    # Send the message
    try:
        proc = subprocess.run(cmd, input=msg, encoding='utf-8', check=True)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)

if __name__ == '__main__':
    main()

