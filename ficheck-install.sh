#!/bin/bash

mkdir -p /etc/ficheck /var/lib/ficheck
cp ficheck.cfg /etc/ficheck/
cp ficheck.py /usr/bin/
cp ficheck.cron /etc/cron.d/ficheck
cp mail_stuff.py /usr/local/bin/
chmod +x /usr/bin/ficheck.py
chmod +r /etc/ficheck/ficheck.cfg
/usr/bin/ficheck.py -u
