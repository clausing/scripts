# scripts
My collection of scripts that I've written over the years as a SANS Internet Storm Center Handler

## Requirements

+ **pngrep.pl** currently requires an old version of NetPacket (v0.43.2), I need to fix it to work
with the current version (and will accept pull requests that fix it :-) ).
+ **sigs.py** requires pysha3 (can be installed with pip) or Python >= 3.6

## Notes
+ **mac-robber.py** has been moved to <https://github.com/att/docker-forensics/blob/master/mac-robber.py>
+ **pngrep.pl** is no longer maintained now that there is a version of ngrep that can be do IPv6 on github
(see <https://github.com/jpr5/ngrep>)
