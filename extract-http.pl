#!/usr/local/bin/perl
#
# Author:	Jim Clausing
# Date:		2006-05-31
# Purpose:	Take an input file which consists of the
#		server->client side of an HTTP connection
#		and extract the contents into a file.  This
#		input file can be generated using tcpflow,
#		tcptrace or ethereal.  I personally like
#		tcptrace since it will tell you if packets
#		are missing and what the name of the file
#		was that it was trying to download.
#
# Example:
#	$ tcpdump -s 0 -w foo.pcap host umn.sourceforge.net
#	...
#	$ wget http://umn.sourceforge.net/sourceforge/srm/srm-1.2.8.tar.gz
#	...
#
#	$ tcptrace -xhttp -r foo.pcap
#	mod_http: Capturing HTTP traffic (port 80)
#	1 arg remaining, starting with 'foo.pcap'
#	Ostermann's tcptrace -- version 6.6.7 -- Thu Nov  4, 2004
#	
#	113 packets seen, 113 TCP packets traced
#	elapsed wallclock time: 0:00:00.010641, 10619 pkts/sec analyzed
#	trace file elapsed time: 0:00:00.455470
#	TCP connection info:
#	  1: my.machine:60477 - torpor.mirror.umn.edu:80 (a2b)   48>   65<  (complete)
#	Http module output:
#	my.machine:60477 ==> torpor.mirror.umn.edu:80 (a2b)
#	  Server Syn Time:      Wed May 31 12:58:57.301102 2006 (1149094737.301)
#	  Client Syn Time:      Wed May 31 12:58:57.253209 2006 (1149094737.253)
#	  Server Fin Time:      Wed May 31 12:58:57.670698 2006 (1149094737.671)
#	  Client Fin Time:      Wed May 31 12:58:57.671034 2006 (1149094737.671)
#	    GET /sourceforge/srm/srm-1.2.8.tar.gz HTTP/1.0
#	 Response Code:       200 (OK)
#	 Request Length:      140
#	 Reply Length:        88328
#	 Content Length:      88067
#	 Content Type  :      application/x-gzip
#	 Time request sent:   Wed May 31 12:58:57.301592 2006 (1149094737.302)
#	 Time reply started:  Wed May 31 12:58:57.374448 2006 (1149094737.374)
#	 Time reply ACKed:    Wed May 31 12:58:57.671034 2006 (1149094737.671)
#	 Elapsed time:  73 ms (request to first byte sent)
#	 Elapsed time:  369 ms (request to content ACKed)
#
#	$ extract-http.pl -f foo.tar.gz b2a_contents.dat
#       $ md5sum foo.tar.gz srm-1.2.8.tar.gz
#	66ba49b1864a7c69763210dbc3efee33  foo.tar.gz
#	66ba49b1864a7c69763210dbc3efee33  srm-1.2.8.tar.gz
#

use Getopt::Std;
use HTTP::Response;

getopts('hf:');

die "

Usage: $0 [-h] [-f outfile] [infile]
        -h          this message
        -f outfile  extract contents into outfile (default: stdout)
	infile      if no input file given, uses stdin

" if ($opt_h);

while (<>) {
  $str .= $_;
}

$r = HTTP::Response->parse($str);

if ($opt_f) {
  close STDOUT;
  open STDOUT, ">$opt_f";
} 
  
print $r->content;
