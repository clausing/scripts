#!/usr/bin/perl
#
# Name:     ip-as-geo.pl
# Version:  1.6
# Date:     2014-01-14
# Author:   Jim Clausing
# Inputs:   IP address
# Outputs:  IP
#           CIDR range(s) assigned to
#           2-letter country code where IP located
#           long country name where IP is located
#           AS number
#           BGP prefix
#           Organization AS assigned to
#
# Changes:  Modified to handle IPv6 addresses (2009-08-11)
#           Requires modified Net::Abuse::Utils and
#            Net::Whois::IANA
#
#           Handle multiple IPs either on command line
#           or via STDIN
#
#	    Clean up an issue with trailing white space
#
#           Fix issue with IPs that aren't in cymru whois
#
#           Fix AutoLoader warning messages in 5.14 and later
#

use strict;
use warnings;
use AutoLoader qw/AUTOLOAD/;

use Getopt::Std;

use Net::Abuse::Utils qw( :all );
use Net::Whois::IANA;
use Net::CIDR;
use Net::IP qw(:PROC);
use Geography::Countries qw (country);

my %opt;
my $ip; 
my $cidr_out;
my $country;
my $country_long;
my @asn;
my $asn_desc;

getopts('hHn',\%opt) || &usage();

&usage() if $opt{'h'};

chomp(@ARGV = <STDIN>) unless @ARGV;
if ($opt{H}) {
  format STDOUT_TOP =
    IP addr     |          CIDR/inetnum             |CC|Country (long)| ASN |    BGP Prefix     |    Owner
----------------|-----------------------------------|--|--------------|-----|-------------------|------------------------------
.
  format STDOUT =
@|||||||||||||| | @|||||||||||||||||||||||||||||||| |@<|@<<<<<<<<<<<<<|@>>>>|@||||||||||||||||| |@<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
    $ip, $cidr_out, $country, $country_long, $asn[0], $asn[1], $asn_desc
.
  $==255;
}

while ($ip = shift(@ARGV)) {
  $ip=~s/\s+$//;
  my $iana = new Net::Whois::IANA;

  if (!ip_is_ipv4($ip) &&  !ip_is_ipv6($ip)) {
      warn "$ip doesn't look like an IP.\n";
      exit;
  }

  $iana->whois_query(-ip=>$ip);

  @asn = get_asn_info($ip);
  if ($#asn > 0) {
    $asn_desc  = get_as_description($asn[0]) || '';
  } else {
    $asn[0] = $asn[1] = $asn_desc = '';
  }

#my $cidr = $iana->cidr();
#
# for some reason $iana->cidr() wasn't returning the CIDR, so we'll do it ourselves
#
  my $net = $iana->inetnum();
  my @cidr = Net::CIDR::range2cidr($net) if !$opt{'n'};

  if ( $opt{'n'} ) {
    $cidr_out = $net;
  } elsif ( $#cidr == 0 ) {
    $cidr_out = $cidr[0];
  } elsif ( $#cidr < 2 ) {
    $cidr_out = join(',',@cidr);
  } else {
# it just looks too crowded if the netrange requires 3 or more CIDR blocks to describe
    $cidr_out = $net;
  }

  $country = get_ip_country($ip);
  if (defined $country) {
    $country_long = country($country) || '';
  } else {
    $country = $country_long = ''
  }

  if ( !$opt{'H'} ) {
    print "$ip|$cidr_out|$country|$country_long|$asn[0]|$asn[1]|$asn_desc\n";
  } else {
    write;
  }
}

exit 0;

sub usage() {
print "$0 [-h][-n] <ip>

	-h	print this message
	-n	print IP range, rather than CIDR(s)
        -H      print headers for each column

";
exit;
}
