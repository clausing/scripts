#!/usr/bin/perl
#
#
# Author: Jim Clausing
# Date:   2011-08-31
# Version: 1.4
#
# Purpose: create ngrep workalike (well, similar) in perl
#
# Updates: (v1.1) add IPv6 support
#          (v1.2) handle routing, hop-by-hop, and dest option headers
#	          now requires minimum of perl 5.10 due to use of ~~ operator
#          (v1.3) fix typo
#          (v1.4) add capability to write to pcap file
#
#          Now that there is a version of ngrep that can handle IPv6 on github
#          this script is no longer maintained
#

use 5.010;

use Data::Dumper;
use Getopt::Std;
use Net::Pcap;
use IO::Socket::INET6;
use NetPacket::Ethernet qw(:strip :types);
use NetPacket::IP 0.43.2 qw(:strip :protos :versions);
use NetPacket::IPv6 qw(:strip :protos :versions);
use NetPacket::TCP qw(:strip);
use NetPacket::UDP qw(:strip);
use NetPacket::ICMP qw(:strip);
use NetPacket::ICMPv6 qw(:strip);
use Net::IP qw(:PROC);
use POSIX qw(strftime);

use vars qw($Matches);

my %opts;
my $version = "1.4";
my $err;
my $pcap;
my $dumper;
my $filter;
#my $filter_str = 'not host 4.5.6.1 and src host 4.5.6.7';
my $filter_str = '';
my $match_pattern = "[[:print:]]{4,}";
my $match_code = '';

getopts('htuivVWd:r:s:w:',\%opts);
die "$0 v$version (c) Jim Clausing, 2009-2011\n" if ($opts{V});
usage() unless $opts{d} || $opts{r};
usage() if (($opts{d} && $opts{r}) || ($opts{u} && $opts{w}) || $opts{h});
usage() if $#ARGV > 1;

if ($#ARGV >= 0) {
  $match_pattern = shift @ARGV;
  if ($#ARGV == 0) {
#    $filter_str .= ' and (' . shift @ARGV;
#    $filter_str .= ')';
    $filter_str = shift @ARGV;
  }
}

$match_pattern =~ s(/)(\\)g;
$match_code .= "\$Matches += "
	. ($opts{v}?'!':'')  . "/" 
	. ($opts{W}?'\b':'') . "$match_pattern"
	. ($opts{W}?'\b':'') . "/"
	. ($opts{i}?'i':'')  . ";";

my $matcher = eval "sub { $match_code }";

if ($opts{d}) {
	$pcap = Net::Pcap::open_live($opts{d}, 1600, 0, 1000, \$err);
} else {
	$pcap = Net::Pcap::open_offline($opts{r}, \$err);
}


die if (Net::Pcap::compile($pcap, \$filter, $filter_str, 0, 0));
Net::Pcap::setfilter($pcap, $filter);
$dumper = Net::Pcap::pcap_dump_open($pcap, $opts{w}) if ($opts{w});
Net::Pcap::loop($pcap, -1, \&process_pkt, undef);
Net::Pcap::pcap_dump_close($dumper) if ($opts{w});
exit(0);

sub process_pkt {
	my ($user_data, $pcap_hdr, $pkt) = @_;

	my $proto;
	my $rec = parse_pkt($pkt);
	return unless $rec;
	$Matches = 0;
	$_ = $rec->{data};
        &{$matcher}();
	return unless $Matches;

        if ($opts{w}) {
            Net::Pcap::pcap_dump($dumper,$pcap_hdr,$pkt);
        } else {
	    if (!$opts{t}) {
		$rec->{time} = sprintf "%s.%06d",
			strftime("%Y-%m-%d-%H:%M:%S", gmtime($pcap_hdr->{tv_sec})),
			$pcap_hdr->{tv_usec};
	    } else {
		$rec->{time} = sprintf "%d.%06d", $pcap_hdr->{tv_sec}, $pcap_hdr->{tv_usec};
	    }

	    #print Dumper ($rec);
	    if ($rec->{proto} == IP_PROTO_TCP) {
	      $proto = "T";
	    } elsif ($rec->{proto} == IP_PROTO_UDP) {
	      $proto = "U";
	    } elsif ($rec->{proto} == IP_PROTO_ICMP) {
	      $proto = "I";
	    } elsif ($rec->{proto} == IP_PROTO_ICMPV6) {
	      $proto = "I6";
	    } else {
	      $proto = $rec->{proto};
	    }
	    if ($rec->{proto} == IP_PROTO_TCP || $rec->{proto} == IP_PROTO_UDP) {
	      print "$rec->{time} $proto $rec->{src_ip}:$rec->{src_port} -> $rec->{dst_ip}:$rec->{dst_port} ";
	    } elsif ($rec->{proto} == IP_PROTO_ICMP || $rec->{proto} == IP_PROTO_ICMPV6) {
	      print "$rec->{time} $proto $rec->{src_ip} -> $rec->{dst_ip} ($rec->{type}/$rec->{code}) ";
	    } else {
	      print "$rec->{time} $proto $rec->{src_ip} -> $rec->{dst_ip} ";
	    }
	    my $data = $rec->{data};
	    $data =~ s/\r\n$//;
	    if ($opts{u}) {
		$data =~ s/([^[:alnum:][:space:]\._-])/sprintf("%%%02x",ord $1)/ge;
		$data =~ s/([\r\n])/sprintf("%%%02x",ord $1)/ge;
	    } else {
		$data =~ s/([^[:print:][:space:]_-])/'.'/ge;
	    }
            print $data;
	    print "\n";
        }

}

sub parse_pkt {
	my $pkt = shift;
	my $rec;
	my $len;
	my @seg_list;
	my $packet;
	my $eth_obj = NetPacket::Ethernet->decode($pkt);
	if ($eth_obj->{type} == ETH_TYPE_IP || $eth_obj->{type} == ETH_TYPE_IPv6 || $eth_obj->{type} == ETH_TYPE_ARP) {
        	$packet = eth_strip($pkt);
	} else {
		$packet = $pkt;
	}
	my $ip_obj = NetPacket::IP->decode($packet);
        if ($ip_obj->{ver} == IP_VERSION_IPv4) {
		$rec->{src_ip} = $ip_obj->{src_ip};
		$rec->{dst_ip} = $ip_obj->{dest_ip};
		$rec->{proto} = $ip_obj->{proto};

		if ($ip_obj->{proto} == IP_PROTO_UDP) {
			my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
			return unless $udp_obj;
			$rec->{src_port} = $udp_obj->{src_port};
			$rec->{dst_port} = $udp_obj->{dest_port};
			return unless ($udp_obj->{data});
			$rec->{data} = $udp_obj->{data};
		} elsif ($ip_obj->{proto} == IP_PROTO_TCP) {
			my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
			return unless $tcp_obj;
			$rec->{src_port} = $tcp_obj->{src_port};
			$rec->{dst_port} = $tcp_obj->{dest_port};
			return unless ($tcp_obj->{data});
			$rec->{data} = $tcp_obj->{data};
		} elsif ($ip_obj->{proto} == IP_PROTO_ICMP) {
			my $icmp_obj = NetPacket::ICMP->decode($ip_obj->{data});
			return unless $icmp_obj;
			$rec->{type} = $icmp_obj->{type};
			$rec->{code} = $icmp_obj->{code};
			return unless ($icmp_obj->{data});
			$rec->{data} = $icmp_obj->{data};
		}

	} elsif ($ip_obj->{ver} == IP_VERSION_IPv6) {
#	} else {
		$ip_obj = NetPacket::IPv6->decode($packet);
		$rec->{src_ip} = $ip_obj->{src_ip};
		$rec->{dst_ip} = $ip_obj->{dest_ip};
		$rec->{proto} = $ip_obj->{nxt};

		while ($ip_obj->{nxt} ~~ [0,43,60]) {
			if ($ip_obj->{nxt} == 43) {
				@seg_list = ();
				$rec->{seg_list} = ();
				($len,$rec->{seg_type},$rec->{seg_left}) = unpack('C3',substr($ip_obj->{data},1,3));
				for (my $i = 0; $i < $len/2; $i++) {
					my @ip = unpack('N4',substr($ip_obj->{data},16*($i)+8,16));
					my $ip_str = NetPacket::IPv6::int_to_hexstr(@ip);
					push @{$rec->{seg_list}},$ip_str;
				}
				#$rec->{seg_list} = @seg_list;
			}
			($ip_obj->{nxt},$len) = unpack('C2',substr($ip_obj->{data},0,2));
			$ip_obj->{data} = substr($ip_obj->{data},8*($len+1));
		}
		if ($ip_obj->{nxt} == IP_PROTO_UDP) {
			my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
			return unless $udp_obj;
			$rec->{src_port} = $udp_obj->{src_port};
			$rec->{dst_port} = $udp_obj->{dest_port};
			return unless ($udp_obj->{data});
			$rec->{data} = $udp_obj->{data};
		} elsif ($ip_obj->{nxt} == IP_PROTO_TCP) {
			my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
			return unless $tcp_obj;
			$rec->{src_port} = $tcp_obj->{src_port};
			$rec->{dst_port} = $tcp_obj->{dest_port};
			return unless ($tcp_obj->{data});
			$rec->{data} = $tcp_obj->{data};
		} elsif ($ip_obj->{nxt} == IP_PROTO_ICMPV6) {
			my $icmpv6_obj = NetPacket::ICMPv6->decode($ip_obj->{data});
			return unless $icmpv6_obj;
			$rec->{type} = $icmpv6_obj->{type};
			$rec->{code} = $icmpv6_obj->{code};
			return unless ($icmpv6_obj->{data});
			$rec->{data} = $icmpv6_obj->{data};
		} else {
			$rec->{data} = $ip_obj->{data};
		}
	}
	return $rec;
}

sub usage {
print STDERR "
$0 [ -hituvVW ] [ -d ifname | -r filename ] [ -w filename ] [ -s snaplen ] <match expr> <bpf filter>

\t<match expr>\tthe pattern to search for (if omitted behaves like strings(1))
\t-h\t\tthis message
\t-d ifname\tinterface on which to listen for live capture
\t-r filename\tpcap file from which to look for data
\t-w filename\tpcap file to which matching data is written
\t-s snaplen\tset bpf snaplen (default: 1500)
\t-t\t\tuse unix timestamps for time (defaults to ISO-ish dates)
\t-u\t\tUnicode encode non-printable or special characters (not valid with -w)
\t-i\t\tcase insensitive
\t-v\t\tinvert search (print packets not matching pattern)
\t-W\t\tword match
\t-V\t\tprint Version
";
exit 1;
}
