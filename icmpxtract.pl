#!/usr/bin/perl
#
#  Name:    icmpxtract.pl
#  Author:  Jim Cluaisng
#  Version: 1.1
#  Date:    2011-08-22
#
#  Notes:  This version doesn't handle out of order packets,
#          duplicates, or IPv6 that will be rectified in v1.1
#
#  Updates: (1.1)  Added IPv6 support, handles out of order
#                  packets now, in case of duplicates we use
#                  the last one.  Any holes are ignored

require 5.010;

use Data::Dumper;
use Getopt::Std;
use Net::Pcap;
use IO::Socket::INET6;
use NetPacket::Ethernet qw(:strip :types);
use NetPacket::IP 0.43.2 qw(:strip :protos :versions);
use NetPacket::IPv6 qw(:strip :protos :versions);
#use NetPacket::TCP qw(:strip);
#use NetPacket::UDP qw(:strip);
use NetPacket::ICMP qw(:ALL);
use NetPacket::ICMPv6 qw(:strip);
#use Net::IP qw(:PROC);
use POSIX qw(strftime);
use Digest::MD5 qw(md5_hex);
use Digest::SHA qw(sha256_hex);

my %buffers;
my $filter_str = 'icmp or icmp6';
my $version='1.1';

getopts('hVd:f:o:',\%opts);
die "$0 v$version (c) Jim Clausing, 2011\n" if ($opts{V});
usage() unless $opts{d} || $opts{f};
usage() if (($opts{d} && $opts{f}) || $opts{h});
usage() if $#ARGV > 0;

chdir($opts{d}) if defined ($opts{d});

if ($#ARGV == 0) {
    $filter_str .= ' and (' . shift @ARGV;
    $filter_str .= ')';
#    $filter_str = shift @ARGV;
}


if ($opts{d}) {
        $pcap = Net::Pcap::open_live($opts{d}, 1600, 0, 1000, \$err);
} else {
        $pcap = Net::Pcap::open_offline($opts{f}, \$err);
}


die if (Net::Pcap::compile($pcap, \$filter, $filter_str, 0, 0));
Net::Pcap::setfilter($pcap, $filter);
Net::Pcap::loop($pcap, -1, \&process_pkt, undef);
foreach $file (keys %buffers) {
	my $tmp = '';
	open OUT,">$file";
	for ($i = 0; $i < $#{$buffers{$file}}; $i++) {
		$tmp .= $buffers{$file}[$i] if (defined $buffers{$file}[$i] && length($buffers{$file}[$i]) > 0);
	}
	print OUT $tmp;
	close OUT;
	$size = length $tmp;
	$md5 = md5_hex($tmp);
	$sha256 = sha256_hex($tmp);
	print "File: $file\n  size: $size\n  MD5: $md5\n  SHA256: $sha256\n";
}
exit(0);

sub process_pkt {
        my ($user_data, $pcap_hdr, $pkt) = @_;

        my $proto;
        my $rec = parse_pkt($pkt);
        my $filename;
        return unless $rec;
        $_ = $rec->{data};

        #print Dumper ($rec);
	$filename = sprintf("%s-%s-0x%02x%02x-0x%04x.raw", $rec->{src_ip},$rec->{dst_ip},$rec->{type},$rec->{code},$rec->{id});
	#open OUT,">>$filename";
	#print OUT $rec->{data};
	#close OUT;
	#print $filename,"\n";
	$buffers{$filename}[$rec->{seq}] = $rec->{data};
	return

}

sub parse_pkt {
        my $pkt = shift;
        my $rec;
        my $dns;
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
#                        my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
#                        return unless $udp_obj;
#                        $rec->{src_port} = $udp_obj->{src_port};
#                        $rec->{dst_port} = $udp_obj->{dest_port};
#                        return unless ($udp_obj->{data});
#                        $rec->{data} = $udp_obj->{data};
                } elsif ($ip_obj->{proto} == IP_PROTO_TCP) {
#                        my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
#                        return unless $tcp_obj;
#                        $rec->{src_port} = $tcp_obj->{src_port};
#                        $rec->{dst_port} = $tcp_obj->{dest_port};
#                        return unless ($tcp_obj->{data});
#                        $rec->{data} = $tcp_obj->{data};
                } elsif ($ip_obj->{proto} == IP_PROTO_ICMP) {
                        my $icmp_obj = NetPacket::ICMP->decode($ip_obj->{data});
                        return unless $icmp_obj;
                        $rec->{type} = $icmp_obj->{type};
                        $rec->{code} = $icmp_obj->{code};
                        return unless ($icmp_obj->{data});
			if ($rec->{type} == ICMP_ECHO || $rec->{type} == ICMP_ECHOREPLY) {
				$rec->{id} = unpack('S>',substr($icmp_obj->{data},0,2));
				$rec->{seq} = unpack('S',substr($icmp_obj->{data},2,2));
				$rec->{data} = substr($icmp_obj->{data},4);
			} else {
                        	$rec->{data} = $icmp_obj->{data};
			}
                }

        } elsif ($ip_obj->{ver} == IP_VERSION_IPv6) {
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
                if ($ip_obj->{nxt} == IP_PROTO_ICMPV6) {
                        my $icmpv6_obj = NetPacket::ICMPv6->decode($ip_obj->{data});
                        return unless $icmpv6_obj;
                        $rec->{type} = $icmpv6_obj->{type};
                        $rec->{code} = $icmpv6_obj->{code};
                        return unless ($icmpv6_obj->{data});
                        $rec->{data} = $icmpv6_obj->{data};
			if ($rec->{type} == ICMPV6_ECHO_REQUEST || $rec->{type} == ICMPV6_ECHO_REPLY) {
				$rec->{id} = $icmpv6_obj->{id};
				$rec->{seq} = $icmpv6_obj->{seq};
				$rec->{data} = $icmpv6_obj->{data};
			}
                } else {
                        $rec->{data} = $ip_obj->{data};
                }
	}
        return $rec;
}

sub usage {
print STDERR "
$0 [ -d ifname | -f <filename> ] [ -o <outdir> ] [ -h ] [<bpf filter>]

\t<bpf filter>\tthis will be and-ed with 'icmp[icmptype]=icmp-echo'
\t-h\t\tthis message
\t-d ifname\tinterface on which to listen for live capture
\t-f <filename>\tpcap file from which to look for data
\t-o <outdir>\tpcap file from which to look for data
\t-V\t\tprint Version
";
exit 1;
}

