#!/usr/bin/perl
#
#
# Author: Jim Clausing
# Date:   2013-11-18
# Version: 1.5.1
#
# Purpose: Report on all DNS queries and responses from network traffic.
#
# Updates: (v1.4) added support for queries over IPv6
#          (v1.5) now handles routing, hop-by-hop and destination IPv6 extension headers
#                 as a result, now requires a minimum of perl 5.10
#          (v1.5.1) fix typo, add some error correction

require 5.010;

use Data::Dumper;
use Getopt::Std;
use Net::Pcap;
use IO::Socket::INET6;
use NetPacket::Ethernet qw(:strip :types);
use NetPacket::IP 0.43.2 qw(:strip :protos :versions);
use NetPacket::IPv6 qw(:strip :protos :versions);
use NetPacket::TCP qw(:strip);
use NetPacket::UDP qw(:strip);
use Net::DNS::Packet;
use Net::DNS::Header;
use Net::DNS::RR;
use Net::IP qw(:PROC);
use POSIX qw(strftime);

my %opts;
my $version = '1.5.1';
getopts('qahHti:r:s:V',\%opts);
die "$0 v$version (c) Jim Clausing, 2009-2013\n" if ($opts{V});
usage() unless $opts{i} || $opts{r};
usage() if (($opts{i} && $opts{r}) || $opts{h});

my $err;
my $pcap;
my $filter;
my $filter_str = '((ip proto 17) or (ip proto 6) or (ip6 protochain 17) or (ip6 protochain 6)) and port 53';
my $sep = ($opts{s}?$opts{s}:'|');

if ($opts{i}) {
	$pcap = Net::Pcap::open_live($opts{i}, 1500, 0, 1000, \$err);
} else {
	$pcap = Net::Pcap::open_offline($opts{r}, \$err);
}

if ($opts{H}) {
	print "time";
	print $sep;
	print "src ip";
	print $sep;
	print "dst ip";
	print $sep;
	print "qname";
	print $sep;
	print "type";
	print $sep;
	print "ttl";
	print $sep;
	print "rcode";
	print $sep;
	print "q/r flag";
	print $sep;
	print "answer\n";
}

die if (Net::Pcap::compile($pcap, \$filter, $filter_str, 0, 0));
Net::Pcap::setfilter($pcap, $filter);
Net::Pcap::loop($pcap, -1, \&process_pkt, undef);
exit(0);

sub process_pkt {
	my ($user_data, $pcap_hdr, $pkt) = @_;

	my $rec = parse_pkt($pkt);
	return unless $rec;

	return if ($opts{a} && !$opts{q} && $rec->{qr} == 0);
	return if ($opts{q} && !$opts{a} && $rec->{qr} == 1);
	if (!$opts{t}) {
		$rec->{time} = sprintf "%s.%06d",
			strftime("%Y-%m-%d-%H:%M:%S", gmtime($pcap_hdr->{tv_sec})),
			$pcap_hdr->{tv_usec};
	} else {
		$rec->{time} = sprintf "%d.%06d", $pcap_hdr->{tv_sec}, $pcap_hdr->{tv_usec};
	}

	if($rec->{qr} == 1) {
		for (my $i = 0; $i < $rec->{ancount}; $i ++) {
			my ($name, $type, $ttl, $str) = split (/\^/, @{$rec->{ans}}[$i]);
			print $rec->{time};
			print $sep;
			print $rec->{src_ip};
			print $sep;
			print $rec->{dst_ip};
			print $sep;
			print $name;
			print $sep;
			print $type;
			print $sep;
			print $ttl;
			print $sep;
			print $rec->{rcode};
			print $sep;
			print $rec->{qr};
			print $sep;
			$str =~ s/;.*$//mg if ($type eq 'SOA');
			$str =~ s/\s+/ /g if ($type eq 'SOA');
			if ($type eq "AAAA") {
				print ip_compress_address($str,6),"\n";
			} else {
				print $str,"\n";
			}
		}

		if ($rec->{ancount} == 0) {
			my ($name,$type,$str) = split(/\^/, pop(@{$rec->{question}}));
			print $rec->{time};
			print $sep;
			print $rec->{src_ip};
			print $sep;
			print $rec->{dst_ip};
			print $sep;
			print $name;
			print $sep;
			print $type;
			print $sep;
			print "-";
			print $sep;
			print $rec->{rcode};
			print $sep;
			print $rec->{qr};
			print $sep;
			print "\n";
		}
	} else {
		my ($name,$type,$str) = split(/\^/, pop(@{$rec->{question}}));
		print $rec->{time};
		print $sep;
		print $rec->{src_ip};
		print $sep;
		print $rec->{dst_ip};
		print $sep;
		print $name;
		print $sep;
		print $type;
		print $sep;
		print "-";
		print $sep;
		print $rec->{rcode};
		print $sep;
		print $rec->{qr};
		print $sep;
		print "\n";
	}
}

sub parse_pkt {
	my $pkt = shift;
	my $rec;
	my $len;
	my @seg_list;
	my $dns;
	my $ip_obj = NetPacket::IP->decode(eth_strip($pkt));
        if ($ip_obj->{ver} == IP_VERSION_IPv4) {
	    return unless ($ip_obj->{proto} == IP_PROTO_UDP || $ip_obj->{proto} == IP_PROTO_TCP);
	    $rec->{src_ip} = $ip_obj->{src_ip};
	    $rec->{dst_ip} = $ip_obj->{dest_ip};

	    if ($ip_obj->{proto} == IP_PROTO_UDP) {
		my $udp_obj = NetPacket::UDP->decode($ip_obj->{data});
		return unless $udp_obj;
		$rec->{src_port} = $udp_obj->{src_port};
		$rec->{dst_port} = $udp_obj->{dest_port};
		return unless ($udp_obj->{data});
		$dns = Net::DNS::Packet->new(\$udp_obj->{data});
	    } else {
		my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
		return unless $tcp_obj;
		$rec->{src_port} = $tcp_obj->{src_port};
		$rec->{dst_port} = $tcp_obj->{dest_port};
		return unless ($tcp_obj->{data});
		$dns = Net::DNS::Packet->new(\$tcp_obj->{data});
	    }

	    unless ($dns) {
		warn "Net::DNS::Packet->new: $!";
		return;
	    }
        } elsif ($ip_obj->{ver} == IP_VERSION_IPv6) {
            $ip_obj = NetPacket::IPv6->decode(eth_strip($pkt));
	    $rec->{src_ip} = $ip_obj->{src_ip};
	    $rec->{dst_ip} = $ip_obj->{dest_ip};

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
		$dns = Net::DNS::Packet->new(\$udp_obj->{data});
	    } else {
		my $tcp_obj = NetPacket::TCP->decode($ip_obj->{data});
		return unless $tcp_obj;
		$rec->{src_port} = $tcp_obj->{src_port};
		$rec->{dst_port} = $tcp_obj->{dest_port};
		return unless ($tcp_obj->{data});
		$dns = Net::DNS::Packet->new(\$tcp_obj->{data});
	    }

	    unless ($dns) {
		warn "Net::DNS::Packet->new: $!";
		return;
	    }
        } else {
                warn "Invalid IP version in packet, continuing...";
                return;
        }

	my $header = $dns->header;
	$rec->{id} = $header->id;
	$rec->{qr} = $header->qr;
	$rec->{opcode} = $header->opcode;
	$rec->{rcode}  = $header->rcode;
	$rec->{aa} = $header->aa;
	$rec->{tc} = $header->tc;
	$rec->{rd} = $header->rd;
	$rec->{ra} = $header->ra;
	$rec->{ad} = $header->ad;
	$rec->{qdcount} = $header->qdcount;
	$rec->{ancount} = $header->ancount;
	$rec->{nscount} = $header->nscount;
	$rec->{adcount} = $header->adcount;

	if ($dns->question) {
		foreach my $rr ($dns->question) {
			push(@{$rec->{question}}, $rr->qname . '^' . $rr->qtype . '^' . $rr->string);
		}
	}
	if ($dns->answer) {
		foreach my $rr ($dns->answer) {
			push(@{$rec->{ans}}, $rr->name . '^' . $rr->type . '^' . $rr->ttl . '^' . $rr->rdatastr);
		}
	}
	if ($dns->authority) {
		foreach my $rr ($dns->authority) {
			if (defined $rec->{auth}) {
				push(@{$rec->{auth}}, $rr->rdatastr);
			}
		}
	}
	if ($dns->additional) {
		foreach my $rr ($dns->additional) {
			if (defined $rec->{addl}) {
				push(@{$rec->{addl}}, $rr->rdatastr);
			}
		}
	}
	return $rec;
}

sub usage {
print STDERR "
$0 [ -i ifname | -r filename ] [ -s sep ] [ -q ] [ -a ] [ -h ] [ -H ] [ -t ]

\t-h\t\tthis message
\t-i ifname\tinterface on which to listen for live capture
\t-r filename\tpcap file from which to extract DNS data
\t-s sep\t\tseparator in the output (default: |)
\t-q\t\tqueries only
\t-a\t\tanswers only
\t-H\t\tinclude header line
\t-t\t\tuse unix timestamps for time
";
exit 1;
}
