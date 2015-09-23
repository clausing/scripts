#!/usr/local/bin/perl 
#
# Author: Jim Clausing
# Date:   2011-07-11
#

use Digest::MD5; 
#use Digest::SHA1;
#use Digest::SHA256;
use Digest::SHA;
use Getopt::Std;

$VERSION = '1.1';
$i = getopts('mMsS25V');

die "Usage: $0 [-m][-s][-M][-S][-2][-5][-V][-h] file...
	-m	No MD5 signature
	-M	Only MD5 signature (md5sum equiv output)
	-s	No SHA1 signature
	-S	Only SHA1 signature (sha1sum equiv output)
	-2	No SHA256 signature
	-5	No SHA512 signature
	-h	This message\n" if defined($i) & $i!=1 & !$opt_m & !$opt_s & !$opt_2 & !$opt_5 & !$opt_M & !$opt_S & !$opt_V;
die "No signatures specified\n" if $opt_m & $opt_s & $opt_2 & $opt_5;
die "$0 v$VERSION\nCopyright (c) 2005-2011 Jim Clausing\nIssue $0 -h for more information\n" if $opt_V;
exit if $#ARGV == -1;

while ($ARGV[0]) {
  $ARGV[0] =~ /^([-\/\@\w.]+)$/;
  $arg = $1;
  $ctx1 = Digest::MD5->new;
  $ctx2 = Digest::SHA->new(1);
  $ctx3 = Digest::SHA->new(256);
  $ctx4 = Digest::SHA->new(512);
  $ctx5 = Digest::SHA->new(512);
  open (FILE1, $arg);
  open (FILE2, $arg);
  open (FILE3, $arg);
  open (FILE4, $arg);
  open (FILE5, $arg);
  $ctx1->addfile(*FILE1);
  $ctx2->addfile(*FILE2);
  $ctx3->addfile(*FILE3);
  $ctx4->addfile(*FILE4);
  $ctx5->addfile(*FILE5);
  $dig1 = $ctx1->hexdigest;
  $dig2 = $ctx2->hexdigest;
  $dig3 = $ctx3->hexdigest;
  $dig4 = $ctx4->hexdigest;
  $dig5 = $ctx4->b64digest;
  while (length($dig5) % 4) {
      $dig5 .= '=';
  }
  close(FILE1);
  close(FILE2);
  close(FILE3);
  close(FILE4);
  close(FILE5);
  if (!$opt_M && !$opt_S) {
      print "$arg:\n";
      print "  MD5:  $dig1\n" if !$opt_m;
      print "  SHA1: $dig2\n" if !$opt_s;
      for ($i=0; $i<8; $i++) {
          push (@line, substr($dig3,$i*8,8));
      } 
    #  @line = split(/ /,$dig3);
      $dig3a = join(' ',@line[0..3]);
      $dig3b = join(' ',@line[4..7]);
      print "  SHA256: $dig3a\n          $dig3b\n" if !$opt_2;
      @line = ();
      for ($i=0; $i<8; $i++) {
          push (@line, substr($dig4,$i*16,16));
      }
    #  @line = split(/ /,$dig4);
      $dig4a = join(' ',@line[0..3]);
      $dig4b = join(' ',@line[4..7]);
      print "  SHA512: $dig4a\n          $dig4b\n" if !$opt_5;
      print "  SHA512: $dig5\n";
  } else {
      print "$dig1\t$arg\n" if $opt_M;
      print "$dig2\t$arg\n" if $opt_S;
  }
  shift;
}
