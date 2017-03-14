#!/usr/bin/perl 
#
# Author: Jim Clausing
# Date:   2016-10-17
#
# Calculate hashes of files
#

use Digest::MD5; 
#use Digest::SHA1;
#use Digest::SHA256;
use Digest::SHA;
use Getopt::Std;
use Digest::SHA3;

$VERSION = '1.4.0';
$i = getopts('ams235V');

die "Usage: $0 [-a][-m][-s][-M][-S][-2][-5][-V][-h] file...
	-a	All (MD5, SHA1, SHA256, SHA512, SHA3-256) (default if no other options)
	-m	Only MD5 signature (md5sum equiv output)
	-s	Only SHA1 signature (sha1sum equiv output)
	-2	Only SHA256 signature
	-3	Only SHA3-256 signature
	-5	Only SHA512 signature (note: base64 encoded rather than hex)
	-V	print version
	-h	This message\n" if (defined($i) && $opt_h) || ($#ARGV==-1 && !$opt_V);
die "$0 v$VERSION\nCopyright (c) 2005-2016 Jim Clausing\nIssue $0 -h for more information\n" if $opt_V;
exit if $#ARGV == -1;

$opt_a = 1 if (!$opt_a && !$opt_m && !$opt_s && !$opt_2 && !$opt_5 && !$opt_3);
if ($opt_a) {
  $num_sigs = 100
} else {
  $num_sigs = $opt_m + $opt_s + $opt_2 + $opt_5 + $opt_3;
}

while ($ARGV[0]) {
  $ARGV[0] =~ /^([-\/\@\w.]+)$/;
  $arg = $1;
  $ctx1 = Digest::MD5->new;
  $ctx2 = Digest::SHA->new(1);
  $ctx3 = Digest::SHA->new(256);
  $ctx4 = Digest::SHA->new(512);
  $ctx5 = Digest::SHA->new(512);
  $ctx6 = Digest::SHA3->new(256);
  open (FILE1, $arg);
  open (FILE2, $arg);
  open (FILE3, $arg);
  open (FILE4, $arg);
  open (FILE5, $arg);
  open (FILE6, $arg);
  binmode(FILE1);
  binmode(FILE2);
  binmode(FILE3);
  binmode(FILE4);
  binmode(FILE5);
  binmode(FILE6);
  $ctx1->addfile(*FILE1);
  $ctx2->addfile(*FILE2);
  $ctx3->addfile(*FILE3);
  $ctx4->addfile(*FILE4);
  $ctx5->addfile(*FILE5);
  $ctx6->addfile(*FILE6);
  $dig1 = $ctx1->hexdigest;
  $dig2 = $ctx2->hexdigest;
  $dig3 = $ctx3->hexdigest;
  $dig4 = $ctx4->hexdigest;
  $dig5 = $ctx5->b64digest;
  while (length($dig5) % 4) {
      $dig5 .= '=';
  }
#  Probably want to change this to b64digest if we change from SHA3-256 to SHA3-512
  $dig6 = $ctx6->hexdigest;
#  or if we change it to SHA3-512 but keep hexdigest, uncomment the following
#  while (length($dig6) % 4) {
#      $dig6 .= '=';
#  }
  close(FILE1);
  close(FILE2);
  close(FILE3);
  close(FILE4);
  close(FILE5);
  close(FILE6);
  $pre1 = ($num_sigs>1?"MD5: ":"");
  $pre2 = ($num_sigs>1?"SHA1: ":"");
  $pre3 = ($num_sigs>1?"SHA256: ":"");
  $pre5 = ($num_sigs>1?"SHA512: ":"");
  $pre6 = ($num_sigs>1?"SHA3-256: ":"");
  if ($opt_a) {
      print "$arg:\n";
      print "  MD5:  $dig1\n";
      print "  SHA1: $dig2\n";
      print "  SHA256: $dig3\n";
#      for ($i=0; $i<8; $i++) {
#          push (@line, substr($dig3,$i*8,8));
#      } 
    #  @line = split(/ /,$dig3);
#      $dig3a = join(' ',@line[0..3]);
#      $dig3b = join(' ',@line[4..7]);
#      print "  SHA256: $dig3a\n          $dig3b\n";
      @line = ();
      for ($i=0; $i<8; $i++) {
          push (@line, substr($dig4,$i*16,16));
      }
    #  @line = split(/ /,$dig4);
      $dig4a = join(' ',@line[0..3]);
      $dig4b = join(' ',@line[4..7]);
      print "  SHA512: $dig4a\n          $dig4b\n";
      print "  SHA512: $dig5\n";
      print "  SHA3-256: $dig6\n";
  } else {
      print "$pre1$dig1\t$arg\n" if $opt_m;
      print "$pre2$dig2\t$arg\n" if $opt_s;
      print "$pre3$dig3\t$arg\n" if $opt_2;
      print "$pre5$dig5\t$arg\n" if $opt_5;
      print "$pre6$dig6\t$arg\n" if $opt_3;
  }
  shift;
}
