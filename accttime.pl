#!/usr/local/bin/perl
#
# $RCSfile: accttime.pl,v $
# $Revision: 1.3 $
# Author:       Jim Clausing <clausing@computer.org>
# $Date: 2002/11/21 19:55:03 $
#
# Purpose:      Take time-machine format lastcomm output and
#               present it in a format similar to what mactime
#               does with MACTimes from the body file.
#
# Switches & arguments:
#       -h              - usage message
#       -n              - numeric uid/gid
#       -d              - debug
#       -f file         - acct/pacct file to use, otherwise stdin
#       -g grpfile      - alternate group file to use (default /etc/group)
#       -p pwdfile      - alternat passwd file to use (default /etc/passwd)
#       -u user         - select records of a particular user (use numeric with -n)
#       time [time2]    - optional start and end time to search
#
# $Log: accttime.pl,v $
# Revision 1.3  2002/11/21 19:55:03  jac
# Fix a typo, add logic to give numeric uid/gid if there
# is no corresponding entry in /etc/passwd or /etc/group
#
# Revision 1.2  2002/09/15 20:40:38  jac
# Put RCS stuff in headers
#
#
use POSIX qw(strftime);
use Getopt::Std;
use Date::Manip;
require "pass.cache.pl";

$debug = 0;
$usage = " usage: $0 [-hnd] [-f file] [-g grpfile] [-p pwdfile] [-u user] [time [time2]]\n";

getopts('f:g:hdnp:u:') || die ;
die $usage if ($opt_h||$#ARGV>1);

$debug = 1 if ($opt_d);
select(STDOUT); $|=1;

$PASSWD = ($opt_p?$opt_p:"/etc/passwd");
$GROUP  = ($opt_g?$opt_g:"/etc/group");

if (!$opt_n) {
  &'load_passwd_info(0,$PASSWD);
  &'load_group_info(0,$GROUP);
}

if ($opt_f) {
  close(STDIN);
  open(STDIN,"$opt_f");
}

$time_one = shift @ARGV if ($#ARGV>=0);
$time_two = shift @ARGV if ($#ARGV>=0);

$time_one = &ParseDate($time_one);
$time_two = &ParseDate($time_two);

if (defined($time_one)) {
  $start_seconds = &UnixDate($time_one,"%s");
} else {
  $start_seconds = 0;
}
if (defined($time_two)) {
  $end_seconds = &UnixDate($time_two,"%s");
} else {
  $end_seconds = time();
}

for $i ( 0..2 ) {
  $junk = <STDIN>;
}

@names = split /\|/,$junk;
push @names,"end_time";

while (<STDIN>) {
  $k++;
  print "." if ($k%20 == 0 && $opt_d);
  $newrec = {};
  @vals = split /\|/;
  for $i ( 0 .. $#vals ) {
    $newrec->{$names[$i]} = $vals[$i];
  }
  if ($opt_u) {
    $flag = 0;
    $flag = 1 if ($opt_n && ($opt_u == $newrec->{uid}));
    $flag = 1 if (!$opt_n && ($opt_u eq $uid2names{$newrec->{uid}}));
    next if !$flag;
  }

  $newrec->{end_time} = int($newrec->{start_time}
        +$newrec->{elapsed_time});
  $newrec->{pseudoid} = substr($newrec->{start_time},-7,7)
        . '-' . base62($#{$starts{$newrec->{start_time}}} + 1);
  push @records, $newrec;
  push @{$starts{$newrec->{start_time}}}, $newrec;
  push @{$ends{$newrec->{end_time}}}, $newrec;
  $time_exists{$newrec->{start_time}} = 1;
  $time_exists{$newrec->{end_time}} = 1;
}

@list = sort( keys %starts );
for $i ( sort keys %time_exists ) {
  next if $i < $start_seconds;
  exit if $i > $end_seconds;
  $date_string = strftime("%Y-%m-%d %H:%M:%S",localtime($i));
  if (defined($starts{$i})) {
    for $j ( 0..$#{$starts{$i}} ) {
      $r = \@{$starts{$i}};
      $c = ($r->[$j]->{elapsed_time}<1.0)?'>':' ';
      if (!$opt_n) {
        printf "%-21s <%s  %-8s %-8s %-16s %-6s %8.2f (%-8s)\n",
          $date_string,$c,
          (defined($uid2names{$r->[$j]->{uid}})?$uid2names{$r->[$j]->{uid}}:$r->[$j]->{uid}),
          (defined($gid2names{$r->[$j]->{gid}})?$gid2names{$r->[$j]->{gid}}:$r->[$j]->{gid}),
          $r->[$j]->{command},
          $r->[$j]->{tty},$r->[$j]->{elapsed_time},$r->[$j]->{pseudoid};
      } else {
        printf "%-21s <%s  %-8d %-8d %-16s %-6s %8.2f (%-8s)\n",
          $date_string,$c,$r->[$j]->{uid},
          $r->[$j]->{gid}, $r->[$j]->{command},
          $r->[$j]->{tty},$r->[$j]->{elapsed_time},$r->[$j]->{pseudoid};
      }
      $date_string = " ";
    }
  }
  if (defined($ends{$i})) {
    for $j ( 0..$#{$ends{$i}} ) {
      $r = \@{$ends{$i}};
      next if ($r->[$j]->{elapsed_time} < 1.0);
      if (!$opt_n) {
        printf "%-21s  >  %-8s %-8s %-16s %-6s %8.2f (%-8s)\n",
          $date_string,
          (defined($uid2names{$r->[$j]->{uid}})?$uid2names{$r->[$j]->{uid}}:$r->[$j]->{uid}),
          (defined($gid2names{$r->[$j]->{gid}})?$gid2names{$r->[$j]->{gid}}:$r->[$j]->{gid}),
          $r->[$j]->{command},
          $r->[$j]->{tty},$r->[$j]->{elapsed_time},$r->[$j]->{pseudoid};
      } else {
        printf "%-21s  >  %-8d %-8d %-16s %-6s %8.2f (%-8s)\n",
          $date_string,$r->[$j]->{uid},
          $r->[$j]->{gid}, $r->[$j]->{command},
          $r->[$j]->{tty},$r->[$j]->{elapsed_time},$r->[$j]->{pseudoid};
      }
      $date_string = " ";
    }
  }
}

sub base62 {
  my @parm = @_;
  if ($parm[0] <= 9) {
    $rc = $parm[0];
  } elsif ($parm[0] > 9 && $parm[0] <= 35) {
    $rc = chr(ord('a') + $parm[0] - 10);
  } else {
    $rc = chr(ord('A') + $parm[0] - 36);
  }
  return $rc
}
