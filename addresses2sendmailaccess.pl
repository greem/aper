#!/usr/bin/perl

# Written by rotaiv@gmail.com (rotaiv@biapo.com)

use LWP::Simple;
use strict;

my $url = 'http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_reply_addresses';
my $exclude = "/root/data/phishing_exclude";
my $accessfile = "/etc/mail/access";
my $logfile = "/var/log/phishing.log";
my $txtre = '^\s*(.+@[^,]+),([A-D]+),([0-9]{8})\s*$';
my ($list, $txt, %web, $email);


# Current date & time in yyyy-mm-dd hh:mm:ss format
my @dt=localtime(time);
my $datetime=sprintf("%.4d-%.2d-%.2d %.2d:%.2d:%.2d",
 $dt[5]+1900,$dt[4]+1,$dt[3],$dt[2],$dt[1],$dt[0]);

# -----------------------------------------------------------------------------
# Read file from web if updated within the last hour
# -----------------------------------------------------------------------------

my ($type, $length, $mod) = head($url);
exit unless time() - $mod > 3600;

my $list = get($url);

die "Could not retrieve list!" unless defined $list;

foreach $txt (split(/[\r\n]+/, $list)) {
  next if $txt =~ /^\s*#/;
  next unless ($txt =~ /$txtre/);
  $web{$1}=1;
}

# -----------------------------------------------------------------------------
# Read exclude file
# -----------------------------------------------------------------------------

open(INFILE,"<$exclude") || die "$!";

while($txt=<INFILE>) {
  # Ignore comments or lines without "@"
  next if $txt =~ '#';
  next if $txt !~ '@';
  chomp($txt);
  delete($web{$txt}) if exists($web{$txt});
}
close(INFILE);

# -----------------------------------------------------------------------------
# Read access file
# -----------------------------------------------------------------------------

open(INFILE,"<$accessfile") || die "$!";

while($txt=<INFILE>) {

  # Ignore comments or lines without "@"
  next if $txt =~ '#';
  next if $txt !~ '@';

  # Look for reject lines
  next unless $txt =~ /^(.*)ERROR/;

  # Convert to lowercase and trim spaces
  $email=lc(rtrim($1));

  if (exists($web{$email})) {
    delete($web{$email});
  }
}
close(INFILE);

# Abort if no new addresses left
exit unless scalar keys %web;

# -----------------------------------------------------------------------------
# Add new addresses
# -----------------------------------------------------------------------------

open(ACCESSFILE,">>$accessfile") || die "$!";
open(LOGFILE,">>$logfile") || die "$!";

while(($email, $txt) = each(%web)) {
  printf ACCESSFILE ("%-45s ERROR:\"550 Blocked by AU ITS\"\n", $email);
  print LOGFILE "$datetime,W,$email\n";
}
close(ACCESSFILE);
close(LOGFILE);

system("/sbin/service sendmail reload > /dev/null");

# =============================================================================
sub rtrim($)
# =============================================================================
{
  my $string = shift;
  $string =~ s/\s+$//;
  return $string;
}
