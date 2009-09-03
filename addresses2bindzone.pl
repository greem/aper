#! /usr/bin/perl
#
# build a bind zone file for phishing e-mail reply-to addresses
# Matthew Newton 2008-03-28
# 
# Debian packages required: libnet-dns-perl libwww-perl
#
# How to use:
#   Set up $zone below
#   Tweak SOA record further down file
#   Create zone in named.conf
#   Add to cron to run phishrelay.pl > zonefile && kick bind
#

use LWP::Simple;
use Net::DNS;
use Digest::MD5 qw(md5_hex);
use strict;

my $zone = 'phish-reply.zone.example';

my $url = 'http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_reply_addresses';
my $linere = '^\s*(.+@[^,]+),([A-D]+),([0-9]{8})\s*$';

my $list = get($url);

#open FILE, "phishing_reply_addresses";
#undef $/;
#my $list = <FILE>;
#close FILE;

die "Could not retrieve list!" unless defined $list;

print header(make_new_serial($zone));

foreach my $line (split(/[\r\n]+/, $list)) {
  next if $line =~ /^\s*#/;
  unless ($line =~ /$linere/) {
    warn "Badly formatted line: $line";
    next;
  }

  # add <md5_of_localpart>.domain.md5 A record for MTA lookup
  print emailtomd5dns($1) . ".md5\t IN A 127.1.0." . codetobit($2) . "\n";

  # add <localpart>.@.domain A record for human lookup
  print emailtoplaindns($1) . "\t IN A 127.1.0." . codetobit($2) . "\n";
  # ditto with TXT record for other info
  print emailtoplaindns($1) . "\t IN TXT lastseen:$3\n";
}

sub codetobit
{
  my $code = shift;
  my $num = 0;
  $num += 1 if $code =~ /a/i;
  $num += 2 if $code =~ /b/i;
  $num += 4 if $code =~ /c/i;
  $num += 8 if $code =~ /d/i;
  return $num;
}

sub emailtoplaindns
{
  my $email = shift;
  #$email =~ s/@/.\\@./;
  $email =~ s/@/.@./;
  return $email;
}

sub emailtomd5dns
{
  my $email = shift;
  my ($l, $d) = split(/@/, $email);
  return md5_hex($l) . ".$d";
}

sub header
{
  my $serial = shift;

  return ";
\$TTL	604800
@	IN	SOA	ns1.example. hostmaster.mail.example. (
			$serial	; Serial
			3600		; Refresh
			600		; Retry
			43200		; Expire
			30 )		; Negative Cache TTL
;
@	IN	NS	ns1.example.

";
}

sub get_serial_number
{
  my ($domain) = @_;
  my $serial;
  my %serials = ();

  # thanks to O'Reilly DNS and Bind for most of this code!

  my $res = new Net::DNS::Resolver;
  my $ns_req = $res->query($domain, "NS");

  die "No name servers found for $domain: ", $res->errorstring, "\n"
    unless defined($ns_req) and ($ns_req->header->ancount > 0);

  my @nameservers = grep { $_->type eq "NS" } $ns_req->answer;
  $res->recurse(0);
  $| = 1;
  foreach my $nsrr (@nameservers) {
    my $ns = $nsrr->nsdname;
    unless ($res->nameservers($ns)) {
      warn "$ns: can't find address: ", $res->errorstring, "\n";
      next;
    }
    my $soa_req = $res->send($domain, "SOA");
    unless (defined($soa_req)) {
      warn "$ns: ", $res->errorstring, "\n";
      next;
    }
    unless ($soa_req->header->aa) {
      warn "$ns is not authoritative for $domain\n";
      next;
    }
    unless ($soa_req->header->ancount == 1) {
      warn "$ns: expected 1 answer, got ", $soa_req->header->ancount, "\n";
      next;
    }
    unless (($soa_req->answer)[0]->type eq "SOA") {
      warn "$ns: expected SOA, got ", ($soa_req->answer)[0]->type, "\n";
      next;
    }
    $serials{$ns} = ($soa_req->answer)[0]->serial;
  }
  foreach my $s (keys %serials) {
    $serial = $serials{$s} unless defined $serial;
    if ($serial != $serials{$s}) {
      die "error: servers differ in serial number!";
    }
  }

  return $serial;
}

sub make_new_serial
{
  my ($domain) = @_;
  my $serial = get_serial_number($domain);
  my @now = gmtime(time);
  my $olddate;
  my $counter;

  my $today = $now[5] + 1900 . sprintf("%02d", $now[4] + 1)
                             . sprintf("%02d", $now[3]);

  # make a new serial number... different cases involving "serial" (serial
  # retrieved from DNS SOA), "olddate" (YYYYMMDD of "serial", i.e. missing
  # the counter) and "today" (YYYYMMDD of today):
  #
  #   1. olddate > today    ERROR; old serial in future!: die
  #   2. olddate < today    serial = today . "1"
  #   3. olddate == today   get counter from olddate and increment
  #   3a.  counter > 9      ERROR; too many updates: die

  if ($serial !~ /^(\d{4}\d{2}\d{2})(\d{2})$/) {
    die "cannot parse current serial number $serial!";
  }

  $olddate = $1;
  $counter = $2;

  if ($olddate > $today) {
    die "current serial date ($olddate) is > than today ($today)!";
  }

  return $today . "01" if ($olddate < $today);

  return $today . "0" . ($counter+1) if ($counter < 9);

  return $today . ($counter+1) if ($counter < 99);

  die "too many updates today, please wait until tomorrow!";
}

