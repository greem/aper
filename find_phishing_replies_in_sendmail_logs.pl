#!/usr/bin/perl -T
# 
# find_phishing_replies_in_sendmail_logs.pl
# code borrowed heavily from 
# http://anti-phishing-email-reply.googlecode.com/svn/trunk/find_phishing_replies.pl
# 
# This will read sendmail logs from stdin and look for email sent to known phishers.

use strict;
use Sys::Syslog;

use Getopt::Long;
my $help=0;
my $syslog=0;
my $list=0;
my $nopurge=0;
GetOptions('help' => \$help, 'syslog' => \$syslog, 'list' => \$list, 'nopurge' => \$nopurge);

if ($help) {
	print "$0 \n	will search sendmail logs for emails sent to known phishing collection points\n\n";
	print "options:\n";
	print "	--help		print this message and exit\n";
	print "	--list		print list of email addresses and exit\n";
	print "	--nopurge	do NOT purge 'from' address after a 'to' address has been seen\n";
	print "	--syslog	also send syslog message\n\n";
	print "Example usage:\n";
	print "	cat /var/log/maillog | $0 \n";
	print "	cat /var/log/maillog* | $0 \n";
	print "	tail -f /var/log/maillog | $0 --syslog \n";
	print "\n";
	exit 1;
}

# the local path to the addresses file
# http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_reply_addresses
my $addresses_file = 'phishing_reply_addresses';

my %badguys;	#list of badguy email addresses

# get the list of addresses
open my $addresses_fh, '<', $addresses_file
    or die "unable to open $addresses_file $!";
while ( <$addresses_fh> ) {
    next if m/^#/;
    my ($addr,$type,$date) = split /,/;
    # TODO: complete this regex
    #$addr =~ m/^([\w%+-]+@[\w.-]+\.\w{2,4})/;
    $addr =~ m/^([\.\w%+-]+@[\w.-]+\.\w{2,4})/;	# updated to allow "."'s in the /user/ portion of the email address
	$badguys{$1} = 1;	# add email address to the $badguy hash
}
close $addresses_fh;

if ($list) {	# just print out a list if user gave --list
	print "scanned for addresses:\n";
	foreach ( keys %badguys ) {
	    print "$_\n";
	}
	exit 1;
}

# build the regex of what to look for....
my $re = qr/^(\S+\s+\S+\s+\S+)\s\S+\ssendmail\[\d+\]:\s([\d\w]+):\s(\w+)=<([\.\w%+-]+@[\w.-]+\.\w{2,4})>/i;
#	$1 = Jan  1 10:14:00
#	$2 = m098asdf898
#	$3 = to/from
#	$4 = email@address.com

# since the "from" addresses are on one line, and the "to" addresses are on another.
# hash to keep track of "from" addresses
my %from;	
# processing a weekly ~200MB sendmail log file of ~200,000 emails takes about ~10MB of RAM, ~30MB if NOT purging "from" addresses.

# scan the logs
while ( <> ) {	# read from stdin
	if ($_ =~ m/$re/) { # if we match the RE
		if ($3 eq "from") { # if this is a "from" line of the logfile
			$from{$2} = $4;	#add the from address to a hash of the messageID
		}
		elsif ($3 eq "to") { # if this is a "to" line of the logfile
			if (exists $badguys{$4}) { #if this line contains a "badguy" destination address
				print "Phishing-Alert :: ".$1." ".$from{$2}." emailed ".$4."\n";
				# syslog message (syslog's parsed on log server to email notifiy.)
				if ($syslog) {	syslog('LOG_WARNING|LOG_LOCAL0',"Phishing-Alert :: ".$1." ".$from{$2}." emailed ".$4);	}
			} else { # if not a badguy destination
				unless ($nopurge) {	# don't remove when user gave --nopurge option
					delete $from{$2}; # remove the "from" out of our messageID hash
				}
			}
		}
	}
}

1;
