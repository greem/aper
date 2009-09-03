#!/usr/bin/perl -T
# 
# find_phishing_replies.pl, DESCRIPTION
# 
# Copyright (C) 2008 Jesse Thompson
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# $Id: find_phishing_replies.pl,v 1.2 2008/03/28 22:29:31 zjt Exp $
# Jesse Thompson <jesse.thompson@doit.wisc.edu>

use strict;

# the local path to the addresses file
# http://anti-phishing-email-reply.googlecode.com/svn/trunk/phishing_reply_addresses
my $addresses_file = 'phishing_reply_addresses';

# what to match in the log file prior to the address
my $pre_re         = 'tcp_\w+\s+avs\w?\s+\w+\s\d+\s[^\s]+\srfc822;';

# what to match in the log file after the address matches
my $post_re        = '\s';



# get the list of addresses
open my $addresses_fh, '<', $addresses_file
    or die "unable to open $addresses_file $!";
my @addresses = ();
while ( <$addresses_fh> ) {
    next if m/^#/;
    my ($addr,$type,$date) = split /,/;
    $addr =~ m/^([\.\w%+-]+@[\w\.-]+\.\w{2,4})/;
    push @addresses, $1;
}
close $addresses_fh;

# build the regex
my $addr_regex = join( '|', @addresses );
my $re = qr/$pre_re($addr_regex)$post_re/i;

# scan the logs
while ( <> ) {
    print if m/$re/;
}

print "\n\n----------------------\n";
print "scanned for addresses:\n";
for ( @addresses ) {
    print "$_\n";
}
