#!/usr/bin/perl
###############################################################################
#
# feed_barracuda_phish.pl
#
# Script to feed phish to a Barracuda "firewall"
#
# Copyright (C) 2008 The University of Chicago
#
# Darren Young <darren.young@chicagogsb.edu>
#
# $Id: feed_barracuda_phish.pl,v 1.10 2008/08/07 17:54:04 dyoung2 Exp $
#
###############################################################################
#
# NOTICE
# ------
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
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, 
# USA.
#
###############################################################################
#
# INSTALLATION
# ------------
# 
# * Obtain the phish file from http://code.google.com/p/anti-phishing-email-reply
#
# * Add the IP of the system you're running this script from in the Barracuda
#   under Basic/Administration/SNMP & API 
#
# * Set the API password in the Barracuda
#
# * Obtain the anti-phishing list via SVN
#
# * Install the svn client on the system this is to run from 
#
# * Install the following Perl modules:
#      - LWP
#      - XML::Simple
#      -  Array::Diff
#
# * Set the variables below to whatever is for your environment
#
###############################################################################
#
# TODO
#
# - Add SSL support for talking to the Barracuda
# - Add checks of the returning XML from the Barracuda API calls
# - Use the type and date from the phish list for the Barracuda comment
# - Improve logging 
# - Deal with @bnblocks = @{$doc->{mta_acl_email_src_block_address}};
# - Errors when there are no current blocks in the Barracuda
# - Work on block_action check
#
###############################################################################
#
# CHANGELOG
# 
# $Log: feed_barracuda_phish.pl,v $
# Revision 1.10  2008/08/07 17:54:04  dyoung2
#   * Added --no-svn option
#
# Revision 1.9  2008/08/07 17:46:16  dyoung2
#   * Changed copyright year
#
# Revision 1.8  2008/08/07 17:42:00  dyoung2
#   * Disabled check in add_block_action until I can fix it.
#
# Revision 1.7  2008/08/07 17:23:54  dyoung2
#   * Added function descriptions
#
# Revision 1.6  2008/08/07 17:14:21  dyoung2
#   * Added --keep-xml option
#   * Changed all comments to say ARGUMENTS instead of REQUIRES
#
# Revision 1.5  2008/08/07 16:50:06  dyoung2
#   * Added bn_comment and bn_email_block_action
#   * Added pod2usage
#   * Added command line options
#   * Added logmsg() and debug() functions
#   * Array::Diff stinks.
#
# Revision 1.4  2008/08/06 22:44:44  dyoung2
#   * Changed comment string
#
# Revision 1.3  2008/08/06 22:44:07  dyoung2
#   * Added TODO items
#
# Revision 1.2  2008/08/06 22:41:58  dyoung2
#   * First version for testing
#
# Revision 1.1  2008/08/06 20:06:24  dyoung2
#   * Initial version into CVS
#
###############################################################################

my $cvsid    = '$Id: feed_barracuda_phish.pl,v 1.10 2008/08/07 17:54:04 dyoung2 Exp $';
my @cvsinfo  = split( ' ', $cvsid );
my $NAME    = File::Basename::basename($0);
my $VERSION = $cvsinfo[2];


###############################################################################
#                               B E G I N
###############################################################################

# Require a Perl version
require 5.008;                  # tested against 5.8

# Pragmas
#use strict;                         # catch my accidental lack of my
use warnings;

use lib '/opt/gsb/idstools/lib';

BEGIN {

    # modules we need to operate
    my @MODs = 
    (   
        # "Standard" modules we use
        'FindBin',
        'Getopt::Long',
        'File::Basename',
        'Pod::Usage',

        # "Extra" modules we need
        # (not included with the Perl distribution)
        'POSIX',
        'LWP',
        'XML::Simple',
        'Array::Diff',

        # "local" modules we need
        # (included with this distribution)
    );  

    # check to see if the required modules are installed
    # and if so, load them up otherwise puke
    for my $mod (@MODs) {
        if ( eval "require $mod" ) { 
            $mod->import();
        } else {
            print "Module $mod not installed!\n" and exit(0);
        }   
    } 
} 
###############################################################################
#                      P A C K A G E   V A R I A B L E S
###############################################################################
our $DEBUG     = 0;                     # Enables debug
our $KEEPXML   = 0;                     # Keep XML results
our $NOSVN     = 0;                     # Don't do SVN update

### Variables you should set
my $svncmd    = "svn";                                      # location of svn
my $phishdir  = "../anti-phishing-email-reply-read-only";   # phish dir
my $phishfile = "phishing_reply_addresses";                 # phish file
my $bnsys     = "http://gsbbn1.chicagogsb.edu:8000";        # Barracuda URL
my $bnpass    = "gsbadmin";                                 # Barracuda API pass

# my vars
my @newphish;
my @curblocks;
my @missing_blocks;
my $num_curblocks;
my $bn_line_num;


###############################################################################
#                   C O M M A N D   L I N E   O P T I O N S
###############################################################################
GetOptions(     
    "help"     => \$HELP,
    "debug"    => \$DEBUG,
    "version"  => sub { print_version(); },
    "keep-xml" => \$KEEPXML,
    "no-svn"   => \$NOSVN,
    );

# dump help or usage if asked to do so
pod2usage(-verbose => 0) if $HELP;


###############################################################################
#                           M A I N   L O O P
###############################################################################

###
### Update the local copy of the anti-phish list
###
unless ( $NOSVN) {
    if ( svn_update($svncmd, $phishdir) ) {
        logmsg("SVN update successful");
    } else {
        logmsg("FAILED to update SVN repository");
        exit(0);    
    }
}

###
### Get new phish from the file we just updated
###
if ( @newphish = get_newphish($phishdir, $phishfile)) {
    logmsg("Caught " . scalar(@newphish) . " phish from the updated file");
} else {
    logmsg("Failed to catch new phish");
}

###
### Get the current blocks from the Barracuda
###
if ( @curblocks = get_bn_blocks($bnsys, $bnpass) ) {
    $num_curblocks = scalar(@curblocks);
} else {
    logmsg("No blocks currently in Barracuda");
    $num_curblocks = 0;
}

###
### Get the new entries
###
my $differ = Array::Diff->diff(\@curblocks, \@newphish);
foreach (@{$differ->added}) {
    push(@missing_blocks, $_) 
}
my $diffc = scalar(@missing_blocks);
logmsg("Updated phish file has $diffc new entries in it");
if ( $diffc == 0 ) {
    logmsg("Nothing to do, exiting");
    exit(0);
}


###
### Add the newly caught phish to the Barracuda
###

# Start the add at the count of the current blocks
# The Barracuda starts numbering at 0, how convenient
$bn_line_num = $num_curblocks; 
foreach my $add (@missing_blocks) {
    logmsg("**************************************");
    logmsg("*** Working on $add");
    logmsg("**************************************");
    # Add teh email as a block
    if ( add_bn_block($bnsys, $bnpass, $add, $bn_line_num) ) {
        # Add a comment to that block
        if ( ! add_bn_comment($bnsys, $bnpass, $add, "KNOWN PHISH") ) {
            logmsg("Failed to add comment for $add");
            next;
        } else {
            # Add the action to that block (Block, Tag, Quarantine)
            if ( ! add_bn_email_block_action($bnsys, $bnpass, $add, "Block") ) {
                logmsg("Failed to add block action for $add");
                next;
            }
        }
        # increment for the next add
        $bn_line_num++;
    } else {
        logmsg("All out failure to add $add to Barracuda block list, sorry");
        next;
    }
}


logmsg("All done, exiting");
exit(0);
### END



###############################################################################
### SUBS
###############################################################################

###############################################################################
# NAME        : svn_update
# DESCRIPTION : Perform an SVN update against a given directory
# ARGUMENTS   : REQUIRED: scalar(svncmd)
#             : REQUIRED: scalar(dir)
# RETURNS     : 0 or 1
# NOTES       : None
###############################################################################
sub svn_update {
    my ($svncmd, $dir) = @_;
    my $success;
    open(SVN, "cd $dir && svn update|") or die "unable to run svn command\n";
    while(<SVN>) {
        chomp();
        logmsg("svn_update: $_");
        if ( $_ =~ /At revision/ ) {
            $success = 1;
        } else {
            $success = 0;
        }
    }
    close(SVN);

    if ( $success ) {
        return(1);
    } else {
        return(0);
    }
}


###############################################################################
# NAME        : get_newphish
# DESCRIPTION : grab the phish addresses from a file
# ARGUMENTS   : REQUIRED: scalar(dir)
#             : REQUIRED: scalar(file)
# RETURNS     : array(addresses)
# NOTES       : None
###############################################################################
sub get_newphish {
    my ($dir, $file) = @_;
    my @newphish;
    open(PHISHFILE, "<$dir/$file") or die "get_newphish: Unable to open phish file";
    while(<PHISHFILE>) {
        chomp();
        next if /#/;
        my ($address, $type, $date) = split(/,/, $_);
        push(@newphish, $address);
    }
    close(PHISHFILE);

    return(@newphish);
}


###############################################################################
# NAME        : get_bn_blocks
# DESCRIPTION : Return an array of the current addresses blocked by a Barracuda
# ARGUMENTS   : REQUIRED: scalar(bnsys)
#             : REQUIRED: scalar(bnpass)
# RETURNS     : array(addresses)
# NOTES       : See http://www.barracuda.com for API details
###############################################################################
sub get_bn_blocks {
    my ($bnsys, $bnpass) = @_;
    my @bnblocks;
    my $req;
    my $res;
    my $xs1; 
    my $doc;
    my $tempxml = "bn.xml";

    my $ua = LWP::UserAgent->new;
    $ua->agent("GSBPostmaster/0.1 ");

    $req = HTTP::Request->new(GET => "$bnsys/cgi-bin/config_get.cgi?variable=mta_acl_email_src_block_address&password=$bnpass");
    $res = $ua->request($req);

    if ($res->is_success) {
        open(TEMPXML, ">$tempxml");
        print TEMPXML $res->content;
        close(TEMPXML);
    } else {
        print $res->status_line, "\n";
    }

    $xs1 = XML::Simple->new();
    $doc = $xs1->XMLin($tempxml, forcearray => 1);

    @bnblocks = @{$doc->{mta_acl_email_src_block_address}};
    logmsg("get_bn_blocks: Got " . scalar(@bnblocks) . " blocks in Barracuda");
    unlink($tempxml) if not $KEEPXML;
    return(@bnblocks);
}


###############################################################################
# NAME        : add_bn_block
# DESCRIPTION : Add a block for an address to a Barracuda
# ARGUMENTS   : REQUIRED: scalar(bnsys)
#             : REQUIRED: scalar(bnpass)
#             : REQUIRED: scalar(address)
#             : REQUIRED: scalar(line)
# RETURNS     : 0 or 1
# NOTES       : See API docs for what "line" is for
###############################################################################
sub add_bn_block {
    my ($bnsys, $bnpass, $address, $line) = @_;
    my $req;
    my $res;

    logmsg("add_bn_block: address => $address, line => $line");

    my $ua = LWP::UserAgent->new;
    $ua->agent("GSBPostmaster/0.1 ");

    $req = HTTP::Request->new(GET => "$bnsys/cgi-bin/config_set.cgi?variable=mta_acl_email_src_block_address&value=$address&row=$line&password=$bnpass");
    $res = $ua->request($req);

    if ($res->is_success) {
        logmsg("add_bn_block: Successfully added $address");
        return(1);
    } else {
        logmsg("add_bn_block: Failed to add $address");
        print $res->status_line, "\n";
        return(0);
    }
}


###############################################################################
# NAME        : add_bn_comment
# DESCRIPTION : Change the comment on the blocked address in a Barracuda
# ARGUMENTS   : REQUIRED: scalar(bnsys)
#             : REQUIRED: scalar(bnpass)
#             : REQUIRED: scalar(address)
#             : REQUIRED: scalar(comment)
# RETURNS     : 0 or 1
# NOTES       : None
###############################################################################
sub add_bn_comment {
    my ($bnsys, $bnpass, $address, $comment) = @_;
    my $req;
    my $res;

    # get the list index for the address
    my $index = get_bn_var_idx($bnsys, $bnpass, "mta_acl_email_src_block_address", $address);
    logmsg("add_bn_comment: index for add => $index");

    my $ua = LWP::UserAgent->new;
    $ua->agent("GSBPostmaster/0.1 ");

    $req = HTTP::Request->new(GET => "$bnsys/cgi-bin/config_set.cgi?variable=mta_acl_email_src_block_comment&value=$comment&row=$index&password=$bnpass");
    $res = $ua->request($req);

    if ($res->is_success) {
        logmsg("add_bn_comment: Successfully added comment for $address");
        return(1);
    } else {
        logmsg("add_bn_comment: Failed to add comment for $address");
        print $res->status_line . "\n";
        return(0);
    }
}


###############################################################################
# NAME        : add_bn_email_block_action
# DESCRIPTION : Add the email block action (Block, Tag, Quarantine)
# ARGUMENTS   : REQUIRED: scalar(bnsys)
#             : REQUIRED: scalar(bnpass)
#             : REQUIRED: scalar(address)
#             : REQUIRED: scalar(type)
# RETURNS     : 0 or 1
# NOTES       : None
###############################################################################
sub add_bn_email_block_action {
    my ($bnsys, $bnpass, $address, $action) = @_;
    my $name = "add_bn_email_block_action";
    my $req;
    my $res;

    # Make sure they gave us the correct tag
    #if ( $action ne "Block" or $action ne "Tag" or $action ne "Quarantine" ) {
    #    logmsg("$name: Invalid action => $action");
    #    logmsg("$name: Must be Block, Tag or Quarantine");
    #    return(0);
    #}

    # get the list index for the address
    my $index = get_bn_var_idx($bnsys, $bnpass, "mta_acl_email_src_block_address", $address);
    logmsg("$name: index => $index");
    logmsg("$name: address => $address, action => $action");

    my $ua = LWP::UserAgent->new;
    $ua->agent("GSBPostmaster/0.1 ");

    $req = HTTP::Request->new(GET => "$bnsys/cgi-bin/config_set.cgi?variable=mta_acl_email_src_block_action&value=$action&row=$index&password=$bnpass");
    $res = $ua->request($req);

    if ($res->is_success) {
        logmsg("$name: Successfully added action for $address");
        return(1);
    } else {
        logmsg("$name: Failed to add action for $address");
        print $res->status_line . "\n";
        return(0);
    }
}


###############################################################################
# NAME        : get_bn_var_idx
# DESCRIPTION : Get the index of a variable/value pair from a Barracuda
# ARGUMENTS   : REQUIRED: scalar(bnsys)
#             : REQUIRED: scalar(bnpass)
#             : REQUIRED: scalar(var)
#             : REQUIRED: scalar(val)
# RETURNS     : scalar(index)
# NOTES       : None
###############################################################################
sub get_bn_var_idx {
    my ($bnsys, $bnpass, $var, $val) = @_;
    my $req;
    my $res;
    my $xs1; 
    my $doc;
    my $tempxml = "varval.xml";

    my $ua = LWP::UserAgent->new;
    $ua->agent("GSBPostmaster/0.1 ");

    # Call the API search function
    $req = HTTP::Request->new(GET => "$bnsys/cgi-bin/config_search.cgi?variable=$var&value=$val&password=$bnpass");
    $res = $ua->request($req);

    if ($res->is_success) {
        open(TEMPXML, ">$tempxml");
        print TEMPXML $res->content;
        close(TEMPXML);
    } else {
        print $res->status_line, "\n";
    }

    $xs1 = XML::Simple->new();
    $doc = $xs1->XMLin($tempxml);

    my ($garbage, $index) = split(/:/, $doc->{$var});

    unlink($tempxml) if not $KEEPXML;
    return($index);
}


###############################################################################
# NAME        : logmsg
# DESCRIPTION : Print a formatted log message to a file handle
# ARGUMENTS   : OPTIONAL: scalar(fh)
#             : REQUIRED: scalar(message)
# RETURN      : True
# NOTES       : None
###############################################################################
sub logmsg {

    my ($package, $filename, $line, $subr) = caller();
    my $message;
    my $fh;

    # 1 arg form vs 2 arg form
    if ( $#_ == 0 ) {       # got 1 arg, assume dest is STDOUT
        $fh = STDOUT;
        $message = $_[0];
    } elsif ( $#_ == 1 ) {  # got 2, they want the message somewhere else
        $fh = $_[0];
        $message = $_[1];
    }   

    my $n = strftime "%Y-%m-%d %H:%M:%S", localtime(time());
    print $fh "[$n] $package(): $message\n";

    return(1);
}


###############################################################################
# NAME        : debug
# DESCRIPTION : Print a debug formatted log message to a file handle
# ARGUMENTS   : OPTIONAL: scalar(fh)
#             : REQUIRED: scalar(message)
# RETURN      : True
# NOTES       : Set a package level variable DEBUG to enable/disable these
###############################################################################
sub debug { 

    my $message;
    my $fh;

    # 1 arg form vs 2 arg form
    if ( $#_ == 0 ) {       # got 1 arg, assume dest is STDOUT
        $fh = STDOUT;
        $message = $_[0];
    } elsif ( $#_ == 1 ) {  # got 2, they want the message somewhere else
        $fh = $_[0];
        $message = $_[1];
    }   

    if ( $main::DEBUG ) { 
        logmsg($fh, "DEBUG: $message");
        return(1); 
    } else {
        return(1);
    }   
} 


###############################################################################
# NAME        : print_version
# DESCRIPTION : Print the version of the program
# ARGUMENTS   : REQUIRED: scalar(VERSION)
# RETURNS     : Nothing
# NOTES       : None
###############################################################################
sub print_version {
    print "$NAME: version $VERSION\n";
    exit(0);
}




__END__

=head1 NAME

feed_barracuda_phish.pl - Feed new phish to a Barracuda

=head1 SYNOPSIS

feed_barracuda_phish.pl [options] 

    options:

       --help        : brief help (this page)
       --version     : prints the version
       --debug       : enables debugging

       --keep-xml    : Keep XML results from Barracuda, useful for troubleshooting

       --no-svn      : Don't SVN update phish file

