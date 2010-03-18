#!/usr/bin/perl

# $Id: gen_phish_reply.pl,v 1.5 2010/03/03 20:12:26 dan Exp $
#--------------------------------------------------------------------------
# 
# gen_phish_reply.pl
#
# Generate Spamassassin rules from the phishing_reply_addresses list
#
$VERSION="1.00";
$RELEASED="Mar 3, 2010";
#
# Copyright (C) 2010 Dan D Niles <dan@more.net>
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
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.
#
#--------------------------------------------------------------------------

use strict;
use vars qw( $VERSION $RELEASED );
use vars qw( %ENV );

use vars qw( $Rebuild $Download $Outfile $OUT );
use vars qw( $Reload $ReloadCommand );
use vars qw( %Ages @Ages );

# What to score the messages 
our $Score="10.000"; # Default value
our $DefAge="old";
# Separate rules into age categories.
%Ages = (
	 day => { name => "_DAY",
		  score => $Score,
		  age => 1*24*60*60,
		  desc => "seen within 1 day",
	      },
	 week => { name => "_WK",
		  score => $Score,
		  age => 7*24*60*60,
		  desc => "seen within 1 week",
	      },
	 month => { name => "_MON",
		  score => $Score,
		  age => 31*24*60*60,
		  desc => "seen within 1 month",
	      },
	 "6mon" => { name => "_6MON",
		     score => $Score,
		     age => 6*31*24*60*60,
		     desc => "seen within 6 months",
	      },
	 year => { name => "_YR",
		  score => sprintf("%.3f", $Score-2.0), 
		  age => 365*24*60*60,
		  desc => "seen within 1 year",
	      },
	 # This is the default
	 $DefAge => { name => "_OLD",
		      score => sprintf("%.3f", $Score-4.0),
		      age => 0,
		      desc => "older than 1 year",
		  },
	 );

# Where to get the list
our $List_URL="https://aper.svn.sourceforge.net/svnroot/aper/phishing_reply_addresses";

our $Tmp_Dir="/tmp";
if( -d "$ENV{HOME}/tmp" ){
    $Tmp_Dir="$ENV{HOME}/tmp";
}

# Where to store the list
our $List_File="$Tmp_Dir/phishing_reply_addresses";

# Where to put the output file
our $Outfile="$Tmp_Dir/local_phishing_reply.cf";
if( -d "/usr/local/etc/mail/spamassassin" ){
    $Outfile="/usr/local/etc/mail/spamassassin/local_phishing_reply.cf";
}

# Command to reload the rules 
# If this is not defined or specified on command line, a guess
# will be made
#$ReloadCommand="/usr/local/etc/rc.d/amavisd reload";

# How often to download the list (in seconds). 0 means always download.
our $List_Age=59*60; # One hour

# The base rule name to derive names from
our $Base_RuleName="PHISH_REPLY";

# How many rules to include in a meta rule?
our $Batch_Size=50;

# Combine A (Reply-To) and B (From) rules?
our $CombineAB=1;

# Output C (body) rules?
our $OutputBody=0;

# Ignore C (body) rules that are also A (Reply-To) or B (From) rules?
our $IgnoreBodyIfHeader=1;

# Output E (other) rules?
our $OutputOther=1;

# Ignore E (other) rules if they are B (From) rules?
our $IgnoreOtherIfFrom=1;

# Treat E (other) rules as B (From) rules?
our $TreatOtherAsFrom=0;

$0 =~ s%.*/%%;
sub print_version {
    &pr_error("%s Version %s Released %s\n", $0, $VERSION, $RELEASED);
}
sub print_usage {
    &pr_error("Usage: $0 [options]\n");
}
sub short_help {
    &print_version();
    &print_usage();
    &pr_error("Use \'$0 --help\' for detailed help.\n");
} 
sub help {

    &print_version();
    &print_usage();
    print STDERR <<EOF;
    -h|--help                 Print help message.
    -V|--Version              Print version and exit.
    -v|--verbose              Be more verbose.
    -r|--rebuild              Rebuild the SA file, dont download.
    -d|--download             Download the list, dont rebuild.
    -o|--outfile <file>       Output the SA file to <file>.
    --reload                  Reload rules if outfile changed.
    -c|--reload-command <com> Set the reload command to <com>.
EOF

}


use vars qw( $OK $Help $Print_Version $VERBOSE  );
use vars qw( $Count );

use Getopt::Long qw(:config no_ignorecase gnu_getopt);
$OK=GetOptions("h|help" => \$Help,
	       "V|Version|version" => \$Print_Version,
	       "v|ve|ver|verbose+" => \$VERBOSE,
	       "r|rebuild" => \$Rebuild,
	       "d|download" => \$Download,
	       "count" => \$Count,  # Count rule types, dont download or anything else
	       "o|outfile=s" => \$Outfile,
	       "reload|restart" => \$Reload,
	       "c|reload-command" => \$ReloadCommand,
	       );

&check_args();

if( $Help ){ &help(); exit; }
if( !$OK ){ &short_help(); exit 255; }
if( $Print_Version ){ &print_version(); exit; }

unless( $Rebuild || $Count || &download_list() ){
    &pr_verbose("No changes to the list, nothing to do!\n");
    exit(0);
}
if( $Download ){ exit(0); }

&read_list();
if( $Count ){
    &print_counts();
}else{
    &output_conf();
}

exit;

sub check_args
{

    if( $Reload && ! $Outfile ){
	pr_warn("--reload specified without an output file!\n");
	pr_warn("NO RESTART WILL TAKE PLACE!!\n");
	$Reload=undef;
    }

    if( $Reload && $ReloadCommand ){
	my($_exec)=split(/\s+/, $ReloadCommand);
	if( ! -x $_exec ){
	    pr_warn("--reload specified but $_exec not executable!\n");
	    pr_warn("NO RESTART WILL TAKE PLACE!!\n");
	    $Reload=undef;
	}
    }

    if( $Reload && !$ReloadCommand ){
	if( -x "/usr/local/etc/rc.d/amavisd" ){
	    $ReloadCommand="/usr/local/etc/rc.d/amavisd reload";
	}elsif( -x "/etc/init.d/amavisd" ){
	    $ReloadCommand="/etc/init.d/amavisd reload";
	}elsif( -x "/usr/local/etc/rc.d/spamd" ){
	    $ReloadCommand="/usr/local/etc/rc.d/spamd reload";
	}elsif( -x "/etc/init.d/spamd" ){
	    $ReloadCommand="/etc/init.d/spamd reload";
	}else{
	    pr_warn("--reload specified but reload command is not!\n");
	    pr_warn("NO RESTART WILL TAKE PLACE!!\n");
	    $Reload=undef;
	}
    }

    if( $Reload && !$VERBOSE ){
	$ReloadCommand .= " 2>/dev/null";
    }
    
    return;
}

#exit;

sub download_list
{
    my $fetch;

    my @stats;
    if( $List_Age && -f $List_File ){
	@stats=stat($List_File);
	if( (time-$stats[9]) < $List_Age ){
	    # File doesn't need to be downloaded
	    return 0;
	}
    }

    my $fetch=undef;
    my @fetch_args=();
    if( -x "/usr/bin/fetch" ){
	$fetch="/usr/bin/fetch";
    }
    elsif ( -x "/usr/bin/wget" ){
	$fetch="/usr/bin/wget";
    }
    elsif( $fetch=`which fetch` ){
	chomp($fetch);
    }
    elsif( $fetch=`which wget` ){
	chomp($fetch);
    }
    else{
	die("Cannot locate program for fetching the list!");
    }

    if( $fetch =~  m%/fetch$% ){
	@fetch_args=("-o", "$List_File.new", $List_URL);
	if( $VERBOSE ){
	    for( my $i=1; $i < $VERBOSE; $i++){
		unshift(@fetch_args, "-v");
	    }
	}
	else{
	    unshift(@fetch_args, "-q");
	}
    }
    elsif ( $fetch =~ m%/wget$% ){
	@fetch_args=("-O", "$List_File.new", $List_URL);
	if( $VERBOSE ){
	    for( my $i=1; $i < $VERBOSE; $i++){
		unshift(@fetch_args, "-v");
	    }
	}
	else{
	    unshift(@fetch_args, "-q");
	}
    }
    else{
	die("Do not know how to set args for $fetch\n");
    }

    &pr_verbose("%s %s\n", $fetch, join(" ", @fetch_args));
    my $rc=system($fetch, @fetch_args);
    if( $rc ){
	die("Failed to fetch the list!");
    }

    if( ! @stats ){
	if( -f $List_File ){ unlink $List_File; }
	rename("$List_File.new", $List_File);
	return 1;
    }
    my @new_stats=stat("$List_File.new");
    if( $new_stats[7] != $stats[7] ||
	`diff -q $List_File.new $List_File` ){
	if( -f $List_File ){ unlink $List_File; }
	rename("$List_File.new", $List_File);
	return 1;
    }
    unlink("$List_File.new");
    system("touch", $List_File);
    return 0;
}

use vars qw( %ReplyTo %From %Body %Other);
use vars qw( %Count );

sub read_list ()
{
    open(LIST, $List_File) or die "Cannot read list file!";

    while(<LIST>){
	if( /^\s*\#/ ){ next; }
	chomp;
	if( /^\s*$/ ){ next; }

	my( $addr, $type, $date )=split(/,/);
    
	my( $age ) = &get_age($date);
	unless( %Ages || grep(/$age/, @Ages) ){
	    push @Ages, $age;
	}

	if( $type =~ s/A//g ){
#         A: The ADDRESS was used in the Reply-To header.
	    $Count{A}++;
	    if( $IgnoreBodyIfHeader && $type =~ s/C//g ){
		$Count{Ch}++;
	    }
	    push @{$ReplyTo{$age}}, $addr;
	}
	if( $type =~ s/B//g ){
#         B: The ADDRESS was used in the From header.
	    $Count{B}++;
	    if( $IgnoreBodyIfHeader && $type =~ s/C//g ){
		$Count{Ch}++;
	    }
	    if( $TreatOtherAsFrom && $type =~ s/E//g ){
		$Count{EB}++;
	    }
	    elsif( $IgnoreOtherIfFrom && $type =~ s/E//g ){
		$Count{EB}++;
	    }
	    push @{$From{$age}}, $addr;
	}
	if( $type =~ s/C//g ){
#         C: The content of the phishing message contained the ADDRESS.
	    $Count{C}++;
	    push @{$Body{$age}}, $addr;
	}
	if( $type =~ s/D//g ){
#         D: The content of the phishing message contained the ADDRESS,
#             and it was obfuscated.
	    $Count{D}++;
	}
	if( $type =~ s/E//g ){
#         E: The ADDRESS (usually in the From header) might receive replies
#             but it was not intended to receive the replies.
	    # Do nothing;
	    $Count{E}++;
	    if( $TreatOtherAsFrom ){
		push @{$From{$age}}, $addr;
	    }
	    else{
		push @{$Other{$age}}, $addr;
	    }
	}
	if( $type ){
	    &pr_warn("Ignoring unhandled types: $type\n");
	    next;
	}
    }
}

use Time::Local;

sub get_age ()
{
    my $date=shift;

    if( ! %Ages ){ return $DefAge; }

    my $now=time;
    my @time=localtime($now);
    unless ( $date =~ m/^(\d{4})(\d{2})(\d{2})$/ ){
	die "Invalid date stamp!";
    }
    $time[3]=$3;
    $time[4]=$2-1;
    $time[5]=$1-1900;
    my $dtime=timelocal(@time);
	
    my $val=undef;
    foreach my $age ( sort by_age keys %Ages ){
	if( $Ages{$age}{age} == 0 ){
	    $val=$age;
	    next;
	}
	if( ($now - $dtime) <= $Ages{$age}{age} ){
	    $val=$age;
	    last;
	}
    }
    if( !$val ){ $val=$DefAge; }

    return $val;
}

sub by_age
{
    if( !$Ages{$a}{age} ){ return 1; }
    if( !$Ages{$b}{age} ){ return 0; }
    return $Ages{$a}{age} <=> $Ages{$b}{age};
}

sub output_conf
{
    if( $Outfile && !$Count ){
	open $OUT, ">$Outfile.new" or die "Cannot open $Outfile.new!";
    }else{
	$OUT=\*STDOUT;
    }

    if( %Ages ){
	@Ages = sort by_age keys %Ages;
    }

    foreach my $age ( @Ages ){
	my $aname;
	my $score;
	if( %Ages ){
	    if( ! defined($Ages{$age}) ){
		die("Invalid age $age!");
	    }
	    $aname=$Ages{$age}{name};
	    $score=$Ages{$age}{score};
	}else{
	    $aname="";
	    $score=$Score;
	}

	if( !$score ){ next; }

	my @combined=();

	if( $ReplyTo{$age} ){
	    my $name=&output_rules("A", $aname, "header", "Reply-To", 
				   $ReplyTo{$age}, $score, $Ages{$age}{desc},
				   $CombineAB);
	    push(@combined, $name) if $name;
	}

	if( $From{$age} ){
	    my $name=&output_rules("B", $aname, "header", "From", 
				   $From{$age}, $score, $Ages{$age}{desc},
				   $CombineAB);
	    push(@combined, $name) if $name;
	}

	if( @combined ){
	    my $s=$score;
	    if( ref($s) && ref($s) eq "HASH" ){$s=$$s{AB};}
	    printf($OUT "meta %s%s (%s)\n",
		       $Base_RuleName, $aname,
		       join(" || ", @combined));
		printf($OUT "score %s%s %s\n",
		       $Base_RuleName, $aname,
		       $s);
		printf($OUT "describe %s%s Phishing From and Reply-To addresses %s\n",
		       $Base_RuleName, $aname,
		       $Ages{$age}{desc},
		       );
	}
	       
	if( $OutputBody && $Body{$age} ){
	    &output_rules("C", $aname, "body", undef, 
			  $Body{$age}, $score, $Ages{$age}{desc});
	}

	if( $OutputOther && $Other{$age} ){
	    &output_rules("E", $aname, "header", "From", 
			  $Other{$age}, $score, $Ages{$age}{desc});
	}
    }

    if( $Outfile ){
	close $OUT;
	if( !-f $Outfile || `diff -q $Outfile.new $Outfile` ){
	    &pr_verbose("Installing new SA cf file: %s\n", $Outfile);
	    if( -f $Outfile ){
		if( -f "$Outfile.old" ){ unlink "$Outfile.old"; }
		rename "$Outfile", "$Outfile.old";
	    }
	    rename "$Outfile.new", "$Outfile";
	    if( $Reload ){
		&pr_verbose("Reloading amavis with command: %s\n", $ReloadCommand);
		system($ReloadCommand);
	    }
	}else{
	    &pr_verbose("No changes to SA cf file, nothing to do!\n");
	}
    }
}

sub output_rules
{
    my $type=shift;
    my $aname=shift;
    my $rule=shift;
    my $header=shift;
    my $aref=shift;
    my $score=shift;
    my $desc=shift;
    my $output_meta=shift; # Output only meta tag?
    my $only_one=0;
    my $name;

    if( $score && ref($score) && ref($score) eq "HASH" ){
	$score=$$score{$type};
    }

    if( !$score && !$output_meta ){ return (); }

    if( scalar(@{$aref}) == 1 ){
	$only_one=1;
    }

    if( $only_one && !$output_meta ){
	$name=sprintf("%s_%s%s", $Base_RuleName, $type, $aname);
    }else{
	$name=sprintf("__%s_%s%s", $Base_RuleName, $type, $aname);
    }
    my @rules=&build_rules($rule, $name, $header, $aref, $only_one);
    my @groups;
    if( $#rules < $Batch_Size ){
	@groups=@rules;
    }else{
	@groups=&group_rules($name."_GRP", \@rules);
    }
    if( ! $output_meta ){
	$name=sprintf("%s_%s%s", $Base_RuleName, $type, $aname);
	printf($OUT "meta %s (%s)\n",
	       $name, join(" || ", @groups)) unless $only_one;
	printf($OUT "score %s %s\n",
	       $name, $score);
	if( $rule eq "header" ){
	    if( $type eq "E" ){
		printf($OUT "describe %s Phishing other addresses %s\n",
		       $name, $desc, );
	    }else{
		printf($OUT "describe %s Phishing %s addresses %s\n",
		       $name, $header, $desc,);
	    }
	}else{
	    printf($OUT "describe %s Phishing addresses in %s %s\n",
		   $name, $rule, $desc,);
	}
	return undef;
    }else{
	printf($OUT "meta %s (%s)\n", $name, join(" || ", @groups)) unless $only_one;
	return $name;
    }
}

sub build_rules
{
    my $rule=shift;
    my $name=shift;
    my $header=shift;
    my $aref=shift;
    my $no_num=shift; # If there is only one, exclude number?
    my @out=();

    if( $no_num && scalar(@{$aref}) != 1 ){
	&pr_warn("no_num option called with a larger array");
	$no_num=0;
    }
	
    my $i=0;
    foreach my $v (@{$aref}){
	$i++;
	my $val=$v;
	$val =~ s/\./\\\./g;
	$val =~ s/\@/\\\@/g;
	if( $rule eq "header" ){
	    if( $no_num ){
		printf ($OUT "%s %s %s =~ /%s/i\n",
			$rule, $name, $header, $val);
	    }else{
		printf ($OUT "%s %s_%d %s =~ /%s/i\n",
			$rule, $name, $i, $header, $val);
	    }
	}
	elsif( $rule eq "body" ){
	    if( $no_num ){
		printf ($OUT "%s %s /%s/i\n",
			$rule, $name, $val);
	    }else{
		printf ($OUT "%s %s_%d /%s/i\n",
			$rule, $name, $i, $val);
	    }
	}
	else{
	    &pr_error("Unknown rule type: $rule\n");
	    next;
	}
	
	push(@out, sprintf("%s_%d", $name, $i));
    }

    return @out;
}

sub group_rules ()
{
    my $name=shift;
    my $aref=shift;
    my @out=();
    my @array;

    my $group=0;
    while ( @{$aref} ){
	$group++;
	@array=splice(@{$aref}, 0, $Batch_Size);
	printf($OUT "meta %s_%d (%s)\n",
	       $name, $group, join(" || ", @array));
	push(@out, sprintf("%s_%d", $name, $group));
    }
    return @out;
}

sub print_counts
{
    print STDERR "Type\tCount\n";
    foreach my $type ( qw( A B C Ch D E EB ) ){
	printf STDERR "%s\t%0d\n", $type,$Count{$type};
    }
    foreach my $age (sort by_age keys %Ages){
	printf STDERR "Addresses %s\n", $Ages{$age}{desc};
	print  STDERR "Type\tCount\n";
	printf STDERR "A\t%0d\n", scalar(@{$ReplyTo{$age}}) if $ReplyTo{$age};
	printf STDERR "B\t%0d\n", scalar(@{$From{$age}}) if $From{$age};
	printf STDERR "C\t%0d\n", scalar(@{$Body{$age}}) if $Body{$age};
	printf STDERR "E\t%0d\n", scalar(@{$Other{$age}}) if $Other{$age};
	
    }
}

#exit;
# Start of print.pl
#

use vars '$Indent';

sub pr_info
{
    my($fmt)=shift;

    printf( $fmt, @_ );
    return 1;
}

sub pr_error
{
    my($fmt)=shift;

    printf( STDERR $fmt, @_ );
    return 1;
}

sub pr_warn
{
    my($fmt)=shift;

    printf( STDERR $fmt, @_ );
    return 1;
}

sub pr_verbose
{
    my($fmt)=shift;

    return 0 unless $VERBOSE;

    printf( STDERR "%s", $Indent) if $Indent;
    printf( STDERR $fmt, @_ );
    return 1;
}

sub pr_vverbose
{
    my($fmt)=shift;

    return 0 unless $VERBOSE > 1;

    printf( STDERR "%s", $Indent) if $Indent;
    printf( STDERR $fmt, @_ );
    return 1;
}

sub pr_vvverbose
{
    my($fmt)=shift;

    return 0 unless $VERBOSE > 2;

    printf( STDERR "%s", $Indent) if $Indent;
    printf( STDERR $fmt, @_ );
    return 1;
}

# End of print.pl
1;
