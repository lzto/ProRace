#!/usr/bin/perl
# this is helper script for olraced,
# it takes several olraced_[tid].input from user
# read them, sort them using TSC,
# and feed them into olraced in order

use strict;
use warnings;

use Path::Class;
use Data::Dumper;
use autodie;

#our $regex = qr/^([^\s]*)\s([^\s]*)\s([^\s]*)(?:\s)?([^\s]*)?.*$/;
our $regex = qr/^([^\s]*)\s([^\s]*)\s([^\s]*)(?:\s)?([^\s]*)?(?:\s)?([^\s]*)?.*$/;

my @ollog = @ARGV;

#print Dumper(@ollog);


sub parse_line
{
	my ($line) = @_;
	my @ret = ($line =~$regex);
	my %olentry=
	(
		'pid'=>$ret[0],
		'tsc'=>$ret[1],
		'op'=>$ret[2],
		'addr'=>$ret[3],
		'ip'=>$ret[4]
	);
	#why tsc is empty?
	if($olentry{'tsc'} eq '')
	{
		$olentry{'tsc'}=1;
	}
	%olentry;
}

sub getNewLine
{
	my ($_ent) = @_;
	my $fh = $$_ent{'fh'};
	my $line = $$fh->getline();
	if(not defined $line)
	{
		$line = "inf inf inf inf inf";
	}
	chomp($line);
	$$_ent{'linebuf'} = $line;
	################################
	#my %olent = parse_line($line);
	#FIXME: howto inline subroutine??
	my @ret = ($line =~ $regex);
	$$_ent{'cur_entry'}{'pid'} = $ret[0];
	$$_ent{'cur_entry'}{'tsc'} = ($ret[1] eq '') ? 1 : $ret[1]; 
	$$_ent{'cur_entry'}{'op'} = $ret[2];
	$$_ent{'cur_entry'}{'addr'} = $ret[3];
	$$_ent{'cur_entry'}{'ip'} = $ret[4];
	#################################
	
	return;
}

#file hash map
our %far;

my $cnt=0;
my $has_input = 0;

foreach my $fn(@ollog)
{
	#print "DBG:fn=>".$fn."\n";
	my $dir = dir("./");
	my $file = $dir->file($fn);
	my $fh = $file->openr();
	my %ent = (
		"filename" => "$fn",
		"fh" => \$fh,
		"linebuf" => "",
		"cur_entry" => {},
	);

	getNewLine(\%ent);

	if($ent{"cur_entry"}{"tsc"} ne "inf")
	{
		$has_input++;
	}
	
	$far{$cnt} = \%ent;
	$cnt++;
}

#parse each file and print in-order
while($has_input)
{
	my $min_tsc = "inf";
	my $min_k = -1;
	#find min tsc
	foreach my $k (keys %far)
	{
		my $mtsc = \$far{$k}{'cur_entry'}{'tsc'};

		if($$mtsc<$min_tsc)
		{
			$min_tsc = $$mtsc;
			$min_k = $k;
		}
	}
	my $ce = \%{$far{$min_k}{'cur_entry'}};
	print "$min_tsc $min_k $$ce{'op'} $$ce{'addr'} $$ce{'ip'}\n";
	getNewLine($far{$min_k});
	if($$ce{'tsc'}=="inf")
	{
		$has_input--;
	}
}

foreach my $k (keys %far)
{
	my $fh = $far{$k}{'fh'};
	$$fh->close();
}

