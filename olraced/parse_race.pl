#!/usr/bin/perl
#helper script for olraced
#accept output from olraced, run addr2line to translate
#ip address to source code line
#
#Nov Tong Zhang<ztong@vt.edu>
#

use strict;
use warnings;

use Path::Class;
use Data::Dumper;
use autodie;
use Storable;
use File::Basename;


my ($exeimg,$racefile) = @ARGV;


#cache result from addr2line
my %addr2line_cache;
my $hashfile = '/tmp/'.basename($exeimg).'.ha';

if(-e $hashfile)
{
	%addr2line_cache = %{retrieve($hashfile)};
}

my $dir = dir("./");
my $file = $dir->file($racefile);
my $fh = $file->openr();

my $regexp = qr/^\[\d*\](0x[0-9|a-f]*),(0x[0-9|a-f]*).*/;

my $cnt = 0;

while(!$fh->eof())
{
	my $line = $fh->getline();
	chomp($line);
	my @res = ( $line =~ $regexp );
	my $size = @res;
	if( $size != 0 )
	{
		my $r1="";
		my $r2="";
		if(exists $addr2line_cache{$res[0]})
		{
			$r1 = $addr2line_cache{$res[0]};
		}else
		{
			$r1 = `addr2line -f -e $exeimg -a $res[0]`;
			$addr2line_cache{$res[0]} = $r1;
		}
		if(exists $addr2line_cache{$res[1]})
		{
			$r2 = $addr2line_cache{$res[1]};
		}else
		{
			$r2 = `addr2line -f -e $exeimg -a $res[1]`;
			$addr2line_cache{$res[1]} = $r2;
		}
		print "--------[RACE $cnt]-----------\n";
		print "$res[0]=>$r1";
		print "$res[1]=>$r2";
		$cnt++;
	}
}
$fh->close();

print "---------------------------------------\n";
print "SUMMARY: $cnt potential race(s) found\n";

store \%addr2line_cache, $hashfile



