#!/bin/bash

EXEIMG=$1

rm -f *input 
#cp $(dirname $EXEIMG)/olraced_*.input .
cp /home/lzto/zperf/olraced_*.input .
#:<<COMMENT
c=0
while [ $c -lt 127 ];do
	echo "0 0 pthread_create 0" >> input
	c=$(($c+1))
done
#COMMENT
./olread.pl olraced_*.input >> input
./olraced <input > output
./parse_race.pl ${EXEIMG} ./output 

