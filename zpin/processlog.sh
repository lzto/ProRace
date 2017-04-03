#!/bin/bash

RESOURCE_FILE=$1

lines=`grep ins ${RESOURCE_FILE} |wc -l` 
echo $lines entries in logfile

strings ${RESOURCE_FILE}|grep ins | cut -d'=' -f2 | sed -e 's/\//,/g' > recov.csv

echo "Calculate recover percentage:"
cat ${RESOURCE_FILE} |grep ins |cut -d'=' -f2| sed -e 's/\//\ /g' |~/zpin/calculator

