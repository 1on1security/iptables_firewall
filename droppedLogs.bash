#!/usr/bin/env bash

# source log
logfile=/var/log/kern.log

# outputs
outputfile=firewall.log
rootDir=~/
tempfile=/tmp/firewall

grep 'Firewall' $logfile > $rootDir/$outputfile

#grep -o -E 'SRC=(([0-9]{1,3}\.){3}[0-9]{1,3})' $tempfile | sed 's/SRC=//g' > $rootDir/$outputfile
rm -f $tempfile
