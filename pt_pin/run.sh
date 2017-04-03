#!/bin/bash

cmd="$*"

ADDITIONAL_OPT="-ifeellucky"

echo "test prog"
time $PIN_ROOT/pin ${ADDITIONAL_OPT} -t obj-intel64/pt.so --f 1 -- $cmd

#cat res.log

