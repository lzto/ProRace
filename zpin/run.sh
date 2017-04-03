#!/bin/bash

cmd="$*"

ADDITIONAL_OPT="-ifeellucky"

echo "test prog"
time $PIN_ROOT/pin ${ADDITIONAL_OPT} -t obj-intel64/zp.so --r 0 -- $cmd

#cat res.log

