#!/bin/bash

CMD="$*"

echo "test prog"
time $PIN_ROOT/pin -t obj-intel64/bd.so -- ${CMD}

#cat res.log

