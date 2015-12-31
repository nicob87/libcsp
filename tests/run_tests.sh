#!/bin/bash
ROOT=`git rev-parse --show-toplevel`
(cd $ROOT &&
./waf configure --build-tests --enable-examples &&
./waf
)
if [ $? -ne 0 ]; then
    exit $?
fi
$ROOT/build/tester server &
SERVER=$!
$ROOT/build/tester client
kill -9 $SERVER
