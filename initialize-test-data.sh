#!/bin/bash

PRJ_ROOT=$(cd $(dirname $0); pwd)

cd $PRJ_ROOT;

rm -rf test

./generate-ca.sh
./generate-cert.sh a.local.org
./generate-cert.sh b.local.org c.local.org
./generate-cert.sh x.local.org local.org '*.local.org'
