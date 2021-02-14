#!/bin/bash

PRJ_ROOT=$(cd $(dirname $0); pwd)

cd $PRJ_ROOT;

rm -rf test

./generate-ca.sh
./generate-rsa-cert.sh a.local.org
./generate-rsa-cert.sh b.local.org c.local.org
./generate-rsa-cert.sh x.local.org local.org '*.local.org'
./generate-ec-cert.sh prime256v1 a.ec.local.org b.ec.local.org
./generate-ec-cert.sh secp521r1 b.ec.local.org
./generate-ec-cert.sh secp521r1 c.ec.local.org d.ec.local.org '*.ec.local.org'

echo "Initialization completed."
echo "Please add a.local.org, b.local.org, c.local.org, x.local.org, local.org,"
echo "dddd.local.org, g.local.org to /etc/hosts or C:/Windows/System32/drivers/etc/hosts"
