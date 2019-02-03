#!/bin/bash

DOMAIN_NAME=$1

CA_ROOT=test/ca
CERTS_ROOT=test/certs
CA_CONF_FILE=$CA_ROOT/ca.conf
CA_CERT=$CA_ROOT/cert.pem
CERT_DIR=$CERTS_ROOT/$DOMAIN_NAME
PRIV_KEY_FILE=$CERT_DIR/key.pem
CERT_FILE=$CERT_DIR/cert.pem
FULLCHAIN_FILE=$CERT_DIR/fullchain.pem
CSR_FILE=$CERT_DIR/csr.pem
CFG_FILE=$CERT_DIR/cert.conf

# Generate CSR for CA

mkdir -p $CERT_DIR

rm -f $CERT_DIR/*

openssl genrsa -out $PRIV_KEY_FILE 2048

echo "[ req ]" > $CFG_FILE
echo "default_bits = 2048" >> $CFG_FILE
echo "default_md = sha256" >> $CFG_FILE
echo "prompt = no" >> $CFG_FILE
echo "utf8 = yes" >> $CFG_FILE
echo "distinguished_name = my_req_distinguished_name" >> $CFG_FILE
echo "req_extensions = my_extensions" >> $CFG_FILE

echo "[ my_req_distinguished_name ]" >> $CFG_FILE
echo "C=CN" >> $CFG_FILE
echo "ST=GD" >> $CFG_FILE
echo "L=Shenzhen" >> $CFG_FILE
echo "O=Local" >> $CFG_FILE
echo "OU=Master" >> $CFG_FILE
echo "CN=$DOMAIN_NAME" >> $CFG_FILE
echo "[ my_extensions ]" >> $CFG_FILE
echo "basicConstraints=CA:FALSE" >> $CFG_FILE
echo "subjectKeyIdentifier=hash" >> $CFG_FILE

i=1
yes=0
hasSAN=0

for san in $@
do
    if [ "$yes" != "1" ]; then

        if [ "$DOMAIN_NAME" = "$san" ]; then

            yes=1
        fi;

        continue;
    fi;

    if [ "$hasSAN" = "0" ]; then

        echo "subjectAltName=@my_subject_alt_names" >> $CFG_FILE
        echo "[ my_subject_alt_names ]" >> $CFG_FILE
        hasSAN=1
    fi;

    echo "DNS.$i = $san" >> $CFG_FILE

    i=$[$i+1];

done

openssl req \
    -new \
    -key $PRIV_KEY_FILE \
    -out $CSR_FILE \
    -config $CFG_FILE \
    -extensions my_extensions

openssl ca \
    -config $CA_CONF_FILE \
    -out $CERT_FILE \
    -infiles $CSR_FILE

cat $CERT_FILE | grep -P '^[^\s]' | grep -P '^(?!Certificate)' > $CERT_FILE

cat $CERT_FILE $CA_CERT > $FULLCHAIN_FILE
