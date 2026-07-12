#!/bin/sh
# Regenerate the OpenSSL-based test fixtures (requires openssl 3).
# Checked-in fixtures are valid for 10 years; rerun this when they expire.
set -e
cd "$(dirname "$0")/fixtures"

# key-matching fixtures: RSA (PKCS#8 + PKCS#1) and EC (SEC1 + PKCS#8)
openssl req -x509 -newkey rsa:2048 -keyout rsa.key -out rsa.crt -days 3650 -nodes -subj "/CN=rsa-test" 2>/dev/null
openssl rsa -in rsa.key -traditional -out rsa-pkcs1.key 2>/dev/null
openssl ecparam -name prime256v1 -genkey -noout -out ec-sec1.key
openssl req -x509 -key ec-sec1.key -out ec.crt -days 3650 -subj "/CN=ec-test" 2>/dev/null
openssl pkcs8 -topk8 -nocrypt -in ec-sec1.key -out ec-pkcs8.key

# extension-decoding fixture
openssl req -x509 -key ec-sec1.key -out rich-ext.crt -days 3650 -subj "/CN=rich-ext.demo" \
  -addext "subjectAltName=DNS:demo.example,DNS:www.demo.example,IP:192.0.2.1" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "authorityInfoAccess=caIssuers;URI:http://ca.demo.example/ca.crt,OCSP;URI:http://ocsp.demo.example" \
  -addext "crlDistributionPoints=URI:http://crl.demo.example/demo.crl" 2>/dev/null

# 3-tier mTLS PKI for the fetch-chain tool test
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout mtls-root.key -out mtls-root.crt -days 3650 -nodes -subj "/CN=Test Root CA" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout mtls-inter.key -out mtls-inter.csr -nodes -subj "/CN=Test Issuing CA" 2>/dev/null
openssl x509 -req -in mtls-inter.csr -CA mtls-root.crt -CAkey mtls-root.key -CAcreateserial -out mtls-inter.crt -days 3650 \
  -extfile /dev/stdin <<CNF 2>/dev/null
basicConstraints=critical,CA:TRUE
CNF
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout mtls-server.key -out mtls-server.csr -nodes -subj "/CN=localhost" 2>/dev/null
openssl x509 -req -in mtls-server.csr -CA mtls-inter.crt -CAkey mtls-inter.key -CAcreateserial -out mtls-server.crt -days 3650 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -keyout mtls-client.key -out mtls-client.csr -nodes -subj "/CN=test-client" 2>/dev/null
openssl x509 -req -in mtls-client.csr -CA mtls-inter.crt -CAkey mtls-inter.key -out mtls-client.crt -days 3650 2>/dev/null
cat mtls-root.crt mtls-inter.crt > mtls-ca-bundle.pem
rm -f mtls-*.csr mtls-*.srl

echo "fixtures regenerated"
