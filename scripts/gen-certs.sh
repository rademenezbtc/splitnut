#!/usr/bin/env bash
# Generate the mTLS files shared by cdk-mintd (client) and the signer (server).
# Based on CDK's crates/cdk-signatory/generate_certs.sh, with one fix: CDK's script issues
# the client certificate as X.509 v1, which rustls rejects ("transport error" in cdk-mintd).
# Here every certificate carries extensions, so it is v3.
set -euo pipefail
DIR="${1:-./certs}"
mkdir -p "$DIR" && cd "$DIR"

openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -new -x509 -days 365 -key ca.key -out ca.pem -subj "/CN=SplitNut dev CA"

openssl genrsa -out server.key 4096 2>/dev/null
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem \
  -extfile <(printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth") 2>/dev/null

openssl genrsa -out client.key 4096 2>/dev/null
openssl req -new -key client.key -out client.csr -subj "/CN=cdk-mintd"
openssl x509 -req -days 365 -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem \
  -extfile <(printf "extendedKeyUsage=clientAuth") 2>/dev/null

rm -f server.csr client.csr
chmod 600 ./*.key
echo "certs written to $(pwd)"
