#!/bin/sh
# The gateway's own HTTPS certificate, made on the server the first time the system starts
# (step 19a, ADR-54). The gateway speaks only HTTPS, behind the reverse proxy too; this certificate
# is for that internal connection only. Visitors see Caddy's certificate from Let's Encrypt.
#
# Runs in the gateway's image as the one-off "gateway-certificate" service (deploy/compose.yaml):
#   /certs/gateway.p12       the private key and certificate, in a keystore locked with SSL_KEYSTORE_PASSWORD
#                            (volume shared with the gateway only)
#   /gateway-ca/gateway.crt  the certificate alone, no key (volume shared with Caddy, which trusts exactly
#                            this certificate for the name "gateway", and nothing else)
#
# Safe to run again: an existing keystore is kept. To replace it, remove both volumes.
set -eu

if [ -s /certs/gateway.p12 ] && [ -s /gateway-ca/gateway.crt ]; then
    echo "The gateway certificate already exists."
    exit 0
fi
: "${SSL_KEYSTORE_PASSWORD:?SSL_KEYSTORE_PASSWORD must be set}"

rm -f /certs/gateway.p12 /gateway-ca/gateway.crt
# keytool reads the password from an environment variable (":env"), so it never appears in the
# process list or in any log.
keytool -genkeypair -alias gateway -keyalg EC -groupname secp256r1 -sigalg SHA256withECDSA \
    -dname "CN=gateway" -ext "SAN=dns:gateway" -ext "KU=digitalSignature" -ext "EKU=serverAuth" \
    -ext "BC=ca:false" -validity 3650 \
    -storetype PKCS12 -keystore /certs/gateway.p12 -storepass:env SSL_KEYSTORE_PASSWORD
keytool -exportcert -rfc -alias gateway -keystore /certs/gateway.p12 -storepass:env SSL_KEYSTORE_PASSWORD \
    -file /gateway-ca/gateway.crt
chmod 600 /certs/gateway.p12
chmod 644 /gateway-ca/gateway.crt
echo "Made the gateway certificate."
