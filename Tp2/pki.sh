#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

# Repartir de zéro (racine.cnf et inter.cnf doivent exister)
rm -rf racine inter
mkdir -p racine/{newcerts,crl} inter/{newcerts,crl}
for d in racine inter; do touch $d/index.txt; echo 1000 > $d/serial; echo 1000 > $d/crlnumber; done

# --- AC racine ---
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out racine/racine.key
chmod 600 racine/racine.key
openssl req -x509 -new -key racine/racine.key -sha384 -days 3650 \
  -subj "/C=BF/O=Universite TP/CN=Racine TP" \
  -addext "basicConstraints=critical,CA:TRUE,pathlen:1" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" -out racine/racine.crt

# --- AC intermédiaire ---
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out inter/inter.key
chmod 600 inter/inter.key
openssl req -new -key inter/inter.key -subj "/C=BF/O=Universite TP/CN=Inter TP" -out inter/inter.csr
openssl ca -batch -notext -config racine.cnf -extensions ext_inter -days 1825 \
  -in inter/inter.csr -out inter/inter.crt

# --- Serveur ---
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out serveur.key
openssl req -new -key serveur.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out serveur.csr
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 -in serveur.csr -out serveur.crt

# --- Clients ---
for u in alice bob; do
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out $u.key
  openssl req -new -key $u.key -subj "/CN=$u@tp.local" \
    -addext "subjectAltName=email:$u@tp.local" -out $u.csr
  openssl ca -batch -notext -config inter.cnf -extensions ext_client -days 90 -in $u.csr -out $u.crt
done

openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt serveur.crt alice.crt bob.crt
echo "PKI construite avec succès"
