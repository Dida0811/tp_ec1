#!/usr/bin/env bash
set -euo pipefail
cd /home/dida/tp-pki          # chemin ABSOLU (cron ne connaît pas ~ de la même façon)
DEST=/etc/nginx/tls
STAMP=$(date +%Y%m%d%H%M%S)

# Ne renouveler que si expiration dans moins de 30 jours (ou option --force)
if [ "${1:-}" != "--force" ] && openssl x509 -in serveur.crt -noout -checkend $((30*86400)); then
  echo "Certificat valable encore plus de 30 jours : rien à faire"; exit 0
fi

# 5. Archive de l'ancien certificat (retour arrière)
mkdir -p archive/$STAMP
cp serveur.key serveur.crt serveur_chaine.crt archive/$STAMP/

rollback() {
  echo "Echec : retour arrière" >&2
  sudo install -m 600 archive/$STAMP/serveur.key $DEST/serveur.key
  sudo install -m 644 archive/$STAMP/serveur_chaine.crt $DEST/
  sudo nginx -t && sudo systemctl reload nginx
  exit 1
}

# 1. Nouvelle clé + nouvelle demande
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out nouveau.key
openssl req -new -key nouveau.key -subj "/CN=www.tp.local" \
  -addext "subjectAltName=DNS:www.tp.local,DNS:tp.local" -out nouveau.csr

# 2. Signature par l'intermédiaire
openssl ca -batch -notext -config inter.cnf -extensions ext_serveur -days 90 \
  -in nouveau.csr -out nouveau.crt

# 3. Vérification AVANT déploiement
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local nouveau.crt
cat nouveau.crt inter/inter.crt > nouveau_chaine.crt

# 4. Installation, test, rechargement
mv nouveau.key serveur.key; mv nouveau.crt serveur.crt; mv nouveau_chaine.crt serveur_chaine.crt
sudo install -m 600 serveur.key $DEST/serveur.key
sudo install -m 644 serveur_chaine.crt $DEST/
sudo nginx -t || rollback
sudo systemctl reload nginx || rollback
echo "Renouvellement terminé : $(openssl x509 -in serveur.crt -noout -enddate)"
