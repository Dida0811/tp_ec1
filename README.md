# EC1 – Ingénierie de la cryptographie : travaux pratiques

Dépôt des trois travaux pratiques du module **EC1 – Ingénierie de la cryptographie** (année universitaire 2026–2027), encadrés par Dr. Zakaria Sawadogo.

Le fil conducteur : **ne réimplémenter aucune primitive**, mais assembler correctement des briques éprouvées, les tester et les exploiter.

| TP | Thème | Outils |
|---|---|---|
| [TP 1](tp1-coffre/) | Chiffrement authentifié et dérivation de clés : un mini-coffre de fichiers | Python, `cryptography`, `argon2-cffi`, `pytest` |
| [TP 2](tp2-pki/) | Infrastructure de gestion de clés : AC racine, AC intermédiaire, révocation | OpenSSL 3 |
| [TP 3](tp3-tls/) | Serveur TLS avec authentification mutuelle, supervision et renouvellement | nginx, OpenSSL, tshark / Wireshark, nmap, Python |

> **Avertissement.** Ce dépôt est un travail pédagogique. Toutes les manipulations utilisent des noms de laboratoire (`*.tp.local`) sur une machine personnelle.

---

## Structure du dépôt

```
.
├── README.md
├
├── Tp1/
│   ├── coffre.py              # module : dérivation, chiffrement, déchiffrement, rechiffrement
│   ├── test_coffre.py         # 9 tests pytest
│   ├── 
│   └── compte_rendu.docx
├── Tp2/
│   ├── racine.cnf             # configuration de l'AC racine
│   ├── inter.cnf              # configuration de l'AC intermédiaire
│   ├── pki.sh                 # construit toute la PKI
│   ├── certs/                 # certificats publics uniquement (.crt)
│   ├
│   └── compte_rendu.docx
└── Tp3/
    ├── tp.conf                # configuration nginx (TLS 1.2/1.3 + mTLS + CRL)
    ├── surveiller.py          # supervision des expirations
    ├── renouveler.sh          # renouvellement automatique avec retour arrière
    ├── 
    ├── captures/              # captures d'écran (Wireshark, terminal)
    └── compte_rendu.docx
```

---

## Prérequis

- Linux (testé sous Kali Linux dans une VM VirtualBox)
- Python 3.10 ou plus récent, OpenSSL 3
- Pour le TP 3 : `nginx`, `nmap`, `tshark` (ou Wireshark), `curl`

```bash
python3 -m venv ~/ec1 && source ~/ec1/bin/activate
pip install cryptography argon2-cffi pytest
openssl version        # doit afficher OpenSSL 3.x
```

---

## TP 1 – Mini-coffre de fichiers

Chiffre un fichier avec un mot de passe : Argon2id pour la clé maîtresse, HKDF-SHA256 pour les sous-clés, AES-256-GCM pour le chiffrement authentifié.

**Format du fichier chiffré**

| Champ | Taille | Rôle |
|---|---|---|
| `CFR1` | 4 octets | Identifiant et version du format |
| Paramètres Argon2id (t, m, p) | 12 octets | Redériver la clé, durcir plus tard |
| Sel | 16 octets | Unique par fichier |
| Nonce | 12 octets | Unique par chiffrement |
| Chiffré + étiquette | variable | AES-GCM |

L'en-tête de 44 octets et le nom du fichier sont les **données associées** : authentifiés sans être chiffrés.

**Utilisation**

```python
import coffre

blob = coffre.chiffrer("mot de passe", "notes.txt", b"contenu")
coffre.dechiffrer("mot de passe", "notes.txt", blob)       # b'contenu'
coffre.rechiffrer("ancien", "nouveau", "notes.txt", blob)  # change le mot de passe
```

**Tests**

```bash
cd tp1-coffre && pytest -v
```

Les tests vérifient : correction, chiffrement probabiliste, rejet d'un mauvais mot de passe, détection d'un octet modifié (chiffré ou en-tête), liaison au nom du fichier, refus d'un format inconnu, rechiffrement et lecture d'anciens fichiers après durcissement des paramètres.

**Paramètres Argon2id retenus** : `t=4, m=256 Mio, p=4`, soit environ 0,5 s sur la machine de test.

---

## TP 2 – Infrastructure de gestion de clés (PKI)

| Élément | Clé et durée | Extensions essentielles |
|---|---|---|
| AC racine | P-384, 10 ans, hors ligne | `CA:TRUE, pathlen:1` |
| AC intermédiaire | P-256, 5 ans | `CA:TRUE, pathlen:0`, contraintes de nom limitées à `tp.local` |
| Serveur `www.tp.local` | P-256, 90 jours | `CA:FALSE`, `serverAuth`, SAN |
| Clients `alice@tp.local`, `bob@tp.local` | P-256, 90 jours | `CA:FALSE`, `clientAuth` |

**Construire la PKI** (le script efface `racine/` et `inter/` : à lancer dans un dossier de travail dédié)

```bash
mkdir ~/pki-essai && cp tp2-pki/{racine.cnf,inter.cnf,pki.sh} ~/pki-essai/
cd ~/pki-essai && ./pki.sh
```

**Valider une chaîne**

```bash
openssl verify -CAfile racine/racine.crt -untrusted inter/inter.crt \
  -verify_hostname www.tp.local serveur.crt            # OK
```

**Révoquer un certificat et publier les CRL**

```bash
openssl ca -config inter.cnf -revoke alice.crt -crl_reason keyCompromise
openssl ca -config inter.cnf  -gencrl -out inter/crl/inter.crl
openssl ca -config racine.cnf -gencrl -out racine/crl/racine.crl
cat inter/crl/inter.crl racine/crl/racine.crl > crls.pem
openssl verify -crl_check_all -CRLfile crls.pem -CAfile racine/racine.crt \
  -untrusted inter/inter.crt alice.crt                 # certificate revoked
```

Un certificat émis pour `www.example.com` est signé par l'intermédiaire mais rejeté à la validation (`permitted subtree violation`) : les contraintes de nom sont appliquées par celui qui valide, pas par l'outil de signature.

> La CRL de l'intermédiaire expire au bout de **7 jours** (`default_crl_days = 7`). Sans régénération, nginx rejette tous les clients.

---

## TP 3 – Canal TLS sécurisé et gestion des certificats

**Déploiement**

```bash
cat serveur.crt inter/inter.crt > serveur_chaine.crt     # jamais la racine
sudo install -m 600 serveur.key /etc/nginx/tls/serveur.key
sudo install -m 644 serveur_chaine.crt racine/racine.crt crls.pem /etc/nginx/tls/
sudo cp tp3-tls/tp.conf /etc/nginx/conf.d/tp.conf
echo "127.0.0.1 www.tp.local" | sudo tee -a /etc/hosts
sudo nginx -t && sudo systemctl start nginx
```

**Tests**

```bash
# Bob (valide) : 200 « Bonjour CN=bob@tp.local »
curl --cacert racine/racine.crt --cert bob_chaine.crt --key bob.key https://www.tp.local/
# Sans certificat : 400 « No required SSL certificate was sent »
curl --cacert racine/racine.crt https://www.tp.local/
# Alice (révoquée) : 400, et « 23:certificate revoked » dans error.log
curl --cacert racine/racine.crt --cert alice_chaine.crt --key alice.key https://www.tp.local/
```

**Supervision des expirations**

```bash
python3 tp3-tls/surveiller.py dossier_de_certificats ; echo $?
```

Trois niveaux : `OK` (30 jours ou plus), `ALERTE` (moins de 30 jours), `CRITIQUE` (moins de 7 jours). Code de sortie 0, 1 ou 2, utilisable par un outil de supervision.

**Renouvellement**

```bash
./tp3-tls/renouveler.sh --force
```

Génère une nouvelle clé et une CSR, la fait signer, vérifie la chaîne **avant** déploiement, installe les fichiers, teste la configuration, recharge nginx sans coupure et archive l'ancien certificat (retour arrière en cas d'échec). Sans `--force`, il ne renouvelle que si le certificat expire dans moins de 30 jours. Planification quotidienne :

```
0 3 * * * /chemin/absolu/vers/renouveler.sh >> /var/log/renouveler.log 2>&1
```

> Adaptez la ligne `cd /home/dida/tp-pki` de `renouveler.sh` à votre chemin.

**Observation de la poignée de main.** En TLS 1.3, le certificat du serveur est chiffré et invisible dans Wireshark sans les clés de session. Avec `SSLKEYLOGFILE`, la capture peut être déchiffrée.

---

## Sécurité du dépôt : à lire avant de pousser

**Ne jamais publier** de clé privée, de mot de passe ni de journal de clés de session.

Le fichier `.gitignore` fourni exclut les clés (`*.key`), les demandes de certificat, les captures réseau et `keys.log`. Avant chaque `git push`, vérifiez :

```bash
git ls-files | grep -E '\.key$|keys\.log|\.pcapng$'     # ne doit rien afficher
git status --short
```

Si une clé a été commitée par erreur, la supprimer du dernier commit **ne suffit pas** : elle reste dans l'historique. Considérez-la comme compromise, régénérez-la et nettoyez l'historique.

Les certificats `.crt` publiés sont des certificats de laboratoire ; ils ne sont valables pour aucune autorité réelle.

---

## Auteur

- **Nom :** _à compléter_
- **Module :** EC1 – Ingénierie de la cryptographie, année 2026–2027
- **Enseignant :** Dr. Zakaria Sawadogo

Ce dépôt est un travail pédagogique rendu dans le cadre d'un enseignement.
