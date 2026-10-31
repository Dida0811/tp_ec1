import os, struct
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"CFR1"
T, M, P = 3, 64 * 1024, 4      # temps, mémoire (Kio), parallélisme
ENTETE = 44                    # 4 (CFR1) + 12 (t,m,p) + 16 (sel) + 12 (nonce)

def cle_maitresse(mot_de_passe: str, sel: bytes, t=T, m=M, p=P) -> bytes:
    """Argon2id -> 32 octets."""
    return hash_secret_raw(mot_de_passe.encode(), sel, time_cost=t,
                           memory_cost=m, parallelism=p, hash_len=32,
                           type=Type.ID)

def sous_cle(maitresse: bytes, usage: bytes) -> bytes:
    """HKDF-SHA256, info = b"coffre-v1|" + usage -> 32 octets."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"coffre-v1|" + usage).derive(maitresse)

def chiffrer(mot_de_passe, nom, donnees, t=T, m=M, p=P) -> bytes:
    sel, nonce = os.urandom(16), os.urandom(12)          # neufs à chaque appel
    entete = MAGIC + struct.pack(">III", t, m, p) + sel + nonce   # 44 octets
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    # données associées = en-tête complet + nom du fichier
    return entete + AESGCM(cle).encrypt(nonce, donnees, entete + nom.encode())

def dechiffrer(mot_de_passe, nom, blob) -> bytes:
    if len(blob) < ENTETE + 16 or blob[:4] != MAGIC:
        raise ValueError("Format inconnu")
    entete = blob[:ENTETE]
    t, m, p = struct.unpack(">III", entete[4:16])         # relire les paramètres
    sel, nonce = entete[16:32], entete[32:44]
    cle = sous_cle(cle_maitresse(mot_de_passe, sel, t, m, p), b"chiffrement")
    return AESGCM(cle).decrypt(nonce, blob[ENTETE:], entete + nom.encode())

def rechiffrer(ancien_mdp, nouveau_mdp, nom, blob, t=T, m=M, p=P) -> bytes:
    """Change le mot de passe (et passe aux paramètres courants t, m, p)."""
    return chiffrer(nouveau_mdp, nom, dechiffrer(ancien_mdp, nom, blob), t, m, p)
