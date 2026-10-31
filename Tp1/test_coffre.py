import pytest
from cryptography.exceptions import InvalidTag
import coffre

FAIBLE = dict(t=1, m=1024, p=1)       # rapide, réservé aux tests
D = b"donnees secretes"

def test_aller_retour():
    """Correction : on retrouve exactement les données."""
    b = coffre.chiffrer("mdp", "a.txt", D, **FAIBLE)
    assert coffre.dechiffrer("mdp", "a.txt", b) == D

def test_probabiliste():
    """Deux chiffrements du même fichier sont différents (sel et nonce neufs)."""
    b1 = coffre.chiffrer("mdp", "a.txt", D, **FAIBLE)
    b2 = coffre.chiffrer("mdp", "a.txt", D, **FAIBLE)
    assert b1 != b2

def test_mauvais_mdp():
    """Un mauvais mot de passe est rejeté."""
    b = coffre.chiffrer("mdp", "a.txt", D, **FAIBLE)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("autre", "a.txt", b)

def test_octet_modifie():
    """Intégrité : un octet du chiffré modifié est détecté."""
    b = bytearray(coffre.chiffrer("mdp", "a.txt", D, **FAIBLE))
    b[50] ^= 1                         # un octet dans la zone chiffrée
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mdp", "a.txt", bytes(b))

def test_entete_modifie():
    """Un octet de l'en-tête (ici le nonce) modifié est détecté."""
    b = bytearray(coffre.chiffrer("mdp", "a.txt", D, **FAIBLE))
    b[40] ^= 1
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mdp", "a.txt", bytes(b))

def test_nom_echange():
    """Liaison au contexte : même fichier présenté sous un autre nom."""
    b = coffre.chiffrer("mdp", "a.txt", D, **FAIBLE)
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("mdp", "b.txt", b)

def test_format_inconnu():
    """Un identifiant de format inconnu est refusé."""
    with pytest.raises(ValueError):
        coffre.dechiffrer("mdp", "a.txt", b"XXXX" + b"\0" * 100)

def test_rechiffrement():
    b = coffre.chiffrer("v1", "a.txt", D, **FAIBLE)
    n = coffre.rechiffrer("v1", "v2", "a.txt", b, **FAIBLE)
    assert coffre.dechiffrer("v2", "a.txt", n) == D
    with pytest.raises(InvalidTag):
        coffre.dechiffrer("v1", "a.txt", n)       # l'ancien mot de passe ne marche plus

def test_ancien_fichier_lisible_apres_durcissement():
    """Un fichier créé avec de faibles paramètres reste lisible : ils sont dans l'en-tête."""
    ancien = coffre.chiffrer("mdp", "a.txt", D, t=1, m=1024, p=1)
    nouveau = coffre.chiffrer("mdp", "a.txt", D, t=2, m=2048, p=1)
    assert coffre.dechiffrer("mdp", "a.txt", ancien) == D
    assert coffre.dechiffrer("mdp", "a.txt", nouveau) == D
