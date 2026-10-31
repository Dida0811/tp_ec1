#!/usr/bin/env python3
import sys, pathlib, datetime
from cryptography import x509

def main(dossier):
    code = 0
    maintenant = datetime.datetime.now(datetime.timezone.utc)
    for f in sorted(pathlib.Path(dossier).glob("*.crt")):
        for c in x509.load_pem_x509_certificates(f.read_bytes()):
            jours = (c.not_valid_after_utc - maintenant).days
            niveau, rc = ("OK", 0) if jours >= 30 else \
                         ("ALERTE", 1) if jours >= 7 else ("CRITIQUE", 2)
            print(f"{niveau:9} {jours:5} j  {f.name}  {c.subject.rfc4514_string()}")
            code = max(code, rc)
    return code

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "."))
