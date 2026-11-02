#!/usr/bin/env python3
"""Vérificateur à lancer avant toute publication du dépôt LSAF.

    python3 outils/verifier_publication.py .
    python3 outils/verifier_publication.py . --liste-interdite ~/lsaf-termes-interdits.txt

La liste interdite est un fichier texte LOCAL, jamais publié, avec un terme par
ligne : noms réels de serveurs, de comptes, d'organisation, de domaines internes,
de collaborateurs, noms de fichiers de preuve réels… Chaque occurrence (sans
tenir compte de la casse) est signalée.

Contrôles génériques :
  * présence de preuves, classeurs, rapports ou PDF hors du dossier exemples/ ;
  * adresses IPv4 hors des plages réservées à la documentation (RFC 5737) ;
  * adresses électroniques hors des domaines d'exemple ;
  * clés privées et mots de passe apparents ;
  * fichiers d'exemple sans la mention « SYNTHETIQUE ».

Code retour : 0 = rien trouvé, 1 = éléments à examiner. Ce contrôle ne prouve pas
l'absence de données confidentielles : une relecture humaine reste nécessaire.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
import unicodedata
from pathlib import Path

DOSSIERS_IGNORES = {".git", "__pycache__", ".pytest_cache", "venv", ".venv", "build", "dist", "lsaf.egg-info"}
SUFFIXES_TEXTE = {".py", ".sh", ".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".csv", ""}
SUFFIXES_INTERDITS = {".xlsx", ".xlsm", ".xls", ".docx", ".doc", ".pdf", ".pptx", ".odt", ".ods", ".dat"}
RE_PREUVE = re.compile(r"^C\d{2}(-\d{2})?_[A-Za-z0-9._-]+_\d{8}_\d{6}")
RE_IPV4 = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.]|\.\d)")
RE_COURRIEL = re.compile(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
RE_SECRET = re.compile(r"BEGIN (RSA |EC |OPENSSH |DSA |)PRIVATE KEY|aws_secret_access_key|"
                       r"(?i:(password|mot_de_passe|passwd)\s*[=:]\s*['\"][^'\"]{4,})")

RESEAUX_AUTORISES = [ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",   # RFC 5737 : documentation
    "127.0.0.0/8", "0.0.0.0/8",                             # boucle locale, « toutes interfaces » (et numéros de version 0.x.y.z)
    "255.255.255.0/24",                                     # masques
)]
# Résolveurs DNS publics utilisés dans les exemples
IP_AUTORISEES = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}
DOMAINES_COURRIEL_AUTORISES = {"example.org", "example.com", "example.net", "noreply.example"}
DOSSIER_EXEMPLES = "exemples"


def sans_accents(texte: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFD", texte) if unicodedata.category(c) != "Mn")


def fichiers(racine: Path):
    for p in sorted(racine.rglob("*")):
        if any(partie in DOSSIERS_IGNORES for partie in p.relative_to(racine).parts):
            continue
        if p.is_file():
            yield p


def verifier(racine: Path, interdits: list[str]) -> list[str]:
    constats = []
    for p in fichiers(racine):
        rel = p.relative_to(racine).as_posix()
        dans_exemples = rel.startswith(DOSSIER_EXEMPLES + "/")
        if p.suffix.lower() in SUFFIXES_INTERDITS:
            constats.append(f"{rel} : document produit ou artefact d'audit binaire — ne pas publier")
        if RE_PREUVE.match(p.name) and not dans_exemples:
            constats.append(f"{rel} : ressemble à un fichier de preuve réel")
        if p.suffix.lower() not in SUFFIXES_TEXTE:
            continue
        try:
            texte = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        if dans_exemples and p.suffix in (".txt", ".json", ".yaml") and "SYNTHETIQUE" not in sans_accents(texte).upper():
            constats.append(f"{rel} : fichier d'exemple sans la mention « SYNTHETIQUE »")
        for n, ligne in enumerate(texte.splitlines(), 1):
            for m in RE_IPV4.finditer(ligne):
                ip = m.group(1)
                try:
                    adresse = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if ip in IP_AUTORISEES or any(adresse in r for r in RESEAUX_AUTORISES):
                    continue
                constats.append(f"{rel}:{n} : adresse IPv4 hors des plages de documentation : {ip}")
            for m in RE_COURRIEL.finditer(ligne):
                if m.group(1).lower() not in DOMAINES_COURRIEL_AUTORISES:
                    constats.append(f"{rel}:{n} : adresse électronique : {m.group(0)}")
            if RE_SECRET.search(ligne) and "RE_SECRET" not in ligne:
                constats.append(f"{rel}:{n} : secret possible")
            bas = ligne.lower()
            for terme in interdits:
                if terme and terme.lower() in bas:
                    constats.append(f"{rel}:{n} : terme de la liste interdite trouvé : {terme!r}")
    return constats


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("racine", nargs="?", default=".")
    ap.add_argument("--liste-interdite", help="fichier local de termes confidentiels (un par ligne, jamais publié)")
    args = ap.parse_args(argv)
    interdits = []
    if args.liste_interdite:
        interdits = [l.strip() for l in Path(args.liste_interdite).read_text(encoding="utf-8").splitlines()
                     if l.strip() and not l.lstrip().startswith("#")]
    constats = verifier(Path(args.racine), interdits)
    for c in constats:
        print(c)
    if constats:
        print(f"\n{len(constats)} élément(s) à examiner avant publication.")
    else:
        print("Aucun élément trouvé par le contrôle automatique (une relecture humaine reste nécessaire).")
    return 1 if constats else 0


if __name__ == "__main__":
    sys.exit(main())
