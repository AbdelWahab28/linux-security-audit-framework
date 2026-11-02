"""Nommage automatique des livrables, sans jamais écraser un fichier existant.

  LSAF_Audit_<LIBELLÉ>_<AAAAMMJJ>.xlsx      (classeur)
  LSAF_Rapport_<LIBELLÉ>_<AAAAMMJJ>.docx    (rapport)
  LSAF_Consolide_<LIBELLÉ>_<AAAAMMJJ>.json  (données consolidées)

LIBELLÉ : nom du serveur s'il n'y en a qu'un, sinon le nom de campagne
(--campagne) ou « MULTI-<n>SRV ». Si le fichier existe déjà, un suffixe _2, _3…
est ajouté.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional


def normaliser(libelle: str) -> str:
    propre = re.sub(r"[^A-Za-z0-9._-]+", "-", libelle or "").strip("-.")
    return propre[:60] or "SANS-LIBELLE"


def libelle_livrable(serveurs: list, campagne: Optional[str] = None) -> str:
    if campagne:
        return normaliser(campagne)
    if len(serveurs) == 1:
        return normaliser(serveurs[0])
    return f"MULTI-{len(serveurs)}SRV"


def chemin_libre(dossier: Path, prefixe: str, libelle: str, extension: str, date: Optional[datetime] = None) -> Path:
    date = date or datetime.now()
    base = f"{prefixe}_{normaliser(libelle)}_{date.strftime('%Y%m%d')}"
    chemin = Path(dossier) / f"{base}{extension}"
    n = 2
    while chemin.exists():
        chemin = Path(dossier) / f"{base}_{n}{extension}"
        n += 1
    return chemin
