"""Lecture des fichiers de preuve (TXT) et des fichiers d'exécution (JSON)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

RE_DEBUT = re.compile(r"^===== LSAF-BLOC DEBUT id=(?P<id>\S+) =====$")
RE_FIN = re.compile(r"^===== LSAF-BLOC FIN id=(?P<id>\S+) code=(?P<code>\S+) statut=(?P<statut>\S+) duree_ms=(?P<duree>\d+) =====$")
RE_ENTETE = re.compile(r"^# (?P<cle>[a-z_]+)\s*: ?(?P<valeur>.*)$")

# Nom : <CONTROLE>_<HOTE>_<AAAAMMJJ>_<HHMMSS>.txt  (et .json, .lynis.txt pour C17)
RE_NOM_PREUVE = re.compile(
    r"^(?P<controle>C\d{2}(?:-\d{2})?)_(?P<hote>[A-Za-z0-9-]+)_(?P<date>\d{8})_(?P<heure>\d{6})(?:-\d+)?"
    r"(?P<extension>\.txt|\.json|\.lynis\.txt)$")

# Titres de section produits par les commandes du collecteur
RE_SECTION = re.compile(r"^(?:=====\s*(?P<a>.+?)\s*=====|###\s*(?P<b>.+?)|-----\s*(?P<d>[^-].*?)\s*-----|---\s*(?P<c>[^-].*?)\s*---)\s*$")


@dataclass
class Bloc:
    id: str
    titre: str = ""
    sortie: str = ""
    code: Optional[int] = None
    statut: str = "inconnu"
    complet: bool = False

    @property
    def execute(self) -> bool:
        """Vrai si les commandes ont été exécutées (quel que soit le code retour)."""
        return self.statut in ("ok", "code_non_nul")

    def sections(self) -> dict:
        """Découpe la sortie selon les titres « ===== X ===== », « ### X », « --- X --- »."""
        return decouper_sections(self.sortie)


def decouper_sections(texte: str) -> dict:
    sections: dict = {}
    courante = "_debut"
    sections[courante] = []
    for ligne in texte.splitlines():
        m = RE_SECTION.match(ligne.strip())
        if m and not set(ligne.strip()) <= {"="}:
            titre = next(g for g in m.groups() if g)
            courante = titre.strip()
            # titres répétés (ex. boucles) : on concatène
            sections.setdefault(courante, [])
            continue
        sections.setdefault(courante, []).append(ligne)
    return {k: "\n".join(v).strip("\n") for k, v in sections.items()}


@dataclass
class FichierPreuve:
    chemin: Path
    entete: dict = field(default_factory=dict)
    blocs: dict = field(default_factory=dict)
    tronque: bool = False

    def bloc(self, id_bloc: str) -> Optional[Bloc]:
        return self.blocs.get(id_bloc)

    def sortie(self, id_bloc: str) -> str:
        b = self.blocs.get(id_bloc)
        return b.sortie if b and b.execute else ""

    def execute(self, id_bloc: str) -> bool:
        b = self.blocs.get(id_bloc)
        return bool(b and b.execute)


def lire_texte_preuve(texte: str, chemin: Optional[Path] = None) -> FichierPreuve:
    preuve = FichierPreuve(chemin=chemin or Path("<mémoire>"))
    courant: Optional[Bloc] = None
    lignes: list = []
    for brute in texte.splitlines():
        if courant is None:
            m = RE_DEBUT.match(brute)
            if m:
                courant = Bloc(id=m.group("id"))
                lignes = []
                continue
            e = RE_ENTETE.match(brute)
            if e and not preuve.blocs:
                preuve.entete[e.group("cle")] = e.group("valeur").strip()
            continue
        idx = brute.find("===== LSAF-BLOC FIN id=")
        if idx > 0:  # marqueur collé à une sortie sans retour à la ligne
            lignes.append(brute[:idx])
            brute = brute[idx:]
        m = RE_FIN.match(brute)
        if m and m.group("id") == courant.id:
            code = m.group("code")
            courant.code = int(code) if code.lstrip("-").isdigit() else None
            courant.statut = m.group("statut")
            courant.complet = True
            courant.sortie = "\n".join(lignes).strip("\n")
            preuve.blocs[courant.id] = courant
            courant = None
            continue
        if brute.startswith("# titre    : ") and not lignes:
            courant.titre = brute[len("# titre    : "):]
            continue
        if brute.startswith("# LSAF : bloc non exécuté") or brute.startswith("# commande : "):
            continue
        lignes.append(brute)
    if courant is not None:
        courant.sortie = "\n".join(lignes)
        courant.statut = "interrompu"
        preuve.blocs[courant.id] = courant
        preuve.tronque = True
    return preuve


def lire_preuve(chemin: Path) -> FichierPreuve:
    return lire_texte_preuve(chemin.read_text(encoding="utf-8", errors="replace"), chemin)


def sha256_fichier(chemin: Path) -> str:
    h = hashlib.sha256()
    with chemin.open("rb") as f:
        for morceau in iter(lambda: f.read(65536), b""):
            h.update(morceau)
    return h.hexdigest()


def lire_json(chemin: Path) -> tuple[Optional[dict], Optional[str]]:
    """Retourne (données, erreur)."""
    try:
        return json.loads(chemin.read_text(encoding="utf-8")), None
    except FileNotFoundError:
        return None, f"fichier absent : {chemin.name}"
    except json.JSONDecodeError as exc:
        return None, f"JSON invalide dans {chemin.name} : {exc.msg} (ligne {exc.lineno})"
    except OSError as exc:
        return None, f"lecture impossible de {chemin.name} : {exc}"
