"""Petites fonctions de lecture communes aux extracteurs."""

from __future__ import annotations

import ipaddress
import re


def lignes(texte: str) -> list[str]:
    return [l for l in (texte or "").splitlines() if l.strip()]


def cle_valeur(texte: str, sep: str = "=") -> dict:
    sortie = {}
    for l in (texte or "").splitlines():
        if sep in l and not l.lstrip().startswith("#"):
            k, _, v = l.partition(sep)
            sortie[k.strip()] = v.strip().strip('"')
    return sortie


def section(sections: dict, *candidats: str) -> str:
    """Section dont le titre est égal à (en priorité) ou contient l'un des candidats."""
    for c in candidats:
        for titre, contenu in sections.items():
            if c.lower() == titre.lower():
                return contenu
    for c in candidats:
        for titre, contenu in sections.items():
            if c.lower() in titre.lower():
                return contenu
    return ""


def classer_adresse(adresse: str) -> str:
    """« toutes interfaces », « boucle locale », « lien local » ou « adresse spécifique »."""
    a = adresse.strip("[]").split("%")[0]
    if a in ("*", "0.0.0.0", "::", ""):
        return "toutes interfaces"
    try:
        ip = ipaddress.ip_address(a)
    except ValueError:
        return "adresse spécifique"
    if ip.is_loopback:
        return "boucle locale"
    if ip.is_link_local:
        return "lien local"
    return "adresse spécifique"


def cle_version(v: str) -> tuple:
    return tuple(int(p) for p in re.split(r"[^0-9]+", v) if p.isdigit())


def lire_stat_access(texte: str) -> list[dict]:
    """Lit la sortie de « stat FICHIER » (format long) : fichier, droits, propriétaire."""
    resultats, courant = [], None
    for l in (texte or "").splitlines():
        m = re.match(r"^\s*File:\s*(.+)$", l)
        if m:
            courant = {"fichier": m.group(1).strip().strip("'‘’")}
            resultats.append(courant)
            continue
        m = re.match(r"^\s*Access:\s*\((\d{3,4})/(\S+)\)\s+Uid:\s*\(\s*\d+/\s*(\S+?)\)\s+Gid:\s*\(\s*\d+/\s*(\S+?)\)", l)
        if m and courant is not None:
            courant.update({"droits": m.group(1), "symbolique": m.group(2), "proprietaire": m.group(3), "groupe": m.group(4)})
    return [r for r in resultats if "droits" in r]
