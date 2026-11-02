"""Lecture du fichier de configuration et du fichier d'inventaire (YAML).

Les deux fichiers sont facultatifs et restent sur le poste de l'auditeur :
ils sont exclus du dépôt par le .gitignore (seuls les fichiers « .exemple.yaml »
sont publiés).

Configuration (lsaf.yaml) — tout est facultatif :
  organisation, intitule, auteur, version, confidentialite (Public | Interne |
  Confidentiel | Secret), campagne, logo, image_pied_de_page,
  historique: [{version, date, auteur, modification}],
  textes: {contexte, appreciation, conclusion, pilotage, politique_interne},
  hors_perimetre: [texte, …],
  referentiels: [{nom, version, utilisation}],
  echelle_criticite: {Critique: {definition, traitement}, …}

Inventaire (inventaire.yaml) — une entrée par nom de serveur tel que détecté
par le collecteur :
  serveurs:
    SRV-EXEMPLE-01:
      role: …, environnement: Production, criticite: Haute, domaine: Hors domaine,
      responsable: …, date_prevue: 2026-11-02, commentaire: …
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

CONFIDENTIALITES = ["Public", "Interne", "Confidentiel", "Secret"]
CHAMPS_INVENTAIRE = {"nom", "adresse_ip", "role", "environnement", "criticite", "domaine", "responsable", "date_prevue",
                     "commentaire"}


class ErreurConfiguration(Exception):
    pass


def _charger_yaml(chemin: Path) -> dict:
    try:
        import yaml
    except ImportError as e:  # pragma: no cover - dépendance déclarée
        raise ErreurConfiguration("le module PyYAML est nécessaire pour lire les fichiers YAML") from e
    try:
        contenu = yaml.safe_load(Path(chemin).read_text(encoding="utf-8")) or {}
    except FileNotFoundError as e:
        raise ErreurConfiguration(f"fichier introuvable : {chemin}") from e
    except yaml.YAMLError as e:
        raise ErreurConfiguration(f"YAML invalide dans {chemin} : {e}") from e
    if not isinstance(contenu, dict):
        raise ErreurConfiguration(f"{chemin} : le contenu doit être un dictionnaire YAML")
    return contenu


def charger_configuration(chemin: Optional[Path]) -> dict:
    if not chemin:
        return {}
    cfg = _charger_yaml(Path(chemin))
    conf = cfg.get("confidentialite")
    if conf and conf not in CONFIDENTIALITES:
        raise ErreurConfiguration(f"confidentialite doit valoir {', '.join(CONFIDENTIALITES)} (reçu : {conf})")
    base = Path(chemin).parent
    for cle in ("logo", "image_pied_de_page"):
        if cfg.get(cle):
            p = Path(cfg[cle])
            if not p.is_absolute():
                p = base / p
            if not p.is_file():
                raise ErreurConfiguration(f"{cle} : fichier introuvable ({p})")
            cfg[cle] = str(p)
    return cfg


def charger_inventaire(chemin: Optional[Path]) -> dict:
    if not chemin:
        return {}
    contenu = _charger_yaml(Path(chemin))
    serveurs = contenu.get("serveurs") or {}
    if not isinstance(serveurs, dict):
        raise ErreurConfiguration("inventaire : la clé « serveurs » doit être un dictionnaire nom → informations")
    resultat = {}
    for nom, infos in serveurs.items():
        infos = infos or {}
        inconnus = set(infos) - CHAMPS_INVENTAIRE
        if inconnus:
            raise ErreurConfiguration(f"inventaire, serveur {nom} : champ(s) inconnu(s) {', '.join(sorted(inconnus))}")
        resultat[str(nom)] = {k: (str(v) if v is not None else None) for k, v in infos.items()}
    return resultat
