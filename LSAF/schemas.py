"""Validation des fichiers LSAF par schéma JSON (dépendance facultative : jsonschema)."""

from __future__ import annotations

import json
from functools import lru_cache
from importlib import resources

try:  # la validation est ignorée si jsonschema n'est pas installé
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None


@lru_cache(maxsize=None)
def _schema(nom: str) -> dict:
    return json.loads(resources.files("lsaf.donnees").joinpath(f"{nom}.schema.json").read_text(encoding="utf-8"))


def disponible() -> bool:
    return jsonschema is not None


def valider(objet: dict, nom: str) -> list[str]:
    """Liste des erreurs de validation (vide si valide ou si jsonschema est absent)."""
    if jsonschema is None:
        return []
    v = jsonschema.Draft202012Validator(_schema(nom))
    return [f"{'/'.join(str(p) for p in e.path) or '<racine>'} : {e.message}" for e in v.iter_errors(objet)]
