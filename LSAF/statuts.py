"""Statuts d'un contrôle (qualité de la collecte et de la preuve).

Ces statuts décrivent si la preuve est exploitable, pas si le serveur est
conforme. La conformité (« État initial » : Conforme, Partiellement conforme,
Non conforme, Non vérifié) est décidée par l'auditeur dans le classeur.

Une absence de preuve n'est jamais considérée comme une réussite.
"""

from __future__ import annotations

REUSSI = "reussi"
EN_ECHEC = "en_echec"
A_VERIFIER = "a_verifier"
NON_EXECUTE = "non_execute"
PARTIEL = "partiel"
COLLECTE_IMPOSSIBLE = "collecte_impossible"
PREUVE_INSUFFISANTE = "preuve_insuffisante"

TOUS = (REUSSI, A_VERIFIER, PARTIEL, PREUVE_INSUFFISANTE, COLLECTE_IMPOSSIBLE, EN_ECHEC, NON_EXECUTE)
AVEC_PREUVE = (REUSSI, A_VERIFIER, PARTIEL, PREUVE_INSUFFISANTE)

LIBELLES = {
    REUSSI: "Réussi",
    A_VERIFIER: "À vérifier",
    PARTIEL: "Partiellement exécuté",
    PREUVE_INSUFFISANTE: "Preuve insuffisante",
    COLLECTE_IMPOSSIBLE: "Collecte impossible",
    EN_ECHEC: "En échec",
    NON_EXECUTE: "Non exécuté",
}

DEFINITIONS = {
    REUSSI: "Tous les blocs de commandes ont été exécutés, la preuve est intègre et les valeurs attendues ont été lues.",
    A_VERIFIER: "La preuve est exploitable mais contient un élément que l'auditeur doit vérifier (commande sans résultat, "
                "outil non adapté au système, empreinte non vérifiable...).",
    PARTIEL: "Au moins un bloc de commandes n'a pas été exécuté (programme absent, délai dépassé, erreur) ; "
             "les autres blocs sont exploitables.",
    PREUVE_INSUFFISANTE: "La preuve existe mais ne permet pas de conclure : fichier modifié après la collecte ou "
                         "valeurs essentielles absentes de la sortie.",
    COLLECTE_IMPOSSIBLE: "Aucun bloc essentiel n'a produit de sortie (outil absent, commande introuvable).",
    EN_ECHEC: "Le contrôle a été lancé mais s'est interrompu ou n'a pas pu être lu (preuve tronquée, erreur d'analyse).",
    NON_EXECUTE: "Le contrôle n'a pas été lancé dans cette session.",
}

DEGRADES = {"outil_absent": "programme absent", "delai_depasse": "délai dépassé", "erreur": "erreur d'exécution",
            "interrompu": "interrompu"}


def determiner_statut(statut_execution: str | None, preuve_presente: bool, tronquee: bool, erreur_analyse: bool,
                      blocs_cles_executes: bool, integrite: str, extraction_complete: bool,
                      blocs_degrades: bool, elements_a_verifier: bool) -> str:
    """Ordre de priorité : non exécuté > en échec > collecte impossible > preuve
    insuffisante > partiel > à vérifier > réussi."""
    if statut_execution in ("non_execute", "simulation") or (not preuve_presente and statut_execution is None):
        return NON_EXECUTE
    if not preuve_presente or tronquee or erreur_analyse or statut_execution == "en_echec":
        return EN_ECHEC
    if not blocs_cles_executes:
        return COLLECTE_IMPOSSIBLE
    if integrite == "modifiee" or not extraction_complete:
        return PREUVE_INSUFFISANTE
    if blocs_degrades:
        return PARTIEL
    if elements_a_verifier or integrite == "non_verifiable":
        return A_VERIFIER
    return REUSSI
