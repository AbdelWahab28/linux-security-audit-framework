"""Interface en ligne de commande « lsaf » (exécutée sur le poste de l'auditeur, jamais sur le serveur).

  lsaf etat      SESSIONS…            résumé des sessions de collecte (statut de chaque contrôle)
  lsaf valider   SESSIONS…            complétude et intégrité des preuves (code retour 1 si erreur)
  lsaf analyser  SESSIONS…            extraction des valeurs et statuts (dossier resultats/ de chaque session)
  lsaf classeur  SESSIONS… [options]  consolidation + classeur Excel (pistes C18 « À QUALIFIER »)
  lsaf rapport   CLASSEUR  [options]  rapport Word à partir du classeur qualifié + contrôle de cohérence
  lsaf verifier  CLASSEUR RAPPORT     contrôle de cohérence Excel ↔ Word
  lsaf demo      [-o DOSSIER]         démonstration complète sur des serveurs FICTIFS

Aucune commande n'envoie de données sur le réseau.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from . import statuts as S


def _ecrire(msg="", flux=None):
    print(msg, file=flux or sys.stdout)


def _sessions(chemins):
    from .session import trouver_sessions
    trouvees = trouver_sessions(chemins)
    if not trouvees:
        raise SystemExit("Erreur : aucune session LSAF trouvée dans " + ", ".join(map(str, chemins)) +
                         " (un dossier de session contient session.json et preuves/).")
    return trouvees


def cmd_etat(args) -> int:
    from .analyse import analyser_session
    from .session import charger_session
    for chemin in _sessions(args.sessions):
        s = charger_session(chemin)
        res = analyser_session(s, ecrire=False)
        _ecrire(f"\n=== {s.hote}  (session {s.id})")
        _ecrire(f"    collecte : {s.date_collecte or 'inconnue'} ; root : {'oui' if s.manifeste.get('execute_en_root') else 'non'}")
        for r in res:
            _ecrire(f"    {r.controle:<7} {S.LIBELLES[r.statut]:<20} {(r.resume or '')[:90]}")
        for a in s.anomalies:
            _ecrire(f"    [{a.niveau}] {a.code} {a.controle or ''} : {a.message}")
    return 0


def cmd_valider(args) -> int:
    from .analyse import analyser_session
    from .session import charger_session
    code = 0
    for chemin in _sessions(args.sessions):
        s = charger_session(chemin)
        res = analyser_session(s, ecrire=False)
        erreurs = s.erreurs()
        manquants = [r.controle for r in res if r.statut not in S.AVEC_PREUVE]
        _ecrire(f"\n=== {s.hote}  (session {s.id})")
        _ecrire(f"    contrôles avec preuve : {sum(1 for r in res if r.statut in S.AVEC_PREUVE)}/{len(res)}")
        for st in S.TOUS:
            n = sum(1 for r in res if r.statut == st)
            if n:
                _ecrire(f"    {S.LIBELLES[st]:<20} {n}")
        if manquants:
            _ecrire(f"    sans preuve exploitable : {', '.join(manquants)} (jamais considérés comme conformes)")
        for a in s.anomalies:
            _ecrire(f"    [{a.niveau}] {a.code} {a.controle or ''} : {a.message}")
        if erreurs:
            code = 1
            _ecrire(f"    → {len(erreurs)} erreur(s) : session à corriger ou à recollecter.")
        else:
            _ecrire("    → aucune erreur bloquante.")
    return code


def cmd_analyser(args) -> int:
    from .analyse import analyser_session
    from .session import charger_session
    for chemin in _sessions(args.sessions):
        s = charger_session(chemin)
        res = analyser_session(s, ecrire=True)
        _ecrire(f"{s.hote} : {len(res)} contrôles analysés → {s.dossier_resultats}")
    return 0


def cmd_classeur(args) -> int:
    from .classeur import generer_classeur
    from .config import charger_inventaire
    from .consolidation import consolider, ecrire_consolide
    from .nommage import chemin_libre, libelle_livrable
    from .session import charger_session
    chemins = _sessions(args.sessions)
    for c in chemins:
        s = charger_session(c)
        for a in s.erreurs():
            _ecrire(f"Attention — {s.hote} : [{a.code}] {a.message}", sys.stderr)
    inventaire = charger_inventaire(Path(args.inventaire)) if args.inventaire else {}
    donnees = consolider(chemins, inventaire, args.campagne, ecrire_resultats=True)
    inconnus = set(inventaire) - {x["libelle"] for x in donnees["serveurs"]}
    if inconnus:
        _ecrire(f"Attention — serveurs de l'inventaire sans session : {', '.join(sorted(inconnus))}", sys.stderr)
    sortie = Path(args.sortie)
    libelle = libelle_livrable([x["libelle"] for x in donnees["serveurs"]], args.campagne)
    chemin_xlsx = chemin_libre(sortie, "LSAF_Audit", libelle, ".xlsx")
    chemin_json = chemin_xlsx.with_name(chemin_xlsx.name.replace("LSAF_Audit_", "LSAF_Consolide_")).with_suffix(".json")
    ecrire_consolide(donnees, chemin_json)
    generer_classeur(donnees, chemin_xlsx)
    i = donnees["indicateurs"]
    _ecrire(f"Classeur     : {chemin_xlsx}")
    _ecrire(f"Consolidé    : {chemin_json}")
    _ecrire(f"Serveurs     : {i['serveurs']} ; lignes de contrôle avec preuve : {i['controles_avec_preuve']}/{i['controles_attendus']}")
    _ecrire(f"Pistes C18   : {i['pistes_c18']} (dont {i['pistes_transversales']} transversales) — À QUALIFIER dans la feuille ANALYSE")
    _ecrire("Étape suivante : qualifier la feuille ANALYSE (référence, risque, priorité, recommandation, action…), "
            "renseigner l'état initial dans CONTROLES_ET_PREUVES, puis lancer « lsaf rapport ».")
    return 0


def _trouver_consolide(classeur: Path, explicite):
    if explicite:
        return json.loads(Path(explicite).read_text(encoding="utf-8"))
    candidat = classeur.with_name(classeur.name.replace("LSAF_Audit_", "LSAF_Consolide_")).with_suffix(".json")
    if candidat != classeur and candidat.exists():
        return json.loads(candidat.read_text(encoding="utf-8"))
    return None


def _afficher_bilan(bilan) -> None:
    for v in bilan.verifications:
        _ecrire(f"  ✔ {v}")
    for a in bilan.alertes:
        _ecrire(f"  ! {a}")
    for e in bilan.erreurs:
        _ecrire(f"  ✘ {e}")


def cmd_rapport(args) -> int:
    from .config import charger_configuration
    from .lecture_classeur import lire_classeur
    from .nommage import chemin_libre, libelle_livrable
    from .rapport import RapportRefuse, generer_rapport
    from .verification import verifier_coherence
    chemin = Path(args.classeur)
    classeur = lire_classeur(chemin)
    consolide = _trouver_consolide(chemin, args.consolide)
    if consolide is None:
        _ecrire("Attention — fichier consolidé introuvable : les informations Lynis (version, tests, indice) seront « N.R. ».",
                sys.stderr)
    config = charger_configuration(Path(args.config)) if args.config else {}
    sortie = Path(args.sortie) if args.sortie else chemin.parent
    libelle = libelle_livrable([s.nom for s in classeur.serveurs], args.campagne or config.get("campagne"))
    cible = chemin_libre(sortie, "LSAF_Rapport" + ("_BROUILLON" if args.brouillon else ""), libelle, ".docx")
    try:
        generer_rapport(classeur, cible, consolide, config, brouillon=args.brouillon,
                        modele=Path(args.modele) if args.modele else None)
    except RapportRefuse as e:
        _ecrire("Rapport définitif refusé : le classeur n'est pas entièrement qualifié.", sys.stderr)
        for p in e.problemes[:40]:
            _ecrire(f"  - {p}", sys.stderr)
        if len(e.problemes) > 40:
            _ecrire(f"  … et {len(e.problemes) - 40} autre(s).", sys.stderr)
        _ecrire("Qualifiez ces lignes dans la feuille ANALYSE, ou utilisez --brouillon pour une version de travail.", sys.stderr)
        return 2
    _ecrire(f"Rapport : {cible}")
    _ecrire("Contrôle de cohérence Excel ↔ Word :")
    bilan = verifier_coherence(chemin, cible, consolide, brouillon=args.brouillon)
    _afficher_bilan(bilan)
    return 0 if bilan.ok else 1


def cmd_verifier(args) -> int:
    from .verification import verifier_coherence
    chemin = Path(args.classeur)
    bilan = verifier_coherence(chemin, Path(args.rapport), _trouver_consolide(chemin, args.consolide), brouillon=args.brouillon)
    _afficher_bilan(bilan)
    return 0 if bilan.ok else 1


def cmd_demo(args) -> int:
    from .classeur import generer_classeur
    from .consolidation import consolider, ecrire_consolide
    from .lecture_classeur import lire_classeur
    from .rapport import generer_rapport
    from .synthetique import INVENTAIRE_DEMO, generer_demo, qualifier_demo
    from .verification import verifier_coherence
    sortie = Path(args.sortie)
    if sortie.exists() and any(sortie.iterdir()):
        raise SystemExit(f"Erreur : le dossier {sortie} existe et n'est pas vide (la démonstration n'écrase rien).")
    sessions = generer_demo(sortie / "sessions")
    donnees = consolider(sessions, INVENTAIRE_DEMO, "DEMO", ecrire_resultats=True)
    brut = generer_classeur(donnees, sortie / "LSAF_Audit_DEMO_brut.xlsx")
    ecrire_consolide(donnees, sortie / "LSAF_Consolide_DEMO.json")
    brouillon = generer_rapport(lire_classeur(brut), sortie / "LSAF_Rapport_DEMO_BROUILLON.docx", donnees, {}, brouillon=True)
    qualifie = qualifier_demo(brut, sortie / "LSAF_Audit_DEMO_qualifie_FICTIF.xlsx")
    config = {"organisation": "Organisation fictive (démonstration)", "auteur": "Auditeur fictif",
              "confidentialite": "Interne", "version": "1.0",
              "textes": {"appreciation": "Texte fictif : en audit réel, l'auditeur rédige ici son appréciation générale.",
                         "pilotage": "Texte fictif : en audit réel, l'auditeur rédige ici sa recommandation de pilotage."}}
    rapport = generer_rapport(lire_classeur(qualifie), sortie / "LSAF_Rapport_DEMO_FICTIF.docx", donnees, config)
    bilan = verifier_coherence(qualifie, rapport, donnees)
    _ecrire("Démonstration générée (DONNÉES ENTIÈREMENT FICTIVES) :")
    for p in (sortie / "sessions", brut, brouillon, qualifie, rapport):
        _ecrire(f"  {p}")
    _ecrire("Contrôle de cohérence du rapport de démonstration :")
    _afficher_bilan(bilan)
    return 0 if bilan.ok else 1


def construire_parseur() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="lsaf", description="Linux Security Audit Framework — traitement des preuves sur le "
                                                         "poste de l'auditeur (aucun envoi réseau).")
    p.add_argument("--version", action="version", version=f"lsaf {__version__}")
    sp = p.add_subparsers(dest="commande", required=True, metavar="COMMANDE")

    for nom, aide, fonction in (("etat", "résumé des sessions", cmd_etat),
                                ("valider", "complétude et intégrité des preuves", cmd_valider),
                                ("analyser", "extraction des valeurs (écrit resultats/ dans chaque session)", cmd_analyser)):
        x = sp.add_parser(nom, help=aide)
        x.add_argument("sessions", nargs="+", help="dossier(s) de session ou dossier parent")
        x.set_defaults(fonction=fonction)

    x = sp.add_parser("classeur", help="consolidation et classeur Excel")
    x.add_argument("sessions", nargs="+", help="dossier(s) de session (une session par serveur)")
    x.add_argument("-o", "--sortie", default="livrables", help="dossier de sortie (défaut : ./livrables)")
    x.add_argument("--inventaire", help="fichier YAML d'inventaire (rôle, environnement, criticité…)")
    x.add_argument("--campagne", help="nom de campagne utilisé dans le nom des fichiers")
    x.set_defaults(fonction=cmd_classeur)

    x = sp.add_parser("rapport", help="rapport Word à partir du classeur qualifié")
    x.add_argument("classeur", help="classeur LSAF_Audit_….xlsx qualifié par l'auditeur")
    x.add_argument("-o", "--sortie", help="dossier de sortie (défaut : celui du classeur)")
    x.add_argument("--consolide", help="fichier LSAF_Consolide_….json (trouvé automatiquement à côté du classeur)")
    x.add_argument("--config", help="fichier YAML de configuration du rapport (organisation, auteur, textes…)")
    x.add_argument("--modele", help="document Word dont les styles, en-têtes et pieds de page sont réutilisés")
    x.add_argument("--campagne", help="nom de campagne utilisé dans le nom du fichier")
    x.add_argument("--brouillon", action="store_true", help="autoriser les pistes non qualifiées (version de travail marquée)")
    x.set_defaults(fonction=cmd_rapport)

    x = sp.add_parser("verifier", help="contrôle de cohérence Excel ↔ Word")
    x.add_argument("classeur")
    x.add_argument("rapport")
    x.add_argument("--consolide")
    x.add_argument("--brouillon", action="store_true")
    x.set_defaults(fonction=cmd_verifier)

    x = sp.add_parser("demo", help="démonstration complète sur des serveurs fictifs")
    x.add_argument("-o", "--sortie", default="lsaf-demo", help="dossier de sortie (doit être vide ou absent)")
    x.set_defaults(fonction=cmd_demo)
    return p


def main(argv=None) -> int:
    args = construire_parseur().parse_args(argv)
    try:
        return args.fonction(args)
    except KeyboardInterrupt:
        _ecrire("Interrompu.", sys.stderr)
        return 130
    except Exception as e:  # message clair, jamais silencieux
        from .config import ErreurConfiguration
        from .consolidation import ErreurConsolidation
        from .lecture_classeur import ErreurClasseur
        if isinstance(e, (ErreurConfiguration, ErreurConsolidation, ErreurClasseur, FileNotFoundError)):
            _ecrire(f"Erreur : {e}", sys.stderr)
            return 2
        raise


if __name__ == "__main__":
    sys.exit(main())
