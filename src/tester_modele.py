"""
╔══════════════════════════════════════════════════════════════╗
║        TESTEUR INTERACTIF — Modèle Random Forest AD          ║
║   Testez le modèle sur des scénarios réels d'attaques AD     ║
╚══════════════════════════════════════════════════════════════╝

Usage :
    python src/tester_modele.py

Le programme vous propose un menu avec des scénarios prédéfinis
et la possibilité de créer votre propre log AD personnalisé.
"""

import pickle
import numpy as np
import os

# ─── Couleurs terminal ────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
GRAY   = "\033[90m"

def banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════╗
║        TESTEUR DE MODÈLE — Détection Anomalies AD            ║
║              Random Forest  |  27 features                   ║
╚══════════════════════════════════════════════════════════════╝{RESET}
""")

def charger_modele():
    """Charge le modèle Random Forest et le scaler depuis le dossier models/"""
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    model_path  = os.path.join(base, "models", "random_forest.pkl")
    scaler_path = os.path.join(base, "models", "scaler.pkl")
    feats_path  = os.path.join(base, "models", "feature_names.pkl")

    print(f"{GRAY}Chargement du modèle...{RESET}")
    with open(model_path,  "rb") as f: model   = pickle.load(f)
    with open(scaler_path, "rb") as f: scaler  = pickle.load(f)
    with open(feats_path,  "rb") as f: feature_names = pickle.load(f)
    print(f"{GREEN}✓ Modèle chargé — {len(feature_names)} features{RESET}\n")
    return model, scaler, feature_names

def predire(model, scaler, features, nom_scenario):
    """
    Prend un vecteur de 27 features, le normalise et prédit.
    Affiche le résultat avec score de confiance et verdict.
    """
    X = np.array(features).reshape(1, -1)
    X_scaled = scaler.transform(X)

    score     = model.predict_proba(X_scaled)[0][1]   # probabilité d'être malveillant
    prediction = model.predict(X_scaled)[0]            # 0=normal, 1=anomalie

    # ─── Affichage du résultat ────────────────────────────────
    print(f"\n{'─'*60}")
    print(f"{BOLD}  Scénario : {nom_scenario}{RESET}")
    print(f"{'─'*60}")

    # Barre de score visuelle
    nb_barres = int(score * 40)
    couleur_bar = RED if score >= 0.8 else YELLOW if score >= 0.5 else GREEN
    barre = couleur_bar + "█" * nb_barres + GRAY + "░" * (40 - nb_barres) + RESET

    print(f"\n  Score d'anomalie : {barre}  {couleur_bar}{BOLD}{score:.3f}{RESET}")

    if score >= 0.80:
        print(f"\n  {RED}{BOLD}🔴 ALERTE CRITIQUE — ATTAQUE PROBABLE{RESET}")
        print(f"  {RED}Action : Bloquer le compte et isoler la machine immédiatement{RESET}")
    elif score >= 0.50:
        print(f"\n  {YELLOW}{BOLD}🟡 ALERTE ÉLEVÉE — Activité suspecte{RESET}")
        print(f"  {YELLOW}Action : Investiguer dans les 30 minutes{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}🟢 NORMAL — Aucune anomalie détectée{RESET}")
        print(f"  {GREEN}Action : Aucune action requise{RESET}")

    # Détail des features les plus importantes
    print(f"\n  {GRAY}{'─'*50}{RESET}")
    print(f"  {CYAN}Détail des features clés :{RESET}")
    feature_names_local = [
        "hour","day_of_week","is_weekend","is_night","is_business","temporal_risk",
        "failure_count_1h","unique_users_1h","unique_hosts_1h","logon_type",
        "is_failed_logon","is_explicit_creds","is_external_ip","ip_risk",
        "is_dc_target","is_admin_account","is_service_acct",
        "privilege_escalation","kerberos_anomaly",
        "is_kerberos_tgt","is_kerberos_tgs","is_special_priv","is_group_change",
        "user_fail_ratio","user_unique_dests","user_unique_ips","risk_score"
    ]
    top_features = [
        ("failure_count_1h",  features[6]),
        ("unique_users_1h",   features[7]),
        ("unique_hosts_1h",   features[8]),
        ("temporal_risk",     features[5]),
        ("is_external_ip",    features[12]),
        ("is_dc_target",      features[14]),
        ("risk_score",        features[26]),
    ]
    for fname, fval in top_features:
        indicateur = f"{RED}⚠{RESET}" if fval > 1 else f"{GREEN}✓{RESET}"
        print(f"    {indicateur}  {fname:<25} = {BOLD}{fval}{RESET}")

    print()
    return score

# ══════════════════════════════════════════════════════════════
# SCÉNARIOS PRÉDÉFINIS
# Format des 27 features (dans l'ordre exact du modèle) :
# [hour, day_of_week, is_weekend, is_night, is_business, temporal_risk,
#  failure_count_1h, unique_users_1h, unique_hosts_1h, logon_type,
#  is_failed_logon, is_explicit_creds, is_external_ip, ip_risk,
#  is_dc_target, is_admin_account, is_service_acct,
#  privilege_escalation, kerberos_anomaly,
#  is_kerberos_tgt, is_kerberos_tgs, is_special_priv, is_group_change,
#  user_fail_ratio, user_unique_dests, user_unique_ips, risk_score]
# ══════════════════════════════════════════════════════════════

SCENARIOS = {

    # ── NORMAUX ──────────────────────────────────────────────────
    "1": {
        "nom":   "✅ Connexion normale — utilisateur bureau (9h lundi)",
        "desc":  "Alice se connecte à son PC le lundi matin depuis le réseau interne.",
        "features": [
            9,   # hour          = 9h du matin
            0,   # day_of_week   = lundi
            0,   # is_weekend    = non
            0,   # is_night      = non
            1,   # is_business   = oui (heures de bureau)
            0,   # temporal_risk = 0 (parfaitement normal)
            0,   # failure_count_1h = 0 échec
            1,   # unique_users_1h  = 1 seul utilisateur
            2,   # unique_hosts_1h  = 2 machines (son PC + serveur fichiers)
            2,   # logon_type    = Interactive (clavier)
            0,   # is_failed_logon  = non
            0,   # is_explicit_creds= non
            0,   # is_external_ip   = non (IP interne)
            0,   # ip_risk          = 0
            0,   # is_dc_target     = non
            0,   # is_admin_account = non
            0,   # is_service_acct  = non
            0,   # privilege_escalation = non
            0,   # kerberos_anomaly = non
            0,   # is_kerberos_tgt  = non
            0,   # is_kerberos_tgs  = non
            0,   # is_special_priv  = non
            0,   # is_group_change  = non
            0.02,# user_fail_ratio  = 2% (très faible)
            3,   # user_unique_dests= 3 destinations habituelles
            1,   # user_unique_ips  = 1 IP fixe
            0.04,# risk_score       = 0.04 (presque zéro)
        ],
    },

    "2": {
        "nom":   "✅ Admin IT — connexion RDP normale (14h mercredi)",
        "desc":  "L'administrateur IT se connecte en RDP à un serveur pour maintenance.",
        "features": [
            14, 2, 0, 0, 1, 0,   # 14h mercredi, heures bureau
            0, 1, 3, 10,          # 0 échec, 1 user, 3 hosts, RDP
            0, 0,                 # pas d'échec ni explicit creds
            0, 0,                 # IP interne, ip_risk=0
            0, 1, 0,              # pas DC, compte admin, pas service
            0, 0,                 # pas d'escalade ni kerberos
            0, 0, 0, 0,           # pas de flags kerberos
            0.01, 5, 1,           # très peu d'échecs, 5 dests, 1 IP
            0.03,                 # risk_score faible
        ],
    },

    # ── PASSWORD SPRAYING ────────────────────────────────────────
    "3": {
        "nom":   "🔴 Password Spraying — 47 comptes depuis IP externe (3h du matin)",
        "desc":  "Un attaquant teste le même mot de passe sur 47 comptes depuis une IP externe, à 3h du matin.",
        "features": [
            3,   # hour          = 3h du matin
            5,   # day_of_week   = samedi
            1,   # is_weekend    = oui
            1,   # is_night      = oui
            0,   # is_business   = non
            4,   # temporal_risk = 4 (maximum : nuit + week-end)
            47,  # failure_count_1h = 47 échecs !
            47,  # unique_users_1h  = 47 utilisateurs différents !
            1,   # unique_hosts_1h  = 1 seule cible (le DC)
            3,   # logon_type    = Network
            1,   # is_failed_logon  = oui
            0,   # is_explicit_creds= non
            1,   # is_external_ip   = oui (IP externe !)
            3,   # ip_risk          = 3 (externe + nuit)
            1,   # is_dc_target     = oui (vise le DC)
            0,   # is_admin_account = non
            0,   # is_service_acct  = non
            0,   # privilege_escalation = non
            0,   # kerberos_anomaly = non
            0, 0, 0, 0,
            0.97,# user_fail_ratio  = 97% d'échecs
            1,   # user_unique_dests= 1 seule destination
            1,   # user_unique_ips  = 1 IP
            0.95,# risk_score       = 0.95
        ],
    },

    "4": {
        "nom":   "🟡 Password Spraying faible — 8 tentatives (discret)",
        "desc":  "Un attaquant prudent teste seulement 8 comptes pour éviter la détection.",
        "features": [
            2, 4, 0, 1, 0, 3,    # 2h vendredi nuit
            8, 8, 1, 3,           # 8 échecs, 8 users, 1 host, Network
            1, 0,                 # échec logon
            1, 3,                 # IP externe, ip_risk=3
            1, 0, 0,              # vise DC
            0, 0,
            0, 0, 0, 0,
            0.80, 1, 1,
            0.65,                 # risk_score modéré
        ],
    },

    # ── ESCALADE DE PRIVILÈGES ───────────────────────────────────
    "5": {
        "nom":   "🔴 Escalade de privilèges — ajout Domain Admins (2h dimanche)",
        "desc":  "Un compte compromis est ajouté aux Domain Admins à 2h du matin un dimanche.",
        "features": [
            2,   # hour          = 2h du matin
            6,   # day_of_week   = dimanche
            1,   # is_weekend    = oui
            1,   # is_night      = oui
            0,   # is_business   = non
            4,   # temporal_risk = 4
            0,   # failure_count_1h = 0 (connexion réussie)
            1,   # unique_users_1h  = 1
            1,   # unique_hosts_1h  = 1 (le DC directement)
            3,   # logon_type    = Network
            0,   # is_failed_logon  = non (connexion réussie !)
            0,   # is_explicit_creds= non
            0,   # is_external_ip   = non (interne)
            1,   # ip_risk          = 1 (nuit)
            1,   # is_dc_target     = oui
            1,   # is_admin_account = oui (vient d'être ajouté aux admins)
            0,   # is_service_acct  = non
            1,   # privilege_escalation = OUI ← signal fort
            0,   # kerberos_anomaly
            0,   # is_kerberos_tgt
            0,   # is_kerberos_tgs
            1,   # is_special_priv  = OUI (Event 4672)
            1,   # is_group_change  = OUI (Event 4728)
            0.05,# user_fail_ratio  = faible
            2,   # user_unique_dests
            1,   # user_unique_ips
            0.88,# risk_score
        ],
    },

    # ── MOUVEMENT LATÉRAL ────────────────────────────────────────
    "6": {
        "nom":   "🔴 Mouvement latéral — Pass-the-Hash sur 12 machines (1h mardi)",
        "desc":  "Un attaquant se déplace de machine en machine avec un hash NTLM volé.",
        "features": [
            1,   # hour          = 1h du matin
            1,   # day_of_week   = mardi
            0,   # is_weekend    = non
            1,   # is_night      = oui
            0,   # is_business   = non
            2,   # temporal_risk = 2 (nuit en semaine)
            0,   # failure_count_1h = 0 (les connexions réussissent !)
            1,   # unique_users_1h  = 1 (même attaquant)
            12,  # unique_hosts_1h  = 12 machines visitées ← signal fort
            9,   # logon_type    = NewCredentials (Pass-the-Hash)
            0,   # is_failed_logon  = non
            1,   # is_explicit_creds= OUI (Event 4648)
            0,   # is_external_ip   = non (interne)
            1,   # ip_risk          = 1 (nuit)
            1,   # is_dc_target     = oui (finit sur le DC)
            0, 0,
            0, 0,
            0, 0, 0, 0,
            0.03,# user_fail_ratio  = faible (connexions réussies)
            12,  # user_unique_dests= 12 destinations !
            1,   # user_unique_ips
            0.82,# risk_score
        ],
    },

    # ── KERBEROASTING ────────────────────────────────────────────
    "7": {
        "nom":   "🔴 Kerberoasting — 5 tickets TGS en 10 secondes",
        "desc":  "Un attaquant demande des tickets Kerberos pour tous les comptes de service afin de cracker les hashs offline.",
        "features": [
            22,  # hour          = 22h (début de nuit)
            3,   # day_of_week   = jeudi
            0,   # is_weekend    = non
            1,   # is_night      = oui
            0,   # is_business   = non
            2,   # temporal_risk = 2
            0,   # failure_count_1h = 0
            5,   # unique_users_1h  = 5 comptes de service ciblés
            1,   # unique_hosts_1h  = 1 (le DC)
            0,   # logon_type    = 0 (Kerberos pur)
            0,   # is_failed_logon  = non
            0,   # is_explicit_creds= non
            0,   # is_external_ip   = non
            1,   # ip_risk          = 1
            1,   # is_dc_target     = oui
            0,   # is_admin_account = non
            1,   # is_service_acct  = OUI (cible les comptes service)
            0,   # privilege_escalation
            1,   # kerberos_anomaly = OUI ← signal fort
            1,   # is_kerberos_tgt  = oui
            1,   # is_kerberos_tgs  = OUI (Event 4769 en masse)
            0, 0,
            0.10,# user_fail_ratio
            1,   # user_unique_dests
            1,   # user_unique_ips
            0.78,# risk_score
        ],
    },

    # ── CAS AMBIGUS ──────────────────────────────────────────────
    "8": {
        "nom":   "🟡 Cas ambigu — admin qui travaille tard (23h vendredi)",
        "desc":  "L'admin travaille tard un vendredi soir. Légitime ou suspect ?",
        "features": [
            23, 4, 0, 1, 0, 2,   # 23h vendredi, nuit
            0, 1, 4, 10,          # 0 échec, 1 user, 4 hosts, RDP
            0, 0,
            0, 1,                 # IP interne, ip_risk=1 (nuit)
            1, 1, 0,              # vise DC, compte admin
            0, 0,
            0, 0, 0, 0,
            0.01, 5, 1,
            0.25,                 # risk_score modéré
        ],
    },
}

# ══════════════════════════════════════════════════════════════
# SAISIE MANUELLE D'UN LOG PERSONNALISÉ
# ══════════════════════════════════════════════════════════════

def saisie_manuelle(model, scaler):
    """Guide l'utilisateur pour saisir son propre log AD."""
    print(f"\n{CYAN}{BOLD}─── Saisie d'un log AD personnalisé ───────────────────{RESET}")
    print(f"{GRAY}Répondez aux questions suivantes (appuyez Entrée pour valider){RESET}\n")

    def ask(question, default, valide=None):
        while True:
            rep = input(f"  {question} [{default}] : ").strip()
            if not rep:
                return default
            try:
                val = float(rep)
                if valide and val not in valide:
                    print(f"    {RED}Valeurs acceptées : {valide}{RESET}")
                    continue
                return val
            except ValueError:
                print(f"    {RED}Entrez un nombre.{RESET}")

    hour         = ask("Heure de connexion (0-23)", 10)
    dow          = ask("Jour de la semaine (0=lundi, 6=dimanche)", 1)
    is_weekend   = 1 if dow >= 5 else 0
    is_night     = 1 if (hour < 6 or hour >= 22) else 0
    is_business  = 1 if (8 <= hour < 18 and dow < 5) else 0
    temporal_risk= is_night * 2 + is_weekend

    print(f"  {GRAY}→ is_night={is_night}, is_weekend={is_weekend}, temporal_risk={temporal_risk}{RESET}")

    fail_count   = ask("Nombre d'échecs d'authentification dans la dernière heure", 0)
    uniq_users   = ask("Nombre d'utilisateurs distincts visés depuis cette IP (1h)", 1)
    uniq_hosts   = ask("Nombre de machines distinctes contactées (1h)", 1)
    logon_type   = ask("Type de connexion (2=Local, 3=Réseau, 9=Pass-Hash, 10=RDP)", 3)
    is_failed    = 1 if fail_count > 0 else 0
    is_extcreds  = ask("Credentials explicites utilisés ? (0=non, 1=oui)", 0, [0,1])
    is_ext_ip    = ask("IP source externe (hors 192.168/10.x) ? (0=non, 1=oui)", 0, [0,1])
    ip_risk      = is_ext_ip * 2 + (1 if is_night else 0)
    is_dc        = ask("La destination est un Domain Controller ? (0=non, 1=oui)", 0, [0,1])
    is_admin     = ask("Compte administrateur impliqué ? (0=non, 1=oui)", 0, [0,1])
    is_svc       = ask("Compte de service ciblé ? (0=non, 1=oui)", 0, [0,1])
    priv_esc     = ask("Escalade de privilèges détectée ? (0=non, 1=oui)", 0, [0,1])
    kerb_anom    = ask("Anomalie Kerberos (trop de TGS) ? (0=non, 1=oui)", 0, [0,1])
    is_tgt       = ask("Event 4768 (demande TGT) ? (0=non, 1=oui)", 0, [0,1])
    is_tgs       = ask("Event 4769 (demande TGS) ? (0=non, 1=oui)", 0, [0,1])
    is_spriv     = ask("Event 4672 (privilèges spéciaux) ? (0=non, 1=oui)", 0, [0,1])
    is_grpchg    = ask("Event 4728/4732 (changement de groupe) ? (0=non, 1=oui)", 0, [0,1])
    fail_ratio   = ask("Ratio d'échecs historique de l'utilisateur (0.0-1.0)", 0.02)
    uniq_dests   = ask("Nombre de destinations distinctes (historique utilisateur)", 3)
    uniq_ips     = ask("Nombre d'IPs distinctes (historique utilisateur)", 1)

    # Calcul du risk_score composite
    risk_score = min(1.0, (
        fail_count  * 0.30 +
        uniq_users  * 0.25 +
        uniq_hosts  * 0.15 +
        temporal_risk * 0.10 +
        ip_risk     * 0.10 +
        priv_esc    * 0.05 +
        kerb_anom   * 0.05
    ) / 15.0)

    features = [
        hour, dow, is_weekend, is_night, is_business, temporal_risk,
        fail_count, uniq_users, uniq_hosts, logon_type,
        is_failed, is_extcreds, is_ext_ip, ip_risk,
        is_dc, is_admin, is_svc,
        priv_esc, kerb_anom,
        is_tgt, is_tgs, is_spriv, is_grpchg,
        fail_ratio, uniq_dests, uniq_ips, risk_score
    ]

    predire(model, scaler, features, "Log personnalisé")

# ══════════════════════════════════════════════════════════════
# TEST EN BATCH — tous les scénarios d'un coup
# ══════════════════════════════════════════════════════════════

def test_batch(model, scaler):
    """Lance tous les scénarios et affiche un résumé."""
    print(f"\n{BOLD}{CYAN}═══ TEST BATCH — Tous les scénarios ═══{RESET}\n")
    resultats = []
    for key, scenario in SCENARIOS.items():
        score = predire(model, scaler, scenario["features"], scenario["nom"])
        resultats.append((scenario["nom"], score))

    print(f"\n{BOLD}{'═'*60}")
    print(f"  RÉSUMÉ FINAL")
    print(f"{'═'*60}{RESET}")
    print(f"  {'Scénario':<45} {'Score':>7}  {'Verdict'}")
    print(f"  {'─'*45} {'─'*7}  {'─'*15}")
    for nom, score in resultats:
        if score >= 0.80:
            verdict = f"{RED}CRITIQUE{RESET}"
        elif score >= 0.50:
            verdict = f"{YELLOW}SUSPECT {RESET}"
        else:
            verdict = f"{GREEN}NORMAL  {RESET}"
        couleur = RED if score >= 0.8 else YELLOW if score >= 0.5 else GREEN
        print(f"  {nom[:45]:<45} {couleur}{score:>7.3f}{RESET}  {verdict}")
    print()

# ══════════════════════════════════════════════════════════════
# MENU PRINCIPAL
# ══════════════════════════════════════════════════════════════

def menu():
    banner()
    model, scaler, feature_names = charger_modele()

    while True:
        print(f"{BOLD}{'─'*60}")
        print(f"  MENU PRINCIPAL")
        print(f"{'─'*60}{RESET}")
        print(f"\n  {CYAN}── Scénarios normaux ──{RESET}")
        print(f"  {GREEN}1{RESET}  Connexion normale utilisateur bureau (9h lundi)")
        print(f"  {GREEN}2{RESET}  Admin IT — connexion RDP normale (14h mercredi)")
        print(f"\n  {CYAN}── Attaques simulées ──{RESET}")
        print(f"  {RED}3{RESET}  Password Spraying — 47 comptes depuis IP externe (3h)")
        print(f"  {YELLOW}4{RESET}  Password Spraying faible — 8 tentatives (discret)")
        print(f"  {RED}5{RESET}  Escalade de privilèges — ajout Domain Admins (2h dimanche)")
        print(f"  {RED}6{RESET}  Mouvement latéral — Pass-the-Hash 12 machines")
        print(f"  {RED}7{RESET}  Kerberoasting — 5 tickets TGS en masse")
        print(f"\n  {CYAN}── Cas ambigus ──{RESET}")
        print(f"  {YELLOW}8{RESET}  Admin qui travaille tard le vendredi soir")
        print(f"\n  {CYAN}── Autres options ──{RESET}")
        print(f"  {BLUE}9{RESET}  Saisir mon propre log AD manuellement")
        print(f"  {BLUE}0{RESET}  Lancer TOUS les scénarios (batch)")
        print(f"  {GRAY}q{RESET}  Quitter\n")

        choix = input(f"  Votre choix : ").strip().lower()

        if choix == "q":
            print(f"\n{GRAY}Au revoir !{RESET}\n")
            break
        elif choix == "0":
            test_batch(model, scaler)
        elif choix == "9":
            saisie_manuelle(model, scaler)
        elif choix in SCENARIOS:
            s = SCENARIOS[choix]
            print(f"\n  {GRAY}{s['desc']}{RESET}")
            predire(model, scaler, s["features"], s["nom"])
        else:
            print(f"  {RED}Choix invalide. Tapez un numéro entre 0 et 9, ou q.{RESET}\n")

        input(f"\n  {GRAY}Appuyez sur Entrée pour continuer...{RESET}")
        print()

if __name__ == "__main__":
    menu()
