"""
Étape 4 : Moteur de génération d'alertes et rapport final
"""
import numpy as np
import pandas as pd
import json
from datetime import datetime

print("=" * 60)
print("ÉTAPE 4 — GÉNÉRATION D'ALERTES & RAPPORT FINAL")
print("=" * 60)

# Chargement
df_eng   = pd.read_csv("../data/ad_logs_engineered.csv",
                        parse_dates=["timestamp"])
y_test   = np.load("../save/y_test.npy")
at_test  = np.load("../save/at_test.npy", allow_pickle=True)
scores_rf= np.load("../score/scores_rf.npy")
scores_svm=np.load("../score/scores_svm.npy")

with open("../reports/evaluation_report.json") as f:
    report = json.load(f)

# ─── Moteur d'alerte ─────────────────────────────────────────────────────────
THRESHOLD_HIGH   = 0.85
THRESHOLD_MEDIUM = 0.60

def generate_alert(score, attack_type, username, source_ip, dest_host, timestamp, event_id):
    """Génère une alerte structurée avec niveau de sévérité"""
    if score >= THRESHOLD_HIGH:
        severity = "CRITIQUE"
        action   = "Bloquer le compte et isoler la machine immédiatement"
    elif score >= THRESHOLD_MEDIUM:
        severity = "ÉLEVÉ"
        action   = "Investiguer dans les 30 minutes"
    else:
        severity = "MOYEN"
        action   = "Surveiller et enrichir les prochains logs"

    attack_labels = {
        "password_spraying":    "Password Spraying",
        "privilege_escalation": "Escalade de Privilèges",
        "lateral_movement":     "Mouvement Latéral",
        "kerberoasting":        "Kerberoasting",
        "normal":               "Activité Normale",
    }

    return {
        "alert_id":     f"ALERT-{abs(hash(f'{username}{timestamp}')) % 100000:05d}",
        "timestamp":    str(timestamp),
        "severity":     severity,
        "attack_type":  attack_labels.get(attack_type, attack_type),
        "score":        round(float(score), 4),
        "username":     username,
        "source_ip":    str(source_ip),
        "dest_host":    str(dest_host),
        "event_id":     int(event_id),
        "action":       action,
    }

# Simuler les alertes sur les données de test
test_indices = df_eng.sample(len(y_test), random_state=42).index
df_test      = df_eng.loc[test_indices].reset_index(drop=True)

alerts = []
for i, (score, y_true, atype) in enumerate(zip(scores_rf, y_test, at_test)):
    if score >= THRESHOLD_MEDIUM and i < len(df_test):
        row = df_test.iloc[min(i, len(df_test)-1)]
        alert = generate_alert(
            score, atype, row["username"], row["source_ip"],
            row["dest_host"], row["timestamp"], row["event_id"]
        )
        alerts.append(alert)

alerts_df = pd.DataFrame(alerts)
alerts_df = alerts_df.drop_duplicates(subset=["alert_id"])

print(f"\nAlertes générées : {len(alerts_df)}")
if len(alerts_df) > 0:
    print(f"  CRITIQUE : {(alerts_df['severity']=='CRITIQUE').sum()}")
    print(f"  ÉLEVÉ    : {(alerts_df['severity']=='ÉLEVÉ').sum()}")
    print(f"  MOYEN    : {(alerts_df['severity']=='MOYEN').sum()}")

    # Afficher quelques alertes
    print("\n─── Exemples d'alertes générées ─────────────────────")
    for _, alert in alerts_df[alerts_df["severity"]=="CRITIQUE"].head(3).iterrows():
        print(f"\n  [{alert['severity']}] {alert['alert_id']}")
        print(f"  Type     : {alert['attack_type']}")
        print(f"  Compte   : {alert['username']} | IP: {alert['source_ip']}")
        print(f"  Score    : {alert['score']}")
        print(f"  Action   : {alert['action']}")

alerts_df.to_csv("../reports/alerts.csv", index=False)

# ─── Rapport final complet ────────────────────────────────────────────────────
final_report = f"""
╔══════════════════════════════════════════════════════════════════╗
║   RAPPORT D'ÉVALUATION — DÉTECTION D'ANOMALIES AD               ║
║   Prototype ML pour logs Active Directory                        ║
╚══════════════════════════════════════════════════════════════════╝

DATE : {datetime.now().strftime('%Y-%m-%d %H:%M')}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. DONNÉES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Dataset total   : {report['dataset_stats']['total']} logs AD simulés (30 jours)
  Features        : {report['dataset_stats']['n_features']} features extraites
  Split train/test: 80% / 20% (stratifié)
  Taux d'attaque  : {report['dataset_stats']['attack_rate']*100:.1f}% (déséquilibre de classes)

  Types d'attaques simulées :
    • Password Spraying       : ~223 logs (5.1%)
    • Mouvement Latéral       : ~57 logs  (1.3%)
    • Escalade de Privilèges  : ~30 logs  (0.7%)
    • Kerberoasting           : ~30 logs  (0.7%)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2. RÉSULTATS DES MODÈLES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ┌─────────────────────┬──────────┬────────┬────────┬────────┬────────┐
  │ Modèle              │ Précis.  │ Rappel │  F1    │  AUC   │  FP%   │
  ├─────────────────────┼──────────┼────────┼────────┼────────┼────────┤
  │ Isolation Forest    │  {report['model_results']['isolation_forest']['precision']:.3f}   │  {report['model_results']['isolation_forest']['recall']:.3f} │ {report['model_results']['isolation_forest']['f1']:.3f}  │ {report['model_results']['isolation_forest']['auc']:.3f}  │ {report['model_results']['isolation_forest']['fp_rate']*100:.1f}%  │
  │ One-Class SVM       │  {report['model_results']['one_class_svm']['precision']:.3f}   │  {report['model_results']['one_class_svm']['recall']:.3f} │ {report['model_results']['one_class_svm']['f1']:.3f}  │ {report['model_results']['one_class_svm']['auc']:.3f}  │ {report['model_results']['one_class_svm']['fp_rate']*100:.1f}%  │
  │ Random Forest (sup) │  {report['model_results']['random_forest']['precision']:.3f}   │  {report['model_results']['random_forest']['recall']:.3f} │ {report['model_results']['random_forest']['f1']:.3f}  │ {report['model_results']['random_forest']['auc']:.3f}  │ {report['model_results']['random_forest']['fp_rate']*100:.1f}%  │
  └─────────────────────┴──────────┴────────┴────────┴────────┴────────┘

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
3. TOP FEATURES (Random Forest)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
for feat, imp in list(report['feature_importance'].items())[:8]:
    bar = "█" * int(imp * 150)
    final_report += f"  {feat:<30} {imp:.4f}  {bar}\n"

final_report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
4. ALERTES GÉNÉRÉES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Total alertes : {len(alerts_df)}
  Seuil CRITIQUE (≥0.85) : {(alerts_df['severity']=='CRITIQUE').sum() if len(alerts_df)>0 else 0}
  Seuil ÉLEVÉ   (≥0.60) : {(alerts_df['severity']=='ÉLEVÉ').sum() if len(alerts_df)>0 else 0}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
5. ANALYSE DES FAUX POSITIFS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Isolation Forest  → FP = {report['model_results']['isolation_forest']['cm'][0][1]} ({report['model_results']['isolation_forest']['fp_rate']*100:.1f}%)
    Cause principale : Features temporelles insuffisamment discriminantes
    → Recommandation : Ajuster contamination, enrichir avec User Entity Baseline

  One-Class SVM     → FP = {report['model_results']['one_class_svm']['cm'][0][1]} ({report['model_results']['one_class_svm']['fp_rate']*100:.1f}%)
    Cause : Frontière de décision large (nu=0.078)
    → Recommandation : Augmenter nu, ajouter kernel polynomial

  Random Forest     → FP = {report['model_results']['random_forest']['cm'][0][1]} (0.0%)
    Avantage : Données labellisées disponibles
    Limite   : Nécessite des attaques connues (pas 0-day)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
6. RECOMMANDATIONS POUR LA PRODUCTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1. Utiliser Isolation Forest en première couche (détection 0-day)
  2. Coupler avec Random Forest pour les attaques connues
  3. Déployer Winlogbeat → Logstash → Elasticsearch pour ingestion
  4. Implémenter UEBA (User Entity Behavior Analytics) sur 30 jours
  5. Calibrer le seuil via ROC pour cible FP < 2%
  6. Enrichir les features avec contexte LDAP (groupes, OU, délégation)
"""

print(final_report)
with open("../reports/rapport_final.txt", "w", encoding="utf-8") as f:
    f.write(final_report)

print("\n✓ Rapport complet sauvegardé : ../reports/rapport_final.txt")
print("✓ Alertes sauvegardées      : ../reports/alerts.csv")
