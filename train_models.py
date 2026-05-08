"""
Étape 3 : Entraînement et évaluation des modèles ML
- Isolation Forest (non supervisé)
- One-Class SVM (non supervisé)
- Random Forest supervisé (baseline)
"""
import numpy as np
import pandas as pd
import pickle, json
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.metrics import (
    classification_report, confusion_matrix,
    roc_auc_score, precision_recall_curve, average_precision_score,
    f1_score, precision_score, recall_score
)
import warnings
warnings.filterwarnings("ignore")

print("=" * 60)
print("ÉTAPE 3 — ENTRAÎNEMENT DES MODÈLES")
print("=" * 60)

# ─── Chargement des données ───────────────────────────────────────────────────
X_train = np.load("/home/claude/ad_anomaly/data/X_train.npy")
X_test  = np.load("/home/claude/ad_anomaly/data/X_test.npy")
y_train = np.load("/home/claude/ad_anomaly/data/y_train.npy")
y_test  = np.load("/home/claude/ad_anomaly/data/y_test.npy")
at_test = np.load("/home/claude/ad_anomaly/data/at_test.npy", allow_pickle=True)

print(f"\nDonnées chargées :")
print(f"  X_train : {X_train.shape} | Anomalies train : {y_train.sum()}/{len(y_train)}")
print(f"  X_test  : {X_test.shape}  | Anomalies test  : {y_test.sum()}/{len(y_test)}")

# ─── Isolation normale pour l'entraînement non supervisé ─────────────────────
# L'Isolation Forest s'entraîne uniquement sur des données normales (idéalement)
X_train_normal = X_train[y_train == 0]
print(f"\n  X_train normal only : {X_train_normal.shape} (pour IF et OC-SVM)")

results = {}

# ═══════════════════════════════════════════════════════════════════════════════
# MODÈLE 1 : ISOLATION FOREST
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "─" * 50)
print("MODÈLE 1 — Isolation Forest (non supervisé)")
print("─" * 50)

# contamination = proportion d'anomalies attendues dans les données
# (7.8% d'attaques dans notre dataset)
iso_forest = IsolationForest(
    n_estimators=200,        # nombre d'arbres d'isolation
    max_samples="auto",      # sous-échantillonnage par arbre
    contamination=0.078,     # taux de contamination attendu
    max_features=1.0,        # features par arbre
    bootstrap=False,
    random_state=42,
    n_jobs=-1
)

print("  Entraînement sur données normales uniquement...")
iso_forest.fit(X_train_normal)

# Prédictions : -1 = anomalie, 1 = normal → convertir en 0/1
y_pred_if_raw  = iso_forest.predict(X_test)
y_pred_if      = (y_pred_if_raw == -1).astype(int)

# Scores d'anomalie (plus négatif = plus anormal)
scores_if      = -iso_forest.decision_function(X_test)
scores_if_norm = (scores_if - scores_if.min()) / (scores_if.max() - scores_if.min())

# Métriques
cm_if    = confusion_matrix(y_test, y_pred_if)
prec_if  = precision_score(y_test, y_pred_if, zero_division=0)
rec_if   = recall_score(y_test, y_pred_if, zero_division=0)
f1_if    = f1_score(y_test, y_pred_if, zero_division=0)
auc_if   = roc_auc_score(y_test, scores_if_norm)
fp_rate  = cm_if[0,1] / max(cm_if[0,:].sum(), 1)
fn_rate  = cm_if[1,0] / max(cm_if[1,:].sum(), 1)

print(f"\n  Matrice de confusion :")
print(f"    TP={cm_if[1,1]} | FP={cm_if[0,1]}")
print(f"    FN={cm_if[1,0]} | TN={cm_if[0,0]}")
print(f"\n  Précision : {prec_if:.3f}")
print(f"  Rappel    : {rec_if:.3f}")
print(f"  F1-score  : {f1_if:.3f}")
print(f"  ROC-AUC   : {auc_if:.3f}")
print(f"  Taux FP   : {fp_rate*100:.1f}%")
print(f"  Taux FN   : {fn_rate*100:.1f}%")

results["isolation_forest"] = {
    "precision": round(prec_if, 4),
    "recall":    round(rec_if, 4),
    "f1":        round(f1_if, 4),
    "auc":       round(auc_if, 4),
    "fp_rate":   round(fp_rate, 4),
    "fn_rate":   round(fn_rate, 4),
    "cm":        cm_if.tolist(),
}

with open("/home/claude/ad_anomaly/models/isolation_forest.pkl", "wb") as f:
    pickle.dump(iso_forest, f)

# ═══════════════════════════════════════════════════════════════════════════════
# MODÈLE 2 : ONE-CLASS SVM
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "─" * 50)
print("MODÈLE 2 — One-Class SVM (non supervisé)")
print("─" * 50)

oc_svm = OneClassSVM(
    kernel="rbf",     # noyau RBF adapté aux données non linéaires
    nu=0.078,         # borne supérieure sur le taux de SVs = contamination
    gamma="scale",    # gamma = 1 / (n_features * X.var())
)

print("  Entraînement sur données normales...")
# OC-SVM plus lent → sous-échantillon si nécessaire
sample_idx = np.random.choice(len(X_train_normal), min(2000, len(X_train_normal)), replace=False)
oc_svm.fit(X_train_normal[sample_idx])

y_pred_svm_raw = oc_svm.predict(X_test)
y_pred_svm     = (y_pred_svm_raw == -1).astype(int)
scores_svm     = -oc_svm.decision_function(X_test)
scores_svm_n   = (scores_svm - scores_svm.min()) / (scores_svm.max() - scores_svm.min())

cm_svm   = confusion_matrix(y_test, y_pred_svm)
prec_svm = precision_score(y_test, y_pred_svm, zero_division=0)
rec_svm  = recall_score(y_test, y_pred_svm, zero_division=0)
f1_svm   = f1_score(y_test, y_pred_svm, zero_division=0)
auc_svm  = roc_auc_score(y_test, scores_svm_n)
fp_svm   = cm_svm[0,1] / max(cm_svm[0,:].sum(), 1)
fn_svm   = cm_svm[1,0] / max(cm_svm[1,:].sum(), 1)

print(f"\n  Matrice de confusion :")
print(f"    TP={cm_svm[1,1]} | FP={cm_svm[0,1]}")
print(f"    FN={cm_svm[1,0]} | TN={cm_svm[0,0]}")
print(f"\n  Précision : {prec_svm:.3f}")
print(f"  Rappel    : {rec_svm:.3f}")
print(f"  F1-score  : {f1_svm:.3f}")
print(f"  ROC-AUC   : {auc_svm:.3f}")
print(f"  Taux FP   : {fp_svm*100:.1f}%")
print(f"  Taux FN   : {fn_svm*100:.1f}%")

results["one_class_svm"] = {
    "precision": round(prec_svm, 4),
    "recall":    round(rec_svm, 4),
    "f1":        round(f1_svm, 4),
    "auc":       round(auc_svm, 4),
    "fp_rate":   round(fp_svm, 4),
    "fn_rate":   round(fn_svm, 4),
    "cm":        cm_svm.tolist(),
}

with open("/home/claude/ad_anomaly/models/one_class_svm.pkl", "wb") as f:
    pickle.dump(oc_svm, f)

# ═══════════════════════════════════════════════════════════════════════════════
# MODÈLE 3 : RANDOM FOREST SUPERVISÉ (baseline comparaison)
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "─" * 50)
print("MODÈLE 3 — Random Forest supervisé (baseline)")
print("─" * 50)

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=12,
    min_samples_leaf=2,
    class_weight="balanced",   # compenser le déséquilibre de classes
    random_state=42,
    n_jobs=-1
)

print("  Entraînement sur données labellisées...")
rf.fit(X_train, y_train)

y_pred_rf   = rf.predict(X_test)
scores_rf   = rf.predict_proba(X_test)[:, 1]
cm_rf       = confusion_matrix(y_test, y_pred_rf)
prec_rf     = precision_score(y_test, y_pred_rf, zero_division=0)
rec_rf      = recall_score(y_test, y_pred_rf, zero_division=0)
f1_rf       = f1_score(y_test, y_pred_rf, zero_division=0)
auc_rf      = roc_auc_score(y_test, scores_rf)
fp_rf       = cm_rf[0,1] / max(cm_rf[0,:].sum(), 1)
fn_rf       = cm_rf[1,0] / max(cm_rf[1,:].sum(), 1)

print(f"\n  Matrice de confusion :")
print(f"    TP={cm_rf[1,1]} | FP={cm_rf[0,1]}")
print(f"    FN={cm_rf[1,0]} | TN={cm_rf[0,0]}")
print(f"\n  Précision : {prec_rf:.3f}")
print(f"  Rappel    : {rec_rf:.3f}")
print(f"  F1-score  : {f1_rf:.3f}")
print(f"  ROC-AUC   : {auc_rf:.3f}")
print(f"  Taux FP   : {fp_rf*100:.1f}%")
print(f"  Taux FN   : {fn_rf*100:.1f}%")

results["random_forest"] = {
    "precision": round(prec_rf, 4),
    "recall":    round(rec_rf, 4),
    "f1":        round(f1_rf, 4),
    "auc":       round(auc_rf, 4),
    "fp_rate":   round(fp_rf, 4),
    "fn_rate":   round(fn_rf, 4),
    "cm":        cm_rf.tolist(),
}

with open("/home/claude/ad_anomaly/models/random_forest.pkl", "wb") as f:
    pickle.dump(rf, f)

# ─── Importance des features (Random Forest) ─────────────────────────────────
with open("/home/claude/ad_anomaly/models/feature_names.pkl", "rb") as f:
    feature_names = pickle.load(f)

importances = pd.Series(rf.feature_importances_, index=feature_names)
importances = importances.sort_values(ascending=False)

print("\n─── Top 10 features les plus importantes (RF) ─────────")
for feat, imp in importances.head(10).items():
    bar = "█" * int(imp * 200)
    print(f"  {feat:<30} {imp:.4f} {bar}")

# ─── Évaluation par type d'attaque ───────────────────────────────────────────
print("\n─── Détection par type d'attaque (Isolation Forest) ───")
attack_eval = {}
for atype in np.unique(at_test):
    mask = at_test == atype
    if mask.sum() == 0:
        continue
    n_total   = mask.sum()
    n_detected = y_pred_if[mask].sum()
    true_label = y_test[mask].values if hasattr(y_test, 'values') else y_test[mask]
    tp = ((y_pred_if[mask] == 1) & (true_label == 1)).sum()
    fp = ((y_pred_if[mask] == 1) & (true_label == 0)).sum()
    det_rate = tp / max(true_label.sum(), 1)
    attack_eval[atype] = {
        "total": int(n_total),
        "detected": int(n_detected),
        "tp": int(tp),
        "fp": int(fp),
        "detection_rate": round(det_rate, 3),
    }
    print(f"  {atype:<25} détectés={tp}/{int(true_label.sum())} ({det_rate*100:.0f}%) | FP={fp}")

# ─── Sauvegarde des résultats ─────────────────────────────────────────────────
report = {
    "model_results": results,
    "attack_evaluation": attack_eval,
    "feature_importance": importances.head(10).to_dict(),
    "dataset_stats": {
        "total": int(len(y_test) + len(y_train)),
        "n_features": len(feature_names),
        "train_size": int(len(y_train)),
        "test_size": int(len(y_test)),
        "attack_rate": round(float((y_train.sum()+y_test.sum())/(len(y_train)+len(y_test))), 4)
    }
}

with open("/home/claude/ad_anomaly/reports/evaluation_report.json", "w") as f:
    json.dump(report, f, indent=2)

# Sauvegarder les scores pour visualisation
np.save("/home/claude/ad_anomaly/data/scores_if.npy",  scores_if_norm)
np.save("/home/claude/ad_anomaly/data/scores_svm.npy", scores_svm_n)
np.save("/home/claude/ad_anomaly/data/scores_rf.npy",  scores_rf)

print("\n✓ Entraînement terminé. Rapport sauvegardé.")
print(f"\n{'─'*50}")
print("COMPARAISON FINALE DES MODÈLES")
print(f"{'─'*50}")
print(f"{'Modèle':<25} {'Précision':>10} {'Rappel':>8} {'F1':>8} {'AUC':>8} {'FP%':>7}")
print(f"{'─'*25} {'─'*10} {'─'*8} {'─'*8} {'─'*8} {'─'*7}")
for name, r in results.items():
    print(f"{name:<25} {r['precision']:>10.3f} {r['recall']:>8.3f} {r['f1']:>8.3f} {r['auc']:>8.3f} {r['fp_rate']*100:>6.1f}%")
