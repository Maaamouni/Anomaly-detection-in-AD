"""
Étape 2 : Feature Engineering & Préprocessing
Transformation des logs AD bruts en features numériques pour le ML
"""
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
import pickle, os

print("=" * 60)
print("ÉTAPE 2 — FEATURE ENGINEERING")
print("=" * 60)

df = pd.read_csv("/home/claude/ad_anomaly/data/ad_logs_raw.csv", parse_dates=["timestamp"])

# ─── 2.1 Features temporelles ────────────────────────────────────────────────
print("\n[2.1] Extraction features temporelles...")
df["hour"]        = df["timestamp"].dt.hour
df["day_of_week"] = df["timestamp"].dt.dayofweek     # 0=lundi, 6=dimanche
df["is_weekend"]  = (df["day_of_week"] >= 5).astype(int)
df["is_night"]    = ((df["hour"] < 6) | (df["hour"] >= 22)).astype(int)
df["is_business"] = ((df["hour"] >= 8) & (df["hour"] < 18) & (df["day_of_week"] < 5)).astype(int)
# Score temporel composite : nuit + week-end = suspicion max
df["temporal_risk"] = df["is_night"] * 2 + df["is_weekend"] + df["off_hours"]

# ─── 2.2 Features comportementales ───────────────────────────────────────────
print("[2.2] Calcul features comportementales par utilisateur...")

df_sorted = df.sort_values("timestamp")

# Ratio échecs/total par utilisateur (fenêtre glissante approximée)
user_fail = df_sorted.groupby("username")["event_id"].apply(
    lambda x: (x == 4625).sum() / max(len(x), 1)
).rename("user_fail_ratio").reset_index()
df = df.merge(user_fail, on="username", how="left")

# Nombre de destinations distinctes par utilisateur
user_hosts = df.groupby("username")["dest_host"].nunique().rename("user_unique_dests").reset_index()
df = df.merge(user_hosts, on="username", how="left")

# Nombre d'IPs sources distinctes par utilisateur
user_ips = df.groupby("username")["source_ip"].nunique().rename("user_unique_ips").reset_index()
df = df.merge(user_ips, on="username", how="left")

# ─── 2.3 Features réseau ─────────────────────────────────────────────────────
print("[2.3] Extraction features réseau...")
df["is_external_ip"] = df["source_ip"].apply(
    lambda ip: 0 if str(ip).startswith(("192.168.", "10.", "172.16.")) else 1
)

# Score IP : externe + hors horaires = très suspect
df["ip_risk"] = df["is_external_ip"] * 2 + df["off_hours"]

# ─── 2.4 Features d'événements Kerberos / NTLM ───────────────────────────────
print("[2.4] Encoding event_id en features sémantiques...")
df["is_failed_logon"]   = (df["event_id"] == 4625).astype(int)
df["is_kerberos_tgt"]   = (df["event_id"] == 4768).astype(int)
df["is_kerberos_tgs"]   = (df["event_id"] == 4769).astype(int)
df["is_special_priv"]   = (df["event_id"] == 4672).astype(int)
df["is_group_change"]   = (df["event_id"].isin([4728, 4732, 4756])).astype(int)
df["is_explicit_creds"] = (df["event_id"] == 4648).astype(int)

# ─── 2.5 Score de risque composite ───────────────────────────────────────────
print("[2.5] Calcul score de risque composite...")
df["risk_score"] = (
    df["failure_count_1h"]    * 0.30 +
    df["unique_users_1h"]     * 0.25 +
    df["unique_hosts_1h"]     * 0.15 +
    df["temporal_risk"]       * 0.10 +
    df["ip_risk"]             * 0.10 +
    df["privilege_escalation"]* 0.05 +
    df["kerberos_anomaly"]    * 0.05
)
# Normaliser entre 0 et 1
df["risk_score"] = (df["risk_score"] - df["risk_score"].min()) / \
                   (df["risk_score"].max() - df["risk_score"].min() + 1e-8)

# ─── 2.6 Sélection et encodage des features finales ──────────────────────────
print("[2.6] Sélection des features pour le modèle ML...")

FEATURES = [
    # Temporelles
    "hour", "day_of_week", "is_weekend", "is_night", "is_business", "temporal_risk",
    # Authentification
    "failure_count_1h", "unique_users_1h", "unique_hosts_1h", "logon_type",
    "is_failed_logon", "is_explicit_creds",
    # Réseau
    "is_external_ip", "ip_risk",
    # Cibles sensibles
    "is_dc_target", "is_admin_account", "is_service_acct",
    # Privilege / Kerberos
    "privilege_escalation", "kerberos_anomaly",
    "is_kerberos_tgt", "is_kerberos_tgs", "is_special_priv", "is_group_change",
    # Comportementales
    "user_fail_ratio", "user_unique_dests", "user_unique_ips",
    # Score composite
    "risk_score",
]

X = df[FEATURES].fillna(0)
y = df["label"]
attack_types = df["attack_type"]

print(f"\nFeatures sélectionnées : {len(FEATURES)}")
print(f"Shape dataset : {X.shape}")

# ─── 2.7 Normalisation ───────────────────────────────────────────────────────
print("\n[2.7] Normalisation StandardScaler...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ─── 2.8 Split train/test stratifié ──────────────────────────────────────────
print("[2.8] Split train (80%) / test (20%) stratifié...")
X_train, X_test, y_train, y_test, at_train, at_test = train_test_split(
    X_scaled, y, attack_types,
    test_size=0.2, random_state=42, stratify=y
)
print(f"  Train : {X_train.shape[0]} samples ({y_train.sum()} anomalies)")
print(f"  Test  : {X_test.shape[0]} samples ({y_test.sum()} anomalies)")

# ─── Sauvegarde ──────────────────────────────────────────────────────────────
np.save("/home/claude/ad_anomaly/data/X_train.npy", X_train)
np.save("/home/claude/ad_anomaly/data/X_test.npy",  X_test)
np.save("/home/claude/ad_anomaly/data/y_train.npy", y_train.values)
np.save("/home/claude/ad_anomaly/data/y_test.npy",  y_test.values)
np.save("/home/claude/ad_anomaly/data/at_test.npy", at_test.values)

with open("/home/claude/ad_anomaly/models/scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)
with open("/home/claude/ad_anomaly/models/feature_names.pkl", "wb") as f:
    pickle.dump(FEATURES, f)

df.to_csv("/home/claude/ad_anomaly/data/ad_logs_engineered.csv", index=False)

print("\n✓ Preprocessing terminé. Fichiers sauvegardés.")

# ─── Statistiques descriptives ───────────────────────────────────────────────
print("\n─── Statistiques par classe ──────────────────────────────")
for label, name in [(0, "Normal"), (1, "Malveillant")]:
    subset = df[df["label"] == label]
    print(f"\n{name} (n={len(subset)}):")
    print(f"  risk_score moyen  : {subset['risk_score'].mean():.3f}")
    print(f"  off_hours moyen   : {subset['off_hours'].mean():.2f}")
    print(f"  is_dc_target moy  : {subset['is_dc_target'].mean():.2f}")
    print(f"  failure_count moy : {subset['failure_count_1h'].mean():.1f}")
