"""
AD Anomaly Detection - Prototype ML Pipeline
Détection supervisée et non supervisée d'attaques Active Directory
Datasets: Mordor Project (Empire + PurpleSharp)
"""

import json
import os
import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (classification_report, confusion_matrix,
                             roc_auc_score, precision_recall_curve,
                             average_precision_score)
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns

# ──────────────────────────────────────────────
# 1. CHARGEMENT DES DONNÉES
# ──────────────────────────────────────────────

DATASET_DIR = "/home/outhmane/Desktop/Projet AD/data"

ATTACK_FILES = {
    "dcsync":               ("empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.json",   "DCSync"),
    "mimikatz":             ("empire_mimikatz_logonpasswords.json",                  "CredDump"),
    "pth":                  ("empire_over_pth_patch_lsass.json",                    "PassTheHash"),
    "rubeus_createnetonly": ("empire_shell_rubeus_asktgt_createnetonly.json",        "KerberosAbuse"),
    "rubeus_ptt":           ("empire_shell_rubeus_asktgt_ptt.json",                 "PassTheTicket"),
    "purplesharp":          ("purplesharp_ad_playbook_I.json",                       "MultiAttack"),
}

def load_jsonl(path):
    records = []
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records

def load_all_datasets():
    frames = []
    for key, (fname, attack_label) in ATTACK_FILES.items():
        path = os.path.join(DATASET_DIR, fname)
        records = load_jsonl(path)
        df = pd.DataFrame(records)
        df['attack_type'] = attack_label
        df['is_malicious'] = 1
        frames.append(df)
        print(f"  [{attack_label:20s}] {len(df):>6,} événements chargés")
    return pd.concat(frames, ignore_index=True)

print("=" * 60)
print("  AD ANOMALY DETECTION — Pipeline ML")
print("=" * 60)
print("\n[1] Chargement des datasets...")
df_raw = load_all_datasets()
print(f"\n  Total : {len(df_raw):,} événements | {df_raw['attack_type'].nunique()} types d'attaques\n")

# ──────────────────────────────────────────────
# 2. FEATURE ENGINEERING
# ──────────────────────────────────────────────

print("[2] Feature Engineering...")

CRITICAL_EVENT_IDS = {
    # Kerberos
    4768: "KerberosTicketRequest",
    4769: "KerberosServiceTicket",
    4771: "KerberosPreAuthFailed",
    # Logon / Logoff
    4624: "SuccessfulLogon",
    4625: "FailedLogon",
    4634: "Logoff",
    4672: "PrivilegedLogon",
    4673: "PrivilegedServiceCalled",
    # Process
    4688: "ProcessCreation",
    4689: "ProcessTermination",
    # Object / LSASS
    4656: "ObjectHandleRequested",
    4663: "ObjectAccess",
    4662: "DirectoryServiceAccess",
    # Sysmon
    1:    "Sysmon_ProcessCreate",
    3:    "Sysmon_NetworkConn",
    10:   "Sysmon_ProcessAccess",
    # PowerShell
    4103: "PSModuleLogging",
    4104: "PSScriptBlock",
    800:  "PSPipelineExecution",
    # Network
    5156: "NetworkPermitted",
    5140: "NetworkShareAccess",
    5145: "NetworkShareCheck",
}

HIGH_VALUE_TARGETS = {'lsass.exe', 'ntds.dit', 'sam', 'system', 'security'}

def engineer_features(df):
    fe = pd.DataFrame()

    # --- Identifiants temporels ---
    df['EventTime'] = pd.to_datetime(df.get('EventTime', pd.NaT), errors='coerce')
    fe['hour'] = df['EventTime'].dt.hour.fillna(-1).astype(int)
    fe['is_night'] = ((fe['hour'] >= 22) | (fe['hour'] <= 5)).astype(int)
    fe['is_weekend'] = df['EventTime'].dt.dayofweek.fillna(0).isin([5, 6]).astype(int)

    # --- EventID et criticité ---
    fe['event_id'] = pd.to_numeric(df.get('EventID', 0), errors='coerce').fillna(0).astype(int)
    fe['is_critical_event'] = fe['event_id'].isin(CRITICAL_EVENT_IDS.keys()).astype(int)

    # Regroupement sémantique des EventIDs
    fe['event_kerberos']   = fe['event_id'].isin([4768, 4769, 4771, 4776]).astype(int)
    fe['event_logon']      = fe['event_id'].isin([4624, 4625, 4634, 4672, 4673]).astype(int)
    fe['event_process']    = fe['event_id'].isin([4688, 4689, 1]).astype(int)
    fe['event_lsass']      = fe['event_id'].isin([10, 4656, 4662, 4663]).astype(int)
    fe['event_powershell'] = fe['event_id'].isin([4103, 4104, 800, 600, 400]).astype(int)
    fe['event_network']    = fe['event_id'].isin([3, 5156, 5140, 5145]).astype(int)

    # --- Accès LSASS (Pass-the-Hash, Mimikatz) ---
    target_img = df.get('TargetImage', pd.Series([''] * len(df))).fillna('').str.lower()
    fe['targets_lsass'] = target_img.str.contains('lsass', regex=False).astype(int)

    granted = df.get('GrantedAccess', pd.Series([''] * len(df))).fillna('').astype(str)
    SENSITIVE_ACCESS = {'0x1010', '0x1410', '0x143a', '0x1038', '0x40', '0x1fffff'}
    fe['sensitive_granted_access'] = granted.isin(SENSITIVE_ACCESS).astype(int)

    # --- Activité PowerShell suspecte ---
    message = df.get('Message', pd.Series([''] * len(df))).fillna('').str.lower()
    ps_keywords = ['invoke-mimikatz', 'invoke-expression', 'bypass', '-enc ', '-encoded',
                   'downloadstring', 'iex(', 'base64', 'rubeus', 'sekurlsa', 'dcsync']
    fe['ps_suspicious'] = message.apply(
        lambda m: int(any(kw in m for kw in ps_keywords))
    )

    # --- DCSync (réplication DS) ---
    fe['dcsync_op'] = (
        df.get('EventID', 0).astype(str).isin(['4662', '5859'])
        & message.str.contains('1131f6aa|1131f6ad|89e95b76|ds-replication', regex=True, case=False)
    ).astype(int)

    # --- Kerberos : TGT anormal (Rubeus) ---
    fe['kerberos_tgt_request'] = fe['event_id'].isin([4768]).astype(int)
    fe['kerberos_service_ticket'] = fe['event_id'].isin([4769]).astype(int)
    preauth = df.get('PreAuthType', pd.Series([''] * len(df))).fillna('').astype(str)
    fe['kerberos_nopreauth'] = preauth.eq('0').astype(int)

    # --- Mouvement latéral réseau ---
    dest_port = pd.to_numeric(df.get('DestPort', 0), errors='coerce').fillna(0)
    fe['lateral_smb']      = (dest_port == 445).astype(int)
    fe['lateral_kerberos'] = (dest_port == 88).astype(int)
    fe['lateral_ldap']     = (dest_port.isin([389, 636])).astype(int)
    fe['lateral_rdp']      = (dest_port == 3389).astype(int)
    fe['lateral_wmi']      = (dest_port == 135).astype(int)

    # --- Privilege escalation ---
    fe['privileged_logon'] = fe['event_id'].isin([4672, 4673]).astype(int)
    fe['is_system_account'] = (
        df.get('AccountName', pd.Series([''] * len(df))).fillna('').str.upper()
        .isin(['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE'])
    ).astype(int)

    # --- Canal source ---
    channel = df.get('Channel', pd.Series([''] * len(df))).fillna('').str.lower()
    fe['channel_security']   = channel.str.contains('security', regex=False).astype(int)
    fe['channel_sysmon']     = channel.str.contains('sysmon', regex=False).astype(int)
    fe['channel_powershell'] = channel.str.contains('powershell', regex=False).astype(int)

    # --- Score de criticité composite ---
    fe['risk_score'] = (
        fe['is_critical_event'] * 2 +
        fe['targets_lsass'] * 3 +
        fe['sensitive_granted_access'] * 3 +
        fe['ps_suspicious'] * 4 +
        fe['dcsync_op'] * 5 +
        fe['kerberos_nopreauth'] * 2 +
        fe['privileged_logon'] * 2 +
        (fe['lateral_smb'] | fe['lateral_kerberos'] | fe['lateral_rdp']).astype(int) * 2
    )

    return fe

df_feat = engineer_features(df_raw)
FEATURES = df_feat.columns.tolist()
print(f"  {len(FEATURES)} features construites")

# ──────────────────────────────────────────────
# 3. PRÉPARATION SUPERVISÉE  (RF)
# ──────────────────────────────────────────────

print("\n[3] Modèle supervisé : Random Forest multi-classe...")

# On crée des pseudo-"normaux" via perturbation des événements bas-risque
normal_mask = df_feat['risk_score'] < 1
normal_df = df_feat[normal_mask].copy()
normal_df_shuffled = normal_df.sample(frac=1, random_state=42)

# Labels : 0 = normal, 1-6 = types d'attaques
le = LabelEncoder()
labels_attack = le.fit_transform(df_raw['attack_type'])

# Dataset complet : attaques (labeled) + quelques normaux (label 0 = "Normal")
X_attack = df_feat.values
y_attack = labels_attack + 1  # 1..6

n_normal = min(len(normal_df), 8000)
X_normal = normal_df.sample(n_normal, random_state=42).values
y_normal = np.zeros(n_normal, dtype=int)

X = np.vstack([X_attack, X_normal])
y = np.concatenate([y_attack, y_normal])

class_names = ['Normal'] + list(le.classes_)

scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

X_tr, X_te, y_tr, y_te = train_test_split(X_scaled, y, test_size=0.25,
                                            random_state=42, stratify=y)

rf = RandomForestClassifier(n_estimators=200, max_depth=20, n_jobs=-1,
                            class_weight='balanced', random_state=42)
rf.fit(X_tr, y_tr)
y_pred = rf.predict(X_te)
y_prob = rf.predict_proba(X_te)

print("\n  Classification Report (Random Forest):")
print(classification_report(y_te, y_pred, target_names=class_names, zero_division=0))

cv_scores = cross_val_score(rf, X_scaled[:5000], y[:5000], cv=5, scoring='f1_macro', n_jobs=-1)
print(f"  Cross-validation F1-macro : {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")

# ──────────────────────────────────────────────
# 4. MODÈLE NON SUPERVISÉ : Isolation Forest
# ──────────────────────────────────────────────

print("\n[4] Modèle non supervisé : Isolation Forest...")

X_attack_only = scaler.transform(df_feat.values)

iforest = IsolationForest(n_estimators=300, contamination=0.15,
                           random_state=42, n_jobs=-1)
iforest.fit(X_attack_only)
anomaly_scores = -iforest.score_samples(X_attack_only)  # plus haut = plus anormal
anomaly_labels = iforest.predict(X_attack_only)  # -1 = anomalie

n_anomalies = (anomaly_labels == -1).sum()
pct = n_anomalies / len(anomaly_labels) * 100
print(f"  Anomalies détectées : {n_anomalies:,} / {len(anomaly_labels):,} ({pct:.1f}%)")

df_raw['anomaly_score'] = anomaly_scores
df_raw['is_anomaly_iforest'] = (anomaly_labels == -1).astype(int)

# Top anomalies par type d'attaque
print("\n  Taux de détection Isolation Forest par type d'attaque :")
agg = df_raw.groupby('attack_type')['is_anomaly_iforest'].agg(['mean', 'sum', 'count'])
agg.columns = ['Taux', 'Détectés', 'Total']
agg['Taux'] = (agg['Taux'] * 100).round(1).astype(str) + '%'
print(agg.to_string())

# ──────────────────────────────────────────────
# 5. MOTEUR D'ALERTES
# ──────────────────────────────────────────────

print("\n[5] Génération des alertes...")

ALERT_RULES = [
    {
        'name': 'DCSync Detected',
        'severity': 'CRITICAL',
        'technique': 'T1003.006',
        'condition': lambda df, fe: (fe['dcsync_op'] == 1),
        'description': 'Réplication DS non autorisée détectée (DsGetNCChanges)',
    },
    {
        'name': 'LSASS Memory Access',
        'severity': 'HIGH',
        'technique': 'T1003.001',
        'condition': lambda df, fe: (fe['targets_lsass'] == 1) & (fe['sensitive_granted_access'] == 1),
        'description': 'Accès mémoire LSASS avec droits sensibles (Mimikatz/PTH)',
    },
    {
        'name': 'Suspicious PowerShell Execution',
        'severity': 'HIGH',
        'technique': 'T1059.001',
        'condition': lambda df, fe: (fe['ps_suspicious'] == 1),
        'description': 'Exécution PowerShell suspecte (encoding, bypass, keywords malveillants)',
    },
    {
        'name': 'Kerberos TGT Anomaly (Rubeus)',
        'severity': 'HIGH',
        'technique': 'T1558.003',
        'condition': lambda df, fe: (fe['kerberos_tgt_request'] == 1) & (fe['is_night'] == 1),
        'description': 'Requête TGT Kerberos hors horaires normaux (Pass-the-Ticket possible)',
    },
    {
        'name': 'Privileged Logon Off-Hours',
        'severity': 'MEDIUM',
        'technique': 'T1078',
        'condition': lambda df, fe: (fe['privileged_logon'] == 1) & (fe['is_night'] == 1),
        'description': 'Connexion privilégiée en dehors des heures de travail',
    },
    {
        'name': 'Lateral Movement via SMB/Kerberos',
        'severity': 'MEDIUM',
        'technique': 'T1021',
        'condition': lambda df, fe: (fe['lateral_smb'] == 1) | (fe['lateral_kerberos'] == 1),
        'description': 'Connexion réseau SMB/Kerberos suspecte (mouvement latéral potentiel)',
    },
    {
        'name': 'IsolationForest Anomaly',
        'severity': 'LOW',
        'technique': 'ML-Unsupervised',
        'condition': lambda df, fe: (df['is_anomaly_iforest'] == 1),
        'description': 'Comportement statistiquement anormal détecté par Isolation Forest',
    },
]

alerts = []
for rule in ALERT_RULES:
    mask = rule['condition'](df_raw, df_feat)
    matched = df_raw[mask]
    for _, row in matched.head(3).iterrows():
        alerts.append({
            'Alert':       rule['name'],
            'Severity':    rule['severity'],
            'Technique':   rule['technique'],
            'AttackType':  row.get('attack_type', '?'),
            'EventID':     row.get('EventID', '?'),
            'Host':        row.get('Hostname', row.get('host', '?')),
            'Time':        row.get('EventTime', '?'),
            'Description': rule['description'],
            'Count':       int(mask.sum()),
        })

df_alerts = pd.DataFrame(alerts).drop_duplicates(subset=['Alert', 'AttackType'])
print(f"\n  {len(df_alerts)} alertes générées\n")
severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
for sev in severity_order:
    subset = df_alerts[df_alerts['Severity'] == sev]
    if not subset.empty:
        print(f"  [{sev}]")
        for _, a in subset.iterrows():
            print(f"    • {a['Alert']} — {a['Count']:,} événements ({a['Technique']})")

# ──────────────────────────────────────────────
# 6. ÉVALUATION FAUX POSITIFS
# ──────────────────────────────────────────────

print("\n[6] Évaluation du taux de faux positifs...")

# On simule un jeu de test avec des normaux synthétiques (faible risk_score)
normal_test_mask = df_feat['risk_score'] == 0
FP_count = df_raw[normal_test_mask & (df_raw['is_anomaly_iforest'] == 1)].shape[0]
TN_count = df_raw[normal_test_mask & (df_raw['is_anomaly_iforest'] == 0)].shape[0]
FP_rate = FP_count / (FP_count + TN_count) if (FP_count + TN_count) > 0 else 0

print(f"  Événements bas-risque (risk_score=0) : {normal_test_mask.sum():,}")
print(f"  Faux positifs Isolation Forest      : {FP_count:,}")
print(f"  Taux de faux positifs estimé        : {FP_rate:.2%}")

rf_fp = ((y_pred != 0) & (y_te == 0)).sum()
rf_tn = ((y_pred == 0) & (y_te == 0)).sum()
rf_fp_rate = rf_fp / (rf_fp + rf_tn) if (rf_fp + rf_tn) > 0 else 0
print(f"  Faux positifs Random Forest (test)  : {rf_fp} / {rf_fp + rf_tn}")
print(f"  Taux de faux positifs RF            : {rf_fp_rate:.2%}")

# ──────────────────────────────────────────────
# 7. VISUALISATIONS
# ──────────────────────────────────────────────

print("\n[7] Génération des visualisations...")

plt.style.use('dark_background')
COLORS = {
    'bg':       '#0d1117',
    'panel':    '#161b22',
    'accent':   '#58a6ff',
    'red':      '#f85149',
    'green':    '#3fb950',
    'yellow':   '#d29922',
    'purple':   '#bc8cff',
    'orange':   '#ffa657',
    'grid':     '#21262d',
    'text':     '#c9d1d9',
}

attack_palette = {
    'DCSync':        '#f85149',
    'CredDump':      '#ffa657',
    'PassTheHash':   '#d29922',
    'KerberosAbuse': '#bc8cff',
    'PassTheTicket': '#58a6ff',
    'MultiAttack':   '#3fb950',
}

fig = plt.figure(figsize=(20, 24), facecolor=COLORS['bg'])
gs = gridspec.GridSpec(4, 2, figure=fig, hspace=0.45, wspace=0.35,
                       left=0.07, right=0.97, top=0.94, bottom=0.05)

fig.suptitle('Active Directory — Tableau de Bord Détection d\'Anomalies ML',
             fontsize=18, fontweight='bold', color=COLORS['text'], y=0.97)

# ── Plot 1 : Distribution des EventIDs critiques ──
ax1 = fig.add_subplot(gs[0, 0])
ax1.set_facecolor(COLORS['panel'])
top_events = df_raw[df_raw['EventID'].isin(CRITICAL_EVENT_IDS.keys())] \
    .groupby(['EventID', 'attack_type']).size().unstack(fill_value=0)
top_events_sum = top_events.sum(axis=1).nlargest(12)
top_events = top_events.loc[top_events_sum.index]
colors_bar = [attack_palette.get(c, '#58a6ff') for c in top_events.columns]
bottom = np.zeros(len(top_events))
for col, color in zip(top_events.columns, colors_bar):
    ax1.barh(top_events.index.astype(str), top_events[col], left=bottom,
             color=color, label=col, alpha=0.9)
    bottom += top_events[col].values
ax1.set_xlabel('Nombre d\'événements', color=COLORS['text'])
ax1.set_title('Top EventIDs critiques par type d\'attaque', color=COLORS['text'], fontweight='bold')
ax1.tick_params(colors=COLORS['text'])
ax1.spines['bottom'].set_color(COLORS['grid'])
ax1.spines['left'].set_color(COLORS['grid'])
for s in ['top', 'right']:
    ax1.spines[s].set_visible(False)
ax1.legend(fontsize=7, loc='lower right',
           labelcolor=COLORS['text'], facecolor=COLORS['bg'])
# Ajout labels EventID
event_labels = {str(k): v for k, v in CRITICAL_EVENT_IDS.items()}
ax1.set_yticklabels([f"{eid}\n{event_labels.get(eid, '')}" for eid in top_events.index.astype(str)],
                     fontsize=7, color=COLORS['text'])

# ── Plot 2 : Risk Score distribution par attaque ──
ax2 = fig.add_subplot(gs[0, 1])
ax2.set_facecolor(COLORS['panel'])
df_raw['risk_score'] = df_feat['risk_score'].values
for atype, color in attack_palette.items():
    sub = df_raw[df_raw['attack_type'] == atype]['risk_score']
    ax2.hist(sub, bins=30, alpha=0.6, color=color, label=atype, density=True)
ax2.axvline(x=5, color=COLORS['red'], linestyle='--', linewidth=1.5, label='Seuil alerte')
ax2.set_xlabel('Risk Score composite', color=COLORS['text'])
ax2.set_ylabel('Densité', color=COLORS['text'])
ax2.set_title('Distribution du Risk Score par type d\'attaque', color=COLORS['text'], fontweight='bold')
ax2.tick_params(colors=COLORS['text'])
for s in ['top', 'right']:
    ax2.spines[s].set_visible(False)
ax2.spines['bottom'].set_color(COLORS['grid'])
ax2.spines['left'].set_color(COLORS['grid'])
ax2.legend(fontsize=7, labelcolor=COLORS['text'], facecolor=COLORS['bg'])

# ── Plot 3 : Heatmap Confusion Matrix RF ──
ax3 = fig.add_subplot(gs[1, 0])
ax3.set_facecolor(COLORS['panel'])
# Sélection des classes présentes
present = sorted(set(y_te) | set(y_pred))
present_names = [class_names[i] for i in present]
cm = confusion_matrix(y_te, y_pred, labels=present)
cm_norm = cm.astype(float) / cm.sum(axis=1, keepdims=True)
im = ax3.imshow(cm_norm, cmap='Blues', aspect='auto', vmin=0, vmax=1)
plt.colorbar(im, ax=ax3)
ax3.set_xticks(range(len(present_names)))
ax3.set_yticks(range(len(present_names)))
ax3.set_xticklabels(present_names, rotation=35, ha='right', fontsize=7, color=COLORS['text'])
ax3.set_yticklabels(present_names, fontsize=7, color=COLORS['text'])
for i in range(len(present)):
    for j in range(len(present)):
        ax3.text(j, i, f'{cm_norm[i,j]:.2f}', ha='center', va='center',
                 fontsize=6, color='white' if cm_norm[i,j] > 0.5 else 'black')
ax3.set_title('Matrice de Confusion — Random Forest (normalisée)', color=COLORS['text'], fontweight='bold')
ax3.set_xlabel('Prédit', color=COLORS['text'])
ax3.set_ylabel('Réel', color=COLORS['text'])

# ── Plot 4 : Feature Importance ──
ax4 = fig.add_subplot(gs[1, 1])
ax4.set_facecolor(COLORS['panel'])
importances = rf.feature_importances_
feat_imp = pd.Series(importances, index=FEATURES).nlargest(15)
colors_imp = [COLORS['accent'] if v > feat_imp.median() else COLORS['purple'] for v in feat_imp.values]
ax4.barh(feat_imp.index, feat_imp.values, color=colors_imp, alpha=0.9)
ax4.set_xlabel('Importance', color=COLORS['text'])
ax4.set_title('Top 15 Features — Random Forest', color=COLORS['text'], fontweight='bold')
ax4.tick_params(colors=COLORS['text'])
ax4.set_yticklabels(feat_imp.index, fontsize=8, color=COLORS['text'])
for s in ['top', 'right']:
    ax4.spines[s].set_visible(False)
ax4.spines['bottom'].set_color(COLORS['grid'])
ax4.spines['left'].set_color(COLORS['grid'])

# ── Plot 5 : Anomaly Score par attaque (Isolation Forest) ──
ax5 = fig.add_subplot(gs[2, 0])
ax5.set_facecolor(COLORS['panel'])
atype_order = list(attack_palette.keys())
scores_by_type = [df_raw[df_raw['attack_type'] == a]['anomaly_score'].values for a in atype_order]
bp = ax5.boxplot(scores_by_type, patch_artist=True, notch=False,
                  medianprops=dict(color='white', linewidth=2))
for patch, atype in zip(bp['boxes'], atype_order):
    patch.set_facecolor(attack_palette[atype])
    patch.set_alpha(0.7)
ax5.set_xticklabels(atype_order, rotation=25, ha='right', fontsize=7, color=COLORS['text'])
ax5.set_ylabel('Anomaly Score', color=COLORS['text'])
ax5.set_title('Distribution Anomaly Score (Isolation Forest)', color=COLORS['text'], fontweight='bold')
ax5.tick_params(colors=COLORS['text'])
for s in ['top', 'right']:
    ax5.spines[s].set_visible(False)
ax5.spines['bottom'].set_color(COLORS['grid'])
ax5.spines['left'].set_color(COLORS['grid'])

# ── Plot 6 : Alertes par sévérité ──
ax6 = fig.add_subplot(gs[2, 1])
ax6.set_facecolor(COLORS['panel'])
sev_colors = {'CRITICAL': COLORS['red'], 'HIGH': COLORS['orange'],
              'MEDIUM': COLORS['yellow'], 'LOW': COLORS['green']}
alert_counts = {}
for rule in ALERT_RULES:
    mask = rule['condition'](df_raw, df_feat)
    alert_counts[rule['name']] = {
        'count': int(mask.sum()),
        'severity': rule['severity']
    }
alert_df = pd.DataFrame(alert_counts).T.sort_values('count', ascending=True)
alert_df['count'] = alert_df['count'].astype(int)
bar_colors = [sev_colors[s] for s in alert_df['severity']]
bars = ax6.barh(alert_df.index, alert_df['count'], color=bar_colors, alpha=0.85)
for bar, (name, row) in zip(bars, alert_df.iterrows()):
    ax6.text(bar.get_width() + 50, bar.get_y() + bar.get_height()/2,
             f"{int(row['count']):,}", va='center', fontsize=7, color=COLORS['text'])
ax6.set_xlabel('Événements déclenchés', color=COLORS['text'])
ax6.set_title('Alertes déclenchées par règle (avec sévérité)', color=COLORS['text'], fontweight='bold')
ax6.tick_params(colors=COLORS['text'])
ax6.set_yticklabels(alert_df.index, fontsize=7, color=COLORS['text'])
for s in ['top', 'right']:
    ax6.spines[s].set_visible(False)
ax6.spines['bottom'].set_color(COLORS['grid'])
ax6.spines['left'].set_color(COLORS['grid'])
# Légende sévérité
from matplotlib.patches import Patch
legend_patches = [Patch(color=c, label=s) for s, c in sev_colors.items()]
ax6.legend(handles=legend_patches, fontsize=7, loc='lower right',
           labelcolor=COLORS['text'], facecolor=COLORS['bg'])

# ── Plot 7 : Timeline des événements par attaque ──
ax7 = fig.add_subplot(gs[3, :])
ax7.set_facecolor(COLORS['panel'])
df_raw['EventTime_dt'] = pd.to_datetime(df_raw['EventTime'], errors='coerce')
df_timeline = df_raw.dropna(subset=['EventTime_dt'])
df_timeline = df_timeline.set_index('EventTime_dt').sort_index()
for atype, color in attack_palette.items():
    sub = df_timeline[df_timeline['attack_type'] == atype]
    if not sub.empty:
        resampled = sub.resample('5min').size()
        ax7.fill_between(resampled.index, resampled.values, alpha=0.4, color=color, label=atype)
        ax7.plot(resampled.index, resampled.values, color=color, linewidth=0.8, alpha=0.8)
ax7.set_xlabel('Temps', color=COLORS['text'])
ax7.set_ylabel('Événements / 5min', color=COLORS['text'])
ax7.set_title('Timeline des événements — Toutes attaques (fenêtre 5 minutes)',
              color=COLORS['text'], fontweight='bold')
ax7.tick_params(colors=COLORS['text'])
for s in ['top', 'right']:
    ax7.spines[s].set_visible(False)
ax7.spines['bottom'].set_color(COLORS['grid'])
ax7.spines['left'].set_color(COLORS['grid'])
ax7.legend(fontsize=8, labelcolor=COLORS['text'], facecolor=COLORS['bg'])

plt.savefig('home/outhmane/Desktop/Projet AD/ad_detection_dashboard.png',
            dpi=150, bbox_inches='tight', facecolor=COLORS['bg'])
plt.close()
print("  Dashboard sauvegardé : ad_detection_dashboard.png")

# ──────────────────────────────────────────────
# 8. RAPPORT SYNTHÈSE
# ──────────────────────────────────────────────

print("\n" + "=" * 60)
print("  RÉSUMÉ — PROTOTYPE DE DÉTECTION AD")
print("=" * 60)
print(f"  Données        : {len(df_raw):,} événements | 6 scénarios d'attaque")
print(f"  Features       : {len(FEATURES)} indicateurs construits")
print(f"  RF F1-macro CV : {cv_scores.mean():.3f} ± {cv_scores.std():.3f}")
print(f"  RF FP rate     : {rf_fp_rate:.2%}")
print(f"  IForest FP rate: {FP_rate:.2%}")
print(f"  Alertes règles : {len(df_alerts)} types d'alertes actives")
print("=" * 60)
print("\nPrototype prêt. Dashboard exporté.\n")
