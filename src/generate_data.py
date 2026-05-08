import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import json

np.random.seed(42)
random.seed(42)

# ─── Paramètres de simulation ───────────────────────────────────────────────
N_USERS         = 80       # utilisateurs légitimes
N_WORKSTATIONS  = 50
N_SERVERS       = 15
N_DCS           = 3        # Domain Controllers
N_NORMAL_LOGS   = 4000
N_ATTACK_LOGS   = 300      # logs malveillants (7% du total)
START_DATE      = datetime(2024, 11, 1, 6, 0, 0)
DAYS            = 30

# ─── Infrastructure AD simulée ───────────────────────────────────────────────
DOMAINS        = ["CORP.LOCAL", "CORP"]
USERS          = [f"user{str(i).zfill(3)}" for i in range(1, N_USERS+1)]
SVC_ACCOUNTS   = ["svc_backup", "svc_sql", "svc_web", "svc_print", "svc_monitor"]
ADMINS         = ["admin_it", "admin_sec", "admin_dc"]
ALL_USERS      = USERS + SVC_ACCOUNTS + ADMINS

WORKSTATIONS   = [f"WS{str(i).zfill(3)}" for i in range(1, N_WORKSTATIONS+1)]
SERVERS        = [f"SRV{str(i).zfill(3)}" for i in range(1, N_SERVERS+1)]
DCS            = [f"DC{str(i).zfill(2)}"  for i in range(1, N_DCS+1)]
ALL_HOSTS      = WORKSTATIONS + SERVERS + DCS

INTERNAL_IPS   = [f"192.168.{random.randint(1,10)}.{random.randint(1,254)}" for _ in range(60)]
EXTERNAL_IPS   = [f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}" for _ in range(20)]

# Event IDs Windows Security Log
EVENT_IDS = {
    4624: "Successful Logon",
    4625: "Failed Logon",
    4648: "Logon using explicit credentials",
    4672: "Special privileges assigned",
    4768: "Kerberos TGT Request",
    4769: "Kerberos Service Ticket Request",
    4776: "NTLM Authentication",
    4720: "User Account Created",
    4728: "Member Added to Security Group",
    4732: "Member Added to Local Group",
    4756: "Member Added to Universal Group",
}

LOGON_TYPES = {
    2: "Interactive",
    3: "Network",
    4: "Batch",
    5: "Service",
    7: "Unlock",
    8: "NetworkCleartext",
    9: "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
}

# ─── Fonctions de génération ─────────────────────────────────────────────────

def business_hour():
    """Heure dans les horaires de bureau (8h-18h, lundi-vendredi)"""
    day_offset = random.randint(0, DAYS-1)
    base = START_DATE + timedelta(days=day_offset)
    # forcer jour ouvrable
    while base.weekday() >= 5:
        base += timedelta(days=1)
    hour = int(np.random.normal(12, 2.5))
    hour = max(8, min(17, hour))
    minute = random.randint(0, 59)
    second = random.randint(0, 59)
    return base.replace(hour=hour, minute=minute, second=second)

def off_hour():
    """Heure hors horaires (nuit / week-end)"""
    day_offset = random.randint(0, DAYS-1)
    base = START_DATE + timedelta(days=day_offset)
    # forcer nuit ou week-end
    if random.random() < 0.5:
        base = base.replace(hour=random.choice(list(range(0,6)) + list(range(22,24))),
                            minute=random.randint(0,59), second=random.randint(0,59))
    else:
        while base.weekday() < 5:
            base += timedelta(days=1)
        base = base.replace(hour=random.randint(0,23),
                            minute=random.randint(0,59), second=random.randint(0,59))
    return base

def make_normal_log():
    """Événement d'authentification normal"""
    user = random.choice(USERS)
    src  = random.choice(WORKSTATIONS)
    dst  = random.choice(WORKSTATIONS + SERVERS[:5])
    ip   = random.choice(INTERNAL_IPS)
    ts   = business_hour()

    return {
        "timestamp":         ts.isoformat(),
        "event_id":          random.choice([4624, 4768, 4769, 4776]),
        "event_name":        EVENT_IDS[4624],
        "username":          user,
        "domain":            "CORP",
        "source_host":       src,
        "dest_host":         dst,
        "source_ip":         ip,
        "logon_type":        random.choice([2, 3, 10]),
        "logon_type_name":   "",
        "failure_count_1h":  0,
        "unique_users_1h":   1,
        "unique_hosts_1h":   random.randint(1, 3),
        "off_hours":         0,
        "is_dc_target":      0,
        "is_admin_account":  0,
        "is_service_acct":   0,
        "privilege_escalation": 0,
        "kerberos_anomaly":  0,
        "attack_type":       "normal",
        "label":             0,
    }

def make_password_spray():
    """
    Password Spraying : un attaquant teste un même mot de passe
    sur de nombreux comptes différents depuis une seule IP
    """
    attacker_ip = random.choice(EXTERNAL_IPS)
    ts_base     = off_hour()
    n_attempts  = random.randint(15, 50)
    targets     = random.sample(USERS, min(n_attempts, len(USERS)))
    logs = []
    for i, target in enumerate(targets):
        ts = ts_base + timedelta(seconds=i * random.randint(2, 8))
        logs.append({
            "timestamp":         ts.isoformat(),
            "event_id":          4625,
            "event_name":        "Failed Logon",
            "username":          target,
            "domain":            "CORP",
            "source_host":       "UNKNOWN",
            "dest_host":         random.choice(DCS),
            "source_ip":         attacker_ip,   # ← même IP pour tous
            "logon_type":        3,
            "logon_type_name":   "Network",
            "failure_count_1h":  i + 1,          # compteur croissant
            "unique_users_1h":   i + 1,           # ← beaucoup d'utilisateurs distincts
            "unique_hosts_1h":   1,
            "off_hours":         1,
            "is_dc_target":      1,
            "is_admin_account":  0,
            "is_service_acct":   0,
            "privilege_escalation": 0,
            "kerberos_anomaly":  0,
            "attack_type":       "password_spraying",
            "label":             1,
        })
    return logs

def make_privilege_escalation():
    """
    Escalade de privilèges : compte compromis ajouté aux Domain Admins
    """
    victim  = random.choice(USERS)
    attacker_host = random.choice(WORKSTATIONS)
    ts      = off_hour()
    logs = []
    # 1. Connexion initiale
    logs.append({
        "timestamp":         ts.isoformat(),
        "event_id":          4624,
        "event_name":        "Successful Logon",
        "username":          victim,
        "domain":            "CORP",
        "source_host":       attacker_host,
        "dest_host":         random.choice(DCS),
        "source_ip":         random.choice(INTERNAL_IPS),
        "logon_type":        3,
        "logon_type_name":   "Network",
        "failure_count_1h":  0,
        "unique_users_1h":   1,
        "unique_hosts_1h":   1,
        "off_hours":         1,
        "is_dc_target":      1,
        "is_admin_account":  0,
        "is_service_acct":   0,
        "privilege_escalation": 1,   # ← flag
        "kerberos_anomaly":  0,
        "attack_type":       "privilege_escalation",
        "label":             1,
    })
    # 2. Ajout au groupe Domain Admins (Event 4728)
    ts2 = ts + timedelta(seconds=random.randint(30, 120))
    logs.append({
        "timestamp":         ts2.isoformat(),
        "event_id":          4728,
        "event_name":        "Member Added to Security Group",
        "username":          victim,
        "domain":            "CORP",
        "source_host":       attacker_host,
        "dest_host":         random.choice(DCS),
        "source_ip":         random.choice(INTERNAL_IPS),
        "logon_type":        3,
        "logon_type_name":   "Network",
        "failure_count_1h":  0,
        "unique_users_1h":   1,
        "unique_hosts_1h":   1,
        "off_hours":         1,
        "is_dc_target":      1,
        "is_admin_account":  1,   # devient admin
        "is_service_acct":   0,
        "privilege_escalation": 1,
        "kerberos_anomaly":  0,
        "attack_type":       "privilege_escalation",
        "label":             1,
    })
    # 3. Attribution de privilèges spéciaux (Event 4672)
    ts3 = ts2 + timedelta(seconds=random.randint(5, 30))
    logs.append({
        "timestamp":         ts3.isoformat(),
        "event_id":          4672,
        "event_name":        "Special Privileges Assigned",
        "username":          victim,
        "domain":            "CORP",
        "source_host":       attacker_host,
        "dest_host":         random.choice(DCS),
        "source_ip":         random.choice(INTERNAL_IPS),
        "logon_type":        3,
        "logon_type_name":   "Network",
        "failure_count_1h":  0,
        "unique_users_1h":   1,
        "unique_hosts_1h":   1,
        "off_hours":         1,
        "is_dc_target":      1,
        "is_admin_account":  1,
        "is_service_acct":   0,
        "privilege_escalation": 1,
        "kerberos_anomaly":  0,
        "attack_type":       "privilege_escalation",
        "label":             1,
    })
    return logs

def make_lateral_movement():
    """
    Mouvement latéral : Pass-the-Hash / connexions RDP/WMI en cascade
    """
    attacker = random.choice(USERS)
    visited  = random.sample(SERVERS + WORKSTATIONS, random.randint(4, 10))
    ts_base  = off_hour()
    logs = []
    for i, host in enumerate(visited):
        ts = ts_base + timedelta(minutes=i * random.randint(2, 15))
        logs.append({
            "timestamp":         ts.isoformat(),
            "event_id":          random.choice([4624, 4648]),
            "event_name":        "Logon using explicit credentials",
            "username":          attacker,
            "domain":            "CORP",
            "source_host":       visited[i-1] if i > 0 else random.choice(WORKSTATIONS),
            "dest_host":         host,          # ← destinations changeantes
            "source_ip":         random.choice(INTERNAL_IPS),
            "logon_type":        random.choice([3, 10]),
            "logon_type_name":   "RemoteInteractive",
            "failure_count_1h":  0,
            "unique_users_1h":   1,
            "unique_hosts_1h":   i + 1,         # ← croît rapidement
            "off_hours":         1,
            "is_dc_target":      1 if host in DCS else 0,
            "is_admin_account":  0,
            "is_service_acct":   0,
            "privilege_escalation": 0,
            "kerberos_anomaly":  0,
            "attack_type":       "lateral_movement",
            "label":             1,
        })
    return logs

def make_kerberoasting():
    """
    Kerberoasting : demandes massives de tickets de service Kerberos
    pour des comptes de service (SPN)
    """
    attacker_ip = random.choice(EXTERNAL_IPS + INTERNAL_IPS)
    ts_base     = off_hour()
    logs = []
    for i, svc in enumerate(SVC_ACCOUNTS):
        ts = ts_base + timedelta(seconds=i * random.randint(1, 5))
        logs.append({
            "timestamp":         ts.isoformat(),
            "event_id":          4769,
            "event_name":        "Kerberos Service Ticket Request",
            "username":          random.choice(USERS),
            "domain":            "CORP",
            "source_host":       "UNKNOWN",
            "dest_host":         random.choice(DCS),
            "source_ip":         attacker_ip,
            "logon_type":        0,
            "logon_type_name":   "Kerberos",
            "failure_count_1h":  0,
            "unique_users_1h":   i + 1,
            "unique_hosts_1h":   1,
            "off_hours":         1,
            "is_dc_target":      1,
            "is_admin_account":  0,
            "is_service_acct":   1,   # ← cible comptes service
            "privilege_escalation": 0,
            "kerberos_anomaly":  1,   # ← anomalie Kerberos
            "attack_type":       "kerberoasting",
            "label":             1,
        })
    return logs

# ─── Construction du dataset ─────────────────────────────────────────────────
print("Génération des logs normaux...")
normal_logs = [make_normal_log() for _ in range(N_NORMAL_LOGS)]

print("Génération des attaques password spraying...")
spray_logs = []
for _ in range(8):   # 8 campagnes de spraying
    spray_logs.extend(make_password_spray())

print("Génération des escalades de privilèges...")
priv_logs = []
for _ in range(10):
    priv_logs.extend(make_privilege_escalation())

print("Génération des mouvements latéraux...")
lat_logs = []
for _ in range(8):
    lat_logs.extend(make_lateral_movement())

print("Génération des attaques Kerberoasting...")
kerb_logs = []
for _ in range(6):
    kerb_logs.extend(make_kerberoasting())

all_logs = normal_logs + spray_logs + priv_logs + lat_logs + kerb_logs
df = pd.DataFrame(all_logs)
df["timestamp"] = pd.to_datetime(df["timestamp"])
df = df.sort_values("timestamp").reset_index(drop=True)
df["logon_type_name"] = df["logon_type"].map(LOGON_TYPES).fillna("Unknown")

print(f"\nDataset généré : {len(df)} entrées")
print(f"  Normaux   : {(df['label']==0).sum()}")
print(f"  Malveillants : {(df['label']==1).sum()}")
print(f"  Taux d'attaque : {df['label'].mean()*100:.1f}%")
print("\nRépartition par type d'attaque :")
print(df['attack_type'].value_counts().to_string())

df.to_csv("../data/ad_logs_raw.csv", index=False)
print("\nFichier sauvegardé : ../data/ad_logs_raw.csv")
