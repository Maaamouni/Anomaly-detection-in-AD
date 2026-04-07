# Détection d'anomalies AD
le sujet cible 3 types d'attaques AD : 
- password spraying
- escalade de privilèges
- mouvement latéral.

1 - NTDS Dumping :

technique utilise en cs pour extraire les motes de passe des utilisateurs d'un domaine Windows, il vient de NTDS.dit (fichier tres important dans AD, il contient user account, mdp sous forme de hash, groups et permissions)
plus precisament, NTDS dumping c'est copier et extraire le contenur de fichier NTDS.dit pour recuperer les hash de mdp..
l'outil qui est tres utilise pour NTDS Dumping c'est : mimikatz.

2 - DCSync :

attaque ou un attaquant fait semblant d'etre un controleur de domainde pour demander les mos de passe a un vrai serveur, DCs se synchronisent entre eux, ils echangent les mdp (hashs) avec DCSync, attaquant limite un DC.

3 - Lateral Mouvement (PsExec) :

apres le systeme est compromis , l'attaquant fait un mouvement lateral pour passer d'une machine a une autre, il utilise souvent PsExec.


purplesharp_ad_playbook_I.zip : dataset est un playbook complet AD qui inclut kerberoasting, enumeration de partages, brute force et execution WinRM sur le reseau
datasets/compound/windows/apt3/ : dossier qui contient des scenrios d'attaque complets en plusieurs etapes qui simulent un vrai acteur malveillant, il donne sequenece d'evenement plus realiste pour entrainer le modele.

## Etape 1 : Extraction des donnes

Datasets :
- **empire_shell_rubeus_asktgt_ptt** : pass-the-ticket Kerberos - demande TGT + injection ticket - escalade de privileges
- **empire_dcsync_dcerpc_drsuapi_DsGetNCChanges** : DCSync - extraction hashes NTLM via replication AD - privileges Domain Admin
- **empire_mimikatz_logonpasswords** : Mimikatz dump memoire LSASS - vol credentials, Sysmon EventId 10
- **empire_shell_rubeus_asktgt_createnetonly** : Rubeus CreateNetOnly — session Kerberos isolée pour mouvement latéral furtif
- **purplesharp_ad_playbook_I** : playbook complet AD - kerberoasting + brute force + WinRM - sequence realistes.
- **empire_over_pth_patch_lsass** : C'est une variante avancée du classique "Pass-the-Hash".

Difference entre Pass the hash & Overpass-the-hash :
Pass-the-Hash (PtH): Utilise le hash NTLM pour s'authentifier via le protocole NTLM directement.
Overpass-the-Hash (OPtH): Utilise le hash NTLM pour forger un ticket Kerberos (TGT), puis s'authentifie via Kerberos


LSASS (Local Security Authority Subsystem Service) est un processus système critique de Windows (lsass.exe) chargé de gérer la sécurité locale, l'authentification des utilisateurs (connexion), la vérification des mots de passe et la création des jetons d'accès. Situé dans C:\Windows\System32, il est essentiel au fonctionnement du système et gère aussi les politiques de sécurité (journalisation, verrouillage de compte).

Fichier     Label   Événements

empire_dcsync...DCSync  8 65
empire_mimikatz...CredDump  6026
empire_over_pth...PassTheHash   10271
empire_shell_rubeus_createnetonly...KerberosAbuse   3590
empire_shell_rubeus_ptt...PassTheTicket 1179
purplesharp_ad_playbook_I...MultiAttack 25993
il n'y a pas de data normale

## Etape 2 : Feature engineering 
on construit 29 variables numeriques.
- Temporelles :
hour : heure de l'evenement
is_night : 1 si entre 22h et 5h
is_weekend : 1 si samedi ou dimanche
- groupes d'Event IDs :
event_kerberos :
event_logon :
event_lsass : 
event_powershell :
event_network :

risk score composite :
risk_score = is_critical_event * 2 + targets_lsass*3 + ps_sus * 4 + dcsync_op * 5 + ...

modele supervise : random forest

Problème : tous mes événements sont malveillants. Pour entraîner un classifieur supervisé, il faut aussi des exemples "normaux". J'ai créé des pseudo-normaux en prenant les événements avec risk_score = 0 (bas risque) et je leur ai assigné le label 0 = "Normal" (8 000 tirés aléatoirement).
Ce que le RF apprend : distinguer 7 classes — Normal, DCSync, CredDump, PassTheHash, KerberosAbuse, PassTheTicket, MultiAttack.

modele non supervise : isolation forest
pas besoin de labels
contamination=0.15 (15% des eveneemnts sont des anomalies fortes)

Moteur d'alertes :

7 règles déterministes qui combinent les features construites à l'étape 2 :

Si targets_lsass=1 ET sensitive_granted_access=1 → alerte HIGH (T1003.001)
Si ps_suspicious=1 → alerte HIGH (T1059.001) — déclenche 7 804 fois
Si dcsync_op=1 → alerte CRITICAL (T1003.006)
Si kerberos_tgt_request=1 ET is_night=1 → alerte HIGH
Si is_anomaly_iforest=1 → alerte LOW

evaluation des fau positifs
Random forest : FP = 97 mauvais
Isolation forest : f= 6.61 acceptable, sans labels il generalise mieux

Ils nous manquent un scenario AD reel sans attaque

-----------