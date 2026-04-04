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

## Etape 2 : Feature engineering 