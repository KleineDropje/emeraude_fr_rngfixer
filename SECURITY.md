# Sécurité

## Signaler un problème

N’ouvrez pas de ticket public si votre rapport contient des données protégées, une ROM, une sauvegarde personnelle ou un chemin révélant des informations privées. Utilisez le signalement privé de vulnérabilité GitHub s’il est activé ; sinon, retirez ces données avant tout rapport public.

Ne joignez jamais de ROM .gba, même pour reproduire un problème. Fournissez uniquement les empreintes, la taille du fichier, le système, la version de Python et le message d’erreur complet après suppression des chemins personnels.

## Garanties attendues

Une modification ne doit pas affaiblir les contrôles suivants :

- reconnaissance exacte de la ROM française prise en charge ;
- ouverture de la source en lecture seule ;
- aucune écriture en place et aucun écrasement de fichier existant ;
- contrôle des offsets avant application ;
- validation cryptographique du résultat avant et après écriture ;
- aucune communication réseau.

Les empreintes MD5 et SHA-1 servent ici à identifier des fichiers connus, pas à assurer une sécurité cryptographique générale.
