# Pokémon Émeraude FR — correctif RNG 32-bit RTC+TIMER

Ce projet applique à Pokémon Version Émeraude française un portage minimal du correctif RNG 32-bit RTC+TIMER de MWisBest. Il corrige l’initialisation déficiente du générateur pseudo-aléatoire au démarrage en combinant la RTC et le Timer 1.

Le dépôt ne contient et ne doit contenir **aucune ROM Pokémon**. Vous devez utiliser une ROM française propre obtenue légalement depuis votre propre cartouche.

## Compatibilité et empreintes

Le script refuse toute ROM qui ne correspond pas exactement à la version prise en charge.

| Élément | Taille | Empreinte |
|---|---:|---|
| ROM FR propre requise | 16 777 216 octets | MD5 '2c00e335288a96650e34785b5e2a7588' |
| ROM FR propre requise | 16 777 216 octets | SHA-256 'e79b40e6189550b4870b06918a5c59e04d3a2e1d7c92718aeda92181201f51e4' |
| ROM obtenue | 16 777 216 octets | MD5 'db02a1ba1e3787114dea02547f8515b2' |
| IPS fourni — utilisation facultative | 99 octets | MD5 'a83f62bab34aeed7037e384adf1a95ac' |

Ces empreintes identifient des fichiers précis ; elles ne prouvent ni leur provenance ni votre droit à les utiliser.

#### Méthode 1 — script autonome recommandé

Prérequis : Python 3.9 ou plus récent, sans module supplémentaire.

Le script contient le correctif nécessaire. Il ne dépend pas du fichier IPS et n’utilise pas le réseau.

1. Placez 'emerald_fr_rng_fix.py' où vous voulez.
2. Lancez-le depuis un terminal :

   python3 -I emerald_fr_rng_fix.py

3. Glissez ou collez le chemin de votre ROM .gba française propre, puis validez.

   Vous pouvez aussi donner le chemin directement :

   python3 -I emerald_fr_rng_fix.py "/chemin/vers/Pokemon - Version Emeraude (France).gba"

Sous Windows, la commande peut être 'py -I emerald_fr_rng_fix.py'. Le mode isolé '-I' évite qu’un fichier Python voisin interfère avec les modules standard chargés par le programme.

#### Méthode 2 — IPS manuel facultatif

Le fichier IPS est fourni dans patch/, mais son utilisation est facultative. Il s'adresse uniquement aux utilisateurs qui préfèrent appliquer le correctif eux-mêmes avec un outil IPS compatible.

Nom :

patch/Pokemon Emeraude FR - 32-bit RTC+TIMER RNG Fix.ips

Avant utilisation, vérifiez impérativement :

Taille : 99 octets
MD5    : a83f62bab34aeed7037e384adf1a95ac

Appliquez-le exclusivement à la ROM propre portant le MD5 '2c00e335288a96650e34785b5e2a7588', puis contrôlez que la ROM obtenue porte le MD5 'db02a1ba1e3787114dea02547f8515b2' et le SHA-1 'a6bfff331ae78f7c284104074404c7d4f1593cd1'. L'application du patch à une version autre que la version FR corrompt les données du jeu. 

## Sécurité

Le programme :

- n’accepte qu’un fichier .gba ordinaire de 16 MiB,
- vérifie MD5, SHA-1 et SHA-256 de la ROM source,
- contrôle cinq signatures binaires et la disponibilité de la zone d’injection,
- applique exactement trois écritures prévues, pour 76 octets écrits au total,
- vérifie en mémoire les empreintes du résultat avant de créer un fichier,
- crée une copie sans écrasement, la relit intégralement et confirme que la source n'a pas changé.

En cas d’erreur après la création du fichier de sortie, le programme indique explicitement que cette sortie peut être incomplète. Ne l’utilisez pas.

## Validation sous mGBA

Le portage a été testé sous mGBA :

L’exécution atteint la routine injectée à 0x089C4F70 puis rejoint InitMainMenu à 0x0802F6F4. La valeur RNG à 0x03005D80 a varié lors de 5000+ redémarrages successifs.

Cette validation ne constitue pas à elle seule une validation sur console réelle ou sur toutes les configurations de cartouches flash et de RTC.

## Crédits

- MWisBest : correctif original 32-bit RTC+TIMER RNG pour Pokémon Emerald.
- Aliogeek : travaux antérieurs sur l'adaptation française d’Émeraude avec RNG corrigée.
- KleineDropje : portage minimal vers Pokémon Version Émeraude française, script et documentation de ce dépôt.

Pokémon et les marques associées appartiennent à leurs ayants droit respectifs. Ce projet est non officiel et n’est affilié ni à Nintendo, ni à The Pokémon Company, ni à Game Freak.

## Licence et éléments tiers

Le code original du script et la documentation de ce dépôt sont proposés sous licence MIT. Cette licence ne couvre pas :

- les 67 octets de routine issus du correctif MWisBest et intégrés au script ;
- le fichier IPS facultatif fourni ;
- Pokémon, la ROM ou tout élément appartenant à des tiers.

Consultez [THIRD_PARTY.md](THIRD_PARTY.md) et [LICENSE](LICENSE) avant toute redistribution.

## Développement

Les contributions doivent préserver les garanties essentielles : aucune ROM dans le dépôt, aucune modification en place de la source, refus strict des variantes incompatibles et vérification du résultat final. Voir [CONTRIBUTING.md](CONTRIBUTING.md).
