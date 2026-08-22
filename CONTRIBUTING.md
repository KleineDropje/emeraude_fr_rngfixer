# Contribuer

Les corrections ciblées, les tests et les améliorations de documentation sont bienvenus.

Avant une proposition :

1. ne placez aucune ROM, sauvegarde ou donnée extraite de ROM dans le dépôt ;
2. conservez le script sans dépendance externe et sans accès réseau ;
3. ne modifiez pas les empreintes ou offsets sans fournir une méthode reproductible de vérification ;
4. ne retirez aucun garde-fou concernant la source, l’écrasement ou la validation finale ;
5. exécutez `python3 -m unittest discover -s tests -v` ;
6. exécutez `python3 -m py_compile emerald_fr_rng_fix.py`.

Toute proposition qui modifie les octets du correctif doit expliquer précisément l’origine des nouveaux octets, leurs droits de redistribution, les offsets affectés et les résultats obtenus sous émulateur et, le cas échéant, sur matériel réel.
