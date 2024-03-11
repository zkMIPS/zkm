# ZKM

ZKM est une infrastructure informatique générale vérifiable basée sur [Plonky2](https://github.com/0xPolygonZero/plonky2) et la [microarchitecture MIPS](https://en.wikipedia.org/wiki/MIPS_architecture), permettant à Ethereum de devenir la couche de règlement global.

# Bâtiment

Afin de créer l'application, zkm nécessite une dernière chaîne d'outils nocturnes. Exécutez simplement `cargo build --release` dans le répertoire zkm.

# Exécuter les exemples

Un exemple de bout en bout a été présenté dans [examples](./examples).

# Conseils pour les contributeurs externes

Tout type de contribution externe est encouragé et bienvenu !

## Conseils généraux pour vos relations publiques

* Le PR corrige un bug
Dans la description du PR, veuillez décrire clairement mais brièvement le bogue, y compris comment le reproduire, l'erreur/exception que vous avez obtenue et comment votre PR corrige les bogues.

* Le PR implémente une nouvelle fonctionnalité

Dans la description du PR, veuillez décrire clairement mais brièvement

> 1. à quoi sert la fonctionnalité
> 2. l'approche adoptée pour le mettre en œuvre
> 3. Tous les PR pour les nouvelles fonctionnalités doivent inclure une suite de tests appropriée.

* Le PR améliore les performances

Pour aider à filtrer les faux positifs, la description du PR pour une amélioration des performances doit clairement identifier

> 1. le goulot d'étranglement cible (un seul par PR pour éviter toute confusion !)
> 2. comment la performance est mesurée
> 3. caractéristiques de la machine utilisée (CPU, OS, #threads si approprié) performances avant et après le PR

# Licenses

Le ZKM est distribué selon les termes de la licence MIT.

# Sécurité

Ce code n'a pas encore été audité et ne doit être utilisé dans aucun système de production.

