# Rapport de TP

## Filtration des URLs

### Introduction

La filtration des URLs occupe une place essentielle dans les systèmes modernes de cybersécurité, car une grande partie des attaques passe aujourd'hui par le web. Les utilisateurs consultent des pages, ouvrent des liens reçus par messagerie, utilisent des plateformes cloud, téléchargent des documents, ouvrent des services de streaming ou de communication, et interagissent en permanence avec des ressources distantes. Dans un tel contexte, une simple URL peut devenir le point de départ d'un incident grave. Elle peut rediriger vers une page de phishing, dissimuler un site de collecte d'identifiants, pointer vers un service malveillant, ou encore servir à contourner une politique interne de navigation.

La filtration des URLs ne consiste donc pas simplement à interdire quelques sites connus. Il s'agit d'un processus de sécurité complet, qui combine plusieurs opérations. Il faut d'abord identifier l'adresse concernée, puis l'analyser, déterminer si elle est propre, suspecte ou malveillante, comparer éventuellement cette adresse à des bases de menaces déjà connues, et enfin décider si la requête doit être autorisée ou bloquée. À cela s'ajoutent la journalisation, la traçabilité et la supervision, car un système de sécurité n'a de valeur que s'il permet de comprendre ce qu'il a observé et ce qu'il a décidé.

Dans ce travail, la filtration des URLs est étudiée à travers les mécanismes mis en place dans le projet. L'analyse porte uniquement sur les composants liés aux URLs, aux domaines, au proxy, à la blocklist et à la supervision du trafic web. Le but est de montrer que la filtration n'est pas une fonction isolée, mais une chaîne logique comprenant plusieurs couches de traitement.

Les principaux volets étudiés sont les suivants :

- le scan statique des URLs ;
- le scan dynamique des URLs ;
- la comparaison avec des URLs malveillantes déjà connues ;
- la filtration en temps réel via le proxy ;
- le contrôle d'accès par blocklist ;
- l'enregistrement des événements dans les logs et le monitoring.

Cette approche permet de construire un rapport centré sur le sous-thème demandé, tout en restant cohérent avec les fonctionnalités réellement présentes dans le projet.

---

## 1. Principe général de la filtration des URLs

La filtration des URLs est un mécanisme destiné à contrôler, analyser et réguler les accès aux ressources web. Elle peut être mise en place pour des raisons de sécurité, mais aussi pour des raisons de gouvernance, de conformité ou de politique interne. Dans une infrastructure réelle, ce mécanisme sert autant à empêcher l'accès à des sites malveillants qu'à limiter l'usage de services non autorisés.

D'un point de vue fonctionnel, la filtration des URLs repose généralement sur trois grandes idées.

La première idée est l'**évaluation du risque**. Une adresse web n'est pas traitée comme une simple chaîne de caractères. Elle est interprétée comme un objet de sécurité. On examine sa structure, son domaine, sa réputation et parfois certains éléments de contenu. Cette étape permet de transformer une URL en informations exploitables.

La deuxième idée est l'**application d'une politique**. Une URL peut être considérée comme dangereuse à cause d'une analyse technique, mais elle peut aussi être interdite simplement parce qu'elle appartient à une catégorie bloquée par l'administrateur. Le système doit donc être capable de prendre des décisions en fonction d'une politique claire.

La troisième idée est la **traçabilité**. Lorsqu'une URL est analysée, autorisée ou bloquée, l'événement doit pouvoir être retrouvé. Sans journaux d'audit, la filtration perd sa dimension opérationnelle. Il devient alors difficile de comprendre pourquoi une décision a été prise, ou de reconstituer une séquence d'actions après un incident.

Ainsi, un bon système de filtration des URLs doit réunir plusieurs composantes :

- une logique d'analyse ;
- une base de connaissance sur les menaces ;
- un mécanisme de blocage ou d'autorisation ;
- une couche de supervision ;
- un stockage des événements.

C'est précisément cette logique globale qui apparaît dans le projet étudié.

---

## 2. Le scan statique des URLs

Le scan statique est la première brique technique de la filtration des URLs. Son rôle est d'examiner une adresse sans exécuter son contenu. Cette méthode est particulièrement adaptée à un système de sécurité, car elle permet de produire un verdict rapide avant même qu'un accès réel ne soit autorisé. Elle est donc compatible avec une logique de filtrage préventif.

Dans le projet, le scan statique des URLs repose sur une démarche multicouche. Cette organisation est très pertinente, car elle évite de dépendre d'un seul critère de détection. Une URL peut sembler bénigne sous un angle et suspecte sous un autre. Multiplier les couches permet donc d'améliorer la robustesse du verdict final.

### 2.1 Validation de la forme de l'URL

La première étape consiste à vérifier la structure générale de l'adresse. À ce niveau, on s'intéresse notamment :

- au protocole utilisé ;
- à la syntaxe globale de l'URL ;
- à la cohérence du domaine ;
- à la présence de motifs inhabituels ;
- à la longueur ou à la complexité excessive de l'adresse.

Cette couche est importante, car de nombreuses attaques reposent sur des URLs conçues pour tromper l'utilisateur. Certaines adresses utilisent des mots rassurants comme `verify`, `confirm`, `secure` ou `update`. D'autres emploient des caractères spéciaux, des redirections implicites, des chaînes très longues ou des formes volontairement ambiguës. Une URL peut donc être suspecte avant même d'être comparée à une base de menaces.

### 2.2 Comparaison avec des menaces déjà connues

Le deuxième niveau du scan statique repose sur la comparaison avec des sources de menaces connues. C'est ici qu'intervient la base de données des URLs malveillantes déjà enregistrées.

Dans le projet, cette fonction s'appuie principalement sur deux tables :

- `threat_urls` ;
- `phishtank_entries`.

La table `threat_urls` est conçue pour stocker des URLs provenant d'une base de menaces importée. Les adresses n'y sont pas stockées en clair de manière simple, mais sous une forme protégée, avec un hash SHA-256 et un champ chiffré. Cela permet de vérifier si une URL est connue comme malveillante tout en gardant une certaine prudence sur la manière dont les données sont conservées. En plus de l'URL elle-même, cette table peut stocker :

- le domaine ;
- le hash du domaine ;
- le type de menace ;
- la source de la menace ;
- un indicateur de vérification.

La table `phishtank_entries`, quant à elle, joue le rôle de base spécialisée sur les URLs de phishing. Elle permet de comparer une URL analysée à des entrées déjà signalées comme frauduleuses. Cette étape est importante dans la détection des tentatives d'usurpation d'identité et des pages de collecte d'identifiants.

Dans le code du projet, la logique de comparaison se trouve dans la couche de lookup des menaces. Le système normalise l'URL, calcule un hash, puis cherche d'abord dans `threat_urls`. Si une correspondance exacte existe, cela constitue un signal fort. Ensuite, le système peut également examiner les correspondances au niveau du domaine. Enfin, il vérifie la table `phishtank_entries` pour détecter les URLs connues comme phishing.

Il faut toutefois noter un point important sur l'état actuel de l'implémentation. La structure des tables existe bien, et la logique de lecture est présente, mais ces tables peuvent rester vides si aucun import n'a été effectué. Dans ce cas, le scanner garde tout de même son utilité, mais cette couche de comparaison ne joue plus qu'un rôle théorique. Le système se repose alors davantage sur les heuristiques statiques et la réputation du domaine.

### 2.3 Réputation du domaine

Après la comparaison avec les menaces connues, le système passe à une couche de réputation. Ici, le but n'est plus seulement de savoir si l'URL est déjà enregistrée comme malveillante, mais d'estimer si le domaine semble fiable ou non.

Cette étape est utile car toutes les menaces ne sont pas déjà connues. De nombreux domaines malveillants sont récents, temporaires ou changent rapidement. Une simple base noire n'est donc jamais suffisante. L'analyse de réputation permet de traiter ces cas intermédiaires en mesurant des indices de confiance ou de risque.

### 2.4 Analyse de contenu et score global

La dernière couche de l'analyse statique consiste à produire un score plus global. Ce score prend en compte différents indicateurs issus des couches précédentes. Dans le projet, la logique statique peut notamment s'appuyer sur des motifs comme :

- la présence de mots liés à la vérification ou à la suspension de compte ;
- l'usage de raccourcisseurs d'URL ;
- la présence de paramètres tels que `token` ou `session` ;
- des caractères spéciaux comme `@` ;
- une longueur excessive de l'adresse ;
- certaines formes d'encodage ou de dissimulation.

Le résultat final de cette analyse prend généralement la forme :

- d'un **statut** : `clean`, `suspicious` ou `malicious` ;
- d'un **threat score** sur 100.

Cette représentation graduelle est importante. Elle évite une décision trop brutale et donne une lecture plus fine du risque. Une URL légèrement douteuse n'est pas traitée comme une URL clairement malveillante, ce qui permet d'adapter la suite du traitement.

---

## 3. La base de données des URLs connues

La présence d'une base de données d'URLs connues est un élément particulièrement important dans un système de filtration. En effet, certaines décisions peuvent être prises beaucoup plus vite lorsqu'une adresse est déjà identifiée comme menaçante.

Dans l'architecture étudiée, cette connaissance est principalement représentée par :

- `threat_urls`, base générique d'URLs malveillantes importées ;
- `phishtank_entries`, base spécialisée sur le phishing.

Ces tables servent à renforcer la couche d'analyse statique. Lorsqu'une URL soumise au scanner correspond à une entrée déjà présente, le système peut immédiatement attribuer un niveau de risque élevé. Cela améliore la rapidité de décision et réduit l'incertitude.

Il faut bien distinguer ici la **base des menaces connues** et la **blocklist administrative**. Les deux n'ont pas exactement le même rôle.

La base des menaces connues correspond à une connaissance issue d'un flux externe ou d'un import de données. Elle répond à la question :

- "Cette URL est-elle déjà connue comme dangereuse ?"

La blocklist administrative, elle, répond à une autre question :

- "Cette URL ou ce domaine est-il interdit par la politique locale ?"

Cette distinction est importante sur le plan conceptuel. Une URL peut être bloquée sans être globalement malveillante, simplement parce qu'elle fait partie d'un service non autorisé. À l'inverse, une URL malveillante connue doit être détectée même si aucune règle locale explicite n'a encore été créée.

Dans l'état actuel du projet, les tables `threat_urls` et `phishtank_entries` doivent être alimentées par import. Si elles sont vides, cela signifie que le système possède bien l'infrastructure pour les utiliser, mais qu'il n'exploite pas encore pleinement ce potentiel. La filtration continue alors à fonctionner grâce aux heuristiques, au proxy et aux règles de blocage manuelles, mais la détection des menaces connues reste incomplète.

---

## 4. Le scan dynamique des URLs

Le scan statique fournit une première décision très utile, mais il ne peut pas tout révéler. Certaines menaces n'apparaissent clairement qu'au moment où un comportement réel est observé. C'est pourquoi le projet inclut également un mécanisme de **scan dynamique des URLs**.

Le principe du scan dynamique est d'observer le comportement associé à une cible web dans un environnement contrôlé. Il ne s'agit plus seulement d'examiner l'URL comme une chaîne de texte, mais de voir ce qui se passe lorsqu'on tente d'interagir avec cette cible. Cette approche permet d'obtenir des informations plus riches, notamment sur :

- les processus lancés ;
- les connexions réseau observées ;
- les actions locales détectées ;
- le comportement général pendant la fenêtre d'observation.

Le projet ne lance cependant pas ce scan dynamique dans tous les cas. Une politique de sécurité est appliquée en amont. Si le scan statique conclut déjà qu'une URL est malveillante, le lancement dynamique peut être refusé. Cette décision est cohérente, car il serait inutile et risqué de poursuivre l'exécution d'une cible déjà clairement classée comme dangereuse. Le scan dynamique est donc réservé aux cas plus ambigus, par exemple lorsque le résultat statique reste propre ou simplement suspect.

Cette articulation entre statique et dynamique est très importante. Elle montre que la filtration des URLs n'est pas un traitement unique, mais une séquence de décisions.

On peut résumer cette logique ainsi :

- le statique sert à filtrer vite et en amont ;
- le dynamique sert à approfondir certains cas ;
- la politique empêche d'exécuter ce qui est déjà clairement malveillant.

Le scan dynamique apporte ainsi une seconde profondeur d'analyse. Il ne remplace pas le statique, mais il le complète.

---

## 5. Le rôle du proxy dans la filtration

Le proxy représente la partie la plus concrète de la filtration des URLs, car c'est lui qui agit au moment réel de la navigation. Alors que le scan manuel permet une analyse ponctuelle, le proxy permet d'intercepter les requêtes envoyées par les machines clientes et d'appliquer la politique de sécurité avant que la communication ne se poursuive.

Lorsqu'une requête passe par le proxy, plusieurs actions peuvent être réalisées :

- identification de la cible ;
- normalisation de l'adresse ;
- comparaison avec la blocklist active ;
- scan statique de la cible ;
- décision d'autorisation ou de blocage ;
- écriture d'un événement dans l'historique et dans les logs.

Cette logique transforme la filtration des URLs en une action réelle, et pas seulement en une analyse théorique. Le proxy devient donc un point de contrôle central.

### 5.1 Trafic HTTP

Dans le cas du trafic HTTP, le proxy peut généralement voir la requête de manière assez complète. Cela signifie qu'il peut souvent reconstruire une URL comprenant le protocole, le domaine, le chemin et parfois la partie requête. Cette visibilité est favorable à une filtration précise, car elle offre davantage de contexte.

### 5.2 Trafic HTTPS

Le trafic HTTPS est plus difficile à analyser. Sans interception TLS complète, le proxy ne voit souvent qu'une demande de type `CONNECT hôte:443`. Cela signifie qu'il connaît surtout le domaine cible, mais pas forcément le chemin exact ni les paramètres de l'URL finale.

Cette limite a une conséquence importante : pour HTTPS, la filtration actuelle est surtout une filtration **par domaine ou par hôte**, et non une inspection totale de l'URL. Cela ne rend pas le système inutile, bien au contraire. Beaucoup de politiques de sécurité peuvent déjà être appliquées efficacement sur cette base. Mais il faut rester honnête sur le niveau de précision réellement atteint.

### 5.3 Décision et application

Lorsqu'une cible correspond à une règle de blocage ou lorsqu'elle est jugée suffisamment dangereuse, le proxy peut refuser la connexion. Dans le cas contraire, la requête est transmise et l'événement est enregistré comme autorisé. Cette combinaison entre observation, analyse et action constitue le cœur même de la filtration en temps réel.

---

## 6. Le contrôle d'accès des URLs et des domaines

Le contrôle d'accès est la partie administrative de la filtration. Il permet de gérer une **blocklist** appliquée au trafic réseau. Dans la base de données, cette logique s'appuie sur la table `proxy_block_rules`.

Cette table contient les motifs de blocage définis localement. On y retrouve notamment :

- le motif ou domaine à bloquer ;
- l'état activé ou désactivé ;
- une note éventuelle ;
- des dates de création et de mise à jour.

Le rôle de cette table est différent de celui de `threat_urls` ou `phishtank_entries`. Ici, on ne parle pas d'une connaissance générale du web malveillant, mais d'une politique locale de contrôle. Cela permet de bloquer :

- des services interdits ;
- des domaines explicitement jugés problématiques ;
- des familles de services complètes ;
- des motifs de blocage adaptés au contexte d'utilisation.

Le système ne se contente pas d'une simple saisie brute. Il normalise les domaines et peut regrouper certaines plateformes connues en familles plus larges. Cette approche est intéressante, car dans la pratique un service peut s'appuyer sur plusieurs domaines associés. Bloquer seulement le domaine principal ne suffit pas toujours.

Une autre fonctionnalité utile est la suggestion. Lorsqu'un administrateur commence à saisir un nom de service ou de domaine, le système peut lui proposer des valeurs cohérentes. Cette aide améliore l'ergonomie et réduit les erreurs de configuration.

Enfin, lorsqu'une règle change, le système peut réinitialiser certaines connexions actives afin de forcer la prise en compte immédiate des nouvelles politiques. Cela est particulièrement utile lorsque des applications conservent des connexions déjà ouvertes.

---

## 7. Les logs et l'audit des URLs

Un système de filtration des URLs doit impérativement fournir une bonne traçabilité. Dans le projet, cette traçabilité s'appuie notamment sur les journaux d'audit et sur l'historique lié au proxy.

Les événements enregistrés peuvent concerner :

- les scans d'URL ;
- les blocages du proxy ;
- les autorisations ;
- les changements de règles ;
- les états de présence et de conformité.

Dans le cas des URLs, les logs peuvent contenir plusieurs informations utiles :

- la cible demandée ;
- l'URL reconstruite lorsque cela est possible ;
- le statut statique ;
- le score de menace ;
- le client ou la machine source ;
- le résultat final, autorisé ou bloqué.

Cette partie est très importante car elle permet de transformer la filtration en un processus explicable. Il ne s'agit pas seulement de bloquer, mais aussi de pouvoir justifier le blocage. Un audit bien structuré permet de comprendre le cheminement de décision et de relire les événements après coup.

---

## 8. Monitoring et supervision du trafic web

La supervision ajoute une couche supplémentaire à la filtration des URLs. Elle permet de suivre non seulement les événements passés, mais aussi l'état des machines, l'activité récente du proxy et la présence des sessions.

Cette dimension est essentielle pour éviter les mauvaises interprétations. Une machine peut sembler encore présente dans l'interface alors qu'elle n'utilise plus réellement le proxy. À l'inverse, une activité proxy récente peut prouver qu'une machine participe encore au trafic filtré. Le monitoring aide donc à distinguer :

- la présence applicative ;
- l'activité réseau récente ;
- l'état du proxy ;
- la conformité du poste par rapport à la politique attendue.

Dans une perspective de filtration des URLs, cela permet de répondre à des questions opérationnelles très importantes :

- quelles machines utilisent encore réellement le proxy ;
- quelles machines ont généré des accès web récents ;
- quelles sessions sont encore actives ;
- quels postes risquent de contourner la politique de filtrage.

Le monitoring complète donc naturellement le scan et l'audit. Il apporte une vision plus globale du fonctionnement du système.

---

## 9. Limites actuelles et perspectives

Même si le système mis en place est déjà riche, plusieurs limites doivent être mentionnées.

La première limite concerne évidemment le HTTPS. Tant qu'il n'existe pas d'interception TLS complète, l'inspection reste principalement fondée sur le domaine et non sur l'URL chiffrée complète. Cette contrainte réduit le niveau de détail disponible dans certains cas.

La deuxième limite concerne l'alimentation des bases de menaces connues. Les tables `threat_urls` et `phishtank_entries` existent bien, la logique de lecture est présente, mais leur efficacité dépend directement de la qualité et de la fraîcheur des données importées. Si ces tables restent vides, la couche de lookup des menaces connues perd une grande partie de son intérêt.

La troisième limite concerne la précision de certains verdicts intermédiaires. Comme dans tout système heuristique, il faut toujours trouver un équilibre entre détection et faux positifs. Une URL inhabituelle n'est pas toujours malveillante, et un domaine très simple peut malgré tout être dangereux.

Parmi les améliorations possibles, on peut citer :

- l'alimentation régulière de `threat_urls` par un vrai flux de menaces ;
- l'enrichissement de `phishtank_entries` ;
- une meilleure corrélation entre utilisateur, machine et historique des accès ;
- une inspection HTTPS plus avancée ;
- des rapports périodiques synthétiques sur les domaines bloqués et les scans les plus critiques.

---

## Conclusion

La filtration des URLs est bien plus qu'un simple mécanisme de blocage. C'est une chaîne complète de sécurité qui combine analyse, décision, application et traçabilité. Le scan statique permet d'évaluer rapidement le risque d'une adresse. La base des menaces connues, représentée par `threat_urls` et `phishtank_entries`, apporte un niveau supplémentaire de détection lorsqu'elle est alimentée correctement. Le scan dynamique permet d'approfondir certains cas en observant un comportement réel. Le proxy transforme ensuite cette logique en filtrage concret du trafic réseau, tandis que le contrôle d'accès permet à l'administrateur d'appliquer des politiques explicites via `proxy_block_rules`.

À cela s'ajoutent les journaux d'audit et le monitoring, qui rendent l'ensemble exploitable sur le plan opérationnel. On ne sait pas seulement qu'une URL a été analysée ; on peut également comprendre quelle décision a été prise, quand elle a été prise, et dans quel contexte.

Ce travail montre donc que la filtration des URLs doit être pensée comme un système cohérent. L'analyse automatique seule ne suffit pas. La blocklist seule ne suffit pas. Le proxy seul ne suffit pas. C'est l'articulation entre ces éléments qui permet de construire une solution de sécurité utile, lisible et administrable.

Dans une version encore plus avancée, l'alimentation continue des bases d'URLs malveillantes, l'amélioration du traitement HTTPS et le renforcement des mécanismes de supervision permettraient d'obtenir une solution encore plus robuste. Malgré cela, l'architecture actuelle offre déjà une base solide pour comprendre et mettre en œuvre les principes fondamentaux de la filtration des URLs.

---

## Remarque finale

Avec une mise en forme académique classique dans Word ou PDF, ce rapport peut être étendu à environ huit pages en ajoutant :

- une page de garde ;
- un sommaire ;
- des captures d'écran du scan d'URL, du proxy, des logs et du contrôle d'accès ;
- une petite webographie ou bibliographie.
