# Domain Aging Strategy Analysis

Ce document explique les différents graphiques générés, les hypothèses sur lesquelles ils reposent, les métriques extraites et la manière dont ils s'articulent pour répondre à la question centrale : **Quand les attaquants militarisent-ils les domaines nouvellement enregistrés ?**

L'ensemble des graphiques est généré par l'analyse des données JSONL (`malicious_domains_takedown_whois_sample_*.jsonl`), filtrées pour ne conserver que les domaines malveillants identifiés lors de la recherche sur des fraudes au WHOIS.

La variable (métrique) centrale du papier est traitée de la manière suivante :
`aging_time = discovery_time - cd` (où `cd` est la Creation Date issue du WHOIS)

---

## 1. L'approche Globale : La distribution du temps d'incubation (Thème 1, Ch 1, Cl 1)

**Fichiers générés :**
* `dist_age_attaque_log.png`
* `cdf_temps_incubation.png`

**L'hypothèse :** Les attaquants adoptent deux stratégies principales et distinctes : 
1. Les **Sprinters** (ou Just-in-time domains) qui sont utilisés immédiatement.
2. Les **Sleepers** (Aged domains) qui sont mis en sommeil pour gagner en confiance (contournement des mécanismes d'anti-Newly Registered Domains). La distribution est donc "Bimodale".

**Méthodologie et Métriques :**
Nous avons calculé la différence `aging_time` en jours. L'histogramme affiche la densité des domaines avec une échelle logarithmique sur l'axe X pour mieux discerner à la fois la concentration énorme de "Sprinters" dans les premières 24/48h et les vallons des "Sleepers" bien plus tard (ex: 30, 90 ou même 300+ jours).
La CDF (Cumulative Distribution Function) quant à elle permet d'extraire des percentiles précis ("XX% des domaines sont militarisés en moins de Y jours").

---

## 2. Le marqueur de "Réveil" et l'Axe Administratif (Thème 2, Ch 8, Cl 7)

**Fichiers générés :**
* `nuage_maj_vs_age.png`
* `dist_maj_sleepers.png`

**L'hypothèse :** Un vieux domaine ne vieillit pas de façon homogène. L'attaque (la militarisation) est précédée d'un événement déclencheur de type cyber-administratif : un changement WHOIS (modification de contact, changement de registrar, etc.). Ce changement d'état est l'indicateur clé du "Réveil".

**Méthodologie et Métriques :**
Nous calculons `update_delay = discovery_time - ud` (différence entre l'attaque et la dernière mise à jour).
Le Scatter plot nous permet de chercher une concentration de vieux domaines (`aging_time` élevé) qui présentent un `update_delay` extrêmement réduit (proche de 0). L'histogramme cible exclusivement les "Sleepers" (> 180 jours d'âge) pour voir l'étendue de cet `update_delay`. S'il est massivement bas, cela valide le piratage de vieux domaines (Domain Hijacking) ou le Drop Catching.

---

## 3. L'infrastructure et les Registrars (Thème 3, Ch 5, Cl 5)

**Fichiers générés :**
* `boxplot_age_par_registrar.png`

**L'hypothèse :** Les "Sleepers" coûtent de l'argent (renouvellement) et doivent survivre longtemps sans être audités ni suspendus. Les attaquants concentrent donc stratégiquement leurs "Sleepers" réveillés et rachetés vers des plateformes de registrars qui possèdent des politiques d'Abus peu réactives ou des vérifications de type "Know Your Customer" (KYC) laxistes.

**Méthodologie et Métriques :**
Nous avons calculé le temps d'incubation (`aging_time`) médian par registrar (`iana_id`) pour le Top 15 des registrars dans les volumes du dataset. Les boîtes à moustaches (Boxplots) démontrent non seulement la médiane mais la variance : un registrar favorisé pour les Sleepers aura une boîte concentrée beaucoup plus haut (sur l'axe Y logarithmique).

---

## 4. Ciblage et Valeur de la Marque (Thème 4, Ch 6, Cl 2)

**Fichiers générés :**
* `barres_age_par_marque.png`

**L'hypothèse :** S'attaquer à "PayPal" ou à une banque demande davantage de sophistication technique pour déjouer les outils de détection antispam et brand protection. Les attaquants choisissent donc d'allouer leurs "Vieux Domaines" coûteux spécifiquement vers ces cibles à haute valeur (High Value Targets), tandis que le phishing "cheap" (Colis postaux, etc.) sera mené avec des "Sprinters".

**Méthodologie et Métriques :**
Extraction de `metadata.trg` (Target). Le diagramme en barres regroupe les cibles les plus attaquées (par volume) et confronte leur Âge Médian face au 90ème percentile (qui représente la frange des opérations les plus sophistiquées sur cette même marque).

---

## 5. L'Évolution Temporelle des Tactiques (Thème 5, Ch 10, Cl 3)

**Fichiers générés :**
* `courbe_evolution_age_par_an.png`

**L'hypothèse :** On observe une forme de *course aux armements*. À mesure que l'industrie cyber a appliqué des règles sévères (ML) pénalisant pénalement les "Newly Registered Domains", les cybercriminels se sont adaptés et forcent leurs domaines malveillants à attendre de plus en plus longtemps.

**Méthodologie et Métriques :**
Extraction de l'année au moment de `discovery_time`. On calcule la médiane du `aging_time` par année. S'il y a une pente croissante du graphique de 2018 à 2024, c'est que les attaquants s'adaptent et laissent "incuber" leurs domaines de plus en plus longtemps.

---

## 6. Les modifications pré-militarisation et la Frise (Thème 6, Ch 4, Cl 4)

**Fichiers générés :**
* `frise_chronologique_mutations.png`

**L'hypothèse :** Un "Sleeper" dormant n'a pas d'infrastructure malveillante pointée vers lui lors de sa gestation (Parking Page). La militarisation se signale par une bascule violente et détectable : IP Churning (modification `arec`) ou Hash visuel/code (modification du `html_ssdeep` ou `html_md5`).

**Méthodologie et Métriques :**
Étude d'un échantillon ciblé de domaines montrant des mutations dans la fenêtre fatidique des 7 jours (`discovery_time - 7 jours`). La frise montre visuellement "Création" ➔ (Très long trou) ➔ IP Change ➔ HTML Change ➔ Attack/Discovery.

---

## 7. Autres Variables Complémentaires (Stratégies DNS, Expiration, Takedown)

* **Ch 2 : Stratégie (Clusters)** (`barres_clusters_strategies.png`) : Les domaines sont disrétisés en 4 bacs (Immediate, Fast, Aged, Sleeper) pour dénombrer visuellement quelle catégorie emporte l'avantage quantitatif.
* **Ch 3 / 4 : Infrastructure Prep** (`boxplot_ips_avant_attaque.png`, `boxplot_versions_html_avant.png`) : Les Sleepers subissent-ils plus de changements de DNS (`unique IPs before attack`) pendant leur enfance ?
* **Ch 7 / Cl 6 : LifeSpan/Durée opérationnelle** (`courbe_survie_vs_age.png`) : Plus le domaine est vieux au moment de l'attaque (`aging_time`), plus il devrait échapper longtemps aux défenses, augmentant de fait le temps de survie opérationnelle (`uptime_dur`) post-attaque.
* **Ch 9 : Expiration Stratégique** (`ch9_expiration_gap.png`) : Formule `Expiration - Attack Time`. Met en exergue l'attaque de type "Burn After Use" (les attaquants utilisent le domaine massivement alors qu'il s'apprête à expirer dans moins de 30 jours, optimisant les coûts d'achat).
