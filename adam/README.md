# Aging domain names: When do Attackers Weaponize Newly Registered Domains?

Ce dépôt contient l'analyse et la génération des graphiques supportant la problématique de recherche sur le cycle de vie des domaines malicieux, depuis leur enregistrement jusqu'à leur militarisation (ou exploitation). 

## L'Hypothèse Centrale
L'objectif est de démontrer que les attaquants ne se contentent pas d'utiliser des noms de domaine fraîchement enregistrés (Newly Registered Domains - NRD) de façon impulsive. Face aux défenses modernes, ils adoptent de plus en plus des stratégies complexes d'**incubation**. En vieillissant artificiellement les domaines avant leur "weaponization", ils tentent de contourner les filtres de réputation, maximisant ainsi la survie de leurs infrastructures d'attaque.

---

## Modèle de Données et Variables Stratégiques

L'analyse repose sur le croisement méticuleux des variables extraites de notre dataset d'incidents (issues de la télémétrie passive DNS, données WHOIS, etc.) :
- `discovery_time` : La date à laquelle le domaine a été détecté comme malicieux et signalé (le "Takedown Trigger" / début de l'attaque publique).
- `cd` (Creation Date) : Date d'enregistrement initiale (WHOIS).
- `ud` (Update Date) : Dernière modification administrative du domaine.
- `ed` (Expiration Date) : Date prévue pour la fin de validité de l'enregistrement.
- `aging_time` : (`discovery_time - cd`). Temps d'attente/incubation absolu avant l'attaque, en jours.
- `uptime_dur` : Temps de survie (résistance au takedown) après la première détection.
- `dns_changes` / `ip_changes` : Signaux techniques mesurant la granularité des changements associés à ce domaine avant sa signalisation publique.

Afin de modéliser ce cycle, nous avons divisé l'échantillon en **Clusters Stratégiques** (du plus urgent au plus patient) :
1. **Militarisation Directe (<1j)** 
2. **Militarisation Rapide (1-7j)**
3. **Incubation Précoce (7-30j)**
4. **Incubation Courte (1-3 mois)**
5. **Incubation Prolongée (3-6 mois)**
6. **Incubation Longue (6-12 mois)**
7. **Infrastructure Mature (>1 an)**

---

## Catalogue Détaillé et Analyse des Graphiques

Le script `generate_adam_graphs_for_prod.py` produit **26 graphiques scientifiques**. Chaque image générée, documentée ci-dessous, est pensée pour valider un argument spécifique du papier de recherche. *Toutes les figures sont exportées dans le dossier `./adam_final/`.*

### I. Répartition et Dynamiques Générales d'Incubation

**1. `dist_age_log.png`** (Distribution globale de l'âge de militarisation)
*   **Hypothèse :** La distribution de "l'âge" au moment de l'attaque (Militarisation) révèle l'existence de la phase d'incubation vs l'impulsivité des attaquants.
*   **Variables :** `aging_time`
*   **Interprétation :** Cet histogramme à échelle logarithmique trace un pic massif dans les premières 24h à 72h (Militarisation Directe) suivi d'une longue traîne "heavy-tailed" démontrant la persistance à long terme des stratégies d'incubations.

**2. `cdf_age_log.png`** (Proportion Cumulée du Vieillissement)
*   **Hypothèse :** À quel percentile précis peut-on affirmer qu'un domaine "Sort" de la phase critique NRD pour devenir un Sleeper ?
*   **Variables :** `aging_time` (en Cumulative Distribution Function)
*   **Interprétation :** Permet une lecture directe de la médiane et du 90ème centile. Exemple : "Seulement X% des domaines malveillants attaquent le premier mois".

**3. `clusters_strategies_vieillissement.png`** (Répartition en barres des stratégies)
*   **Hypothèse :** Les attaquants privilégient des tranches de temps spécifiques en fonction des règles de l'industrie (ex. période de grâce, règles de l'ICANN).
*   **Variables :** `aging_cluster` (Count pure)
*   **Interprétation :** Un décompte clair et simple par bloc "Immédiat" vs "Incubation" pour quantifier les volumes de chaque stratégie de manière agrégée.

### II. L'Évolution Temporelle des Modes d'Attaque

**4. `tendance_age_median_annuel.png`** (L'âge médian annuel)
*   **Hypothèse :** Avec le temps et le renforcement des blocklists/NRD-lists, les cybercriminels sont obligés de s'adapter et d'incuber leurs domaines plus longtemps.
*   **Variables :** `year`, `aging_time` (Médiane)
*   **Interprétation :** Une courbe en hausse de l'âge médian d'année en année démontre de façon macroscopique l'adoption croissante de l'approche Sleeper.

**5. `tendance_age_mensuelle_globale.png`** (Tendance mensuelle lissée)
*   **Variables :** `year_month`, `aging_time` (Médiane).
*   **Interprétation :** Fournit une vue plus granulaire par mois que le point n°4, pour montrer si certains événements ou vagues d'attaques drastiques ont modifié le profil médian.

**6. Fichiers `monthly_age_trend_YYYY.png`** (Zoom par année)
*   **Interprétation :** Casse la macro-tendance (graph n°5) pour isoler les dynamiques purement intra-annuelles (micro-campagnes).

**7. `strategies_vieillissement_annuel.png`**
*   **Variables :** `year`, `extended_cluster`
*   **Interprétation :** Un graphique à colonnes empilées (ou regroupées) pour observer année par année l'explosion relative ou absolue des clusters "Deep Sleeper" vs "Militarisation Directe".

**8. `volume_attaques_trimestriel.png`**
*   **Variables :** `quarter` (Q1, Q2...)
*   **Interprétation :** Ce graphique atteste du bruit de fond général : le volume d'attaque fluctue-t-il massivement et impacte-t-il nos conclusions sur le vieillissement ?

**9. `saisonnalite_mensuelle.png`**
*   **Hypothèse :** Y a-t-il une "période" de récolte ? Par exemple, les attaques immédiates explosent-elles pendant les fêtes (BlackFriday) comparativement à un flux stable de domaines incubés ?
*   **Variables :** `month`, `strat_group`
*   **Interprétation :** Montre le volume d'attaques mois par mois entre 1 et 12, ce qui lisse l'effet des années pour détecter un "modèle" saisonnier selon la tactique.

### III. Spécialisation et Influence de l'Écosystème (Registrars & Marques)

**10. `vieillissement_par_registrar.png`** (Top 15 des Registrars, Boxplot de Vieillissement)
*   **Hypothèse :** La décision d'incuber n'est pas techniquement agnostique. Elle dépend de la qualité, du prix et du temps de tolérance du "fournisseur" du domaine.
*   **Variables :** `registrar_name`, `aging_time`
*   **Interprétation :** Ce Boxplot montre si certains hébergeurs/registrars attirent majoritairement des campagnes "Hit and Run", tandis que d'autres concentrent les "Sleepers". 

**11. `ratio_strategique_registrars.png`** (Le % interne aux top 10 registrars)
*   **Variables :** `registrar_name`, `strat_group` (Incendie vs Incubation calculé en %)
*   **Interprétation :** Confirme de façon incontestable que l'écosystème d'attaques est fragmenté (certains registrars ont 90% d'incubation, d'autres 20%).

**12. `ratio_strategique_tld.png`** (Spécialisation par extension de domaine TLD)
*   **Hypothèse :** Les extensions très régulées obligent l'attaquant à faire de l'incubation alors que les TLD pas chers / laxistes sont brûlés immédiatement.
*   **Variables :** `tld`, `strat_group`
*   **Interprétation :** Même concept que le n°11 mais appliqué aux Extensions (`.com`, `.net`, ccTLD).

**13. `vieillissement_par_marque.png`** (Le type de cible)
*   **Hypothèse :** Les attaques réclamant une haute crédibilité et risquant très gros (Ex: Usurpation bancaire) exigent une maturation plus longue du domaine.
*   **Variables :** `trg` (Target Brand), `aging_time` (Median & P90)
*   **Interprétation :** Compare les stratégies d'âges déployées par cible usurpée.

### IV. Anatomie du Déclencheur Technico-Administratif (The Trigger)

**14. `maj_whois_vs_age.png`** 
*   **Hypothèse :** Pour réveiller un vieux domaine, un attaquant va déclencher involontairement une mise à jour administrative traçable.
*   **Variables :** `aging_time`, `update_delay` (`discovery_time - ud`) (Hexbin Map)
*   **Interprétation :** Démontre la présence de domaines de plus en plus vieux mais dont la dernière MAJ précède immédiatement (0-3 jours) l'attaque (ligne horizontale basse). 

**15. `dist_mises_a_jour_incubation.png`** 
*   **Hypothèse :** Un zoom ciblé sur les très vieux sleepers.
*   **Variables :** Domaines > 180j ; Histogramme de `update_delay`
*   **Interprétation :** Prouve que sur une cohorte de domaines dormants (ex > 180j), les mises à jour WHOIS ne sont pas distribuées aléatoirement : elles se massent pile avant l'agression.

**16. `preuve_drop_catching.png`** (Pie chart Drop Catching)
*   **Hypothèse :** Le Drop Catching est un sous-ensemble critique des Sleepers de plus d'un an, trahissant un rachat et une modification expresse.
*   **Variables :** Proportion des domaines avec `aging_time > 1 an` où `update_delay < 3 jours`.
*   **Interprétation :** Atteste du rachat industriel et de la Militarisation quasi immédiate de domaines périmés (Drop catching d'opportunité).

**17. `frise_pre_militarisation.png`** (Les Signaux Physiques)
*   **Hypothèse :** Le domaine, pendant son "rêve" (incubation), oscille techniquement (parking pages, Fast flux, etc.) avant de passer au stade actif.
*   **Variables :** Échantillon timeline: `cd`, `discovery_time`, détections des variations d'adresses IP (`ip_change`) et de HTML statique.
*   **Interprétation :** Offre une frise visuelle de l'activité préparatoire (Pre-Attack Recon) confirmant l'incubation *active*.

**18. `complexite_infrastructure_ips.png`**
*   **Hypothèse :** Les domaines subissant un long vieillissement finissent de toute manière par muter, que ce soit pour échapper aux détecteurs statiques IP ou migrer d'hébergeur.
*   **Variables :** `dns_changes` (Nb d'IP uniques attachées pré-attaque) vs `aging_cluster` (Boxplot)
*   **Interprétation :** Les sleepers affichent statistiquement une infrastructure IP bien plus mouvante (complexité malveillante) que la Militarisation Directe. 

**19. `analyse_weekend_gap.png`** (Le Tempo Temporel Opérationnel)
*   **Hypothèse :** Les Sleepers (scripts automatisés crons/vagues planifiées) s'exécutent sur un modèle calendaire différent du hit and run quotidien.
*   **Variables :** `weekday`, `strat_group`
*   **Interprétation :** Met en évidence le "Weekend Gap" (creux des attaques) et observe si les stratégies incubées en sont affranchies (automatisation).

**20. `longueur_domaine_vs_age.png`** (La Crédibilité par le Lexique)
*   **Hypothèse :** Les fraudeurs générant des domaines aléatoires très longs (DGA like) n'ont aucune raison d'incuber une ressource de mauvaise facture sémantique.
*   **Variables :** `rd_len` (Longueur), `aging_time`
*   **Interprétation :** Prouve que les noms super longs (>10-15 chars) "crament" plus vite, tandis que les noms courts (crédibles/premium) sont couvés patiemment.

### V. Le Retour sur Investissement (Takedown & "Burn After Use")

**21. `survie_vs_age.png`** (Hexbin de Corrélation Uptime)
*   **Hypothèse :** On paye pour incuber *parce que ça marche*. L'âge du domaine avant l'attaque influence sa résistance post-lancement.
*   **Variables :** `aging_time`, `uptime_dur` 
*   **Interprétation :** Une visualisation fine de densité (Hexagram) pour chercher la "tache" prouvant l'inefficacité des défenses réactives face aux vieux domaines.

**22. `roi_incubation_survie.png`** (Calcul ROI brut)
*   **Variables :** Médiane absolue de `uptime_dur` comparée selon le `aging_cluster`
*   **Interprétation :** La preuve formelle finale : "Incuber 3 mois fait gagner 48h de durée de vie de l'attaque en moyenne." 

**23. `resistance_takedown_par_age.png`** (Boxplot Uptime Log)
*   **Variables :** `uptime_dur` vs `extended_cluster`
*   **Interprétation :** Similaire au 22, mais avec moustache pour démontrer la persistance à longue traine des "Heavy Sleepers" (ce n'est pas qu'une moyenne poussée par quelques anomalies).

**24. `ecart_expiration_dist.png`** (La fin de vie)
*   **Hypothèse :** De nombreux domaines légitimes ou achetés en Bulk pourissent sans être utilisés. Les fraudeurs les exploitent juste avant leur disparition : le **Burn After Use**.
*   **Variables :** `expiration_gap` (`ed - discovery_time`). 
*   **Interprétation :** La distribution générale nous indique combien d'attaques tombent proches du couperet de "zéro jour restant". 

**25. `militarisation_tardive_densite.png`** (KDE Density plot Burn After Use)
*   **Variables :** `expiration_gap`, `strat_group`
*   **Interprétation :** Différencie par une courbe fluide KDE les domaines Incubation (Militarisation tardive) des domaines d'attaques directes proches de leur expiration. 

**26. `militarisation_tardive_comparaison.png`** (Burn After Use : Facet Grid)
*   **Variables :** `expiration_gap` éclaté sur deux graphes `strat_group` superposés.
*   **Interprétation :** Offre une version séparée (et plus académique que la 25ème) comparant les attaques en début de cycle (1 an vs proche expiration). On découvre visuellement la vague d'attaques de la classe "Incubation" se cognant contre la limite d'expiration (axvline à 0).
