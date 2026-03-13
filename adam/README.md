# ADAM : Aging Domain Analysis & Monitoring

Projet de recherche sur la militarisation des noms de domaines : **"Aging domain names: When Do Attackers Weaponize Newly Registered Domains"**.

## 1. Objectif
Analyser le temps d'incubation (Aging Time) entre la création d'un domaine (`cd`) et sa découverte en tant qu'entité malveillante (`discovery_time`).
L'ensemble des analyses est consolidé dans un script unique optimisé pour les fichiers JSONL massifs (21 Go+).

## 2. Guide des Graphiques Générés
Les graphiques sont numérotés et nommés de manière explicite pour faciliter l'intégration dans le rapport :

### Analyses de Base (Thèmes 1 à 6)
*   `01_distribution_age_log.png` : Distribution globale de l'âge (échelle log).
*   `02_proportion_cumulee_age.png` : Proportion cumulée (CDF) de militarisation.
*   `03_maj_whois_vs_age.png` : Corrélation entre l'âge et la dernière mise à jour WHOIS.
*   `04_dist_maj_sleepers.png` : Distribution des délais de MAJ pour les domaines anciens (>180j).
*   `05_age_par_registrar.png` : Comparaison des stratégies par Registrar (Top 15).
*   `06_age_par_marque.png` : Âge médian vs 90e centile par marque ciblée.
*   `07_evolution_annuelle_age.png` : Évolution de la maturité des domaines par année.
*   `08_frise_chronologique_mutations.png` : (Conditionnel) Visualisation des changements IP/HTML pré-attaque.

### Métriques Stratégiques (Compléments)
*   `09_classification_clusters_strategies.png` : Répartition par clusters (Immédiat, Rapide, Moyen, Sleeper).
*   `10_courbe_survie_vs_age.png` : Relation entre le temps de vieillissement et la durée de survie (Uptime).
*   `11_expiration_gap_strategique.png` : Analyse de l'utilisation des domaines juste avant leur expiration.

### Analyses Sophistiquées (Wave 2)
*   `12_analyse_weekend_gap_sprinters_vs_sleepers.png` : Tempo opérationnel Sprinters vs Sleepers.
*   `13_correlation_longueur_domaine_vs_age.png` : Relation entre longueur lexicale et temps d'incubation.
*   `14_repartition_tld_sprinters_sleepers.png` : Stratégies de choix des extensions (TLD).
*   `15_saisonnalite_mensuelle_attaques.png` : Volume d'attaques par mois.
*   `16_roi_survie_mediane_par_cluster_age.png` : Efficacité réelle du vieillissement sur la survie.

## 3. Optimisation et Exécution
Le script `generate_adam_graphs.py` utilise le **streaming** pour traiter des fichiers de plus de 21 Go sans saturer la RAM.

```bash
venv/bin/python adam/generate_adam_graphs.py
```
