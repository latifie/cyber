# 🔍 Analyse des Domaines Malicieux - Projet Cyber

Ce projet analyse le vieillissement des domaines malveillants et leur utilisation par les attaquants, en se concentrant sur les transitions DNS (NOERROR → NXDOMAIN) et les takedowns.

## 📋 Structure du Projet

```
cyber/
├── analyze_domains.py              # Script principal d'analyse
├── analyze_malicious_domains.py    # Script d'analyse spécialisé pour domaines malicieux
├── contexte.txt                    # Documentation technique complète
├── sample_data/                    # Échantillons de données pour tests
│   ├── down_domains_sample.jsonl
│   └── down_domains_malicious_sample.jsonl
├── uptimes/                        # Schémas et exemples
│   ├── schema.json
│   └── sample.json
└── Documentation/
    ├── CREATION_DOWN_DOMAINS_MALICIOUS.md
    ├── EXPLICATION_GRAPHIQUES_MALICIEUX.md
    └── GRAPHIQUES_DOMAINES_MALICIEUX.md
```

## 🚀 Utilisation

### Mode Normal (Analyse Complète)

```bash
# Analyse complète de tous les fichiers
python3 analyze_domains.py

# Mode DNS-only (seulement transitions DNS)
python3 analyze_domains.py --dns-only
```

### Mode Échantillon (Tests Rapides)

```bash
# Utilise les fichiers d'échantillon dans sample_data/
python3 analyze_domains.py --sample

# Analyse des domaines malicieux avec échantillon
python3 analyze_malicious_domains.py --sample
```

## 📊 Génération des Graphiques

Les graphiques générés incluent un suffixe indiquant le mode d'exécution :

- `_full` : Analyse complète (toutes les données)
- `_sample` : Mode échantillon (données d'échantillon)
- `_dns-only` : Mode DNS-only (seulement transitions DNS)
- `_sample_dns-only` : Mode échantillon + DNS-only

**Exemples :**
- `creation_delays_full.png` : Analyse complète
- `creation_delays_sample.png` : Analyse sur échantillon
- `malicious_attack_source_analysis_full.png` : Analyse complète des domaines malicieux

## 📁 Échantillons de Données

Les échantillons dans `sample_data/` contiennent 1000 lignes extraites des fichiers complets :

- `down_domains_sample.jsonl` : Échantillon de tous les domaines avec transition
- `down_domains_malicious_sample.jsonl` : Échantillon des domaines malicieux uniquement

**Créer de nouveaux échantillons :**
```bash
head -1000 analysis_results/down_domains.jsonl > sample_data/down_domains_sample.jsonl
head -1000 analysis_results/down_domains_malicious.jsonl > sample_data/down_domains_malicious_sample.jsonl
```

## 🔧 Dépendances

- Python 3.6+
- `matplotlib`, `pandas`, `numpy` (pour les graphiques)
- `tqdm` (optionnel, pour les barres de progression)
- `zstd` (pour lire les fichiers compressés `.zst`)

**Installation :**
```bash
pip install matplotlib pandas numpy tqdm
```

## 📖 Documentation

- **`contexte.txt`** : Documentation technique complète du projet
- **`CREATION_DOWN_DOMAINS_MALICIOUS.md`** : Explication de la création du fichier de domaines malicieux
- **`EXPLICATION_GRAPHIQUES_MALICIEUX.md`** : Explication détaillée de chaque graphique
- **`GRAPHIQUES_DOMAINES_MALICIEUX.md`** : Liste des graphiques basés sur les domaines malicieux

## 🎯 Fonctionnalités Principales

1. **Analyse des transitions DNS** : Détection NOERROR → NXDOMAIN
2. **Filtrage des domaines malicieux** : Identification des domaines qui restent down
3. **Calcul des délais** : Création → utilisation, découverte → takedown
4. **Analyses spécialisées** : Par source, target, registraire, TLD, etc.
5. **Visualisations** : Graphiques PNG haute résolution (300 DPI)

## 📝 Notes

- Les fichiers volumineux (`.zst`, `.jsonl` complets) sont exclus du dépôt Git
- Seuls les échantillons dans `sample_data/` sont versionnés
- Les résultats d'analyse sont dans `analysis_results/` (exclus du Git)

## 🔗 Dépôt Git

**Remote :** `git@gitlab.ensimag.fr:piconf/cyber.git`

**Cloner le dépôt :**
```bash
git clone git@gitlab.ensimag.fr:piconf/cyber.git
```

---

**Auteur :** Projet Cyber - Analyse automatique  
**Date :** 2025
