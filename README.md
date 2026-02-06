# 🔍 Analyse des Domaines Malicieux - Projet Cyber

Ce projet se concentre sur l'identification et l'analyse des domaines malveillants, en particulier ceux ayant fait l'objet d'un "takedown" lié au **WHOIS**.

## 📋 Structure du Projet

```
cyber/
├── extract_malicious_domains_with_takedown_whois.py  # Script principal d'extraction
├── common_utils.py                                   # Utilitaires partagés (lecture JSONL/ZST)
├── visualisation/                                    # Outils de visualisation et graphiques
│   └── jsonl_viewer.py                               # Visualiseur de fichiers JSONL
├── analysis_results/                                 # Dossier de sortie des résultats
├── sample_data/                                      # Données d'échantillon pour tests
├── uptimes/                                          # Dossier source des données (non versionné si volumineux)
├── old_analyse/                                      # Anciens scripts et résultats archivés
└── 2022/, 2023/, 2025/ ...                           # Dossiers de données brutes par année
```

## 🚀 Utilisation

### Extraction des domaines malicieux

Le script principal `extract_malicious_domains_with_takedown_whois.py` parcourt les fichiers de données uptime et extrait les domaines dont le takedown est de type "whois".

```bash
# Mode Normal (analyse les fichiers dans le dossier 'uptimes/')
python3 extract_malicious_domains_with_takedown_whois.py

# Mode Échantillon (analyse les fichiers dans 'sample_data/uptimes/')
python3 extract_malicious_domains_with_takedown_whois.py --sample
```

**Sortie :** Les fichiers résultats sont générés dans `analysis_results/` avec le format `malicious_domains_takedown_whois_{mode}_{timestamp}.jsonl`.

### Visualisation

Des outils de visualisation sont disponibles dans le dossier `visualisation/`.

```bash
# Lancer le visualiseur JSONL (exemple)
python3 visualisation/jsonl_viewer.py
```

## 🔧 Dépendances et Prérequis

- **Python 3.6+**
- **Outil système `zstd`** : Requis pour la lecture des fichiers compressés `.zst` (utilisé via `zstdcat`).

**Installation :**

Sur Linux (Debian/Ubuntu) :
```bash
sudo apt install zstd
```

Le projet utilise principalement la librairie standard Python. Les dépendances spécifiques pour la visualisation (comme `matplotlib`, `pandas`) peuvent être requises si vous utilisez les scripts dans `visualisation/` ou `old_analyse/`.

## 📝 Notes

- Les données volumineuses (fichiers `.zst` complets) sont généralement exclues du contrôle de version.
- `common_utils.py` gère la lecture transparente des fichiers bruts (`.json`) et compressés (`.zst`).

## 🔗 Dépôt Git

**Remote :** `git@gitlab.ensimag.fr:piconf/cyber.git`
