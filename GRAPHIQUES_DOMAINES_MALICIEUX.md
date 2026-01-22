# 📊 RÉCAPITULATIF DES GRAPHIQUES - DOMAINES MALICIEUX

Ce document liste **tous les graphiques** générés par les scripts d'analyse et indique lesquels sont basés **uniquement sur les domaines malicieux** (NOERROR → NXDOMAIN qui restent en NXDOMAIN).

---

## 🔍 DÉFINITION : DOMAINES MALICIEUX

**Domaines malicieux** = Domaines qui :
1. Ont fait une transition **NOERROR → NXDOMAIN**
2. **RESTENT en NXDOMAIN** (ne reviennent pas à NOERROR)
3. Ont `remains_nxdomain = true` dans les données

**Fichier source :** `analysis_results/down_domains_malicious.jsonl`

---

## 📈 GRAPHIQUES GÉNÉRÉS PAR `analyze_domains.py`

### ✅ **1. `takedown_durations.png`** 
**🔴 BASÉ UNIQUEMENT SUR DOMAINES MALICIEUX**

- **Méthode :** `_plot_takedown_durations()`
- **Filtre appliqué :** Oui, ligne 1145-1156
  ```python
  domains_that_remain_down = set()
  for transition in self.stats['dns_transitions']:
      if transition.get('remains_nxdomain', False):
          domains_that_remain_down.add(transition.get('rd', ''))
  
  filtered_durations = [d for d in self.stats['takedown_durations'] 
                       if d.get('rd', '') in domains_that_remain_down]
  ```
- **Contenu :**
  - Histogramme des durées avant takedown (domaines restant down uniquement)
  - Takedowns par raison (Top 10, domaines restant down uniquement)
- **Données :** `self.stats['takedown_durations']` filtré pour `remains_nxdomain = true`

---

### ✅ **2. `takedown_duration_by_6months.png`**
**🔴 BASÉ UNIQUEMENT SUR DOMAINES MALICIEUX**

- **Méthode :** `_plot_takedown_duration_by_6months()`
- **Filtre appliqué :** Oui, ligne 1331-1333
  ```python
  remains_nxdomain = transition.get('remains_nxdomain', False)
  if not remains_nxdomain:
      continue  # Ignorer les takedowns légitimes (re-up)
  ```
- **Source de données :** Lit directement `down_domains.jsonl` et filtre pour `remains_nxdomain = true`
- **Contenu :**
  - Durée moyenne et médiane par période de 6 mois
  - Distribution des durées par période (box plot)
  - Nombre de takedowns illégitimes par période
  - Évolution de la durée médiane
- **Titre du graphique :** "Domaines down pour raisons illégitimes"

---

### ⚠️ **3. `temporal_evolution.png`**
**🟡 PARTIELLEMENT FILTRÉ (1 sous-graphique sur 4)**

- **Méthode :** `_plot_temporal_evolution()`
- **Sous-graphiques :**
  1. **Domaines par année** → ❌ PAS de filtre (tous les domaines)
  2. **Transitions DNS par année** → ❌ PAS de filtre (toutes les transitions)
  3. **Délais moyens par année** → ❌ PAS de filtre (tous les délais)
  4. **Takedowns par année** → ✅ **FILTRÉ** (ligne 1060-1082, uniquement domaines restant down)
- **Note :** Seul le 4ème sous-graphique filtre pour les domaines malicieux

---

### ⚠️ **4. `year_comparison.png`**
**🟡 PARTIELLEMENT FILTRÉ (1 sous-graphique sur 4)**

- **Méthode :** `_plot_year_comparison()`
- **Sous-graphiques :**
  1. **Volume total par année** → ❌ PAS de filtre (tous les domaines)
  2. **Délais moyens** → ❌ PAS de filtre (tous les délais)
  3. **Taux de transitions permanentes** → ⚠️ Montre le taux mais pas filtré (calcule le %)
  4. **Durées moyennes takedown** → ✅ **FILTRÉ** (ligne 1257-1280, uniquement domaines restant down)
- **Note :** Seul le 4ème sous-graphique filtre pour les domaines malicieux

---

### ❌ **5. `creation_delays.png`**
**❌ PAS DE FILTRE (TOUS LES DOMAINES)**

- **Méthode :** `_plot_creation_delays()`
- **Filtre appliqué :** Non
- **Données :** `self.stats['creation_to_usage_delays']` (tous les domaines, pas seulement malicieux)
- **Contenu :**
  - Distribution globale des délais création → utilisation
  - Box plot par année
  - Distribution logarithmique
  - Courbe cumulative
- **Note :** Analyse tous les domaines malveillants, pas seulement ceux qui restent down

---

### ⚠️ **6. `dns_transitions.png`**
**🟡 MONTRE LES DEUX CATÉGORIES (PAS DE FILTRE)**

- **Méthode :** `_plot_dns_transitions()`
- **Filtre appliqué :** Non (mais distingue permanents vs temporaires)
- **Contenu :**
  - Graphique en camembert : Proportion transitions permanentes vs temporaires
  - Barres par année : Total transitions vs Permanentes
- **Note :** Montre TOUTES les transitions, mais distingue celles qui restent down (permanentes) de celles qui re-up (temporaires). Ne filtre PAS pour ne garder que les malicieux, mais les SÉPARE visuellement.

---

## 📊 GRAPHIQUES GÉNÉRÉS PAR `analyze_malicious_domains.py`

**🔴 TOUS LES GRAPHIQUES DE CE SCRIPT SONT BASÉS UNIQUEMENT SUR DOMAINES MALICIEUX**

**Source de données :** `analysis_results/down_domains_malicious.jsonl`
- Ce fichier contient **uniquement** les domaines avec `remains_nxdomain = true`
- Tous les graphiques de ce script sont donc **100% basés sur les domaines malicieux**

### ✅ **1. `malicious_attack_source_analysis.png`**
**🔴 BASÉ UNIQUEMENT SUR DOMAINES MALICIEUX**

- Analyse par type d'attaque (source) : `metadata.src`
- Délais création → takedown par source
- Durées moyennes avant takedown par source
- Distribution des sources
- Évolution temporelle par source

---

### ✅ **2. `malicious_attack_target_analysis.png`**
**🔴 BASÉ UNIQUEMENT SUR DOMAINES MALICIEUX**

- Analyse par type d'attaque (target) : `metadata.trg`
- Délais création → takedown par target
- Durées moyennes avant takedown par target
- Distribution des targets
- Évolution temporelle par target

---

### ✅ **3. `malicious_registrar_analysis.png`**
**🔴 BASÉ UNIQUEMENT SUR DOMAINES MALICIEUX**

- Analyse par registraire : `whois_bd.iana_id`
- Top registraires par volume
- Durées moyennes avant takedown par registraire
- Distribution délais par registraire
- Volume vs Durée moyenne takedown

---

### ✅ **4. `malicious_tld_analysis.png`**
**🔴 BASÉ UNIQUEMENT SUR DOMAINES MALICIEUX**

- Analyse par TLD : `metadata.tld`
- Distribution des TLDs
- Durées moyennes avant takedown par TLD
- Distribution délais par TLD
- Évolution volume par TLD

---

### ✅ **5. `malicious_discovery_to_takedown.png`**
**🔴 BASÉ UNIQUEMENT SUR DOMAINES MALICIEUX**

- Durée entre découverte et takedown
- Distribution des durées
- Distribution logarithmique
- Évolution temporelle (moyenne et médiane)
- Distribution par année

---

### ✅ **6. `malicious_age_at_takedown.png`**
**🔴 BASÉ UNIQUEMENT SUR DOMAINES MALICIEUX**

- Âge des domaines au moment du takedown
- Distribution de l'âge (0-365 jours)
- Distribution par catégorie d'âge (<1j, 1-7j, 7-30j, 30j-1an, >1an)
- Box plot par catégorie
- Évolution âge moyen au takedown

---

### ✅ **7. `malicious_ip_changes.png`**
**🔴 BASÉ UNIQUEMENT SUR DOMAINES MALICIEUX**

- Changements d'IP avant takedown
- Distribution du nombre de changements d'IP
- Distribution du nombre d'IPs uniques
- Proportion domaines avec/sans changement d'IP
- Statistiques des changements

---

## 📋 RÉSUMÉ PAR SCRIPT

### `analyze_domains.py` (6 graphiques)

| Graphique | Basé sur domaines malicieux ? | Détails |
|-----------|-------------------------------|---------|
| `takedown_durations.png` | ✅ **OUI** | 100% filtré |
| `takedown_duration_by_6months.png` | ✅ **OUI** | 100% filtré |
| `temporal_evolution.png` | 🟡 **PARTIELLEMENT** | 1/4 sous-graphiques filtré |
| `year_comparison.png` | 🟡 **PARTIELLEMENT** | 1/4 sous-graphiques filtré |
| `creation_delays.png` | ❌ **NON** | Tous les domaines |
| `dns_transitions.png` | ⚠️ **SÉPARATION** | Montre permanents vs temporaires (pas de filtre) |

### `analyze_malicious_domains.py` (7 graphiques)

| Graphique | Basé sur domaines malicieux ? | Détails |
|-----------|-------------------------------|---------|
| `malicious_attack_source_analysis.png` | ✅ **OUI** | 100% filtré |
| `malicious_attack_target_analysis.png` | ✅ **OUI** | 100% filtré |
| `malicious_registrar_analysis.png` | ✅ **OUI** | 100% filtré |
| `malicious_tld_analysis.png` | ✅ **OUI** | 100% filtré |
| `malicious_discovery_to_takedown.png` | ✅ **OUI** | 100% filtré |
| `malicious_age_at_takedown.png` | ✅ **OUI** | 100% filtré |
| `malicious_ip_changes.png` | ✅ **OUI** | 100% filtré |

---

## 🎯 TOTAL

- **Graphiques 100% basés sur domaines malicieux :** 9
  - 2 dans `analyze_domains.py`
  - 7 dans `analyze_malicious_domains.py`

- **Graphiques partiellement basés sur domaines malicieux :** 2
  - `temporal_evolution.png` (1/4 sous-graphiques)
  - `year_comparison.png` (1/4 sous-graphiques)

- **Graphiques NON basés sur domaines malicieux :** 2
  - `creation_delays.png` (tous les domaines)
  - `dns_transitions.png` (montre tous, mais sépare permanents vs temporaires)

---

## 📝 NOTES IMPORTANTES

1. **Filtre `remains_nxdomain = true`** : Ce filtre identifie les domaines qui sont passés de NOERROR à NXDOMAIN et qui **restent** en NXDOMAIN (ne reviennent pas à NOERROR).

2. **Fichier `down_domains_malicious.jsonl`** : Contient uniquement les domaines avec `remains_nxdomain = true`, marqués comme `malicious: true` et `takedown_reason: 'registrar_takedown'`.

3. **Graphiques partiels** : Certains graphiques ont plusieurs sous-graphiques, et seul un sous-graphique peut être filtré. Dans ce cas, le graphique est marqué comme "partiellement filtré".

4. **Graphique `dns_transitions.png`** : Ne filtre pas, mais **sépare visuellement** les transitions permanentes (malicieux) des temporaires (légitimes). C'est utile pour voir la proportion, mais ne se concentre pas uniquement sur les malicieux.

---

**Généré le :** 2025  
**Scripts analysés :** `analyze_domains.py`, `analyze_malicious_domains.py`
