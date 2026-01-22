# 📝 CRÉATION DU FICHIER `down_domains_malicious.jsonl`

Ce document explique en détail comment le fichier `down_domains_malicious.jsonl` est créé à partir des données sources.

---

## 🔄 PROCESSUS EN 2 ÉTAPES

La création de `down_domains_malicious.jsonl` se fait en **2 étapes principales** :

1. **Étape 1 :** Création de `down_domains.jsonl` (tous les domaines avec transition NOERROR → NXDOMAIN)
2. **Étape 2 :** Filtrage pour créer `down_domains_malicious.jsonl` (uniquement ceux qui restent down)

---

## 📊 ÉTAPE 1 : CRÉATION DE `down_domains.jsonl`

### **Quand ?**
Lors de l'exécution de `analyze_domains.py`, pendant le traitement des fichiers **uptimes**.

### **Méthode :** `process_uptime_record()`
**Ligne :** 412-500 dans `analyze_domains.py`

### **Processus détaillé :**

#### 1. **Lecture des fichiers uptimes**
- Les fichiers uptimes sont dans `uptimes/*.json.zst` ou `uptimes/*.json`
- Format : Une ligne JSON par domaine avec un historique DNS/WHOIS

#### 2. **Détection des transitions DNS**
Pour chaque domaine, le script :
- Extrait toutes les entrées DNS de l'historique `uptime`
- Trie les entrées par date
- Cherche les transitions **NOERROR → NXDOMAIN**

```python
# Exemple de détection (ligne 436)
if current_status == 'NOERROR' and next_status == 'NXDOMAIN':
    # Transition détectée !
```

#### 3. **Vérification si la transition est permanente**
Pour chaque transition détectée, le script vérifie si le domaine **reste en NXDOMAIN** :

```python
# Ligne 438-454
remains_nxdomain = True
check_limit = min(i + 50, len(dns_entries))

# Vérifier les 50 entrées suivantes (ou jusqu'à la fin)
for j in range(i + 2, check_limit):
    if dns_entries[j].get('dns_status') != 'NXDOMAIN':
        remains_nxdomain = False  # Le domaine est revenu à NOERROR
        break

# Si on a vérifié jusqu'à la fin et que tout est NXDOMAIN, c'est permanent
if remains_nxdomain and check_limit == len(dns_entries):
    # Vérifier les 10 dernières entrées pour confirmer
    last_entries = dns_entries[-10:] if len(dns_entries) >= 10 else dns_entries
    if all(e.get('dns_status') == 'NXDOMAIN' for e in last_entries):
        remains_nxdomain = True
    else:
        remains_nxdomain = False
```

**Logique :**
- Si le domaine revient à `NOERROR` dans les 50 entrées suivantes → `remains_nxdomain = False` (temporaire)
- Si le domaine reste en `NXDOMAIN` jusqu'à la fin → `remains_nxdomain = True` (permanent)

#### 4. **Écriture dans `down_domains.jsonl`**
Pour **chaque transition** détectée (permanente ou temporaire), le script écrit un enregistrement dans `down_domains.jsonl` :

```python
# Ligne 470-497
domain_info = {
    'rd': record.get('rd', 'unknown'),              # Root domain
    'fqdn': record.get('fqdn', 'unknown'),          # Fully qualified domain name
    'url': record.get('url', 'unknown'),             # URL d'origine
    'sid': record.get('sid', 'unknown'),             # Source ID
    'discovery_time': record.get('discovery_time', ''),
    'metadata': record.get('metadata', {}),          # src, trg, tld, etc.
    'transition': {
        'transition_date': next_entry.get('dt', ''), # Date de la transition
        'previous_date': current.get('dt', ''),
        'previous_status': current_status,           # 'NOERROR'
        'new_status': next_status,                   # 'NXDOMAIN'
        'remains_nxdomain': remains_nxdomain,        # ⭐ Clé pour le filtrage
        'year': transition['year']
    },
    'whois_bd': record.get('whois_bd', {}),         # Date création, registraire, etc.
    'takedown': record.get('takedown', {}),          # Durée avant takedown
    'dns_context': {
        'before': [...],  # 5 entrées DNS avant la transition
        'after': [...]   # 10 entrées DNS après la transition
    }
}
self.down_domains_file.write(json.dumps(domain_info, ensure_ascii=False) + '\n')
```

**Résultat :** `down_domains.jsonl` contient **TOUS** les domaines avec transition NOERROR → NXDOMAIN, qu'ils soient permanents ou temporaires.

---

## 🔍 ÉTAPE 2 : FILTRAGE POUR CRÉER `down_domains_malicious.jsonl`

### **Quand ?**
À la **fin** du traitement de tous les fichiers, après la fermeture de `down_domains.jsonl`.

**Ligne :** 852-853 dans `analyze_domains.py`

```python
# Fermer le fichier des domaines down
if self.down_domains_file:
    self.down_domains_file.close()
    # ...
    # Créer un fichier filtré avec seulement les domaines malicieux
    self._filter_malicious_domains(down_domains_path)
```

### **Méthode :** `_filter_malicious_domains()`
**Ligne :** 855-930 dans `analyze_domains.py`

### **Processus détaillé :**

#### 1. **Ouverture des fichiers**
```python
# Ligne 878-879
with open(down_domains_path, 'r', encoding='utf-8') as f_in:
    with open(malicious_domains_path, 'w', encoding='utf-8') as f_out:
```

- **Lecture :** `down_domains.jsonl` (tous les domaines)
- **Écriture :** `down_domains_malicious.jsonl` (domaines malicieux uniquement)

#### 2. **Traitement ligne par ligne (streaming)**
Le script lit `down_domains.jsonl` ligne par ligne pour optimiser la mémoire :

```python
# Ligne 892-922
for line in iterator:
    line = line.strip()
    if not line:
        continue
    
    try:
        record = json.loads(line)  # Parser la ligne JSON
        stats['total_read'] += 1
        
        # Extraire la transition
        transition = record.get('transition') or {}
        if not isinstance(transition, dict):
            continue
        
        # ⭐ CRITÈRE DE FILTRAGE
        remains_nxdomain = transition.get('remains_nxdomain', False)
        
        # Ne garder que les domaines malicieux (reste down)
        if remains_nxdomain:
            # Ajouter des champs supplémentaires
            record['malicious'] = True
            record['takedown_reason'] = 'registrar_takedown'
            
            # Écrire dans le fichier malicieux
            f_out.write(json.dumps(record, ensure_ascii=False) + '\n')
            stats['malicious_count'] += 1
        else:
            stats['legitimate_count'] += 1  # Compteur pour stats
```

#### 3. **Critère de filtrage**
**Seul critère :** `remains_nxdomain = True`

- ✅ **Inclus :** Domaines avec `remains_nxdomain = True` (reste en NXDOMAIN)
- ❌ **Exclus :** Domaines avec `remains_nxdomain = False` (re-up, redevient NOERROR)

#### 4. **Champs ajoutés**
Pour chaque domaine malicieux, le script ajoute deux champs :

```python
record['malicious'] = True
record['takedown_reason'] = 'registrar_takedown'
```

#### 5. **Statistiques affichées**
À la fin du filtrage, le script affiche :

```python
print(f"  ✓ {stats['malicious_count']:,} domaines malicieux extraits")
print(f"    • Total lu: {stats['total_read']:,}")
print(f"    • Malicieux (reste down): {stats['malicious_count']:,}")
print(f"    • Légitimes (re-up): {stats['legitimate_count']:,}")
```

---

## 📋 RÉSUMÉ DU PROCESSUS COMPLET

```
┌─────────────────────────────────────────────────────────────┐
│  FICHIERS UPTIMES (uptimes/*.json.zst)                      │
│  - Historique DNS/WHOIS par domaine                         │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  process_uptime_record()                                    │
│  1. Détecte transitions NOERROR → NXDOMAIN                 │
│  2. Vérifie si reste NXDOMAIN (remains_nxdomain)            │
│  3. Écrit dans down_domains.jsonl                            │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  down_domains.jsonl                                         │
│  - TOUS les domaines avec transition NOERROR → NXDOMAIN    │
│  - Inclut : permanents (remains_nxdomain=true)              │
│            + temporaires (remains_nxdomain=false)          │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  _filter_malicious_domains()                                │
│  1. Lit down_domains.jsonl ligne par ligne                  │
│  2. Filtre pour remains_nxdomain = true                     │
│  3. Ajoute malicious=true et takedown_reason                │
│  4. Écrit dans down_domains_malicious.jsonl                  │
└──────────────────────┬──────────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────────┐
│  down_domains_malicious.jsonl                                │
│  - UNIQUEMENT les domaines malicieux                        │
│  - remains_nxdomain = true                                  │
│  - malicious = true                                         │
│  - takedown_reason = 'registrar_takedown'                    │
└─────────────────────────────────────────────────────────────┘
```

---

## 🔑 POINTS CLÉS

### **1. Critère de filtrage unique**
Le seul critère pour déterminer si un domaine est malicieux est :
```python
remains_nxdomain = True
```

### **2. Interprétation**
- **`remains_nxdomain = True`** → Domaine malicieux (reste down, takedown par registrar)
- **`remains_nxdomain = False`** → Domaine légitime (re-up, redevient NOERROR)

### **3. Vérification de permanence**
La vérification se fait en analysant les **50 entrées DNS suivantes** (ou jusqu'à la fin) :
- Si une seule entrée revient à `NOERROR` → temporaire
- Si toutes restent en `NXDOMAIN` → permanent (malicieux)

### **4. Traitement en streaming**
- Les fichiers sont traités **ligne par ligne** pour optimiser la mémoire
- Pas de chargement complet en mémoire
- Support des fichiers compressés `.zst`

### **5. Champs ajoutés**
Chaque domaine dans `down_domains_malicious.jsonl` a :
- `malicious: true`
- `takedown_reason: 'registrar_takedown'`
- Tous les autres champs de `down_domains.jsonl`

---

## 📊 EXEMPLE DE DONNÉES

### **Dans `down_domains.jsonl` (tous les domaines) :**
```json
{
  "rd": "example.com",
  "transition": {
    "remains_nxdomain": true,  // ← Ce domaine sera inclus
    "transition_date": "2024-03-15T10:30:00"
  }
}
```

```json
{
  "rd": "legitimate.com",
  "transition": {
    "remains_nxdomain": false,  // ← Ce domaine sera EXCLU
    "transition_date": "2024-03-15T10:30:00"
  }
}
```

### **Dans `down_domains_malicious.jsonl` (filtré) :**
```json
{
  "rd": "example.com",
  "malicious": true,  // ← Ajouté
  "takedown_reason": "registrar_takedown",  // ← Ajouté
  "transition": {
    "remains_nxdomain": true,
    "transition_date": "2024-03-15T10:30:00"
  }
}
```

**Note :** Le domaine `legitimate.com` n'apparaît **pas** dans `down_domains_malicious.jsonl` car `remains_nxdomain = false`.

---

## ⚙️ COMMANDES POUR GÉNÉRER LE FICHIER

### **Génération complète :**
```bash
python3 analyze_domains.py
```
- Traite tous les fichiers uptimes
- Crée `down_domains.jsonl`
- Filtre automatiquement pour créer `down_domains_malicious.jsonl`

### **Mode DNS-only (seulement transitions DNS) :**
```bash
python3 analyze_domains.py --dns-only
```
- Ignore les fichiers JSONL (années)
- Traite seulement les fichiers uptimes
- Crée quand même `down_domains.jsonl` et `down_domains_malicious.jsonl`

### **Mode test :**
```bash
python3 analyze_domains.py --test
```
- Limite le traitement à 200 lignes par fichier
- Crée des fichiers de test plus petits

---

## 📍 EMPLACEMENT DES FICHIERS

- **Source :** `uptimes/*.json.zst` ou `uptimes/*.json`
- **Intermédiaire :** `analysis_results/down_domains.jsonl`
- **Final :** `analysis_results/down_domains_malicious.jsonl`

---

**Généré le :** 2025  
**Script :** `analyze_domains.py`  
**Méthodes :** `process_uptime_record()`, `_filter_malicious_domains()`
