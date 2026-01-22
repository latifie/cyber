# Propositions d'analyses - Domaines malicieux (down_domains_malicious.jsonl)

## 📊 INFORMATIONS DISPONIBLES DANS down_domains_malicious.jsonl

### Structure complète des données

Chaque enregistrement contient :

#### 1. Champs principaux (100% présents)
- **`rd`** : Nom de domaine racine (ex: `10056185201986206.com`)
- **`fqdn`** : Nom de domaine complet (ex: `fbcaseid.10056185201986206.com`)
- **`url`** : URL complète malveillante (ex: `https://...`)
- **`sid`** : Source ID (identifiant unique de la source)
- **`discovery_time`** : Date/heure de découverte (ex: `2023-02-08T05:35:05`)
- **`dt`** : Date de l'enregistrement (ex: `2023-02-08`)
- **`malicious`** : `True` (tous les domaines sont malicieux)
- **`takedown_reason`** : `'registrar_takedown'` (tous down par le registrar)

#### 2. Transition DNS (100% présents)
- **`transition.transition_date`** : Date de transition NOERROR→NXDOMAIN (ex: `2023-02-09T22:45:36`)
- **`transition.previous_date`** : Date avant la transition (ex: `2023-02-09T07:20:23`)
- **`transition.previous_status`** : `'NOERROR'`
- **`transition.new_status`** : `'NXDOMAIN'`
- **`transition.remains_nxdomain`** : `True` (tous restent down)
- **`transition.year`** : Année de la transition (ex: `'2023'`)

#### 3. WHOIS_BD - Informations WHOIS (57.6% présents)
- **`whois_bd.rd`** : Nom de domaine
- **`whois_bd.cd`** : Date de création du domaine (ex: `2023-02-07`)
- **`whois_bd.ed`** : Date d'expiration (ex: `2024-02-07`)
- **`whois_bd.ud`** : Date de mise à jour WHOIS (ex: `2023-02-07`)
- **`whois_bd.dt`** : Date de requête WHOIS (ex: `2023-02-08T05:46:40`)
- **`whois_bd.iana_id`** : ID IANA du registraire (ex: `1479`)
- **`whois_bd.rdap`** : Booléen RDAP (ex: `False`)

#### 4. Takedown - Informations sur le takedown (100% présents)
- **`takedown.uptime_dur`** : Durée avant takedown en heures (ex: `1545.32`)
- **`takedown.takedown_reason`** : Raison du takedown (`'whois'`, `'dns'`, `'content'`)
- **`takedown.takedowns`** : Liste des takedowns avec :
  - `type` : Type de takedown (`'whois'`, `'dns'`, `'content'`)
  - `dt` : Date du takedown
  - `index` : Index dans la séquence

#### 5. Metadata - Métadonnées du domaine (100% présents)
- **`metadata.src`** : Source de la détection (ex: `'PHISHTANK'`, `'URLHAUS'`, etc.)
- **`metadata.trg`** : Type d'attaque cible (ex: `'Other'`, `'Phishing'`, etc.)
- **`metadata.tld`** : TLD du domaine (ex: `'com'`, `'org'`, etc.)
- **`metadata.tldindex`** : Index du TLD (ex: `0.24`)
- **`metadata.special_type`** : Type spécial (souvent `None`)
- **`metadata.sid`** : Source ID (identique à `sid`)
- **`metadata.indirect`** : Booléen indirect (ex: `False`)

#### 6. DNS_Context - Contexte DNS autour de la transition (100% présents)
- **`dns_context.before`** : Liste des entrées DNS avant transition (5 éléments typiquement)
  - Chaque élément : `dt` (date), `status` (NOERROR), `arec` (adresses IP), `type`, etc.
- **`dns_context.after`** : Liste des entrées DNS après transition (10 éléments typiquement)
  - Chaque élément : `dt` (date), `status` (NXDOMAIN), `arec` (vide), `type`, etc.
- **`dns_context.transition_index`** : Index de la transition dans la séquence

---

## 🎯 PROPOSITIONS D'ANALYSES

### ANALYSES PRIORITAIRES (Haute valeur ajoutée)

#### 1. **Durée entre achat et takedown par période de 6 mois** ✅ (déjà implémenté)
**Données** : `whois_bd.cd` (création) × `transition.transition_date` (takedown)
**Métriques** :
- Distribution de la durée en jours par période (2022-H1 à 2025-H2)
- Moyenne, médiane, quartiles par période
- Évolution temporelle

**Graphique** : `takedown_duration_by_6months.png` ✅ (existe déjà)

---

#### 2. **Analyse par type d'attaque (source)**
**Données** : `metadata.src` × `whois_bd.cd` × `transition.transition_date`
**Métriques** :
- Délai création → takedown par source (Top 10 sources)
- Durée avant takedown par source
- Évolution temporelle par source
- Distribution des sources malicieux

**Graphiques** :
- Box plot délais par source
- Bar chart durées moyennes par source
- Évolution temporelle par source
- Pie chart distribution des sources

**Questions** : Quelle source détecte le plus rapidement ? Y a-t-il des sources plus rapides que d'autres ?

---

#### 3. **Analyse par type d'attaque (target)**
**Données** : `metadata.trg` × délais
**Métriques** :
- Délai création → takedown par type d'attaque (phishing, malware, etc.)
- Durée avant takedown par type d'attaque
- Distribution des types d'attaques

**Graphiques** :
- Comparaison délais par type d'attaque
- Distribution des types d'attaques
- Corrélation type d'attaque × durée avant takedown

**Questions** : Les domaines de phishing sont-ils takedown plus vite que les autres ?

---

#### 4. **Analyse par registraire (IANA ID)**
**Données** : `whois_bd.iana_id` × délais
**Métriques** :
- Top registraires par nombre de domaines malicieux
- Durée moyenne avant takedown par registraire
- Taux de takedown par registraire

**Graphiques** :
- Bar chart top registraires (nombre de domaines)
- Bar chart durée moyenne avant takedown par registraire
- Scatter plot : nombre domaines × durée moyenne takedown

**Questions** : Quels registraires sont les plus utilisés par les attaquants ? Y a-t-il des registraires plus réactifs ?

---

#### 5. **Analyse par TLD**
**Données** : `metadata.tld` × délais
**Métriques** :
- Distribution des domaines malicieux par TLD (Top 20)
- Durée moyenne avant takedown par TLD
- Évolution des TLDs dans le temps

**Graphiques** :
- Pie chart distribution TLDs (Top 15)
- Bar chart délais moyens par TLD
- Évolution temporelle des TLDs

**Questions** : Quels TLDs sont les plus utilisés ? Y a-t-il des TLDs plus rapides à takedown ?

---

#### 6. **Analyse de la durée d'activité malveillante (discovery → takedown)**
**Données** : `discovery_time` × `transition.transition_date`
**Métriques** :
- Durée entre découverte et takedown (en jours/heures)
- Distribution de cette durée
- Évolution temporelle de la vitesse de réaction

**Graphiques** :
- Histogramme durée découverte → takedown
- Évolution temporelle de la vitesse de réaction
- Box plot par année

**Questions** : Combien de temps les domaines restent-ils actifs après découverte ? La vitesse de réaction s'améliore-t-elle ?

---

#### 7. **Analyse de l'âge des domaines au moment du takedown**
**Données** : `whois_bd.cd` (création) × `transition.transition_date` (takedown)
**Métriques** :
- Distribution de l'âge des domaines au moment du takedown
- Catégories : <1 jour, 1-7 jours, 1-30 jours, 1-365 jours, >1 an
- Durée d'activité selon l'âge

**Graphiques** :
- Histogramme âge au takedown
- Pie chart distribution par catégorie d'âge
- Box plot durée d'activité par catégorie d'âge

**Questions** : Les domaines sont-ils takedown rapidement après leur création ? Y a-t-il des domaines anciens utilisés ?

---

#### 8. **Analyse des changements d'IP avant takedown**
**Données** : `dns_context.before[].arec` (adresses IP avant transition)
**Métriques** :
- Nombre de changements d'IP par domaine
- Nombre d'IPs distinctes utilisées
- Stabilité des IPs avant takedown
- Patterns d'IP (IPs fixes vs changeantes)

**Graphiques** :
- Distribution nombre de changements d'IP
- Distribution nombre d'IPs distinctes
- Proportion domaines avec IP fixe vs changeante
- Timeline moyenne des changements d'IP avant takedown

**Questions** : Les attaquants changent-ils souvent d'IP ? Y a-t-il des patterns de migration ?

---

#### 9. **Analyse des délais entre création et première utilisation malveillante**
**Données** : `whois_bd.cd` (création) × `discovery_time` (découverte)
**Métriques** :
- Délai entre création et première détection malveillante
- Proportion de domaines utilisés immédiatement (<1 jour)
- Distribution des délais

**Graphiques** :
- Histogramme délais création → découverte
- Proportion domaines utilisés immédiatement
- Évolution temporelle des délais

**Questions** : Les domaines sont-ils utilisés immédiatement après création ? Y a-t-il un vieillissement volontaire ?

---

#### 10. **Analyse de la raison de takedown**
**Données** : `takedown.takedown_reason` × `takedown.takedowns[]`
**Métriques** :
- Distribution des raisons de takedown (whois, dns, content)
- Durée avant takedown par raison
- Nombre de takedowns multiples par domaine

**Graphiques** :
- Pie chart distribution des raisons
- Box plot durée avant takedown par raison
- Bar chart nombre de takedowns multiples

**Questions** : Quelle raison de takedown est la plus fréquente ? Y a-t-il des corrélations entre raison et durée ?

---

#### 11. **Analyse des patterns temporels (jours/heures)**
**Données** : Dates extraites de `whois_bd.cd`, `discovery_time`, `transition.transition_date`
**Métriques** :
- Distribution des créations par jour de la semaine
- Distribution des créations par heure (0-23)
- Distribution des takedowns par jour/heure
- Heatmap jour × heure

**Graphiques** :
- Bar chart créations par jour de la semaine
- Bar chart créations par heure
- Heatmap créations jour × heure
- Heatmap takedowns jour × heure

**Questions** : Y a-t-il des pics d'activité à certains moments ? Les créations sont-elles concentrées certains jours ?

---

#### 12. **Analyse de la durée de vie du domaine (création → expiration)**
**Données** : `whois_bd.cd` (création) × `whois_bd.ed` (expiration)
**Métriques** :
- Durée de vie prévue des domaines (expiration - création)
- Proportion de domaines avec durée de vie courte (<1 an)
- Corrélation durée de vie × durée avant takedown

**Graphiques** :
- Distribution durée de vie prévue
- Scatter plot durée de vie × durée avant takedown
- Proportion domaines courte durée (<1 an)

**Questions** : Les domaines malicieux ont-ils des durées de vie courtes ? Y a-t-il une corrélation ?

---

### ANALYSES SECONDAIRES (Valeur moyenne)

#### 13. **Analyse des sous-domaines (FQDN vs RD)**
**Données** : `rd` vs `fqdn`
**Métriques** :
- Proportion domaines avec sous-domaines malveillants
- Distribution nombre de sous-domaines
- Patterns dans les sous-domaines (longueur, caractères)

**Graphiques** :
- Proportion domaines entiers vs sous-domaines
- Distribution longueur des sous-domaines
- Patterns fréquents dans les noms de sous-domaines

---

#### 14. **Analyse des URLs malveillantes**
**Données** : `url`
**Métriques** :
- Distribution longueur des URLs
- Patterns dans les chemins (paths)
- Paramètres fréquents (query strings)
- Distribution par schéma (http vs https)

**Graphiques** :
- Histogramme longueur des URLs
- Top patterns de paths
- Distribution http vs https
- Analyse des paramètres fréquents

---

#### 15. **Analyse de l'indirect (metadata.indirect)**
**Données** : `metadata.indirect`
**Métriques** :
- Proportion domaines indirects vs directs
- Différences de comportement entre indirect et direct
- Durée avant takedown selon indirect

**Graphiques** :
- Proportion indirect vs direct
- Comparaison délais indirect vs direct

---

### ANALYSES AVANCÉES (Complexité élevée)

#### 16. **Analyse des patterns de noms de domaines**
**Données** : `rd`, `fqdn`
**Métriques** :
- Longueur moyenne des noms
- Patterns dans les noms (caractères spéciaux, chiffres)
- Similarité entre noms (domaines similaires)
- Distribution caractères aléatoires vs mots

**Graphiques** :
- Histogramme longueur des noms
- Distribution utilisation de caractères spéciaux
- Top patterns de noms (DGA vs humain)

---

#### 17. **Analyse temporelle des takedowns multiples**
**Données** : `takedown.takedowns[]` (liste des takedowns)
**Métriques** :
- Proportion domaines avec takedowns multiples
- Délais entre takedowns multiples
- Patterns de résilience (domaines qui reviennent)

**Graphiques** :
- Distribution nombre de takedowns par domaine
- Timeline des takedowns multiples
- Délais entre takedowns

---

#### 18. **Analyse de corrélation multi-facteurs**
**Données** : Combinaison de plusieurs champs
**Métriques** :
- Matrice de corrélation entre variables
- Clustering des domaines par similarité
- Facteurs prédictifs de durée avant takedown

**Graphiques** :
- Heatmap matrice de corrélation
- Scatter plots multi-dimensionnels
- Analyse en composantes principales (ACP)

---

## 📊 RECOMMANDATIONS D'IMPLÉMENTATION

### Priorité 1 (Impact élevé, complexité faible)
1. ✅ **Durée achat → takedown par période 6 mois** (déjà fait)
2. **Analyse par type d'attaque (source)** - `metadata.src`
3. **Analyse par type d'attaque (target)** - `metadata.trg`
4. **Analyse par TLD** - `metadata.tld`

### Priorité 2 (Impact moyen, complexité faible)
5. **Durée découverte → takedown** - `discovery_time` × `transition.transition_date`
6. **Âge au takedown** - `whois_bd.cd` × `transition.transition_date`
7. **Raison de takedown** - `takedown.takedown_reason`
8. **Patterns temporels** - Extraction jours/heures des dates

### Priorité 3 (Impact élevé, complexité moyenne)
9. **Analyse par registraire** - `whois_bd.iana_id`
10. **Changements d'IP** - `dns_context.before[].arec`
11. **Délai création → découverte** - `whois_bd.cd` × `discovery_time`

---

## 🔧 NOTES TECHNIQUES

### Données manquantes
- `whois_bd` : Présent dans seulement 57.6% des cas
  - → Les analyses basées sur `whois_bd.cd` doivent gérer les valeurs manquantes
- `arec` (IPs) : Peut être vide dans `dns_context.after` (domaines down)

### Optimisations mémoire
- Traiter le fichier en streaming (ligne par ligne)
- Stocker seulement métriques agrégées, pas données brutes
- Utiliser des générateurs pour les calculs complexes

### Format de sortie
- Graphiques PNG 300 DPI (comme `analyze_domains.py`)
- Rapports textuels dans `analysis_results/`
- Fichiers JSONL intermédiaires si nécessaire

---

## 📝 EXEMPLES DE DONNÉES

### Exemple de domaine malicieux :
```json
{
  "rd": "10056185201986206.com",
  "fqdn": "fbcaseid.10056185201986206.com",
  "url": "https://fbcaseid.10056185201986206.com/?fbclid=...",
  "sid": "679d69372253faccda40313d894c4b43",
  "discovery_time": "2023-02-08T05:35:05",
  "malicious": true,
  "takedown_reason": "registrar_takedown",
  "transition": {
    "transition_date": "2023-02-09T22:45:36",
    "previous_date": "2023-02-09T07:20:23",
    "year": "2023"
  },
  "whois_bd": {
    "cd": "2023-02-07",  // Création
    "ed": "2024-02-07",  // Expiration
    "iana_id": "1479"     // Registraire
  },
  "takedown": {
    "uptime_dur": 1545.32,  // Heures
    "takedown_reason": "whois"
  },
  "metadata": {
    "src": "PHISHTANK",
    "trg": "Other",
    "tld": "com"
  },
  "dns_context": {
    "before": [...],  // 5 entrées DNS avant
    "after": [...]    // 10 entrées DNS après
  }
}
```

---

## 🎯 QUESTIONS DE RECHERCHE À RÉPONDRE

1. **Quels types d'attaques sont les plus rapides à takedown ?**
   - Utiliser `metadata.src` et `metadata.trg`

2. **Quels registraires sont les plus réactifs ?**
   - Utiliser `whois_bd.iana_id`

3. **Y a-t-il des patterns temporels dans les créations/takedowns ?**
   - Extraire jours/heures des dates

4. **Les domaines malicieux changent-ils souvent d'IP ?**
   - Analyser `dns_context.before[].arec`

5. **La vitesse de réaction (découverte → takedown) s'améliore-t-elle ?**
   - `discovery_time` × `transition.transition_date`

6. **Quels TLDs sont les plus utilisés par les attaquants ?**
   - Utiliser `metadata.tld`

7. **Y a-t-il une corrélation entre durée de vie prévue et durée avant takedown ?**
   - `whois_bd.cd` × `whois_bd.ed` × `transition.transition_date`
