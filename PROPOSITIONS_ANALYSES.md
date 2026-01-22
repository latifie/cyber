# Propositions d'analyses supplémentaires

Basé sur le contexte du projet et les données disponibles, voici des analyses pertinentes à implémenter.

## 📊 ANALYSES PRIORITAIRES (Haute valeur ajoutée)

### 1. **Analyse du vieillissement par type d'attaque**
**Objectif**: Comprendre si le vieillissement dépend du type d'attaque (spam, phishing, etc.)

**Métriques à calculer**:
- Délai création → utilisation par `src` (source) et `trg` (target)
- Durée avant takedown par type d'attaque
- Taux de transitions permanentes par type d'attaque
- Distribution de l'âge des domaines par type d'attaque

**Graphiques**:
- Box plot délais par type d'attaque (Top 10)
- Heatmap: Type d'attaque × Période (6 mois) × Durée moyenne
- Comparaison domaines anciens vs nouveaux par type

**Données nécessaires**: `metadata.src`, `metadata.trg`, `whois_bd.cd`, `discovery_time`

---

### 2. **Détection de changement de propriétaire WHOIS**
**Objectif**: Identifier les domaines légitimes rachetés (changement WHOIS = vieillissement artificiel)

**Métriques à calculer**:
- Nombre de changements WHOIS (active → inactive ou changement de registrant)
- Délai entre création et changement de propriétaire
- Durée entre changement de propriétaire et utilisation malveillante
- Proportion de domaines avec changement WHOIS vs nouveaux domaines

**Graphiques**:
- Timeline: Création → Changement WHOIS → Utilisation malveillante
- Distribution des délais entre changement WHOIS et utilisation
- Comparaison comportement domaines rachetés vs nouveaux

**Données nécessaires**: `uptime` entries avec `type='whois'`, changements de `whois_status` ou registrant

---

### 3. **Analyse des ruptures DNS (changements d'IP)**
**Objectif**: Détecter les changements d'IP suspects (migration, compromission)

**Métriques à calculer**:
- Nombre de changements d'IP par domaine (dans `arec`)
- Fréquence des changements d'IP avant/après transition
- Stabilité des IPs (domaines avec IP fixe vs IPs changeantes)
- Corrélation changements d'IP et takedown

**Graphiques**:
- Distribution du nombre de changements d'IP par domaine
- Timeline des changements d'IP autour de la transition NOERROR→NXDOMAIN
- Heatmap: Période × Nombre changements IP × Durée avant takedown

**Données nécessaires**: `uptime` entries avec `type='dns'`, `arec` (array d'IPs)

---

### 4. **Analyse des domaines anciens vs nouveaux**
**Objectif**: Comparer le comportement des domaines selon leur âge

**Métriques à calculer**:
- Distribution de l'âge des domaines au moment de l'utilisation malveillante
- Durée avant takedown selon l'âge du domaine (catégories: <1an, 1-5ans, >5ans)
- Taux de transitions permanentes selon l'âge
- Proportion domaines anciens (>5ans) par type d'attaque

**Graphiques**:
- Histogramme de l'âge des domaines au moment de l'utilisation
- Box plot durée avant takedown par catégorie d'âge
- Évolution de l'âge moyen des domaines malveillants dans le temps

**Données nécessaires**: `whois_bd.cd`, `discovery_time`, calcul de l'âge

---

### 5. **Patterns temporels d'activité**
**Objectif**: Identifier les patterns temporels (jours de la semaine, heures, saisons)

**Métriques à calculer**:
- Distribution des créations de domaines par jour de la semaine
- Distribution des transitions NOERROR→NXDOMAIN par jour/heure
- Durée avant takedown selon le jour de création
- Patterns saisonniers (pics d'activité)

**Graphiques**:
- Heatmap: Jour de la semaine × Heure × Nombre de transitions
- Graphique en radar: Activité par jour de la semaine
- Timeline avec marqueurs des pics d'activité

**Données nécessaires**: Extraction jour/heure depuis `discovery_time`, `transition_date`

---

## 📊 ANALYSES SECONDAIRES (Valeur moyenne)

### 6. **Analyse des domaines avec re-up (takedowns légitimes)**
**Objectif**: Comprendre pourquoi certains domaines redeviennent actifs

**Métriques à calculer**:
- Durée moyenne en NXDOMAIN avant re-up
- Nombre de cycles NOERROR→NXDOMAIN→NOERROR
- Proportion de domaines avec re-up par type d'attaque
- Délai entre re-up et nouveau takedown

**Graphiques**:
- Distribution des durées en NXDOMAIN avant re-up
- Timeline des cycles pour domaines avec multiples transitions
- Comparaison domaines avec re-up vs permanents

**Données nécessaires**: `uptime` entries, détection cycles NOERROR→NXDOMAIN→NOERROR

---

### 7. **Analyse par registraire/TLD**
**Objectif**: Identifier les registraires/TLDs les plus utilisés par les attaquants

**Métriques à calculer**:
- Distribution des domaines par TLD (.com, .org, .net, etc.)
- Top registraires (si disponible dans whois_bd)
- Durée avant takedown par TLD
- Taux de transitions permanentes par TLD

**Graphiques**:
- Pie chart des TLDs (Top 15)
- Bar chart durée moyenne avant takedown par TLD
- Évolution de la distribution des TLDs dans le temps

**Données nécessaires**: Extraction TLD depuis `rd`/`fqdn`, `whois_bd` (si registraire disponible)

---

### 8. **Analyse de la corrélation délai création → utilisation et durée avant takedown**
**Objectif**: Comprendre si les domaines utilisés rapidement sont takedown plus vite

**Métriques à calculer**:
- Corrélation entre délai création→utilisation et durée avant takedown
- Scatter plot avec régression
- Catégorisation: domaines rapides (<1j) vs lents (>30j) et leur durée avant takedown

**Graphiques**:
- Scatter plot: Délai création→utilisation × Durée avant takedown
- Box plot durée avant takedown par catégorie de délai création→utilisation
- Matrice de corrélation

**Données nécessaires**: `creation_to_usage_delays`, `takedown_durations`

---

## 📊 ANALYSES AVANCÉES (Complexité élevée)

### 9. **Détection de domaines légitimes compromis**
**Objectif**: Identifier les signaux indiquant un domaine légitime détourné

**Signaux à analyser**:
- Domaine ancien (>5ans) utilisé soudainement pour malveillance
- Changement WHOIS récent avant utilisation malveillante
- Changement d'IP brutal (passage d'IP légitime à IP suspecte)
- Subdomain malveillant sur domaine légitime (analyse de `url`)

**Métriques**:
- Nombre de domaines avec signaux de compromission
- Délai entre compromission et détection
- Comparaison comportement domaines compromis vs nouveaux

**Graphiques**:
- Timeline des événements pour domaines compromis
- Distribution des signaux de compromission
- Comparaison métriques domaines compromis vs nouveaux

**Données nécessaires**: Combinaison de plusieurs sources (âge, WHOIS, DNS, URL)

---

### 10. **Analyse des subresources malveillantes**
**Objectif**: Détecter les URL injections et hébergement non voulu

**Métriques à calculer**:
- Proportion de domaines avec path malveillant (ex: google.com/phishing)
- Distribution des paths malveillants
- Durée avant takedown pour subresources vs domaines entiers
- Patterns dans les URLs (longueur, caractères spéciaux, etc.)

**Graphiques**:
- Distribution des longueurs d'URL
- Top patterns de paths malveillants
- Comparaison durée avant takedown: domaine entier vs subresource

**Données nécessaires**: Analyse de `url` pour extraire path, détection patterns suspects

---

### 11. **Analyse de la vitesse de réaction (détection → takedown)**
**Objectif**: Mesurer l'efficacité des systèmes de détection

**Métriques à calculer**:
- Délai entre `discovery_time` et transition NOERROR→NXDOMAIN
- Délai entre `discovery_time` et takedown
- Évolution de la vitesse de réaction dans le temps
- Vitesse de réaction par type d'attaque

**Graphiques**:
- Distribution des délais détection→takedown
- Évolution temporelle de la vitesse de réaction
- Comparaison par type d'attaque

**Données nécessaires**: `discovery_time`, `transition_date`, `takedown.uptime_dur`

---

### 12. **Analyse des domaines avec multiples transitions**
**Objectif**: Comprendre les domaines "résilients" (multiples takedowns)

**Métriques à calculer**:
- Nombre de domaines avec >1 transition NOERROR→NXDOMAIN
- Durée moyenne entre transitions multiples
- Patterns de résilience (domaines qui reviennent plusieurs fois)
- Durée totale d'activité malveillante

**Graphiques**:
- Distribution du nombre de transitions par domaine
- Timeline des domaines avec transitions multiples
- Durée totale d'activité vs nombre de transitions

**Données nécessaires**: Comptage transitions par domaine dans `dns_transitions`

---

## 🎯 RECOMMANDATIONS D'IMPLÉMENTATION

### Priorité 1 (Impact élevé, complexité moyenne)
1. **Analyse du vieillissement par type d'attaque** (#1)
2. **Détection de changement de propriétaire WHOIS** (#2)
3. **Analyse des domaines anciens vs nouveaux** (#4)

### Priorité 2 (Impact moyen, complexité faible)
4. **Patterns temporels d'activité** (#5)
5. **Analyse par TLD** (#7)
6. **Corrélation délais** (#8)

### Priorité 3 (Impact élevé, complexité élevée)
7. **Détection domaines légitimes compromis** (#9)
8. **Analyse des ruptures DNS** (#3)
9. **Analyse subresources malveillantes** (#10)

---

## 📝 NOTES D'IMPLÉMENTATION

### Données disponibles à exploiter
- ✅ `metadata.src` / `metadata.trg` : Types d'attaques
- ✅ `whois_bd.cd` : Date création (calcul âge)
- ✅ `uptime` entries : Historique DNS/WHOIS complet
- ✅ `arec` : Adresses IP (détection changements)
- ✅ `url` : Paths (détection subresources)
- ✅ `discovery_time` : Détection (calcul vitesse réaction)
- ⚠️ `whois_bd` : Peut contenir registraire (à vérifier)

### Optimisations mémoire
- Toujours utiliser streaming pour nouvelles analyses
- Stocker seulement métriques agrégées, pas données brutes
- Utiliser des générateurs pour traitements complexes
- Libérer mémoire après chaque analyse (gc.collect())

### Format de sortie
- Graphiques PNG 300 DPI (comme existants)
- Rapports textuels dans `analysis_results/`
- Fichiers JSONL intermédiaires si nécessaire (avec compression)
