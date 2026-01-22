# 📊 EXPLICATION DES GRAPHIQUES - ANALYSE DES DOMAINES MALICIEUX

Ce document explique chaque graphique généré par `analyze_malicious_domains.py`, les données utilisées et leur signification.

**Source des données :** `analysis_results/down_domains_malicious.jsonl`
- Contient uniquement les domaines malicieux (qui restent en NXDOMAIN après transition)
- Chaque ligne = un domaine avec ses métadonnées complètes

---

## 1. 📈 `malicious_attack_source_analysis.png`

### **Données sources :**
- `metadata.src` : Type/source de l'attaque (ex: "phishing", "malware", "spam", etc.)
- `whois_bd.cd` : Date de création du domaine
- `transition.transition_date` : Date du takedown (transition NOERROR → NXDOMAIN)
- `takedown.uptime_dur` : Durée d'activité avant takedown (en heures)

### **4 sous-graphiques :**

#### **1.1. Délais création → takedown par source (Top 10)**
- **Type :** Box plot (boîte à moustaches)
- **Axe X :** Top 10 sources d'attaque les plus fréquentes
- **Axe Y :** Délai en jours entre création du domaine et takedown
- **Signification :** 
  - Montre la distribution des délais pour chaque type d'attaque
  - Permet de voir si certains types d'attaques sont détectés/takedown plus rapidement
  - La médiane (ligne dans la boîte) indique le délai typique

#### **1.2. Durées moyennes avant takedown par source (Top 10)**
- **Type :** Barres horizontales
- **Axe X :** Durée moyenne en jours avant takedown
- **Axe Y :** Top 10 sources d'attaque
- **Signification :**
  - Temps moyen pendant lequel un domaine malicieux reste actif avant d'être détecté/takedown
  - Plus la barre est longue, plus les domaines de ce type restent actifs longtemps
  - Indique l'efficacité de détection selon le type d'attaque

#### **1.3. Distribution des sources (Top 15)**
- **Type :** Barres horizontales
- **Axe X :** Nombre de domaines
- **Axe Y :** Top 15 sources d'attaque
- **Signification :**
  - Volume de domaines malicieux par type d'attaque
  - Identifie les types d'attaques les plus fréquents
  - Permet de prioriser les efforts de détection

#### **1.4. Évolution délais moyens par source (Top 5)**
- **Type :** Lignes temporelles
- **Axe X :** Année
- **Axe Y :** Délai moyen en jours
- **Lignes :** Une ligne par source (Top 5)
- **Signification :**
  - Évolution dans le temps de la vitesse de détection/takedown
  - Si une ligne descend : détection plus rapide au fil du temps
  - Si une ligne monte : détection plus lente (ou domaines plus résistants)

---

## 2. 🎯 `malicious_attack_target_analysis.png`

### **Données sources :**
- `metadata.trg` : Cible/type de cible de l'attaque (ex: "banking", "social_media", "ecommerce", etc.)
- `whois_bd.cd` : Date de création du domaine
- `transition.transition_date` : Date du takedown
- `takedown.uptime_dur` : Durée d'activité avant takedown

### **4 sous-graphiques :**

#### **2.1. Délais création → takedown par target (Top 10)**
- **Type :** Box plot
- **Axe X :** Top 10 cibles d'attaque
- **Axe Y :** Délai en jours
- **Signification :**
  - Distribution des délais selon la cible visée
  - Certaines cibles (ex: banques) peuvent être protégées plus rapidement
  - Montre les différences de réactivité selon le secteur ciblé

#### **2.2. Durées moyennes avant takedown par target (Top 10)**
- **Type :** Barres horizontales
- **Axe X :** Durée moyenne en jours
- **Axe Y :** Top 10 cibles
- **Signification :**
  - Temps moyen d'activité avant takedown selon la cible
  - Indique quelles cibles sont mieux protégées (takedown rapide)
  - Ou quelles cibles sont plus vulnérables (takedown lent)

#### **2.3. Distribution des targets (Top 15)**
- **Type :** Barres horizontales
- **Axe X :** Nombre de domaines
- **Axe Y :** Top 15 cibles
- **Signification :**
  - Volume de domaines malicieux par secteur ciblé
  - Identifie les secteurs les plus attaqués
  - Aide à comprendre les priorités des attaquants

#### **2.4. Évolution délais moyens par target (Top 5)**
- **Type :** Lignes temporelles
- **Axe X :** Année
- **Axe Y :** Délai moyen en jours
- **Signification :**
  - Évolution de la réactivité selon la cible
  - Montre si certains secteurs s'améliorent dans la détection
  - Peut révéler des tendances de protection

---

## 3. 🏢 `malicious_registrar_analysis.png`

### **Données sources :**
- `whois_bd.iana_id` : Identifiant IANA du registraire (ex: 2, 49, 146, etc.)
- `whois_bd.cd` : Date de création
- `transition.transition_date` : Date du takedown
- `takedown.uptime_dur` : Durée avant takedown

### **4 sous-graphiques :**

#### **3.1. Top registraires par volume (Top 15)**
- **Type :** Barres horizontales
- **Axe X :** Nombre de domaines malicieux
- **Axe Y :** Top 15 registraires (par IANA ID)
- **Signification :**
  - Identifie les registraires qui hébergent le plus de domaines malicieux
  - Peut indiquer des registraires moins stricts dans leurs politiques
  - Utile pour cibler les efforts de prévention

#### **3.2. Durées moyennes avant takedown par registraire (Top 15)**
- **Type :** Barres horizontales
- **Axe X :** Durée moyenne en jours
- **Axe Y :** Top 15 registraires
- **Signification :**
  - Temps moyen avant takedown selon le registraire
  - Registraires avec barres courtes = réaction rapide
  - Registraires avec barres longues = réaction lente ou moins efficace

#### **3.3. Distribution délais par registraire (Top 10)**
- **Type :** Box plot
- **Axe X :** Top 10 registraires
- **Axe Y :** Délai création → takedown (jours)
- **Signification :**
  - Distribution complète des délais pour chaque registraire
  - Montre la variabilité (écart-type) dans les délais
  - Permet de comparer la cohérence des politiques

#### **3.4. Volume vs Durée moyenne takedown par registraire**
- **Type :** Nuage de points (scatter plot)
- **Axe X :** Nombre de domaines
- **Axe Y :** Durée moyenne avant takedown (jours)
- **Signification :**
  - Corrélation entre volume et vitesse de réaction
  - Registraires en bas à gauche = beaucoup de domaines, réaction rapide (bon)
  - Registraires en haut à droite = beaucoup de domaines, réaction lente (problématique)
  - Aide à identifier les registraires problématiques

---

## 4. 🌐 `malicious_tld_analysis.png`

### **Données sources :**
- `metadata.tld` : Extension du domaine (ex: ".com", ".net", ".org", ".xyz", etc.)
- `whois_bd.cd` : Date de création
- `transition.transition_date` : Date du takedown
- `takedown.uptime_dur` : Durée avant takedown

### **4 sous-graphiques :**

#### **4.1. Distribution des TLDs (Top 20)**
- **Type :** Barres verticales
- **Axe X :** Top 20 TLDs
- **Axe Y :** Nombre de domaines
- **Signification :**
  - Volume de domaines malicieux par extension
  - Certains TLDs (ex: .xyz, .top) sont souvent utilisés pour le spam/malware
  - Aide à identifier les TLDs à risque

#### **4.2. Durées moyennes avant takedown par TLD (Top 15)**
- **Type :** Barres horizontales
- **Axe X :** Durée moyenne en jours
- **Axe Y :** Top 15 TLDs
- **Signification :**
  - Temps moyen d'activité avant takedown selon l'extension
  - Certains TLDs peuvent être mieux surveillés que d'autres
  - Peut révéler des différences de politique selon le TLD

#### **4.3. Distribution délais par TLD (Top 10)**
- **Type :** Box plot
- **Axe X :** Top 10 TLDs
- **Axe Y :** Délai création → takedown (jours)
- **Signification :**
  - Distribution complète des délais pour chaque TLD
  - Montre la variabilité dans les délais
  - Permet de comparer les TLDs entre eux

#### **4.4. Évolution volume par TLD (Top 5)**
- **Type :** Lignes temporelles
- **Axe X :** Année
- **Axe Y :** Nombre de domaines
- **Lignes :** Une ligne par TLD (Top 5)
- **Signification :**
  - Évolution du volume de domaines malicieux par TLD
  - Montre si certains TLDs deviennent plus/moins populaires chez les attaquants
  - Peut révéler des tendances d'utilisation

---

## 5. ⏱️ `malicious_discovery_to_takedown.png`

### **Données sources :**
- `discovery_time` : Date/heure de découverte du domaine malicieux (timestamp ou string)
- `transition.transition_date` : Date du takedown

### **Calcul :**
- **Durée = `transition_date - discovery_time`** (en jours)

### **4 sous-graphiques :**

#### **5.1. Distribution des durées**
- **Type :** Histogramme
- **Axe X :** Durée découverte → takedown (jours)
- **Axe Y :** Nombre de domaines
- **Ligne rouge :** Médiane
- **Signification :**
  - Distribution générale de la vitesse de réaction
  - Montre combien de temps s'écoule entre découverte et takedown
  - Pic à gauche = réaction rapide, pic à droite = réaction lente

#### **5.2. Distribution logarithmique**
- **Type :** Histogramme (échelle log)
- **Axe X :** log10(Durée + 1) jours
- **Axe Y :** Nombre de domaines
- **Signification :**
  - Même distribution mais en échelle logarithmique
  - Permet de mieux voir les variations sur une large plage
  - Utile car les durées peuvent varier de quelques heures à plusieurs mois

#### **5.3. Évolution vitesse de réaction (moyenne et médiane)**
- **Type :** Lignes temporelles
- **Axe X :** Année
- **Axe Y :** Durée en jours
- **Lignes :** Moyenne (bleue) et Médiane (corail)
- **Signification :**
  - Évolution de la vitesse de réaction dans le temps
  - Ligne descendante = amélioration (réaction plus rapide)
  - Ligne montante = détérioration (réaction plus lente)
  - Médiane généralement plus basse que moyenne = quelques cas très lents tirent la moyenne vers le haut

#### **5.4. Distribution par année**
- **Type :** Box plot
- **Axe X :** Année
- **Axe Y :** Durée découverte → takedown (jours)
- **Signification :**
  - Comparaison de la distribution des durées entre années
  - Permet de voir si la réactivité s'améliore ou se dégrade
  - Montre aussi la variabilité (écart-type) par année

---

## 6. 🎂 `malicious_age_at_takedown.png`

### **Données sources :**
- `whois_bd.cd` : Date de création du domaine
- `transition.transition_date` : Date du takedown

### **Calcul :**
- **Âge = `transition_date - creation_date`** (en jours)
- **Catégories :**
  - `<1j` : Moins de 1 jour
  - `1-7j` : 1 à 7 jours
  - `7-30j` : 7 à 30 jours
  - `30j-1an` : 30 jours à 1 an
  - `>1an` : Plus de 1 an

### **4 sous-graphiques :**

#### **6.1. Distribution de l'âge au takedown (0-365 jours)**
- **Type :** Histogramme
- **Axe X :** Âge au takedown (jours)
- **Axe Y :** Nombre de domaines
- **Ligne rouge :** Médiane
- **Signification :**
  - Montre l'âge typique des domaines malicieux au moment du takedown
  - Pic à gauche = domaines très jeunes (créés récemment)
  - Pic à droite = domaines plus anciens
  - **Question clé :** Les attaquants utilisent-ils des domaines neufs ou vieux ?

#### **6.2. Distribution par catégorie d'âge**
- **Type :** Barres verticales
- **Axe X :** Catégories d'âge
- **Axe Y :** Nombre de domaines
- **Signification :**
  - Répartition des domaines par tranche d'âge
  - Montre la proportion de domaines neufs vs anciens
  - **Insight :** Si majorité <1j ou 1-7j = attaquants utilisent des domaines fraîchement créés

#### **6.3. Distribution par catégorie d'âge (box plot)**
- **Type :** Box plot
- **Axe X :** Catégories d'âge
- **Axe Y :** Âge en jours
- **Signification :**
  - Distribution détaillée dans chaque catégorie
  - Montre la variabilité au sein de chaque tranche
  - Permet de voir les outliers (domaines très anciens dans catégorie jeune)

#### **6.4. Évolution âge moyen au takedown**
- **Type :** Lignes temporelles
- **Axe X :** Année
- **Axe Y :** Âge moyen en jours
- **Lignes :** Moyenne (bleue) et Médiane (corail)
- **Signification :**
  - Évolution de l'âge typique des domaines malicieux
  - Ligne montante = attaquants utilisent des domaines de plus en plus anciens (stratégie de vieillissement)
  - Ligne descendante = attaquants utilisent des domaines de plus en plus jeunes (stratégie de fraîcheur)

---

## 7. 🔄 `malicious_ip_changes.png`

### **Données sources :**
- `dns_context.before[]` : Tableau d'entrées DNS avant la transition
- Chaque entrée contient `arec[]` : Tableau d'adresses IP (A records)

### **Calcul :**
- Pour chaque domaine, analyse toutes les entrées DNS avant le takedown
- Compte le nombre de **changements d'IP** (quand l'IP change entre deux observations)
- Compte le nombre d'**IPs uniques** utilisées

### **4 sous-graphiques :**

#### **7.1. Distribution du nombre de changements d'IP**
- **Type :** Barres verticales
- **Axe X :** Nombre de changements d'IP
- **Axe Y :** Nombre de domaines
- **Signification :**
  - Montre la fréquence des changements d'IP avant takedown
  - 0 changement = domaine avec IP stable
  - Plusieurs changements = domaine qui change d'hébergement/IP fréquemment
  - **Insight :** Les attaquants changent-ils souvent d'IP pour éviter la détection ?

#### **7.2. Distribution du nombre d'IPs uniques (0-20)**
- **Type :** Barres verticales
- **Axe X :** Nombre d'IPs uniques utilisées
- **Axe Y :** Nombre de domaines
- **Signification :**
  - Montre combien d'IPs différentes un domaine a utilisées
  - 1 IP = hébergement stable
  - Plusieurs IPs = rotation d'hébergement ou CDN/proxy
  - **Insight :** Les domaines malicieux utilisent-ils plusieurs IPs pour la résilience ?

#### **7.3. Proportion domaines avec/sans changement d'IP**
- **Type :** Graphique en camembert (pie chart)
- **Segments :** "Avec changements" vs "Sans changement"
- **Signification :**
  - Pourcentage de domaines qui ont changé d'IP au moins une fois
  - Proportion élevée "avec changements" = stratégie de rotation d'IP
  - Proportion élevée "sans changement" = hébergement stable

#### **7.4. Statistiques des changements**
- **Type :** Texte (statistiques)
- **Contenu :**
  - Total domaines analysés
  - Moyenne/médiane/max changements d'IP
  - Nombre avec/sans changements
  - Moyenne/médiane/max IPs uniques
- **Signification :**
  - Résumé numérique des métriques
  - Permet de quantifier précisément les patterns
  - Utile pour comprendre l'ampleur du phénomène

---

## 📝 NOTES IMPORTANTES

### **Interprétation générale :**

1. **Tous les graphiques analysent uniquement les domaines malicieux** (qui restent en NXDOMAIN après transition)

2. **Les délais sont calculés en jours** :
   - Délai création → takedown : Temps entre création du domaine et son takedown
   - Durée découverte → takedown : Temps entre détection et takedown
   - Âge au takedown : Âge du domaine au moment du takedown

3. **Les données proviennent de `down_domains_malicious.jsonl`** qui contient :
   - Domaines avec `remains_nxdomain = true`
   - Domaines marqués comme `malicious: true`
   - Domaines avec `takedown_reason: 'registrar_takedown'`

4. **Les filtres appliqués :**
   - Délais entre 0 et 50 ans (18250 jours) pour éviter les valeurs aberrantes
   - Durées découverte → takedown entre 0 et 10 ans (3650 jours)

### **Questions que ces graphiques permettent de répondre :**

- ✅ Quels types d'attaques sont les plus fréquents ?
- ✅ Quels registraires hébergent le plus de domaines malicieux ?
- ✅ Quels TLDs sont les plus utilisés par les attaquants ?
- ✅ Combien de temps les domaines malicieux restent-ils actifs ?
- ✅ Les attaquants utilisent-ils des domaines neufs ou anciens ?
- ✅ Les domaines malicieux changent-ils souvent d'IP ?
- ✅ La réactivité s'améliore-t-elle dans le temps ?

---

**Généré par :** `analyze_malicious_domains.py`  
**Date :** 2025  
**Source :** `analysis_results/down_domains_malicious.jsonl`
