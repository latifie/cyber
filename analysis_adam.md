# Suivi de Recherche - Analyse Avancée des Hypothèses

Ce document recense les graphiques d'analyse générés par le script **`analyze_adam_hyp.py`**. Lancé uniquement sur des données de tests.

---

## Hypothèse 2 : Corrélation entre Âge et Durée de Survie

**Objectif** : Vérifier si le fait de faire vieillir un domaine permet à l'attaquant de contourner les filtres et de garder son attaque active plus longtemps (augmenter sa "durée de survie" avant d'être bloqué).

![Graphique Corrélation Âge vs Survie](/home/khalidad/cyber/analysis_results/graphs_advanced/h2_age_vs_survie.png)

> [!NOTE]
> **Observation** : La majorité écrasante des domaines est collée à l'axe vertical (âge proche de 0). C'est le comportement classique de *hit-and-run*.
> La ligne de tendance rouge montre que le retour sur investissement de l'attaquant est quasiment nul. Même un domaine ayant vieilli plus de 2000 jours se fait neutraliser (takedown) aussi vite qu'un domaine créé la veille après une attaque. Le vieillissement ne semble donc pas offrir d'immunité significative face aux takedowns.

---

## Hypothèse 3 : L'Âge du domaine au moment du Takedown

**Objectif** : Vérifier si la nature de la sanction (`whois`, `dns`, `content`) dépend de la maturité du domaine visé. Un domaine très ancien subit-il le même processus de blocage qu'un domaine tout juste créé pour l'attaque ?

![Graphique Type de Takedown vs Age](/home/khalidad/cyber/analysis_results/graphs_advanced/h3_type_takedown_age.png)

> [!TIP]
> **Observation** : L'échelle de gauche (Âge) est logarithmique. 
> La ligne extrême au-dessus de la boîte `content` montre une valeur aberrante énorme (plus de 1000 jours). Cela valide la théorie selon laquelle les "Content Takedowns" (suppression des fichiers de la page) ciblent très souvent de **vieux sites internet légitimes qui se sont simplement fait hacker à leur insu** (injections URL, hébergement caché).
> À l'inverse, les actions `whois` (suspension totale du domaine par le Registrar) concentrent presque 100% de domaines récents créés spécifiquement dans un but malveillant.

---

## Hypothèse 4 : Résilience des attaques (Fast-Flux / Re-Up)

**Objectif** : Observer le comportement post-sanction. Combien de domaines déclarés morts ou bloqués (`NXDOMAIN` au niveau DNS) parviennent à ressusciter et redevenir en ligne (`NOERROR`) ? C'est le phénomène de *Re-up*.

![Graphique Résilience Re-Up](/home/khalidad/cyber/analysis_results/graphs_advanced/h4_resilience_reup.png)

> [!WARNING]
> **Observation** : Moins de **4%** des domaines (dans cet échantillon) tentent de faire un *Re-Up* après un premier échec de résolution DNS.
> Cela confirme encore la nature jetable des noms de domaine malveillants aujourd'hui. Une écrasante majorité des assaillants ne cherchent pas à défendre leur nom de domaine mais se contentent d'en racheter un autre à bas coût.

---

## Hypothèse 5 : Spécialisation selon les Extensions (TLDs)

**Objectif** : L'attaque diffère-t-elle selon que l'agresseur utilise une extension Premium/stricte (`.com`, `.fr`, `.org`) ou un TLD low-cost et souvent peu surveillé (`.top`, `.click`, `.xin`) ?

![Graphique Spécialisation TLD](/home/khalidad/cyber/analysis_results/graphs_advanced/h5_specialisation_tld.png)

> [!IMPORTANT]
> **Observation** : Les deux courbes de densité montrent l'écrasante différence de comportement.
> La **courbe rouge (TLD Low-cost)** forme un pic vertical serré sur le zéro. Les attaquants qui utilisent des domaines `top` font du *hit-and-run* de masse et immédiat.
> La **courbe bleue (TLD Premium)** s'étale sur des centaines et des milliers de jours. Les extensions sérieuses (comme le `.com`) ne sont presque jamais utilisées de manière jetable. Elles sont soit compromises (légitimes à l'origine), soit font l'objet d'un veillissement prudent avant d'être utilisées par des attaquants.

---

## Hypothèse 6 : Drop Catching (Recyclage de vieux domaines)

**Objectif** : Identifier si des attaquants utilisent le rachat de vieux domaines expirés, pour contourner les filtres de sécurité.

**Méthode** : Dans la base de données WHOIS, nous comparons deux informations : 
1. La **Date de Création (`cd`)** : le moment où le domaine a existé pour la toute première fois.
2. La **Date de Mise à jour (`ud`)** : le moment où le domaine a changé administrativement (souvent un changement de propriétaire ou de registrar).

![Graphique Drop Catching](/home/khalidad/cyber/analysis_results/graphs_advanced/h6_drop_catching.png)

> [!NOTE]
> **Comment lire le graphique et Conclusion** :
> Ce graphique met en relation l'Âge total du domaine en jours (Axe horizontal) et le délai entre la dernière "Mise à Jour" WHOIS et l'attaque en jours (Axe vertical).
> - La **ligne rouge en pointillés (diagonale)** représente les domaines "naturels". Pour eux, la date de création est presque la même que la date de mise à jour. Ils sont récents, c'est du *Hit-and-Run* classique.
> - **Ce qu'il faut en tirer** : L'objectif de cette figure est de localiser les points en **bas tout à droite de l'image**. Ces points correspondent à des domaines vieux de plusieurs milliers de jours mais qui ont été mis à jour administrativement à peine quelques jours avant l'attaque. Une forte concentration de ces points prouve de façon scientifique que les attaquants de notre échantillon recyclent massivement la réputation de vieux domaines "échus" pour ne pas éveiller les soupçons des pare-feux. Ce n'est pas le cas pour le moment mais à confirmer avec des données plus importantes.

---

## Hypothèse 7 : Réactivité Défensive par Secteur Cible

**Objectif** : Vérifier si le secteur d'activité ou la marque usurpée (ex: les banques, les services postaux, les impôts) influence la rapidité à laquelle l'attaque est neutralisée (le moment du Takedown).

**Méthode** : Nous croisons la cible de l'attaque (`metadata.trg`, qui donne la marque usurpée comme *PayPal*, *Meta* ou *USPS*) avec la durée de survie totale du domaine malveillant avant qu'il ne soit tué (`takedown_hours`). 

![Graphique Réactivité par Cible](/home/khalidad/cyber/analysis_results/graphs_advanced/h7_reactivite_cible.png)

> [!TIP]
> **Comment lire le graphique et Conclusion** : 
> Chaque boîte montre la durée de vie de l'attaque, triée pour avec le top 5 des cibles les plus usurpées dans le jeu de données de test.
> - **Ce qu'il faut en tirer** : Ce graphique permet de comparer publiquement l'efficacité des équipes de cybersécurité des différentes industries. Par exemple, si la boîte d'une grande banque est très écrasée vers le bas (entre 0 et 5 heures), cela démontre que le secteur financier possède des procédures légales express pour faire censurer les sites instantanément. À l'inverse, si une cible comme un service de livraison colis montre des boîtes très étirées vers le haut, cela trahit publiquement une lenteur administrative dans leurs procédures de plainte, les rendant par définition plus vulnérables à des attaques prolongées.

---

## Hypothèse 8 : Morphologie du Nom de Domaine

**Objectif** : Analyser si la taille et la complexité (tirets, chiffres) du nom de domaine ont un impact sur sa durée de survie.

![Graphique Morphologie](/home/khalidad/cyber/analysis_results/graphs_advanced/h8_morphologie_longueur.png)

> [!NOTE]
> **Observation** : Les attaquants font souvent l'erreur de générer des noms très longs avec plein de mots clés pour tromper la victime (ex: `security-update-bancoestado-chile-2024.com`). Ce graphique permet de voir si ces domaines à rallonge sont repérés plus vite que les domaines courts et d'apparence propre.

---

## Hypothèse 9 : Infrastructure et IPs Partagées (Fast-Flux)

**Objectif** : Déterminer si les attaquants s'abritent derrière des infrastructures résilientes (plusieurs adresses IP tournantes) ou s'ils utilisent de l'hébergement bas de gamme.

![Graphique IP Infrastructure](/home/khalidad/cyber/analysis_results/graphs_advanced/h9_infrastructure_ips.png)

> [!WARNING]
> **Observation** : L'axe logaritimique cache une réalité très tranchée. En analysant le volume d'adresses IPv4/IPv6 (`arec`) uniques relevées, on constate que :
> - La majorité (plus de 70%) des domaines tournent sur une ou deux IP. C'est du Spam/Phishing de masse amateur, leur espérance de vie est microscopique (en moyenne 4 à 10 jours).
> - Les domaines enregistrant virtuellement le plus grand nom d'IPs (7 serveurs) sont aussi paradoxalement les plus jeunes de tout l'échantillon (4 jours). Probablement des armées de bots qui crament d'un coup leur infra sans effort de camouflage.
> - **L'anomalie professionnelle** : La seule catégorie montrant des domaines considérablement vieux est celle des infrastructures à 4 IPs distinctes. Ce cluster très défini (4 serveurs) semble être l'architecture de prédilection des cybercriminels, qui, pour maximiser ce setup, l'installent exclusivement sur des noms de domaine extrêmement vieillis en amont (Âge moyen record de +470 jours !).

---

## Conclusion et Synthèse : Le Score de Sophistication (Hypothèse 10)

**Objectif** : Consolider l'ensemble des métriques extraites (Âge, TLD Premium, Nom propre, Fast-Flux IP, Drop Catching) pour calculer une note globale sur 100 de l'attaque.

![Graphique Score Sophistication](/home/khalidad/cyber/analysis_results/graphs_advanced/h10_sophistication_score.png)

> [!IMPORTANT]
> **Observation** : Ce graphique de distribution sépare les "Script Kiddies" (Score < 25) faisant du phishing de masse avec des `.tk` jetables instantanément, des cybercriminels "APT" (Score > 60) qui investissent dans des domaines en `.com`, propres, hébergés sur des infrastructures complexes et qu'ils ont pris le soin de racheter et de faire vieillir.
> La majorité des attaques de notre échantillon se concentrent sur la tranche de faible sophistication, confirmant la politique du "Hit-and-Run" pas cher et jetable.
