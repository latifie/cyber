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
