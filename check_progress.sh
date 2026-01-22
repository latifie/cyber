#!/bin/bash
echo "=== État du traitement ==="
echo ""
echo "Processus en cours:"
ps aux | grep -E "analyze_domains|python3.*analyze" | grep -v grep | head -2
echo ""
echo "Taille des fichiers (dernière modification):"
ls -lh analysis_results/down_domains*.jsonl 2>/dev/null | awk '{print "  " $9 " : " $5 " (" $6 " " $7 " " $8 ")"}'
echo ""
echo "Dernières lignes du log (si disponible):"
tail -10 analysis_full_dns.log 2>/dev/null | tail -5 || echo "  (log non encore créé)"
echo ""
echo "Pour voir le log en temps réel:"
echo "  tail -f analysis_full_dns.log"
