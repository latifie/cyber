import sys, re
from datetime import datetime
from scipy.stats import mannwhitneyu

com_ages = []
top_ages = []

def get_age_days(cd_str, dt_str):
    try:
        if 'T' in cd_str: cd = datetime.fromisoformat(cd_str.replace('Z', '+00:00'))
        else: cd = datetime.strptime(cd_str, '%Y-%m-%d')
        if 'T' in dt_str: dt = datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        else: dt = datetime.strptime(dt_str, '%Y-%m-%d')
        return (dt - cd).total_seconds() / 86400.0
    except: return None

cd_patt = re.compile(r'"cd"\s*:\s*"([^"]+)"')
dt_patt = re.compile(r'"discovery_time"\s*:\s*"([^"]+)"')

with open('analysis_results/com_top_subset.jsonl', 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        is_com = '.com"' in line
        is_top = '.top"' in line
        if not (is_com or is_top): continue
        
        cd_m = cd_patt.search(line)
        dt_m = dt_patt.search(line)
        if not cd_m or not dt_m: continue
        
        cd = cd_m.group(1)
        dt = dt_m.group(1)
        
        age = get_age_days(cd, dt)
        if age is not None and 0 <= age <= 18250:
            if is_com: com_ages.append(age)
            elif is_top: top_ages.append(age)

if com_ages and top_ages:
    stat, p = mannwhitneyu(com_ages, top_ages, alternative='two-sided')
    print('Mann-Whitney U statistic=%.3f, p=%.3e' % (stat, p))
    com_ages.sort()
    top_ages.sort()
    print(f"Median .com: {com_ages[len(com_ages)//2]:.1f}")
    print(f"Median .top: {top_ages[len(top_ages)//2]:.1f}")
else:
    print(f"Not enough data to compute. Found {len(com_ages)} .com and {len(top_ages)} .top")
