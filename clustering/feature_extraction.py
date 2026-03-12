def extract_features(record):
    """
    Extracts relevant features from an uptime domain record for clustering.

    Actual data structure:
    {
        "rd": "example.com",           # registered domain
        "fqdn": "www.example.com",
        "metadata": {
            "src": "APWG",             # detection source
            "trg": "BancoEstado",      # phishing target (brand)
            "tld": "com",
        },
        "uptime": [
            {
                "type": "whois",
                "iana_id": 433,        # registrar IANA ID
                "cd": "2022-12-12",    # creation date
                ...
            }, ...
        ]
    }
    """
    if not isinstance(record, dict):
        return {}

    # --- Domain ID ---
    domain_id = record.get("rd") or record.get("fqdn") or record.get("id", "unknown")

    # --- Metadata block ---
    metadata = record.get("metadata") or {}
    tld = metadata.get("tld", "")
    src = metadata.get("src", "")
    trg = metadata.get("trg", "")

    # Fallback for tld
    if not tld and domain_id and "." in domain_id:
        tld = domain_id.split(".")[-1]

    # --- Uptime block: find whois entry for registrar + creation date ---
    iana_id = -1
    creation_ts = ""
    for entry in record.get("uptime") or []:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") == "whois":
            if iana_id == -1 and entry.get("iana_id"):
                iana_id = entry["iana_id"]
            if not creation_ts and entry.get("cd"):
                creation_ts = entry["cd"]
            break  # first whois entry is enough

    # --- Build text features for hashing ---
    # This includes brand target, source, domain n-grams — key signals for campaign clustering
    text_parts = []
    if trg:
        text_parts.append(f"trg_{trg}")
    if src:
        text_parts.append(f"src_{src}")

    # Domain n-grams (character 3-grams to detect similar name patterns)
    domain_base = domain_id.split(".")[0] if "." in domain_id else domain_id
    if len(domain_base) >= 3:
        text_parts += [domain_base[i:i+3] for i in range(len(domain_base) - 2)]

    return {
        "id": domain_id,
        "registrar_id": iana_id,
        "tld": tld,
        "asn": -1,           # not present in this dataset
        "creation_ts": creation_ts,
        "text_features": " ".join(text_parts),
    }
