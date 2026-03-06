def extract_features(record):
    """
    Extracts relevant features from a raw JSON domain record for clustering.
    Handles potentially missing fields gracefully.
    """
    if not isinstance(record, dict):
        return {}
        
    # Attempt to extract known keys or defaults
    domain_id = record.get("id", record.get("domain_name", "unknown"))
    
    # Registrar Info
    registrar_id = record.get("registrar_id", -1)
    if registrar_id == -1 and "registrar" in record and isinstance(record["registrar"], dict):
        registrar_id = record["registrar"].get("id", -1)
        
    # ASN Info
    asn = record.get("asn", -1)
    if asn == -1 and "as_info" in record and isinstance(record["as_info"], dict):
        asn = record["as_info"].get("asn", -1)
        
    # Creation TS
    creation_ts = record.get("creation_ts", 0)
    if not creation_ts:
        creation_ts = record.get("creation_date", 0)
        
    # TLD
    tld = record.get("tld", "")
    if not tld and domain_id != "unknown" and "." in domain_id:
        tld = domain_id.split(".")[-1]
        
    # Hashes or text
    text_features = record.get("hashes", "") 
    if not text_features:
        text_features = record.get("certificate_hash", "")
        
    return {
        "id": domain_id,
        "registrar_id": registrar_id,
        "tld": tld,
        "asn": asn,
        "creation_ts": creation_ts,
        "text_features": text_features
    }
