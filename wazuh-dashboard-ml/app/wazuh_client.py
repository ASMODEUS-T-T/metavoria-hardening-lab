"""
Connecteur Wazuh Indexer (OpenSearch REST API).
Récupère les alertes et les transforme en DataFrame pandas exploitable.
"""
import os
import requests
import pandas as pd
import urllib3
from datetime import datetime, timedelta

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WAZUH_INDEXER_URL = os.getenv("WAZUH_INDEXER_URL", "https://192.168.56.105:9200")
WAZUH_INDEXER_USER = os.getenv("WAZUH_INDEXER_USER", "admin")
WAZUH_INDEXER_PASSWORD = os.getenv("WAZUH_INDEXER_PASSWORD", "")


def fetch_alerts(days: int = 7, size: int = 10000) -> pd.DataFrame:
    """
    Récupère les alertes des N derniers jours depuis l'indexer Wazuh
    et les retourne sous forme de DataFrame pandas.
    """
    since = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S")

    query = {
        "size": size,
        "sort": [{"@timestamp": {"order": "desc"}}],
        "query": {
            "range": {
                "@timestamp": {"gte": since}
            }
        }
    }

    resp = requests.post(
        f"{WAZUH_INDEXER_URL}/wazuh-alerts-*/_search",
        json=query,
        auth=(WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD),
        verify=False,
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    rows = []
    for hit in data.get("hits", {}).get("hits", []):
        src = hit.get("_source", {})
        rule = src.get("rule", {})
        agent = src.get("agent", {})
        rows.append({
            "timestamp": src.get("@timestamp"),
            "level": rule.get("level"),
            "description": rule.get("description", ""),
            "groups": ",".join(rule.get("groups", []) or []),
            "rule_id": rule.get("id"),
            "agent_name": agent.get("name", "unknown"),
            "mitre_technique": ",".join((rule.get("mitre") or {}).get("technique", []) or []),
        })

    df = pd.DataFrame(rows)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["level"] = pd.to_numeric(df["level"], errors="coerce").fillna(0).astype(int)
    return df


def severity_bucket(level: int) -> str:
    """
    Classification officielle des niveaux Wazuh en 4 buckets de sévérité.
    (0-6: Low, 7-11: Medium, 12-14: High, 15+: Critical)
    """
    if level >= 15:
        return "Critical"
    if level >= 12:
        return "High"
    if level >= 7:
        return "Medium"
    return "Low"
