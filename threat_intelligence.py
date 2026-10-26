import os
import requests
api_key = os.getenv("VIRUSTOTAL_API_KEY")

# =========================================================
# MOCK CTI
# =========================================================

def mock_enrich_ip(source_ip):
    """
    Local mock CTI provider.
    Used for testing and demonstrations.
    """

    known_threats = {
        "192.0.2.10": {
            "reputation": "Malicious",
            "threat_score": 95,
            "country": "Test",
            "organization": "Test Threat Actor",
            "categories": [
                "Network Scanning",
                "Suspicious Activity"
            ]
        },

        "192.168.1.50": {
            "reputation": "Suspicious",
            "threat_score": 70,
            "country": "Private Network",
            "organization": "Internal Host",
            "categories": [
                "Port Scanning"
            ]
        }
    }

    result = known_threats.get(source_ip)

    if result:
        return {
            "ip": source_ip,
            "found": True,
            "provider": "Mock CTI",
            **result
        }

    return {
        "ip": source_ip,
        "found": False,
        "provider": "Mock CTI",
        "reputation": "Unknown",
        "threat_score": 0,
        "country": "Unknown",
        "organization": "Unknown",
        "categories": []
    }


# =========================================================
# REAL CTI - VIRUSTOTAL
# =========================================================

def real_enrich_ip(source_ip):
    """
    Query VirusTotal for real IP threat intelligence.
    """

    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "ip": source_ip,
            "found": False,
            "provider": "VirusTotal",
            "error": "VIRUSTOTAL_API_KEY is not configured",
            "reputation": "Unavailable",
            "threat_score": 0,
            "country": "Unknown",
            "organization": "Unknown",
            "categories": []
        }

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{source_ip}"

    headers = {
        "x-apikey": api_key
    }

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        if response.status_code != 200:

            return {
                "ip": source_ip,
                "found": False,
                "provider": "VirusTotal",
                "error": f"VirusTotal returned HTTP {response.status_code}",
                "reputation": "Unavailable",
                "threat_score": 0,
                "country": "Unknown",
                "organization": "Unknown",
                "categories": []
            }

        data = response.json()

        attributes = (
            data
            .get("data", {})
            .get("attributes", {})
        )

        # VirusTotal analysis statistics
        stats = attributes.get(
            "last_analysis_stats",
            {}
        )

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        total = sum(stats.values())

        # Calculate a normalized score from VT detections
        if total > 0:
            threat_score = round(
                ((malicious + (suspicious * 0.5)) / total) * 100
            )
        else:
            threat_score = 0

        threat_score = min(100, threat_score)

        # Determine reputation
        if malicious > 0:
            reputation = "Malicious"
        elif suspicious > 0:
            reputation = "Suspicious"
        else:
            reputation = "Clean"

        country = attributes.get(
            "country",
            "Unknown"
        )

        organization = attributes.get(
            "as_owner",
            "Unknown"
        )

        categories = attributes.get(
            "tags",
            []
        )

        return {
            "ip": source_ip,
            "found": True,
            "provider": "VirusTotal",
            "reputation": reputation,
            "threat_score": threat_score,
            "country": country,
            "organization": organization,
            "categories": categories,
            "malicious": malicious,
            "suspicious": suspicious,
            "total_engines": total
        }

    except requests.RequestException as e:

        return {
            "ip": source_ip,
            "found": False,
            "provider": "VirusTotal",
            "error": str(e),
            "reputation": "Unavailable",
            "threat_score": 0,
            "country": "Unknown",
            "organization": "Unknown",
            "categories": []
        }


# =========================================================
# CTI PROVIDER SWITCH
# =========================================================

def enrich_ip(source_ip, mode="mock"):
    """
    Select the CTI provider.

    mode="mock" -> local demonstration data
    mode="real" -> VirusTotal
    """

    if mode == "real":
        return real_enrich_ip(source_ip)

    return mock_enrich_ip(source_ip)