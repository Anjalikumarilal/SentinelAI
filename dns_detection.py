from collections import defaultdict


# Suspicious DNS characteristics
SUSPICIOUS_KEYWORDS = {
    "login",
    "verify",
    "account",
    "secure",
    "update",
    "password",
    "signin",
    "bank",
    "wallet",
    "credential",
}


def detect_suspicious_dns(connections, threshold=5):
    """
    Detect possible suspicious DNS activity.

    A domain is considered suspicious when:
    1. The same source repeatedly queries the same domain.
    2. The domain contains security-sensitive keywords.

    connections should contain:
        source_ip
        destination_ip
        destination_port
        dns_query
    """

    dns_activity = defaultdict(int)

    for connection in connections:

        source_ip = connection.get("source_ip")
        destination_ip = connection.get("destination_ip")
        dns_query = connection.get("dns_query")

        if not source_ip or not destination_ip or not dns_query:
            continue

        query = str(dns_query).lower().strip()

        if not query:
            continue

        key = (
            source_ip,
            destination_ip,
            query
        )

        dns_activity[key] += 1

    detections = []

    for (
        source_ip,
        destination_ip,
        dns_query
    ), query_count in dns_activity.items():

        query_lower = dns_query.lower()

        keyword_matches = [
            keyword
            for keyword in SUSPICIOUS_KEYWORDS
            if keyword in query_lower
        ]

        # Require repeated queries OR suspicious keyword
        if query_count < threshold and not keyword_matches:
            continue

        # Risk calculation
        risk_score = 40

        if query_count >= 10:
            risk_score = 60

        if query_count >= 20:
            risk_score = 75

        if keyword_matches:
            risk_score += 15

        risk_score = min(100, risk_score)

        # Severity
        if risk_score >= 80:
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        confidence = min(
            100,
            query_count * 5 + len(keyword_matches) * 10
        )

        detections.append({
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": 53,
            "dns_query": dns_query,
            "query_count": query_count,
            "keyword_matches": keyword_matches,
            "attack_type": "Suspicious DNS Activity",
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "mitre_technique": "T1071.004 - DNS"
        })

    return detections