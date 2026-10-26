from collections import defaultdict


# Common authentication/service ports
AUTH_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3389: "RDP",
    5900: "VNC",
}


def detect_brute_force(connections, threshold=10):
    """
    Detect possible brute-force activity.

    A brute-force attempt is suspected when the same source IP
    repeatedly connects to the same destination IP and
    authentication-related service.

    connections should contain:
        source_ip
        destination_ip
        destination_port
    """

    connection_counts = defaultdict(int)

    for connection in connections:

        source_ip = connection.get("source_ip")
        destination_ip = connection.get("destination_ip")
        destination_port = connection.get("destination_port")

        if not source_ip or not destination_ip or not destination_port:
            continue

        try:
            destination_port = int(destination_port)
        except (TypeError, ValueError):
            continue

        # Only monitor common authentication/service ports
        if destination_port not in AUTH_PORTS:
            continue

        key = (
            source_ip,
            destination_ip,
            destination_port
        )

        connection_counts[key] += 1

    detections = []

    for (
        source_ip,
        destination_ip,
        destination_port
    ), attempts in connection_counts.items():

        if attempts < threshold:
            continue

        # Risk increases with repeated attempts
        if attempts >= 50:
            risk_score = 95
        elif attempts >= 30:
            risk_score = 85
        elif attempts >= 20:
            risk_score = 75
        else:
            risk_score = 60

        confidence = min(100, attempts * 5)

        if risk_score >= 80:
            severity = "CRITICAL"
        elif risk_score >= 60:
            severity = "HIGH"
        elif risk_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        service = AUTH_PORTS[destination_port]

        detections.append({
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "service": service,
            "attempts": attempts,
            "attack_type": "Brute Force",
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "mitre_technique": "T1110 - Brute Force"
        })

    return detections