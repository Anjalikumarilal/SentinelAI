from collections import defaultdict


def detect_port_scan(connections, threshold=10):
    """
    Detect possible port-scanning activity.

    connections should be a list of dictionaries containing:
    source_ip, destination_ip, destination_port
    """

    port_activity = defaultdict(set)

    for connection in connections:
        source_ip = connection.get("source_ip")
        destination_ip = connection.get("destination_ip")
        destination_port = connection.get("destination_port")

        if not source_ip or not destination_ip or not destination_port:
            continue

        key = (source_ip, destination_ip)

        port_activity[key].add(destination_port)

    detections = []

    for (source_ip, destination_ip), ports in port_activity.items():

        if len(ports) >= threshold:
            ports_scanned = len(ports)

            confidence = min(100, ports_scanned * 5)

            # Risk increases as more ports are scanned
            if ports_scanned >= 50:
                risk_score = 95
            elif ports_scanned >= 30:
                risk_score = 85
            elif ports_scanned >= 20:
                risk_score = 75
            elif ports_scanned >= 10:
                risk_score = 60
            else:
                risk_score = 40

            # Determine severity from risk score
            if risk_score >= 80:
                severity = "CRITICAL"
            elif risk_score >= 60:
                severity = "HIGH"
            elif risk_score >= 40:
                severity = "MEDIUM"
            else:
                severity = "LOW"

            detections.append({
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "ports_scanned": ports_scanned,
                "attack_type": "Port Scan",
                "severity": severity,
                "confidence": confidence,
                "risk_score": risk_score,
                "mitre_technique": "T1046 - Network Service Scanning"
            })

    return detections