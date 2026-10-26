from collections import defaultdict


def detect_udp_flood(connections, threshold=50):
    """
    Detect possible UDP flood activity.

    A UDP flood is suspected when the same source IP
    sends a large number of UDP packets toward the same
    destination IP and destination port.

    connections should contain:
        source_ip
        destination_ip
        destination_port
        protocol
    """

    udp_activity = defaultdict(int)

    for connection in connections:

        source_ip = connection.get("source_ip")
        destination_ip = connection.get("destination_ip")
        destination_port = connection.get("destination_port")
        protocol = connection.get("protocol")

        if not source_ip or not destination_ip:
            continue

        if not destination_port or not protocol:
            continue

        if str(protocol).upper() != "UDP":
            continue

        key = (
            source_ip,
            destination_ip,
            destination_port
        )

        udp_activity[key] += 1

    detections = []

    for (
        source_ip,
        destination_ip,
        destination_port
    ), packet_count in udp_activity.items():

        if packet_count < threshold:
            continue

        if packet_count >= 200:
            risk_score = 95
        elif packet_count >= 100:
            risk_score = 85
        else:
            risk_score = 75

        confidence = min(
            100,
            packet_count // 2
        )

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
            "destination_port": destination_port,
            "packet_count": packet_count,
            "attack_type": "UDP Flood",
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "mitre_technique": "T1498.001 - Direct Network Flood"
        })

    return detections