from collections import defaultdict


def detect_syn_flood(connections, threshold=50):
    """
    Detect possible TCP SYN flood activity.

    A SYN flood is suspected when the same source IP
    sends a large number of TCP SYN connections toward
    the same destination IP and destination port.

    connections should contain:
        source_ip
        destination_ip
        destination_port
        tcp_flags
    """

    syn_activity = defaultdict(int)

    for connection in connections:

        source_ip = connection.get("source_ip")
        destination_ip = connection.get("destination_ip")
        destination_port = connection.get("destination_port")
        tcp_flags = connection.get("tcp_flags")

        if not source_ip or not destination_ip:
            continue

        if not destination_port or not tcp_flags:
            continue

        flags = str(tcp_flags).upper()

        # SYN packet should have SYN set without ACK
        if "S" not in flags or "A" in flags:
            continue

        key = (
            source_ip,
            destination_ip,
            destination_port
        )

        syn_activity[key] += 1

    detections = []

    for (
        source_ip,
        destination_ip,
        destination_port
    ), syn_count in syn_activity.items():

        if syn_count < threshold:
            continue

        if syn_count >= 200:
            risk_score = 95
        elif syn_count >= 100:
            risk_score = 85
        else:
            risk_score = 75

        confidence = min(
            100,
            syn_count // 2
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
            "syn_count": syn_count,
            "attack_type": "SYN Flood",
            "severity": severity,
            "confidence": confidence,
            "risk_score": risk_score,
            "mitre_technique": "T1498.001 - Direct Network Flood"
        })

    return detections