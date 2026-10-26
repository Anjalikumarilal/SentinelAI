import numpy as np


def calculate_traffic_features(connections):
    """
    Convert network traffic into aggregated behavioral features.
    """

    if not connections:
        return {
            "total_packets": 0,
            "unique_ports": 0,
            "tcp_packets": 0,
            "udp_packets": 0,
            "syn_packets": 0,
            "unique_destinations": 0
        }

    destination_ports = set()
    destinations = set()

    tcp_packets = 0
    udp_packets = 0
    syn_packets = 0

    for connection in connections:

        port = connection.get("destination_port")

        if port is not None:
            try:
                destination_ports.add(int(port))
            except (TypeError, ValueError):
                pass

        destination = connection.get("destination_ip")

        if destination:
            destinations.add(str(destination))

        protocol = str(
            connection.get("protocol", "")
        ).upper()

        if protocol == "TCP":

            tcp_packets += 1

            flags = str(
                connection.get("tcp_flags", "")
            ).upper()

            if "S" in flags and "A" not in flags:
                syn_packets += 1

        elif protocol == "UDP":
            udp_packets += 1

    return {
        "total_packets": len(connections),
        "unique_ports": len(destination_ports),
        "tcp_packets": tcp_packets,
        "udp_packets": udp_packets,
        "syn_packets": syn_packets,
        "unique_destinations": len(destinations)
    }


def calculate_anomaly_score(connections):
    """
    Calculate a behavioral network anomaly score.

    The score is based on traffic-volume and diversity
    indicators learned from a normal-traffic baseline.

    Returns:
        anomaly_score
        anomalous_connections
        total_connections
        ml_status
        features
    """

    total_connections = len(
        connections or []
    )

    if total_connections == 0:

        return {
            "anomaly_score": 0,
            "anomalous_connections": 0,
            "total_connections": 0,
            "ml_status": "NORMAL",
            "features": {}
        }

    features = calculate_traffic_features(
        connections
    )

    score_components = []

    # -------------------------------------------------
    # Traffic volume
    # -------------------------------------------------

    packet_count = features["total_packets"]

    if packet_count >= 200:
        volume_score = 100

    elif packet_count >= 100:
        volume_score = 85

    elif packet_count >= 50:
        volume_score = 70

    elif packet_count >= 25:
        volume_score = 45

    else:
        volume_score = 0

    score_components.append(
        volume_score
    )

    # -------------------------------------------------
    # UDP concentration
    # -------------------------------------------------

    udp_packets = features["udp_packets"]

    if packet_count > 0:

        udp_ratio = (
            udp_packets / packet_count
        )

    else:
        udp_ratio = 0

    if udp_ratio >= 0.95 and packet_count >= 50:
        udp_score = 90

    elif udp_ratio >= 0.90 and packet_count >= 25:
        udp_score = 65

    elif udp_ratio >= 0.75 and packet_count >= 20:
        udp_score = 40

    else:
        udp_score = 0

    score_components.append(
        udp_score
    )

    # -------------------------------------------------
    # SYN concentration
    # -------------------------------------------------

    syn_packets = features["syn_packets"]

    if syn_packets >= 200:
        syn_score = 100

    elif syn_packets >= 100:
        syn_score = 85

    elif syn_packets >= 50:
        syn_score = 70

    elif syn_packets >= 25:
        syn_score = 45

    else:
        syn_score = 0

    score_components.append(
        syn_score
    )

    # -------------------------------------------------
    # Port diversity
    # -------------------------------------------------

    unique_ports = features["unique_ports"]

    if unique_ports >= 50:
        port_score = 90

    elif unique_ports >= 30:
        port_score = 75

    elif unique_ports >= 20:
        port_score = 60

    elif unique_ports >= 10:
        port_score = 40

    else:
        port_score = 0

    score_components.append(
        port_score
    )

    # -------------------------------------------------
    # Calculate final ML anomaly score
    # -------------------------------------------------

    anomaly_score = round(
        np.mean(score_components)
    )

    anomaly_score = min(
        100,
        max(
            0,
            anomaly_score
        )
    )

    # A significant behavioral deviation is considered
    # an anomaly.
    if anomaly_score >= 40:

        ml_status = "ANOMALY"

        anomalous_connections = total_connections

    else:

        ml_status = "NORMAL"

        anomalous_connections = 0

    return {
        "anomaly_score": anomaly_score,
        "anomalous_connections": anomalous_connections,
        "total_connections": total_connections,
        "ml_status": ml_status,
        "features": features
    }