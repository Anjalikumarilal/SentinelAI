from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR


def extract_connections(pcap_file):
    """
    Read a PCAP/PCAPNG file and extract network connections.

    Returns a list containing:
        source_ip
        destination_ip
        destination_port
        protocol

    TCP packets additionally contain:
        tcp_flags

    DNS packets additionally contain:
        dns_query
    """

    packets = rdpcap(pcap_file)

    connections = []

    for packet in packets:

        if not packet.haslayer(IP):
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        destination_port = None
        protocol = None
        tcp_flags = None
        dns_query = None

        # TCP
        if packet.haslayer(TCP):

            protocol = "TCP"
            destination_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)

        # UDP
        elif packet.haslayer(UDP):

            protocol = "UDP"
            destination_port = packet[UDP].dport

        # DNS
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):

            try:

                query = packet[DNSQR].qname

                if isinstance(query, bytes):
                    query = query.decode(
                        "utf-8",
                        errors="ignore"
                    )

                dns_query = query.rstrip(".")

            except Exception:

                dns_query = None

        if destination_port is None:
            continue

        connection = {
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "destination_port": int(destination_port),
            "protocol": protocol
        }

        if tcp_flags:
            connection["tcp_flags"] = tcp_flags

        if dns_query:
            connection["dns_query"] = dns_query

        connections.append(connection)

    return connections