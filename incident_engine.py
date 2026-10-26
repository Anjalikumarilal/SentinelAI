from config.supabase_client import supabase


def create_incident(alert):
    """
    Create a security incident from a security alert.
    """

    incident = {
        "title": f"{alert.get('attack_type', 'Security Threat')} Investigation",
        "description": (
            f"Incident automatically created from a "
            f"{alert.get('severity', 'Unknown')} security alert."
        ),
        "severity": alert.get("severity", "Medium"),
        "status": "Open",
        "source_ip": alert.get("source_ip"),
        "attack_type": alert.get("attack_type"),
        "risk_score": alert.get("risk_score", 0),
        "mitre_technique": alert.get("mitre_technique"),
        "assigned_analyst": None,
        "investigation_notes": "Automatic incident creation. Investigation pending."
    }

    response = (
        supabase
        .table("incidents")
        .insert(incident)
        .execute()
    )

    return response.data