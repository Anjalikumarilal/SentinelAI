from config.supabase_client import supabase
from cti.threat_intelligence import enrich_ip
from risk.risk_engine import calculate_final_risk, calculate_severity


def create_alert(detection, cti_mode="mock"):
    """
    Enrich a detection with CTI, calculate the final risk score,
    save the alert, and automatically create or update an incident
    for HIGH or CRITICAL alerts.

    Risk components:
        Detection = 50%
        CTI       = 30%
        ML        = 20%
    """

    source_ip = detection.get("source_ip")

    if not source_ip:
        raise ValueError(
            "Detection does not contain a source IP."
        )

    # ---------------------------------------------------------
    # CTI ENRICHMENT
    # ---------------------------------------------------------

    cti_result = enrich_ip(
        source_ip,
        mode=cti_mode
    )

    # ---------------------------------------------------------
    # RISK COMPONENTS
    # ---------------------------------------------------------

    detection_score = detection.get(
        "risk_score",
        0
    )

    cti_score = cti_result.get(
        "threat_score",
        0
    )

    ml_score = detection.get(
        "ml_score",
        0
    )

    # Keep all values safely between 0 and 100

    detection_score = max(
        0,
        min(100, detection_score)
    )

    cti_score = max(
        0,
        min(100, cti_score)
    )

    ml_score = max(
        0,
        min(100, ml_score)
    )

    # ---------------------------------------------------------
    # FINAL RISK
    # ---------------------------------------------------------

    final_risk = calculate_final_risk(
        detection_score,
        cti_score,
        ml_score
    )

    severity = calculate_severity(
        final_risk
    )

    # ---------------------------------------------------------
    # CTI INFORMATION
    # ---------------------------------------------------------

    categories = cti_result.get(
        "categories",
        []
    )

    if not categories:
        categories_text = "None"
    else:
        categories_text = ", ".join(
            str(category)
            for category in categories
        )

    provider = cti_result.get(
        "provider",
        "Unknown"
    )

    reputation = cti_result.get(
        "reputation",
        "Unknown"
    )

    country = cti_result.get(
        "country",
        "Unknown"
    )

    organization = cti_result.get(
        "organization",
        "Unknown"
    )

    threat_intelligence = (
        f"Provider: {provider}; "
        f"Reputation: {reputation}; "
        f"Threat Score: {cti_score}; "
        f"Country: {country}; "
        f"Organization: {organization}; "
        f"Categories: {categories_text}"
    )

    # ---------------------------------------------------------
    # CREATE ALERT
    # ---------------------------------------------------------

    alert = {
        "source_ip": source_ip,

        "destination_ip": detection.get(
            "destination_ip"
        ),

        "attack_type": detection.get(
            "attack_type"
        ),

        "ai_confidence": detection.get(
            "confidence",
            0
        ),

        # Final risk
        "risk_score": final_risk,

        "severity": severity,

        # Risk components
        "detection_score": detection_score,
        "cti_score": cti_score,
        "ml_score": ml_score,

        "threat_intelligence": threat_intelligence,

        "mitre_technique": detection.get(
            "mitre_technique"
        ),

        "status": "Open"
    }

    response = (
        supabase
        .table("alerts")
        .insert(alert)
        .execute()
    )

    created_alerts = response.data

    if not created_alerts:
        return []

    created_alert = created_alerts[0]

    # ---------------------------------------------------------
    # AUTOMATIC INCIDENT MANAGEMENT
    # ---------------------------------------------------------

    if severity in ("HIGH", "CRITICAL"):

        attack_type = created_alert.get(
            "attack_type"
        )

        existing_response = (
            supabase
            .table("incidents")
            .select("*")
            .eq(
                "source_ip",
                source_ip
            )
            .eq(
                "attack_type",
                attack_type
            )
            .eq(
                "status",
                "Open"
            )
            .execute()
        )

        existing_incidents = (
            existing_response.data or []
        )

        if existing_incidents:

            existing_incident = (
                existing_incidents[0]
            )

            existing_risk = existing_incident.get(
                "risk_score",
                0
            )

            updated_risk = max(
                existing_risk,
                final_risk
            )

            updated_severity = calculate_severity(
                updated_risk
            )

            incident_id = existing_incident.get(
                "id"
            )

            (
                supabase
                .table("incidents")
                .update({
                    "risk_score": updated_risk,
                    "severity": updated_severity,
                    "mitre_technique": created_alert.get(
                        "mitre_technique"
                    ),
                    "investigation_notes": (
                        "Incident automatically updated from "
                        "latest CTI and ML-enriched security alert."
                    )
                })
                .eq(
                    "id",
                    incident_id
                )
                .execute()
            )

            (
                supabase
                .table("alerts")
                .update({
                    "incident_id": incident_id
                })
                .eq(
                    "id",
                    created_alert.get("id")
                )
                .execute()
            )

        else:

            incident = {
                "title": (
                    f"{attack_type} Investigation"
                ),

                "description": (
                    f"Incident automatically created from a "
                    f"{severity} security alert enriched with "
                    f"CTI and behavioral ML analysis."
                ),

                "severity": severity,

                "status": "Open",

                "source_ip": source_ip,

                "attack_type": attack_type,

                "risk_score": final_risk,

                "mitre_technique": created_alert.get(
                    "mitre_technique"
                ),

                "assigned_analyst": None,

                "investigation_notes": (
                    "Automatic incident creation. "
                    "CTI enrichment completed. "
                    "ML behavioral analysis completed. "
                    "Investigation pending."
                )
            }

            incident_response = (
                supabase
                .table("incidents")
                .insert(incident)
                .execute()
            )

            created_incidents = (
                incident_response.data or []
            )

            if created_incidents:

                incident_id = (
                    created_incidents[0].get("id")
                )

                (
                    supabase
                    .table("alerts")
                    .update({
                        "incident_id": incident_id
                    })
                    .eq(
                        "id",
                        created_alert.get("id")
                    )
                    .execute()
                )

    return created_alerts