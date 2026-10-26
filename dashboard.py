from flask import Blueprint, render_template, session, redirect, url_for
from config.supabase_client import supabase

dashboard = Blueprint("dashboard", __name__)


@dashboard.route("/dashboard")
def dashboard_page():

    # Protect dashboard
    if not session.get("user_id"):
        return redirect(url_for("auth.login_page"))


    # =====================================================
    # THREAT SEARCHES
    # =====================================================
    searches_response = (
        supabase
        .table("threat_searches")
        .select("*")
        .order("id", desc=True)
        .execute()
    )

    searches = searches_response.data or []
    total_searches = len(searches)


    # =====================================================
    # SECURITY ALERTS
    # =====================================================
    alerts_response = (
        supabase
        .table("alerts")
        .select("*")
        .order("id", desc=True)
        .execute()
    )

    alerts = alerts_response.data or []


    # =====================================================
    # ALERT SEVERITY COUNTS
    # =====================================================
    critical_alerts = len([
        alert for alert in alerts
        if alert.get("severity", "").upper() == "CRITICAL"
    ])

    high_alerts = len([
        alert for alert in alerts
        if alert.get("severity", "").upper() == "HIGH"
    ])

    medium_alerts = len([
        alert for alert in alerts
        if alert.get("severity", "").upper() == "MEDIUM"
    ])

    low_alerts = len([
        alert for alert in alerts
        if alert.get("severity", "").upper() == "LOW"
    ])

    informational = len([
        alert for alert in alerts
        if alert.get("severity", "").upper() == "INFORMATIONAL"
    ])


    # =====================================================
    # DASHBOARD RISK COUNTS
    # =====================================================
    high_risk = high_alerts
    medium_risk = medium_alerts


    # =====================================================
    # ATTACK TYPE STATISTICS
    # =====================================================
    attack_type_counts = {}

    for alert in alerts:
        attack_type = alert.get("attack_type") or "Unknown"

        attack_type_counts[attack_type] = (
            attack_type_counts.get(attack_type, 0) + 1
        )


    # =====================================================
    # ML / ANOMALY STATISTICS
    # =====================================================
    ml_alerts = [
        alert for alert in alerts
        if alert.get("ml_score") is not None
        and alert.get("ml_score", 0) > 0
    ]

    anomaly_alerts = [
        alert for alert in ml_alerts
        if alert.get("ml_score", 0) >= 40
    ]

    ml_anomaly_count = len(anomaly_alerts)
    ml_analyzed_count = len(ml_alerts)

    if ml_alerts:
        average_ml_score = round(
            sum(alert.get("ml_score", 0) for alert in ml_alerts)
            / len(ml_alerts)
        )
    else:
        average_ml_score = 0


    # =====================================================
    # RISK STATISTICS
    # =====================================================
    if alerts:
        average_risk_score = round(
            sum(alert.get("risk_score", 0) or 0 for alert in alerts)
            / len(alerts)
        )
    else:
        average_risk_score = 0


    # =====================================================
    # MITRE ATT&CK STATISTICS
    # =====================================================
    mitre_counts = {}

    for alert in alerts:
        technique = alert.get("mitre_technique")

        if technique:
            technique_id = technique.split(" - ")[0]

            mitre_counts[technique_id] = (
                mitre_counts.get(technique_id, 0) + 1
            )


    # =====================================================
    # RECENT SECURITY ALERTS
    # =====================================================
    recent_alerts = alerts[:10]


    # =====================================================
    # INCIDENTS
    # =====================================================
    incidents_response = (
        supabase
        .table("incidents")
        .select("*")
        .order("id", desc=True)
        .execute()
    )

    incidents = incidents_response.data or []


    # =====================================================
    # INCIDENT STATUS COUNTS
    # =====================================================
    open_incidents = len([
        incident for incident in incidents
        if incident.get("status", "").upper() == "OPEN"
    ])

    investigating_incidents = len([
        incident for incident in incidents
        if incident.get("status", "").upper()
        == "INVESTIGATING"
    ])

    resolved_incidents = len([
        incident for incident in incidents
        if incident.get("status", "").upper()
        in ("RESOLVED", "CLOSED")
    ])


    # =====================================================
    # RECENT INCIDENTS
    # =====================================================
    recent_incidents = incidents[:5]


    # =====================================================
    # RENDER DASHBOARD
    # =====================================================
    return render_template(
        "dashboard.html",

        # Threat searches
        total_searches=total_searches,

        # Risk cards
        high_risk=high_risk,
        medium_risk=medium_risk,

        # Alert severity
        critical_alerts=critical_alerts,
        high_alerts=high_alerts,
        medium_alerts=medium_alerts,
        low_alerts=low_alerts,
        informational=informational,

        # Attack statistics
        attack_type_counts=attack_type_counts,

        # ML statistics
        ml_analyzed_count=ml_analyzed_count,
        ml_anomaly_count=ml_anomaly_count,
        average_ml_score=average_ml_score,

        # Risk statistics
        average_risk_score=average_risk_score,

        # MITRE statistics
        mitre_counts=mitre_counts,

        # Incidents
        open_incidents=open_incidents,
        investigating_incidents=investigating_incidents,
        resolved_incidents=resolved_incidents,
        recent_incidents=recent_incidents,

        # Tables
        recent_alerts=recent_alerts,
        searches=searches
    )