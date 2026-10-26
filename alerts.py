from flask import Blueprint, render_template, session, redirect, url_for
from config.supabase_client import supabase

alerts = Blueprint("alerts", __name__)

# =========================================================
# ALERT LIST
# =========================================================

@alerts.route("/alerts")
def alerts_page():

    if not session.get("user_id"):
        return redirect(url_for("auth.login_page"))

    response = (
        supabase
        .table("alerts")
        .select("*")
        .order("created_at", desc=True)
        .execute()
    )

    alert_data = response.data or []

    return render_template(
        "alerts.html",
        alerts=alert_data
    )


# =========================================================
# ALERT DETAIL
# =========================================================

@alerts.route("/alerts/<int:alert_id>")
def alert_detail(alert_id):

    if not session.get("user_id"):
        return redirect(url_for("auth.login_page"))


    # -----------------------------------------------------
    # 1. Get alert
    # -----------------------------------------------------

    response = (
        supabase
        .table("alerts")
        .select("*")
        .eq("id", alert_id)
        .execute()
    )

    alerts_data = response.data or []

    if not alerts_data:
        return "Alert not found", 404

    alert = alerts_data[0]
    

    # -----------------------------------------------------
    # 2. Find related incident
    # -----------------------------------------------------

    related_incident = None

    source_ip = alert.get("source_ip")
    attack_type = alert.get("attack_type")

    if source_ip and attack_type:

        incident_response = (
            supabase
            .table("incidents")
            .select("*")
            .eq("source_ip", source_ip)
            .eq("attack_type", attack_type)
            .order("id", desc=True)
            .limit(1)
            .execute()
        )

        incidents_data = incident_response.data or []

        if incidents_data:
            related_incident = incidents_data[0]

    # -----------------------------------------------------
    # 3. Render alert detail
    # -----------------------------------------------------

    return render_template(
        "alert_detail.html",
        alert=alert,
        related_incident=related_incident
    )