from utils.authorization import admin_required
from flask import Blueprint, render_template, request, session , redirect, url_for
from config.supabase_client import supabase

incidents = Blueprint("incidents", __name__)


@incidents.route("/incidents")
def incidents_page():

    if not session.get("user_id"):
        return redirect(url_for("auth.login_page"))

    response = (
        supabase
        .table("incidents")
        .select("*")
        .order("id", desc=True)
        .execute()
    )

    return render_template(
        "incidents.html",
        incidents=response.data
    )


@incidents.route("/incidents/<int:incident_id>")
def incident_detail(incident_id):

    if not session.get("user_id"):
        return redirect(url_for("auth.login_page"))
    # ---------------------------------------------------------
    # Get incident
    # ---------------------------------------------------------

    response = (
        supabase
        .table("incidents")
        .select("*")
        .eq("id", incident_id)
        .single()
        .execute()
    )

    incident = response.data

    if not incident:
        return "Incident not found", 404

    # ---------------------------------------------------------
    # Get the alert linked to this incident
    # ---------------------------------------------------------

    alert_response = (
        supabase
        .table("alerts")
        .select("*")
        .eq("incident_id", incident_id)
        .order("id", desc=True)
        .limit(1)
        .execute()
    )

    linked_alerts = alert_response.data or []

    destination_ip = "Unknown"

    if linked_alerts:
        destination_ip = (
            linked_alerts[0].get("destination_ip")
            or "Unknown"
        )

    # Add destination IP to incident data for the template
    incident["destination_ip"] = destination_ip

    return render_template(
        "incident_detail.html",
        incident=incident
    )


@incidents.route("/incidents/<int:incident_id>/update", methods=["POST"])
@admin_required
def update_incident(incident_id):

    if not session.get("user_id"):
        return redirect(url_for("auth.login_page"))

    assigned_analyst = (
        request.form.get("assigned_analyst", "").strip()
    )

    status = (
        request.form.get("status", "Open").strip()
    )

    investigation_notes = (
        request.form.get("investigation_notes", "").strip()
    )

    update_data = {
        "assigned_analyst": assigned_analyst or None,
        "status": status,
        "investigation_notes": investigation_notes
    }

    try:

        (
            supabase
            .table("incidents")
            .update(update_data)
            .eq("id", incident_id)
            .execute()
        )

        return redirect(
            url_for(
                "incidents.incident_detail",
                incident_id=incident_id
            )
        )

    except Exception as e:

        return f"Error updating incident: {str(e)}", 500