from flask import Blueprint, render_template, session, redirect, url_for
from config.supabase_client import supabase


mitre = Blueprint("mitre", __name__)


@mitre.route("/mitre")
def mitre_page():

    if not session.get("user_id"):
        return redirect(url_for("auth.login_page"))

    techniques = [

        {
            "id": "T1046",
            "name": "Network Service Scanning",
            "attack_types": ["Port Scan"],
            "description": (
                "Adversaries may scan network services to identify "
                "available ports, services and potential targets."
            )
        },

        {
            "id": "T1110",
            "name": "Brute Force",
            "attack_types": ["Brute Force"],
            "description": (
                "Adversaries may use repeated authentication attempts "
                "to gain access to accounts or services."
            )
        },

        {
            "id": "T1071.004",
            "name": "DNS",
            "attack_types": ["Suspicious DNS Activity"],
            "description": (
                "Adversaries may use DNS to communicate with or control "
                "systems, or abuse DNS-related activity during attacks."
            )
        },

        {
            "id": "T1498.001",
            "name": "Direct Network Flood",
            "attack_types": ["SYN Flood", "UDP Flood"],
            "description": (
                "Adversaries may perform network denial-of-service "
                "attacks by directly flooding a target with network traffic."
            )
        }

    ]

    response = (
        supabase
        .table("alerts")
        .select("*")
        .order("id", desc=True)
        .execute()
    )

    alerts = response.data or []

    for technique in techniques:

        technique["alert_count"] = sum(
            1
            for alert in alerts
            if alert.get("mitre_technique", "").startswith(
                technique["id"]
            )
        )

    return render_template(
        "mitre.html",
        techniques=techniques
    )