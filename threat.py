import re
from urllib.parse import urlparse

from flask import (
    Blueprint,
    render_template,
    request,
    session,
    redirect,
    url_for
)

from config.supabase_client import supabase
from cti.threat_intelligence import enrich_ip


threat = Blueprint("threat", __name__)


# ---------------------------------------------------------
# Indicator Type Detection
# ---------------------------------------------------------
def detect_indicator_type(indicator):

    # IPv4 address
    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    if re.match(ip_pattern, indicator):
        parts = indicator.split(".")

        if all(0 <= int(part) <= 255 for part in parts):
            return "IP"

        return "UNKNOWN"

    # URL
    if indicator.startswith(("http://", "https://")):
        parsed_url = urlparse(indicator)

        if parsed_url.netloc:
            return "URL"

        return "UNKNOWN"

    # MD5
    if re.match(r"^[a-fA-F0-9]{32}$", indicator):
        return "MD5"

    # SHA-1
    if re.match(r"^[a-fA-F0-9]{40}$", indicator):
        return "SHA1"

    # SHA-256
    if re.match(r"^[a-fA-F0-9]{64}$", indicator):
        return "SHA256"

    # Domain
    domain_pattern = (
        r"^(?=.{1,253}$)"
        r"(?:[a-zA-Z0-9]"
        r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    )

    if re.match(domain_pattern, indicator):
        return "DOMAIN"

    return "UNKNOWN"


# ---------------------------------------------------------
# Base Threat Score
# ---------------------------------------------------------
def calculate_threat_score(indicator_type):

    scores = {
        "IP": (40, "MEDIUM"),
        "DOMAIN": (30, "LOW"),
        "URL": (50, "MEDIUM"),
        "MD5": (60, "MEDIUM"),
        "SHA1": (60, "MEDIUM"),
        "SHA256": (60, "MEDIUM"),
        "UNKNOWN": (0, "UNKNOWN")
    }

    return scores.get(
        indicator_type,
        (0, "UNKNOWN")
    )


# ---------------------------------------------------------
# Threat Search API
# ---------------------------------------------------------
@threat.route("/threat-search", methods=["POST"])
def threat_search():

    # Protect API route
    if not session.get("user_id"):
        return {
            "error": "Authentication required."
        }, 401

    data = request.get_json() or {}

    indicator = data.get(
        "indicator",
        ""
    ).strip()

    if not indicator:
        return {
            "error": "Please enter a threat indicator"
        }, 400

    indicator_type = detect_indicator_type(
        indicator
    )

    threat_score, risk_level = calculate_threat_score(
        indicator_type
    )

    try:

        supabase.table("threat_searches").insert({
            "indicator": indicator,
            "indicator_type": indicator_type,
            "threat_score": threat_score,
            "risk_level": risk_level
        }).execute()

        return {
            "message": (
                f"Indicator '{indicator}' "
                "saved successfully!"
            )
        }, 201

    except Exception as e:

        return {
            "error": str(e)
        }, 500


# ---------------------------------------------------------
# Threat Intelligence Page
# ---------------------------------------------------------
@threat.route("/threat-intelligence", methods=["GET"])
def threat_intelligence_page():

    # Protect Threat Intelligence page
    if not session.get("user_id"):
        return redirect(
            url_for("auth.login_page")
        )

    indicator = request.args.get(
        "indicator",
        ""
    ).strip()

    mode = request.args.get(
        "mode",
        "mock"
    ).lower()

    # Only allow Mock or Real
    if mode not in ("mock", "real"):
        mode = "mock"

    cti_result = None
    indicator_type = None
    analysis_score = None
    analysis_risk = None
    search_saved = False
    error_message = None

    # -----------------------------------------------------
    # Analyze indicator
    # -----------------------------------------------------
    if indicator:

        indicator_type = detect_indicator_type(
            indicator
        )

        analysis_score, analysis_risk = (
            calculate_threat_score(
                indicator_type
            )
        )

        # -------------------------------------------------
        # CTI enrichment
        # -------------------------------------------------
        if indicator_type == "IP":

            try:

                cti_result = enrich_ip(
                    indicator,
                    mode=mode
                )

            except Exception as e:

                error_message = str(e)

        # -------------------------------------------------
        # Save search to Supabase
        # -------------------------------------------------
        try:

            supabase.table(
                "threat_searches"
            ).insert({

                "indicator": indicator,
                "indicator_type": indicator_type,
                "threat_score": analysis_score,
                "risk_level": analysis_risk

            }).execute()

            search_saved = True

        except Exception as e:

            error_message = (
                f"Search result could not be saved: {str(e)}"
            )

    # -----------------------------------------------------
    # Render page
    # -----------------------------------------------------
    return render_template(
        "threat_intelligence.html",
        indicator=indicator,
        indicator_type=indicator_type,
        analysis_score=analysis_score,
        analysis_risk=analysis_risk,
        cti_result=cti_result,
        mode=mode,
        search_saved=search_saved,
        error_message=error_message
    )