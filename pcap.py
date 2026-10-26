import os
import tempfile

from flask import Blueprint, render_template, request, session, redirect, url_for

from detection.pcap_parser import extract_connections
from detection.port_scan import detect_port_scan
from detection.brute_force import detect_brute_force
from detection.dns_detection import detect_suspicious_dns
from detection.syn_flood import detect_syn_flood
from detection.udp_flood import detect_udp_flood
from detection.alert_engine import create_alert

from ml.anomaly_detector import calculate_anomaly_score


pcap = Blueprint("pcap", __name__)


@pcap.route("/pcap-analysis", methods=["GET", "POST"])
def pcap_analysis_page():

    if not session.get("user_id"):
        return redirect(url_for("auth.login_page"))

    results = []
    error_message = None
    filename = None
    ml_result = None

    if request.method == "POST":

        uploaded_file = request.files.get("pcap_file")

        if not uploaded_file or uploaded_file.filename == "":
            error_message = "Please select a PCAP file."

        else:

            filename = uploaded_file.filename

            allowed_extensions = (
                ".pcap",
                ".pcapng"
            )

            if not filename.lower().endswith(
                allowed_extensions
            ):
                error_message = (
                    "Only .pcap and .pcapng files are supported."
                )

            else:

                temp_path = None

                try:

                    file_extension = os.path.splitext(
                        filename
                    )[1]

                    temp_file = tempfile.NamedTemporaryFile(
                        delete=False,
                        suffix=file_extension
                    )

                    temp_path = temp_file.name
                    temp_file.close()

                    uploaded_file.save(
                        temp_path
                    )

                    # -----------------------------------------
                    # Extract network connections
                    # -----------------------------------------

                    connections = extract_connections(
                        temp_path
                    )

                    # -----------------------------------------
                    # AI / ML anomaly detection
                    # -----------------------------------------

                    ml_result = calculate_anomaly_score(
                        connections
                    )

                    # -----------------------------------------
                    # Traditional detection engines
                    # -----------------------------------------

                    # Port Scan
                    port_scan_detections = detect_port_scan(
                        connections
                    )

                    # Brute Force
                    brute_force_detections = detect_brute_force(
                        connections
                    )

                    # Suspicious DNS
                    dns_detections = detect_suspicious_dns(
                        connections
                    )

                    # SYN Flood
                    syn_flood_detections = detect_syn_flood(
                        connections
                    )

                    # UDP Flood
                    udp_flood_detections = detect_udp_flood(
                        connections
                    )

                    # -----------------------------------------
                    # Combine detections
                    # -----------------------------------------

                    detections = (
                        port_scan_detections
                        + brute_force_detections
                        + dns_detections
                        + syn_flood_detections
                        + udp_flood_detections
                    )

                    # -----------------------------------------
                    # Create alerts
                    # -----------------------------------------

                    for detection in detections:

                        # Add the ML anomaly score to the detection
                        detection["ml_score"] = ml_result.get(
                            "anomaly_score",
                            0
                        )

                        alert_result = create_alert(
                            detection,
                            cti_mode="mock"
                        )

                        results.append({
                            "detection": detection,
                            "alert": alert_result
                        })

                except Exception as e:

                    error_message = (
                        f"PCAP analysis failed: {str(e)}"
                    )

                finally:

                    if (
                        temp_path
                        and os.path.exists(temp_path)
                    ):

                        try:
                            os.remove(
                                temp_path
                            )

                        except PermissionError:
                            pass

    return render_template(
        "pcap_analysis.html",
        results=results,
        error_message=error_message,
        filename=filename,
        ml_result=ml_result
    )