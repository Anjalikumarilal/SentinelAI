def calculate_final_risk(
    detection_score,
    cti_score,
    ml_score=0
):
    """
    Calculate the final SentinelAI risk score.

    Detection score = score produced by the detection engine.
    CTI score = threat-intelligence reputation score.
    ML score = behavioral anomaly score.

    All scores are expected to be between 0 and 100.

    Weights:
        Detection = 50%
        CTI       = 30%
        ML        = 20%
    """

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

    final_score = (
        detection_score * 0.50
        + cti_score * 0.30
        + ml_score * 0.20
    )

    return round(final_score)


def calculate_severity(risk_score):
    """
    Convert the final risk score into a SentinelAI severity.
    """

    if risk_score >= 80:
        return "CRITICAL"

    if risk_score >= 60:
        return "HIGH"

    if risk_score >= 40:
        return "MEDIUM"

    if risk_score >= 20:
        return "LOW"

    return "INFORMATIONAL"