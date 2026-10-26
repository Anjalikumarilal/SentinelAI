import os

from flask import Flask, redirect, url_for

from routes.auth import auth
from routes.dashboard import dashboard
from routes.threat import threat
from routes.alerts import alerts
from routes.incidents import incidents
from routes.pcap import pcap
from routes.mitre import mitre
from datetime import timedelta

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY")

if not app.secret_key:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing. "
        "Set it in your environment before starting the application."
    )

# Session expires after 30 minutes of inactivity
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

# Session cookie security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable this when deploying over HTTPS
app.config["SESSION_COOKIE_SECURE"] = os.getenv(
    "SESSION_COOKIE_SECURE", "false"
).lower() == "true"


# =========================================================
# REGISTER BLUEPRINTS
# =========================================================

app.register_blueprint(auth)
app.register_blueprint(dashboard)
app.register_blueprint(threat)
app.register_blueprint(alerts)
app.register_blueprint(incidents)
app.register_blueprint(pcap)
app.register_blueprint(mitre)


# =========================================================
# HOME ROUTE
# =========================================================

@app.route("/")
def home():
    return redirect(url_for("auth.login_page"))


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":
    app.run(debug=True)