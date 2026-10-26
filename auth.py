from flask import Blueprint, request, render_template, session, redirect, url_for, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from config.supabase_client import supabase

auth = Blueprint("auth", __name__)


# -----------------------------
# REGISTER PAGE
# -----------------------------
@auth.route("/register", methods=["GET"])
def register_page():
    return render_template("register.html")


# -----------------------------
# REGISTER
# -----------------------------
@auth.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if not data:
        return {"error": "Invalid request."}, 400

    name = data.get("name", "").strip()
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not name or not email or not password:
        return {"error": "All fields are required."}, 400

    if len(password) < 6:
        return {"error": "Password must contain at least 6 characters."}, 400

    try:
        existing_response = (
            supabase
            .table("users")
            .select("id")
            .eq("email", email)
            .execute()
        )

        existing_users = existing_response.data or []

        if existing_users:
            return {
                "error": "An account with this email already exists."
            }, 409

        hashed_password = generate_password_hash(password)

        supabase.table("users").insert({
            "name": name,
            "email": email,
            "password": hashed_password,
            "role": "user"
        }).execute()

        return {
            "message": "Registration successful."
        }, 201

    except Exception as e:
        print("REGISTRATION ERROR:", e)

        return {
            "error": "Registration failed. Please try again."
        }, 500


# -----------------------------
# LOGIN PAGE
# -----------------------------
@auth.route("/login", methods=["GET"])
def login_page():

    # If already logged in, don't show login page
    if session.get("user_id"):
        return redirect(url_for("dashboard.dashboard_page"))

    response = make_response(render_template("login.html"))

    # Prevent browser from caching login page
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response


# -----------------------------
# LOGIN
# -----------------------------
@auth.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    if not data:
        return {"error": "Invalid request."}, 400

    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return {
            "error": "Email and password are required."
        }, 400

    try:
        response = (
            supabase
            .table("users")
            .select("*")
            .eq("email", email)
            .execute()
        )

        users = response.data or []

        if not users:
            return {
                "error": "Invalid email or password."
            }, 401

        user = users[0]

        if not check_password_hash(user["password"], password):
            return {
                "error": "Invalid email or password."
            }, 401

        # Validate the role stored in Supabase
        role = user.get("role")

        if role not in ("admin", "user"):
            return {
                "error": "This account has an invalid role. Please contact the administrator."
            }, 403

        # Create a fresh session
        session.clear()

        session["user_id"] = user["id"]
        session["user_name"] = user["name"]
        session["user_email"] = user["email"]
        session["user_role"] = role
        print("Logged-in user role:", session["user_role"])

        return {
            "message": "Login successful.",
            "user_id": user["id"],
            "name": user["name"]
        }, 200

    except Exception as e:
        print("LOGIN ERROR:", e)

        return {
            "error": "Login failed. Please try again."
        }, 500


# -----------------------------
# LOGOUT
# -----------------------------
@auth.route("/logout")
def logout():

    # Completely remove login session
    session.clear()

    # Redirect to login page
    response = redirect(url_for("auth.login_page"))

    # Prevent browser from caching protected pages
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"

    return response