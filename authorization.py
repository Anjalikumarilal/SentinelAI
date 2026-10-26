from functools import wraps
from flask import session, redirect, url_for, abort


def admin_required(view_function):
    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        # Require login
        if not session.get("user_id"):
            return redirect(url_for("auth.login_page"))

        # Require admin role
        if session.get("user_role") != "admin":
            abort(403)

        return view_function(*args, **kwargs)

    return wrapped_view