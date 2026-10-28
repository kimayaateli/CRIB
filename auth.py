"""Authentication and Role-Based Access Control (RBAC) for CRIB.

Roles:
- EMPLOYEE: Personal training dashboard, incident response scenarios, performance history.
- MANAGER: Supervisor oversight, team performance tracking, scenario assignments, feedback.
- ADMIN: User creation, supervisor assignments, account status management, audit logs.
"""

from functools import wraps
from flask import session, redirect, url_for, flash, abort, request
from werkzeug.security import generate_password_hash, check_password_hash
import database


def hash_password(password: str) -> str:
    """Hash password securely using Werkzeug's secure hash."""
    if not password or len(password) < 6:
        raise ValueError("Password must be at least 6 characters long.")
    return generate_password_hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """Verify password against stored hash."""
    if not stored_hash or not password:
        return False
    return check_password_hash(stored_hash, password)


def login_user(user: dict) -> None:
    """Initialize authenticated session for user."""
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["full_name"] = user["full_name"]
    database.update_last_login(user["id"])
    database.log_audit_event(
        user_id=user["id"],
        action="USER_LOGIN",
        details=f"User {user['username']} logged in successfully with role {user['role']}",
        ip_address=request.remote_addr if request else "127.0.0.1",
    )


def logout_user() -> None:
    """Clear session data on logout."""
    user_id = session.get("user_id")
    if user_id:
        database.log_audit_event(
            user_id=user_id,
            action="USER_LOGOUT",
            details="User logged out",
            ip_address=request.remote_addr if request else "127.0.0.1",
        )
    session.clear()


def get_current_user() -> dict | None:
    """Retrieve full user dictionary for currently logged-in user, or None."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    user = database.get_user_by_id(user_id)
    if not user or not user.get("is_active"):
        return None
    return user


def login_required(f):
    """Decorator requiring an authenticated active session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please sign in to access this page.", "info")
            return redirect(url_for("login_view", next=request.path))
        user = get_current_user()
        if not user:
            session.clear()
            flash("Session expired or account is inactive. Please sign in again.", "error")
            return redirect(url_for("login_view"))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*allowed_roles):
    """Decorator requiring specific role(s) to access route."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get("user_id"):
                flash("Please sign in to access this page.", "info")
                return redirect(url_for("login_view", next=request.path))
            user = get_current_user()
            if not user:
                session.clear()
                flash("Session expired. Please sign in again.", "error")
                return redirect(url_for("login_view"))

            user_role = user.get("role", "").upper()
            allowed = [r.upper() for r in allowed_roles]

            if user_role not in allowed and user_role != "ADMIN":
                flash("Access restricted: You do not have permission to view this resource.", "error")
                return redirect(url_for("dashboard"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator
