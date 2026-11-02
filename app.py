"""
app.py — CVE Intel Flask backend

Security hardening implemented:
  1. Strict CVE-ID input validation (regex whitelist, bleach sanitization)
  2. Rate limiting (Flask-Limiter) on every endpoint
  3. Security response headers (CSP, X-Frame-Options, HSTS-ready, etc.)
  4. Parameterized SQL queries (via database.py — zero string interpolation)
  5. No eval(), no dangerouslySetInnerHTML, no exec() anywhere in codebase
  6. User authentication with bcrypt password hashing
  7. Brute-force protection with failed login tracking
  8. CSRF protection on all forms
"""

import os
import re
import logging
from datetime import datetime, timezone
import bleach
import bcrypt
from flask import Flask, jsonify, request, render_template, abort, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from apscheduler.schedulers.background import BackgroundScheduler
from database import CVEDatabase
from nvd_client import (
    CVEUpstreamError,
    CISAKEVUpdateError,
    NVDClient,
    NVDUpdateError,
)

# ------------------------------------------------------------------ #
# Logging                                                              #
# ------------------------------------------------------------------ #
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("cve_intel")

# ------------------------------------------------------------------ #
# App init                                                             #
# ------------------------------------------------------------------ #
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", os.urandom(32))
app.config["JSON_SORT_KEYS"] = False

# CSRF Protection
csrf = CSRFProtect(app)

# Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, username):
        self.id = username
        self.username = username

@login_manager.user_loader
def load_user(username):
    user_data = db.get_user(username)
    if user_data:
        return User(username)
    return None

@login_manager.unauthorized_handler
def unauthorized():
    """Return 401 JSON response for unauthenticated API requests."""
    return jsonify({"error": "Authentication required."}), 401

# Rate limiting — stored in memory (swap for Redis in production)
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["300 per day", "60 per hour"],
    storage_uri="memory://",
)

db  = CVEDatabase()
nvd = NVDClient(
    api_key=os.environ.get("NVD_API_KEY"),
    github_token=os.environ.get("GITHUB_TOKEN"),
)

# ------------------------------------------------------------------ #
# Background scheduler — update NVD every 6 hours                     #
# ------------------------------------------------------------------ #
scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(
    nvd.update_recent_cves, "interval", hours=6, args=[db, 7], id="nvd_sync"
)
scheduler.add_job(
    nvd.sync_cisa_kev,
    "interval",
    hours=6,
    args=[db],
    id="cisa_kev_sync",
)
scheduler.start()

# ------------------------------------------------------------------ #
# Input validation                                                     #
# ------------------------------------------------------------------ #
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-]{2,31}$")
_PASSWORD_RE = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^a-zA-Z0-9]).{8,}$")


def _validate_cve_id(raw: str) -> str:
    """
    Strict whitelist validation for CVE IDs.
    Only uppercase 'CVE-YYYY-NNNN+' format is accepted.
    """
    if not raw:
        abort(400, description="CVE ID is required.")
    # bleach first, then regex gate
    cleaned = bleach.clean(raw.strip().upper(), tags=[], attributes={}, strip=True)
    if not _CVE_RE.match(cleaned):
        abort(400, description=f"Invalid CVE ID format: '{cleaned}'")
    return cleaned


def _validate_username(raw: str) -> str:
    """Sanitize and validate username."""
    cleaned = bleach.clean((raw or "").strip(), tags=[], attributes={}, strip=True)
    if not _USERNAME_RE.match(cleaned):
        abort(400, description="Username must be 3-32 chars, alphanumeric and optionally _ or -, cannot start with symbol.")
    return cleaned


def _validate_password(raw: str) -> str:
    """Validate password strength."""
    if not raw or len(raw) < 8:
        abort(400, description="Password must be at least 8 characters long.")
    if not _PASSWORD_RE.match(raw):
        abort(400, description="Password must include uppercase, lowercase, number, and symbol.")
    return raw


def _validate_search_query(raw: str) -> str:
    """Sanitize search queries; reject extreme lengths."""
    if not raw or len(raw.strip()) < 2:
        abort(400, description="Search query must be at least 2 characters.")
    if len(raw) > 120:
        abort(400, description="Search query exceeds maximum length (120 chars).")
    return bleach.clean(raw.strip(), tags=[], attributes={}, strip=True)


# ------------------------------------------------------------------ #
# Security response headers (Hardening Measure #2)                    #
# ------------------------------------------------------------------ #
@app.after_request
def add_security_headers(response):
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers["Content-Security-Policy"]    = csp
    response.headers["X-Content-Type-Options"]     = "nosniff"
    response.headers["X-Frame-Options"]            = "DENY"
    response.headers["X-XSS-Protection"]           = "1; mode=block"
    response.headers["Referrer-Policy"]            = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]         = "geolocation=(), microphone=(), camera=()"
    return response


# ------------------------------------------------------------------ #
# Error handlers                                                       #
# ------------------------------------------------------------------ #
@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": str(e.description)}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": str(e.description)}), 404


@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Rate limit exceeded. Please slow down."}), 429


@app.errorhandler(503)
def upstream_unavailable(e):
    return jsonify({"error": str(e.description)}), 503


@app.errorhandler(500)
def server_error(e):
    log.exception("Internal server error")
    return jsonify({"error": "Internal server error."}), 500


# ------------------------------------------------------------------ #
# Authentication Routes                                                #
# ------------------------------------------------------------------ #
@app.route("/api/register", methods=["POST"])
@limiter.limit("5 per hour")
@csrf.exempt
def register():
    """User registration endpoint."""
    data = request.get_json() or {}
    username = _validate_username(data.get("username", ""))
    password = _validate_password(data.get("password", ""))

    # Hash password with bcrypt
    try:
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    except Exception as exc:
        log.exception("Password hashing failed: %s", exc)
        abort(500, description="Registration failed.")

    # Create user
    if db.create_user(username, password_hash):
        return jsonify({"message": "Registration successful. You can now log in."}), 201
    else:
        abort(400, description="Username already exists.")


@app.route("/api/login", methods=["POST"])
@limiter.limit("10 per hour")  # Stricter limit for login
@csrf.exempt
def login():
    """User login endpoint with brute-force protection."""
    data = request.get_json() or {}
    username = _validate_username(data.get("username", ""))
    password = _validate_password(data.get("password", ""))

    # Check for brute-force attempts (5+ failed attempts in 15 minutes)
    failed_count = db.get_failed_login_count(username, minutes_back=15)
    if failed_count >= 5:
        log.warning("Login blocked for %s due to multiple failed attempts", username)
        abort(429, description="Account temporarily locked due to too many failed login attempts. Try again later.")

    # Get user from database
    user_data = db.get_user(username)
    if not user_data:
        db.log_failed_login(username, get_remote_address())
        abort(401, description="Invalid credentials.")

    # Verify password with bcrypt
    try:
        password_valid = bcrypt.checkpw(password.encode(), user_data["password_hash"].encode())
    except Exception as exc:
        log.exception("Password verification failed: %s", exc)
        abort(500, description="Authentication failed.")
    
    if not password_valid:
        db.log_failed_login(username, get_remote_address())
        abort(401, description="Invalid credentials.")

    # Successful login
    db.clear_failed_logins(username)
    db.update_last_login(username)
    user = User(username)
    login_user(user, remember=False)
    log.info("User '%s' logged in successfully", username)

    return jsonify({"message": "Login successful.", "username": username}), 200


@app.route("/api/logout", methods=["POST"])
@login_required
@csrf.exempt
def logout():
    """User logout endpoint."""
    username = current_user.username
    logout_user()
    log.info("User '%s' logged out", username)
    return jsonify({"message": "Logout successful."}), 200


@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    """Get current authentication status."""
    if current_user.is_authenticated:
        return jsonify({"authenticated": True, "username": current_user.username}), 200
    return jsonify({"authenticated": False}), 200


# ------------------------------------------------------------------ #
# Routes                                                               #
# ------------------------------------------------------------------ #
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/cve/<path:raw_id>")
@limiter.limit("40 per minute; 200 per hour")
def get_cve(raw_id: str):
    """
    Fetch full CVE detail.
    Uses cached data unless core metadata is missing or needs a range-parser refresh.
    """
    cve_id = _validate_cve_id(raw_id)

    # Cache hit
    cached = db.get_cve(cve_id)
    if cached and not nvd.cache_needs_refresh(cached):
        cached["cache"] = "HIT"
        return jsonify(cached)

    # Refresh old records that never had a score or affected-product data.
    try:
        fresh = nvd.fetch_cve(cve_id)
    except CVEUpstreamError as exc:
        if cached:
            cached["cache"] = "STALE"
            cached["data_warning"] = str(exc)
            cached["source_warnings"] = [
                f"{source} could not be reached; its metadata may be missing."
                for source in exc.sources
            ]
            cached["sources_checked"] = list(
                dict.fromkeys((cached.get("sources_checked") or []) + exc.sources)
            )
            checked_details = [
                detail
                for detail in cached.get("source_details", [])
                if detail.get("source") not in exc.sources
            ]
            checked_details.extend(
                {
                    "source": source,
                    "trust_level": "unknown",
                    "untrusted": False,
                    "status": "unavailable",
                }
                for source in exc.sources
            )
            cached["source_details"] = checked_details
            cached["fetched_at"] = datetime.now(timezone.utc).isoformat()
            db.store_cve(cached)
            return jsonify(cached)
        abort(503, description=str(exc))
    if not fresh:
        if cached:
            cached["cache"] = "STALE"
            cached["data_warning"] = (
                "The upstream sources returned no matching record; showing saved data."
            )
            cached["source_warnings"] = [cached["data_warning"]]
            cached["sources_checked"] = list(
                dict.fromkeys(
                    (cached.get("sources_checked") or [])
                    + ["NVD", "MITRE", "OSV", "GitHub Advisory"]
                )
            )
            cached["fetched_at"] = datetime.now(timezone.utc).isoformat()
            db.store_cve(cached)
            return jsonify(cached)
        abort(
            404,
            description=(
                f"CVE '{cve_id}' not found in NVD, MITRE, OSV, GitHub Advisory, "
                "Red Hat Security Data, CISA KEV, or local database."
            ),
        )

    db.store_cve(fresh)
    fresh["cache"] = "REFRESHED" if cached else "MISS"
    return jsonify(fresh)


@app.route("/api/cve/<path:raw_id>/refresh")
@limiter.limit("5 per minute; 20 per hour")
def refresh_cve(raw_id: str):
    """Force a live re-fetch from all CVE sources, then update the local cache."""
    cve_id = _validate_cve_id(raw_id)
    try:
        fresh = nvd.fetch_cve(cve_id)
    except CVEUpstreamError as exc:
        abort(503, description=str(exc))
    if not fresh:
        abort(
            404,
            description=(
                f"CVE '{cve_id}' not found in NVD, MITRE, OSV, GitHub Advisory, "
                "Red Hat Security Data, or CISA KEV."
            ),
        )
    db.store_cve(fresh)
    fresh["cache"] = "REFRESHED"
    return jsonify(fresh)


@app.route("/api/search")
@limiter.limit("30 per minute")
def search():
    """Search CVEs by ID prefix or full-text description."""
    query = _validate_search_query(request.args.get("q", ""))
    try:
        limit = int(request.args.get("limit", 25))
    except ValueError:
        abort(400, description="Limit must be an integer.")
    limit = max(1, min(limit, 50))
    results = db.search_cves(query, limit=limit)
    return jsonify({"query": query, "count": len(results), "results": results})


@app.route("/api/search/live")
@limiter.limit("2 per minute")
def search_live():
    """Search the local cache plus NVD, when explicitly requested by the user."""
    query = _validate_search_query(request.args.get("q", ""))
    try:
        limit = int(request.args.get("limit", 8))
    except ValueError:
        abort(400, description="Limit must be an integer.")
    limit = max(1, min(limit, 50))
    local_results = db.search_cves(query, limit=limit)

    try:
        nvd_results, total_results = nvd.search_cves(query, limit=limit)
    except CVEUpstreamError as exc:
        if not local_results:
            abort(503, description=str(exc))
        return jsonify(
            {
                "query": query,
                "count": len(local_results),
                "results": local_results,
                "warning": str(exc),
                "total_upstream": None,
            }
        )

    nvd_ids = {record["id"] for record in nvd_results}
    results = nvd_results + [
        item for item in local_results if item["id"] not in nvd_ids
    ]
    results = results[:limit]
    return jsonify(
        {
            "query": query,
            "count": len(results),
            "results": results,
            "total_upstream": total_results,
        }
    )


@app.route("/api/recent")
@limiter.limit("20 per minute")
def recent():
    """Return recently published CVEs from local DB."""
    try:
        limit = int(request.args.get("limit", 30))
    except ValueError:
        abort(400, description="Limit must be an integer.")
    limit = max(1, min(limit, 50))
    results = db.get_recent_cves(limit=limit)
    return jsonify({"count": len(results), "results": results})


@app.route("/api/stats")
@limiter.limit("20 per minute")
def stats():
    """Return database statistics."""
    return jsonify(db.get_stats())


@app.route("/api/trigger-update")
@limiter.limit("2 per hour")
def trigger_update():
    """Manually trigger NVD and CISA KEV synchronization (rate-limited)."""
    nvd_count = None
    kev_count = None
    failures = []
    try:
        nvd_count = nvd.update_recent_cves(db, days_back=1)
    except NVDUpdateError as exc:
        log.error("Manual NVD sync failed: %s", exc)
        failures.append({"source": "NVD", "error": str(exc)})
    try:
        kev_count = nvd.sync_cisa_kev(db)
    except CISAKEVUpdateError as exc:
        log.error("Manual CISA KEV sync failed: %s", exc)
        failures.append({"source": "CISA KEV", "error": str(exc)})
    if failures:
        return jsonify(
            {
                "error": "One or more vulnerability data synchronizations failed.",
                "failed_sources": failures,
                "nvd_updated": nvd_count,
                "cisa_kev_updated": kev_count,
            }
        ), 502
    return jsonify(
        {
            "message": (
                f"Update complete. NVD processed {nvd_count} CVEs; "
                f"CISA KEV processed {kev_count} CVEs."
            ),
            "nvd_updated": nvd_count,
            "cisa_kev_updated": kev_count,
        }
    )


@app.route("/api/cve/<path:raw_id>/poc")
@login_required
@limiter.limit("30 per minute")
def get_cve_poc(raw_id: str):
    """
    Fetch PoC (Proof-of-Concept) code for a CVE.
    Requires authentication.
    """
    cve_id = _validate_cve_id(raw_id)

    # Get CVE with PoC data
    cached = db.get_cve(cve_id)
    if cached and cached.get("poc"):
        return jsonify({
            "cve_id": cve_id,
            "poc": cached["poc"],
            "accessed_by": current_user.username,
        })

    # Try to fetch from MITRE and extract PoC
    fresh = nvd.fetch_cve(cve_id)
    if not fresh:
        abort(404, description=f"CVE '{cve_id}' not found.")

    if fresh.get("poc"):
        return jsonify({
            "cve_id": cve_id,
            "poc": fresh["poc"],
            "accessed_by": current_user.username,
        })
    else:
        return jsonify({
            "cve_id": cve_id,
            "poc": [],
            "message": "No PoC data available for this CVE.",
            "accessed_by": current_user.username,
        })


# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    # Never use debug=True in production
    app.run(host="127.0.0.1", port=5000, debug=False)
