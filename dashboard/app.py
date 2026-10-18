"""Authenticated multi-page security dashboard and local scan service."""

import json
import io
import hashlib
import os
import secrets
import threading
import time
import uuid
from collections import Counter
from datetime import timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template, request,
    send_file, session, url_for,
)
from flask_wtf.csrf import CSRFError, CSRFProtect
from webauthn import (
    base64url_to_bytes, generate_authentication_options,
    generate_registration_options, options_to_json,
    verify_authentication_response, verify_registration_response,
)
from webauthn.helpers.structs import (
    AuthenticatorAttachment, AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor, ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.helpers import bytes_to_base64url
from werkzeug.middleware.proxy_fix import ProxyFix

from backend.security_pipeline import (
    DEFAULT_DATA_DIR, DEFAULT_REPORT_PATH, REPORT_HISTORY_DIR, run_analysis,
)
from compliance.benchmarks.benchmark_engine import attach_benchmarks
from connectors.collect import OUTPUTS, collect
from connectors.provider_credentials import save as save_provider_credentials, statuses as provider_connection_statuses
from dashboard.auth import (
    authenticate, audit, create_scan_job, create_user, get_scan_job, get_user,
    get_passkey, init_db, list_passkeys, list_users, passkey_credentials,
    recent_audit, recent_scan_jobs, save_passkey, update_passkey_usage,
    update_scan_job, user_count, verify_user_password,
)
from ml.risk_model import model_metadata, train_model
from remediation.aws_remediation import enable_s3_block_public_access
from remediation.recommendations import REMEDIATIONS
from remediation.manual_configuration import apply_changes as apply_manual_changes, validate_changes
from normalizer.common_model import normalize_s3_bucket
from security.s3_rules import check_s3_security
from backend.security_pipeline import process_resource, summarize_results
from verification.verification_engine import verify_remediation
from dashboard.cloud_assistant import answer as answer_cloud_question


NAVIGATION = [
    ("dashboard", "Dashboard", "⌂", "dashboard_page"),
    ("resources", "Cloud Resources", "☁", "resources_page"),
    ("findings", "Security Findings", "⚑", "findings_page"),
    ("risk", "Risk Analysis", "▥", "risk_page"),
    ("remediation", "Remediation", "🔧", "remediation_page"),
    ("compliance", "Compliance", "▤", "compliance_page"),
    ("ml", "Machine Learning", "◈", "ml_page"),
    ("reports", "Reports", "▧", "reports_page"),
    ("connections", "Connections", "⌁", "connections_page"),
    ("settings", "Settings", "⚙", "settings_page"),
]
PROVIDERS = ("aws", "azure", "cisco", "cloudflare")
SCAN_LOCK = threading.Lock()


def _read_report():
    if not DEFAULT_REPORT_PATH.exists():
        return None
    try:
        report = json.loads(DEFAULT_REPORT_PATH.read_text(encoding="utf-8"))
        from examples.demo_portfolio import DATA_FILE
        if DATA_FILE.exists():
            from examples.demo_portfolio import load_or_create
            demos = load_or_create()
            live = [resource for resource in report.get("resources", []) if not resource.get("is_demo")]
            report["resources"] = live + demos
            report["summary"] = summarize_results(report["resources"])
            report["demo_portfolio_loaded"] = True
        else:
            report["demo_portfolio_loaded"] = False
        return report
    except (OSError, json.JSONDecodeError):
        return None


def _base_resources(report):
    return report.get("resources", []) if report else []


def _canonical_resource_id(provider, resource_id):
    """Restore the leading slash omitted by Flask's path URL builder for Azure IDs."""
    if provider == "azure":
        return "/" + str(resource_id).lstrip("/")
    return resource_id


def _findings(resources):
    recommendations = {}
    rows = []
    for resource in resources:
        for recommendation in resource.get("recommendations", []):
            recommendations[recommendation.get("rule")] = recommendation
        for finding in resource.get("findings", []):
            row = dict(finding)
            row["provider"] = resource.get("provider", "unknown")
            row["resource_id"] = resource.get("resource_id", "unknown")
            row["risk_score"] = resource.get("risk_score")
            row["recommendation"] = next(
                (rec for rec in resource.get("recommendations", [])
                 if rec.get("rule") == finding.get("rule")), None
            )
            row["resource_url"] = url_for(
                "resource_detail", provider=row["provider"], resource_id=row["resource_id"]
            )
            row["can_fix"] = bool((row.get("recommendation") or {}).get("supported") and g.current_user["role"] == "admin")
            rows.append(row)
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(rows, key=lambda item: (severity_order.get(item.get("severity"), 4), -(item.get("risk_score") or 0)))


def _provider_stats(resources):
    stats = []
    for provider in PROVIDERS:
        subset = [resource for resource in resources if resource.get("provider") == provider]
        scores = [r.get("risk_score") for r in subset if isinstance(r.get("risk_score"), (int, float))]
        counts = Counter((r.get("ml_assessment") or {}).get("risk_band", "LOW") for r in subset)
        stats.append({
            "name": provider,
            "count": len(subset),
            "findings": sum(len(r.get("findings", [])) for r in subset),
            "risk": round(sum(scores) / len(scores), 1) if scores else 0,
            "coverage": round(sum(r.get("risk_coverage", 0) for r in subset) / len(subset), 1) if subset else 0,
            "ml_band": counts.most_common(1)[0][0] if counts else "LOW",
        })
    maximum_findings = max((p["findings"] for p in stats), default=0)
    for stat in stats:
        stat["finding_percent"] = max(2, round(stat["findings"] / maximum_findings * 100)) if maximum_findings else 2
    return stats


def _status_counts(resources):
    secure = at_risk = unknown = 0
    remediation = Counter()
    for resource in resources:
        statuses = [b.get("status") for b in resource.get("benchmarks", [])]
        assessed = any(status in {"PASS", "FAIL"} for status in statuses)
        if not assessed:
            unknown += 1
        elif resource.get("findings") or "FAIL" in statuses:
            at_risk += 1
        else:
            secure += 1
        verification = (resource.get("verification") or {}).get("status")
        if verification == "VERIFIED":
            remediation["VERIFIED"] += 1
        elif verification in {"REMEDIATION_FAILED", "APPLIED_RESCAN_FAILED"}:
            remediation["FAILED"] += 1
        elif resource.get("remediation"):
            remediation["PENDING"] += 1
    total = len(resources) or 1
    return {
        "secure": secure, "at_risk": at_risk, "unknown": unknown,
        "secure_percent": round(secure / total * 100),
        "risk_percent_end": round((secure + at_risk) / total * 100),
        "remediation": remediation,
    }


def _resource_posture(resource):
    statuses = [item.get("status") for item in resource.get("benchmarks", [])]
    if resource.get("findings") or "FAIL" in statuses:
        return "AT RISK"
    if "PASS" in statuses:
        return "SECURE"
    return "UNKNOWN"


def _passkey_site():
    origin = os.environ.get("WEBAUTHN_ORIGIN") or f"{request.scheme}://{request.host}"
    rp_id = os.environ.get("WEBAUTHN_RP_ID") or urlsplit(origin).hostname
    if not rp_id:
        raise ValueError("Could not determine the passkey site name.")
    if urlsplit(origin).scheme != "https" and rp_id not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("Passkeys require HTTPS outside localhost. Configure WEBAUTHN_ORIGIN and WEBAUTHN_RP_ID for your HTTPS site.")
    return rp_id, origin


def _recommendations(resources):
    rows = []
    for resource in resources:
        recs = {item.get("rule"): item for item in resource.get("recommendations", [])}
        for finding in resource.get("findings", []):
            recommendation = recs.get(finding.get("rule"), {})
            rows.append({
                **recommendation,
                "provider": resource.get("provider"),
                "resource_id": resource.get("resource_id"),
                "finding_title": finding.get("title"),
                "rule": finding.get("rule"),
                "can_fix": bool(recommendation.get("supported") and g.current_user["role"] == "admin"),
                "resource_url": url_for("resource_detail", provider=resource.get("provider"), resource_id=resource.get("resource_id")),
            })
    return rows


def _report_history():
    reports = []
    if REPORT_HISTORY_DIR.exists():
        for path in sorted(REPORT_HISTORY_DIR.glob("scan-*.json"), reverse=True)[:100]:
            try:
                report = json.loads(path.read_text(encoding="utf-8"))
                summary = report.get("summary", {})
                reports.append({
                    "path": path,
                    "run_id": report.get("run_id", path.stem.removeprefix("scan-")),
                    "generated_at": report.get("generated_at"),
                    "resource_count": summary.get("resource_count", 0),
                    "finding_count": summary.get("finding_count", 0),
                    "average_risk": summary.get("average_risk", 0),
                })
            except (OSError, json.JSONDecodeError):
                continue
    return reports


def login_required(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        if not getattr(g, "current_user", None):
            if request.is_json:
                return jsonify(error="Your sign-in has expired. Sign in again, then retry the fix."), 401
            return redirect(url_for("login", next=request.path))
        return function(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(function):
        @wraps(function)
        @login_required
        def wrapped(*args, **kwargs):
            if g.current_user["role"] not in roles:
                abort(403)
            return function(*args, **kwargs)
        return wrapped
    return decorator


def _page_context(page, title):
    report = _read_report()
    resources = _base_resources(report)
    for resource in resources:
        resource["posture"] = _resource_posture(resource)
        resource["posture_class"] = {"AT RISK": "atrisk", "SECURE": "secure", "UNKNOWN": "unknown"}[resource["posture"]]
    summary = report.get("summary", {}) if report else {}
    summary.setdefault("resource_count", len(resources))
    summary.setdefault("finding_count", sum(len(r.get("findings", [])) for r in resources))
    summary.setdefault("average_risk", 0)
    summary.setdefault("high_risk_count", 0)
    summary.setdefault("provider_counts", {})
    summary.setdefault("findings_by_severity", {})
    summary.setdefault("benchmark_counts", {"PASS": 0, "FAIL": 0, "NOT_EVALUATED": 0})
    statuses = _status_counts(resources)
    return {
        "page": page,
        "page_title": title,
        "navigation": NAVIGATION,
        "report": report,
        "report_error": "The saved report could not be read. Run a new scan." if DEFAULT_REPORT_PATH.exists() and not report else None,
        "resources": resources,
        "summary": summary,
        "providers": _provider_stats(resources),
        "findings": _findings(resources),
        "recommendations": _recommendations(resources),
        "secure_count": statuses["secure"],
        "at_risk_count": statuses["at_risk"],
        "unknown_count": statuses["unknown"],
        "secure_percent": statuses["secure_percent"],
        "risk_percent_end": statuses["risk_percent_end"],
        "remediation_counts": statuses["remediation"],
        "benchmark_rows": [
            {
                "provider": r.get("provider"), "resource_id": r.get("resource_id"),
                "id": b.get("benchmark_id"), "name": b.get("name"),
                "status": b.get("status"), "check": b.get("check"),
                "refs": b.get("cis", []) + b.get("nist_csf", []) + b.get("nist_sp_800_53", []),
            }
            for r in resources for b in r.get("benchmarks", [])
        ],
        "benchmark_counts": summary.get("benchmark_counts", {"PASS": 0, "FAIL": 0, "NOT_EVALUATED": 0}),
        "model": model_metadata(),
        "reports": _report_history(),
        "users": list_users() if g.current_user["role"] == "admin" else [],
        "passkeys": list_passkeys(g.current_user["id"]) if page == "settings" and g.current_user["role"] == "admin" else [],
        "audit_events": recent_audit(100) if page in {"settings", "remediation"} else [],
        "scan_jobs": recent_scan_jobs(20) if page == "settings" else [],
        "bind_address": os.environ.get("MCS_HOST", "127.0.0.1"),
        "secure_cookie": os.environ.get("COOKIE_SECURE", "0").lower() in {"1", "true", "yes"},
        "connection_status": provider_connection_statuses(),
        "demo_portfolio_loaded": bool(report and report.get("demo_portfolio_loaded")),
        "companies": sorted({r.get("metadata", {}).get("company_name") for r in resources if r.get("metadata", {}).get("company_name")}),
    }


def _render(page, title, template=None, **extra):
    context = _page_context(page, title)
    context.update(extra)
    return render_template(template or f"{page}.html", **context)


def _scan_worker(app, job_id, username, providers):
    errors = {}
    collected = 0
    with app.app_context():
        try:
            update_scan_job(job_id, "running", "Starting provider scans")
            for provider in providers:
                update_scan_job(job_id, "running", f"Collecting {provider}")
                try:
                    records = collect(provider)
                    output = DEFAULT_DATA_DIR / OUTPUTS[provider]
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
                    collected += 1
                    errors[provider] = {"status": "collected", "count": len(records)}
                except Exception as error:
                    errors[provider] = {"status": "error", "message": str(error)}
            update_scan_job(job_id, "running", "Analyzing collected snapshots")
            report = run_analysis()
            failed = any(value["status"] == "error" for value in errors.values())
            result = {"providers": errors, "summary": report["summary"]}
            state = "completed_with_errors" if failed else "completed"
            update_scan_job(job_id, state, "Scan complete" if not failed else "Scan complete with provider errors", json.dumps(result))
            audit(username, "scan.completed", ",".join(providers), "partial" if failed else "success", f"resources={report['summary']['resource_count']}")
        except Exception as error:
            update_scan_job(job_id, "failed", "Scan failed", json.dumps({"error": str(error), "providers": errors}))
            audit(username, "scan.failed", ",".join(providers), "failed", str(error)[:500])
        finally:
            SCAN_LOCK.release()


def create_app():
    app = Flask(__name__, template_folder="templates", static_folder="static")
    host = os.environ.get("MCS_HOST", "127.0.0.1")
    secret = os.environ.get("FLASK_SECRET_KEY")
    if not secret and host not in {"127.0.0.1", "localhost", "::1"}:
        raise RuntimeError("Set FLASK_SECRET_KEY before binding beyond localhost.")
    if not secret:
        key_path = DEFAULT_DATA_DIR / "dashboard_secret.key"
        key_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with key_path.open("x", encoding="ascii") as key_file:
                key_file.write(secrets.token_urlsafe(48))
        except FileExistsError:
            pass
        secret = key_path.read_text(encoding="ascii").strip()
        if len(secret) < 32:
            raise RuntimeError(f"Local session key is missing or invalid: {key_path}")
    app.config.update(
        SECRET_KEY=secret,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0").lower() in {"1", "true", "yes"},
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        MAX_CONTENT_LENGTH=1024 * 1024,
        WTF_CSRF_TIME_LIMIT=60 * 60,
        PREFERRED_URL_SCHEME="https" if os.environ.get("COOKIE_SECURE") == "1" else "http",
    )
    if os.environ.get("TRUST_PROXY", "0") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    CSRFProtect(app)
    init_db()

    @app.errorhandler(CSRFError)
    def csrf_expired(error):
        if request.is_json:
            return jsonify(error="The page security token expired. Refresh this page, sign in again if asked, then retry the fix."), 400
        return render_template("error.html", code=400, message="The page security token expired. Refresh the page and try again."), 400

    @app.before_request
    def canonicalize_localhost_for_passkeys():
        bind_host = os.environ.get("MCS_HOST", "127.0.0.1")
        request_host = urlsplit(request.url).hostname
        if request.method in {"GET", "HEAD"} and bind_host in {"127.0.0.1", "localhost", "::1"} and request_host == "127.0.0.1":
            parts = urlsplit(request.url)
            return redirect(parts._replace(netloc=request.host.replace("127.0.0.1", "localhost", 1)).geturl(), code=302)

    @app.before_request
    def load_current_user():
        user_id = session.get("user_id")
        g.current_user = get_user(user_id) if user_id else None
        if user_id and not g.current_user:
            session.clear()

    @app.context_processor
    def inject_user():
        return {"current_user": getattr(g, "current_user", None)}

    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        response.headers["Cache-Control"] = "no-store"
        if app.config["SESSION_COOKIE_SECURE"]:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response

    @app.get("/")
    def home():
        return redirect(url_for("dashboard_page"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if g.current_user:
            return redirect(url_for("dashboard_page"))
        if request.method == "POST":
            username = request.form.get("username", "")
            password = request.form.get("password", "")
            user, error = authenticate(username, password)
            if user:
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                audit(user["username"], "auth.login", None, "success")
                target = request.args.get("next", "")
                if not target.startswith("/") or target.startswith("//"):
                    target = url_for("dashboard_page")
                return redirect(target)
            audit(username[:80] or None, "auth.login", None, "failed", error)
            flash(error or "Sign-in failed.", "error")
        return render_template("login.html", no_accounts=user_count() == 0)

    @app.post("/logout")
    @login_required
    def logout():
        audit(g.current_user["username"], "auth.logout")
        session.clear()
        return redirect(url_for("login"))

    @app.get("/dashboard")
    @login_required
    def dashboard_page():
        return _render("dashboard", "Dashboard")

    @app.get("/resources")
    @login_required
    def resources_page():
        return _render("resources", "Cloud Resources")

    @app.get("/resources/<provider>/<path:resource_id>")
    @login_required
    def resource_detail(provider, resource_id):
        resource_id = _canonical_resource_id(provider, resource_id)
        report = _read_report()
        resource = next((r for r in _base_resources(report)
                         if r.get("provider") == provider and r.get("resource_id") == resource_id), None)
        if not resource:
            abort(404)
        resource["posture"] = _resource_posture(resource)
        can_fix = g.current_user["role"] == "admin" and any(
            f.get("rule") in REMEDIATIONS and REMEDIATIONS[f.get("rule")].get("supported")
            for f in resource.get("findings", [])
        )
        return _render("resource_detail", "Resource Details", resource=resource, can_fix=can_fix,
                       can_configure=g.current_user["role"] == "admin",
                       supported_remediations={rule for rule, item in REMEDIATIONS.items() if item.get("supported")})

    @app.post("/demo/portfolio/load")
    @roles_required("admin")
    def load_demo_portfolio():
        from examples.demo_portfolio import load_or_create
        resources = load_or_create()
        audit(g.current_user["username"], "demo.portfolio_loaded", "fictional-enterprises", "success", f"resources={len(resources)}")
        flash(f"Evaluator demo portfolio loaded: {len(resources)} fictional cloud resources across four companies. Use Simulate demo fix to demonstrate remediation without cloud credentials.", "success")
        return redirect(url_for("resources_page"))

    @app.post("/demo/portfolio/remove")
    @roles_required("admin")
    def remove_demo_portfolio():
        from examples.demo_portfolio import disable
        disable()
        audit(g.current_user["username"], "demo.portfolio_removed", "fictional-enterprises", "success")
        flash("Fictional demo resources removed from the inventory.", "success")
        return redirect(url_for("resources_page"))

    @app.post("/demo/portfolio/reset")
    @roles_required("admin")
    def reset_demo_portfolio():
        from examples.demo_portfolio import reset_portfolio
        resources = reset_portfolio()
        findings = sum(len(resource.get("findings", [])) for resource in resources)
        audit(g.current_user["username"], "demo.portfolio_reset", "fictional-enterprises", "success", f"resources={len(resources)}; findings={findings}")
        flash(f"Demo portfolio reset: {len(resources)} fictional resources with {findings} seeded findings. Auto and manual demo fixes are available.", "success")
        return redirect(url_for("resources_page"))

    @app.post("/demo/configuration/<provider>")
    @roles_required("admin")
    def simulate_demo_configuration(provider):
        payload = request.get_json(silent=True) or {}
        resource_id = str(payload.get("resource_id") or "")
        changes = payload.get("changes")
        if payload.get("confirm") is not True or not resource_id:
            return jsonify(error="Confirm the demo configuration and select a resource."), 400
        report = _read_report()
        resource = next((item for item in _base_resources(report)
                         if item.get("provider") == provider and item.get("resource_id") == resource_id and item.get("is_demo")), None)
        if not resource:
            return jsonify(error="Fictional demo resource was not found."), 404
        try:
            from examples.demo_portfolio import simulate_manual_configuration
            updated = simulate_manual_configuration(provider, resource_id, changes)
            still_flagged = bool(updated.get("findings"))
            if still_flagged:
                audit(g.current_user["username"], "configuration.completed", resource_id, "saved_finding_remains", "manual_demo_edit; policy still violated; no_provider_api_called")
                message = "Settings saved locally, but the security finding remains because the saved configuration still violates the rule. Review the required values and rescan."
                status = "still_at_risk"
            else:
                audit(g.current_user["username"], "configuration.completed", resource_id, "simulated", "manual_demo_edit; configuration re-evaluated; no_provider_api_called")
                message = "Settings saved locally and the latest configuration checks pass. No cloud service was contacted."
                status = "simulated"
            return jsonify(status=status, message=message, findings=updated.get("findings", []), report_url=url_for("resource_detail", provider=provider, resource_id=resource_id))
        except ValueError as error:
            return jsonify(error=str(error)), 400
        except Exception as error:
            audit(g.current_user["username"], "configuration.failed", resource_id, "simulation_failed", str(error)[:500])
            return jsonify(error="Could not save the demo configuration."), 409

    @app.post("/demo/remediation/<provider>")
    @roles_required("admin")
    def simulate_demo_remediation(provider):
        payload = request.get_json(silent=True) or {}
        rule = payload.get("rule")
        resource_id = str(payload.get("resource_id") or "")
        if not resource_id:
            return jsonify(error="Choose a demo resource before simulating a fix."), 400
        if payload.get("confirm") is not True:
            return jsonify(error="Confirm the demo simulation before continuing."), 400
        report = _read_report()
        resource = next((item for item in _base_resources(report)
                         if item.get("provider") == provider and item.get("resource_id") == resource_id and item.get("is_demo")), None)
        if not resource or rule not in REMEDIATIONS or not REMEDIATIONS[rule].get("supported"):
            return jsonify(error="No supported fictional demo fix is available for this resource."), 409
        if not any(finding.get("rule") == rule for finding in resource.get("findings", [])):
            return jsonify(error="This demo finding is already fixed or is no longer present."), 409
        try:
            from examples.demo_portfolio import simulate_remediation
            simulate_remediation(provider, resource_id, rule)
            audit(g.current_user["username"], "remediation.completed", resource_id, "simulated", f"demo_rule={rule}; no_provider_api_called")
            return jsonify(status="simulated", message="Demo fix simulated locally. No cloud service was contacted.", report_url=url_for("resource_detail", provider=provider, resource_id=resource_id))
        except Exception as error:
            audit(g.current_user["username"], "remediation.failed", resource_id, "simulation_failed", str(error)[:500])
            return jsonify(error=str(error)), 409

    @app.get("/findings")
    @login_required
    def findings_page():
        return _render("findings", "Security Findings")

    @app.get("/risk")
    @login_required
    def risk_page():
        return _render("risk", "Risk Analysis")

    @app.get("/remediation")
    @login_required
    def remediation_page():
        return _render("remediation", "Remediation")

    @app.post("/api/assistant")
    @login_required
    def cloud_assistant_api():
        payload = request.get_json(silent=True) or {}
        question = str(payload.get("message", "")).strip()
        if not question:
            return jsonify(error="Type a cloud security question first."), 400
        if len(question) > 1500:
            return jsonify(error="Please keep questions under 1,500 characters."), 413
        selected = None
        provider = str(payload.get("provider", ""))[:30]
        resource_id = str(payload.get("resource_id", ""))[:500]
        if provider and resource_id:
            report = _read_report()
            selected = next((item for item in _base_resources(report)
                             if item.get("provider") == provider and item.get("resource_id") == resource_id), None)
        return jsonify(answer=answer_cloud_question(question, selected))

    @app.get("/compliance")
    @login_required
    def compliance_page():
        return _render("compliance", "Compliance")

    @app.get("/ml")
    @login_required
    def ml_page():
        return _render("ml", "Machine Learning")

    @app.post("/ml/train")
    @roles_required("admin")
    def train_ml():
        train_model()
        audit(g.current_user["username"], "ml.model_trained", "risk-triage", "success", "synthetic-baseline")
        flash("The baseline risk triage model has been trained and saved.", "success")
        return redirect(url_for("ml_page"))

    @app.get("/reports")
    @login_required
    def reports_page():
        return _render("reports", "Reports")

    @app.get("/reports/latest.json")
    @login_required
    def reports_download():
        report = _read_report()
        if not report:
            abort(404)
        body = io.BytesIO(json.dumps(report, indent=2, ensure_ascii=False).encode("utf-8"))
        return send_file(body, as_attachment=True, download_name="multicloudsecurity-report.json", mimetype="application/json")

    def find_report(run_id):
        if run_id == "latest":
            return _read_report()
        path = next((item["path"] for item in _report_history() if item["run_id"] == run_id), None)
        if not path:
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def report_as_text(report):
        summary = report.get("summary", {})
        lines = [
            "MULTICLOUDSECURITY SCAN REPORT",
            f"Generated: {report.get('generated_at', 'Unknown')}",
            f"Run ID: {report.get('run_id', 'Unknown')}",
            "",
            "SUMMARY",
            f"Resources: {summary.get('resource_count', 0)}",
            f"Findings: {summary.get('finding_count', 0)}",
            f"Average risk: {summary.get('average_risk', 0)} / 100",
            f"Risk evidence coverage: {summary.get('average_risk_coverage', 0)}%",
            "",
            "RESOURCES AND FINDINGS",
        ]
        for resource in report.get("resources", []):
            lines.extend([
                "",
                f"{resource.get('provider', 'Unknown').upper()} — {resource.get('resource_id', 'Unknown')}",
                f"Type: {resource.get('resource_type', 'Unknown')} | Risk: {resource.get('risk_score', 'Not scored')} | Evidence coverage: {resource.get('risk_coverage', 0)}%",
            ])
            findings = resource.get("findings", [])
            if findings:
                for finding in findings:
                    lines.append(f"  [{finding.get('severity', 'UNKNOWN')}] {finding.get('rule', '')}: {finding.get('title', 'Finding')}")
                    if finding.get("description"):
                        lines.append(f"    {finding['description']}")
            else:
                lines.append("  No active findings in this scan.")
            for benchmark in resource.get("benchmarks", []):
                lines.append(f"  Control {benchmark.get('benchmark_id', '')}: {benchmark.get('status', 'NOT_EVALUATED')} — {benchmark.get('name', '')}")
        lines.extend(["", "This report reflects the evidence collected at scan time. NOT_EVALUATED means there was insufficient evidence."])
        return "\n".join(lines) + "\n"

    @app.get("/reports/latest")
    @login_required
    def latest_report_view():
        report = find_report("latest")
        if not report:
            abort(404)
        return render_template("report_view.html", report=report, page_title="Readable Scan Report", is_latest=True)

    @app.get("/reports/<run_id>/view")
    @login_required
    def report_view_by_id(run_id):
        report = find_report(run_id)
        if not report:
            abort(404)
        return render_template("report_view.html", report=report, page_title="Readable Scan Report", is_latest=False)

    @app.get("/reports/latest.txt")
    @login_required
    def latest_report_text():
        report = find_report("latest")
        if not report:
            abort(404)
        body = io.BytesIO(report_as_text(report).encode("utf-8"))
        return send_file(body, as_attachment=True, download_name="multicloudsecurity-report.txt", mimetype="text/plain; charset=utf-8")

    @app.get("/reports/<run_id>.txt")
    @login_required
    def report_text_by_id(run_id):
        report = find_report(run_id)
        if not report:
            abort(404)
        body = io.BytesIO(report_as_text(report).encode("utf-8"))
        return send_file(body, as_attachment=True, download_name=f"multicloudsecurity-{run_id}.txt", mimetype="text/plain; charset=utf-8")

    @app.get("/reports/<run_id>.json")
    @login_required
    def report_download_by_id(run_id):
        path = next((item["path"] for item in _report_history() if item["run_id"] == run_id), None)
        if not path:
            abort(404)
        return send_file(path, as_attachment=True, download_name=f"multicloudsecurity-{run_id}.json", mimetype="application/json")

    @app.post("/security/passkeys/register/options")
    @roles_required("admin")
    def passkey_registration_options():
        payload = request.get_json(silent=True) or {}
        if not verify_user_password(g.current_user["id"], payload.get("password", "")):
            return jsonify(error="Password confirmation failed. Enter your current MultiCloudSecurity admin password to enroll Windows Hello."), 401
        name = (payload.get("name") or "Windows Hello").strip()[:60] or "Windows Hello"
        try:
            rp_id, origin = _passkey_site()
            credentials = passkey_credentials(g.current_user["id"])
            options = generate_registration_options(
                rp_id=rp_id,
                rp_name="MultiCloudSecurity",
                user_id=str(g.current_user["id"]).encode("utf-8"),
                user_name=g.current_user["username"],
                user_display_name=g.current_user["username"],
                authenticator_selection=AuthenticatorSelectionCriteria(
                    authenticator_attachment=AuthenticatorAttachment.PLATFORM,
                    resident_key=ResidentKeyRequirement.PREFERRED,
                    user_verification=UserVerificationRequirement.REQUIRED,
                ),
                exclude_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(item["credential_id"])) for item in credentials],
            )
        except Exception as error:
            return jsonify(error=str(error)), 400
        session["passkey_register_challenge"] = bytes_to_base64url(options.challenge)
        session["passkey_register_expires"] = int(time.time()) + 300
        session["passkey_register_origin"] = origin
        session["passkey_register_rp_id"] = rp_id
        session["passkey_register_name"] = name
        return jsonify(options=json.loads(options_to_json(options)))

    @app.post("/security/passkeys/register/verify")
    @roles_required("admin")
    def passkey_registration_verify():
        challenge = session.pop("passkey_register_challenge", None)
        expires = session.pop("passkey_register_expires", 0)
        origin = session.pop("passkey_register_origin", None)
        rp_id = session.pop("passkey_register_rp_id", None)
        name = session.pop("passkey_register_name", "Windows Hello")
        if not challenge or int(expires or 0) < time.time():
            return jsonify(error="Passkey setup timed out. Start setup again."), 400
        credential = (request.get_json(silent=True) or {}).get("credential")
        if not isinstance(credential, dict):
            return jsonify(error="Passkey setup response was missing."), 400
        try:
            verification = verify_registration_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=rp_id,
                expected_origin=origin,
                require_user_verification=True,
            )
            credential_id = bytes_to_base64url(verification.credential_id)
            save_passkey(
                g.current_user["id"], credential_id,
                verification.credential_public_key, verification.sign_count,
                json.dumps(credential.get("response", {}).get("transports", [])), name,
            )
        except Exception as error:
            audit(g.current_user["username"], "passkey.enrollment", None, "failed", type(error).__name__)
            return jsonify(error="Windows Hello setup could not be verified. Try again from this same browser address."), 400
        audit(g.current_user["username"], "passkey.enrollment", name, "success")
        return jsonify(status="registered", name=name)

    @app.get("/settings")
    @roles_required("admin")
    def settings_page():
        return _render("settings", "Settings")

    connection_forms = [
        ("aws", "Amazon Web Services", [("access_key_id", "Access key ID", "AKIA…"), ("secret_access_key", "Secret access key", "Secret key"), ("session_token", "Session token (optional)", "Temporary session token"), ("region", "Default region (optional)", "us-east-1")], "https://console.aws.amazon.com/s3/home"),
        ("azure", "Microsoft Azure", [("subscription_id", "Subscription ID", "Subscription ID"), ("tenant_id", "Tenant ID", "Directory tenant ID"), ("client_id", "Client ID", "Application client ID"), ("client_secret", "Client secret", "Application secret")], "https://portal.azure.com/#view/HubsExtension/BrowseResource/resourceType/Microsoft.Storage%2FStorageAccounts"),
        ("cisco", "Cisco Meraki", [("api_key", "Dashboard API key", "API key")], "https://dashboard.meraki.com/"),
        ("cloudflare", "Cloudflare", [("api_token", "API token", "Scoped API token")], "https://dash.cloudflare.com/"),
    ]

    @app.get("/connections")
    @roles_required("admin")
    def connections_page():
        return _render("connections", "Service Connections", connection_forms=connection_forms)

    def _save_connection(provider):
        if provider not in PROVIDERS:
            abort(404)
        allowed = {key for item_provider, _, fields, _portal in connection_forms if item_provider == provider for key, _, _ in fields}
        save_provider_credentials(provider, {key: request.form.get(key, "") for key in allowed})
        audit(g.current_user["username"], "provider.credentials_saved", provider, "success")

    @app.post("/connections/<provider>/save")
    @roles_required("admin")
    def save_connection(provider):
        _save_connection(provider)
        flash(f"{provider.title()} connection details saved encrypted on this computer.", "success")
        return redirect(url_for("connections_page"))

    @app.post("/connections/<provider>/test")
    @roles_required("admin")
    def test_connection(provider):
        _save_connection(provider)
        try:
            records = collect(provider)
            flash(f"{provider.title()} connection works. Read access confirmed for {len(records)} resource(s).", "success")
        except Exception as error:
            audit(g.current_user["username"], "provider.connection_test", provider, "failed", type(error).__name__)
            flash(f"Could not connect to {provider.title()}: {str(error)[:250]}", "error")
        return redirect(url_for("connections_page"))

    @app.post("/settings/users")
    @roles_required("admin")
    def settings_create_user():
        try:
            create_user(
                request.form.get("username", ""),
                request.form.get("password", ""),
                request.form.get("role", "viewer"),
            )
            audit(g.current_user["username"], "account.provisioned", request.form.get("username", "")[:80], "success")
            flash("Account created.", "success")
        except ValueError as error:
            flash(str(error), "error")
        return redirect(url_for("settings_page"))

    @app.post("/api/scan")
    @roles_required("admin", "operator")
    def api_start_scan():
        payload = request.get_json(silent=True) or {}
        providers = list(dict.fromkeys(payload.get("providers", [])))
        if not providers or any(provider not in PROVIDERS for provider in providers):
            return jsonify(error="Select one or more supported providers."), 400
        if not SCAN_LOCK.acquire(blocking=False):
            return jsonify(error="A scan is already running."), 409
        job_id = uuid.uuid4().hex
        try:
            create_scan_job(job_id, g.current_user["username"], providers)
            thread = threading.Thread(
                target=_scan_worker,
                args=(app, job_id, g.current_user["username"], providers),
                daemon=True,
            )
            thread.start()
        except Exception:
            SCAN_LOCK.release()
            raise
        audit(g.current_user["username"], "scan.requested", ",".join(providers), "success")
        return jsonify(job_id=job_id, status="queued"), 202

    @app.get("/api/scan/<job_id>")
    @roles_required("admin", "operator", "viewer")
    def api_scan_status(job_id):
        job = get_scan_job(job_id)
        if not job:
            return jsonify(error="Scan job not found."), 404
        if job["requested_by"] != g.current_user["username"] and g.current_user["role"] != "admin":
            abort(403)
        result = json.loads(job["result"]) if job.get("result") else None
        return jsonify(status=job["status"], message=job["message"], result=result)

    @app.post("/remediation/passkey/options/<provider>/<path:resource_id>")
    @roles_required("admin")
    def remediation_passkey_options(provider, resource_id):
        resource_id = _canonical_resource_id(provider, resource_id)
        requested_rule = (request.get_json(silent=True) or {}).get("rule")
        report = _read_report()
        resource = next((r for r in _base_resources(report)
                         if r.get("provider") == provider and r.get("resource_id") == resource_id), None)
        active = [f for f in (resource or {}).get("findings", []) if f.get("rule") == requested_rule and f.get("rule") in REMEDIATIONS and REMEDIATIONS[f.get("rule")].get("supported")]
        if not resource or not active:
            return jsonify(error="No current supported fix is available for this resource."), 409
        # Check provider write credentials before prompting for Windows Hello. A
        # browser login to the provider does not grant this server API access.
        if not resource.get("is_demo") and provider in {"azure", "cisco", "cloudflare"} and not provider_connection_statuses().get(provider):
            label = {"azure": "Azure", "cisco": "Meraki", "cloudflare": "Cloudflare"}[provider]
            return jsonify(
                error=f"{label} API credentials are not connected. Add and test a provider API credential in Service Connections, then retry. A website password cannot authorize this change.",
                connect_url=url_for("connections_page"),
            ), 409
        credentials = passkey_credentials(g.current_user["id"])
        if not credentials:
            return jsonify(error="Enroll Windows Hello in Settings before approving fixes."), 409
        try:
            rp_id, origin = _passkey_site()
            options = generate_authentication_options(
                rp_id=rp_id,
                allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(item["credential_id"])) for item in credentials],
                user_verification=UserVerificationRequirement.REQUIRED,
            )
        except Exception as error:
            return jsonify(error=str(error)), 400
        session["passkey_fix_challenge"] = bytes_to_base64url(options.challenge)
        session["passkey_fix_expires"] = int(time.time()) + 300
        session["passkey_fix_origin"] = origin
        session["passkey_fix_rp_id"] = rp_id
        session["passkey_fix_provider"] = provider
        session["passkey_fix_resource"] = resource_id
        session["passkey_fix_rule"] = active[0].get("rule")
        return jsonify(options=json.loads(options_to_json(options)))

    @app.post("/remediation/apply/<provider>/<path:resource_id>")
    @roles_required("admin")
    def apply_provider_remediation(provider, resource_id):
        resource_id = _canonical_resource_id(provider, resource_id)
        if provider not in PROVIDERS:
            abort(404)
        rule = session.get("passkey_fix_rule")
        payload = request.get_json(silent=True) or {}
        if payload.get("confirm") is not True:
            audit(g.current_user["username"], "remediation.requested", resource_id, "rejected", "explicit_confirmation_missing")
            return jsonify(error="Explicit change confirmation is required."), 400
        challenge = session.pop("passkey_fix_challenge", None)
        expires = session.pop("passkey_fix_expires", 0)
        origin = session.pop("passkey_fix_origin", None)
        rp_id = session.pop("passkey_fix_rp_id", None)
        authorized_provider = session.pop("passkey_fix_provider", None)
        authorized_resource = session.pop("passkey_fix_resource", None)
        authorized_rule = session.pop("passkey_fix_rule", None)
        credential = payload.get("credential")
        if not challenge or int(expires or 0) < time.time() or authorized_provider != provider or authorized_resource != resource_id or authorized_rule != rule:
            audit(g.current_user["username"], "remediation.requested", resource_id, "rejected", "passkey_challenge_missing_or_expired")
            return jsonify(error="Windows Hello confirmation expired. Start the fix again."), 401
        if not isinstance(credential, dict) or not credential.get("id"):
            return jsonify(error="Windows Hello confirmation was not received."), 400
        passkey = get_passkey(g.current_user["id"], credential["id"])
        if not passkey:
            audit(g.current_user["username"], "remediation.requested", resource_id, "rejected", "unknown_passkey")
            return jsonify(error="This Windows Hello credential is not registered to your administrator account."), 401
        try:
            verification = verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=rp_id,
                expected_origin=origin,
                credential_public_key=passkey["public_key"],
                credential_current_sign_count=passkey["sign_count"],
                require_user_verification=True,
            )
            update_passkey_usage(passkey["credential_id"], verification.new_sign_count)
        except Exception as error:
            audit(g.current_user["username"], "remediation.requested", resource_id, "rejected", f"passkey_verification_failed:{type(error).__name__}")
            return jsonify(error="Windows Hello confirmation failed. Try again and complete the device verification prompt."), 401

        report = _read_report()
        resource = next((r for r in _base_resources(report)
                         if r.get("provider") == provider and r.get("resource_id") == resource_id), None)
        active = [f for f in (resource or {}).get("findings", []) if f.get("rule") == authorized_rule]
        if not resource or not active:
            return jsonify(error="The current report does not contain this active finding."), 409
        recommendation = next((r for r in resource.get("recommendations", []) if r.get("rule") == authorized_rule and r.get("supported")), None)
        if not recommendation or recommendation.get("remediation_type") != REMEDIATIONS.get(authorized_rule, {}).get("remediation_type"):
            return jsonify(error="No reviewed remediation is available for this finding."), 409

        username = g.current_user["username"]
        audit(username, "remediation.requested", resource_id, "approved", "passkey_verified; explicit_confirmation")
        if resource.get("is_demo"):
            try:
                from examples.demo_portfolio import simulate_remediation
                simulate_remediation(provider, resource_id, authorized_rule)
                audit(username, "remediation.completed", resource_id, "simulated", f"demo_rule={authorized_rule}; no_provider_api_called")
                return jsonify(status="simulated", message="Demo fix simulated locally. No cloud service was contacted.", report_url=url_for("resource_detail", provider=provider, resource_id=resource_id)), 200
            except Exception as error:
                audit(username, "remediation.failed", resource_id, "simulation_failed", str(error)[:500])
                return jsonify(error=str(error), action_applied=False), 409
        applied = False
        try:
            if provider == "aws" and authorized_rule == "AWS-S3-001":
                from connectors.provider_credentials import get as provider_credentials
                action_result = enable_s3_block_public_access(resource_id, region_name=resource.get("metadata", {}).get("region"), credentials=provider_credentials("aws"))
            elif provider == "azure" and authorized_rule == "AZURE-STORAGE-001":
                from remediation.azure_remediation import secure_storage_account
                from connectors.provider_credentials import get as provider_credentials
                action_result = secure_storage_account(resource_id, provider_credentials("azure"))
            elif provider == "cisco" and authorized_rule == "CISCO-FW-001":
                from remediation.cisco_remediation import deny_any_any_rules
                from connectors.provider_credentials import get as provider_credentials
                action_result = deny_any_any_rules(resource_id, provider_credentials("cisco"))
            elif provider == "cloudflare" and authorized_rule == "CLOUDFLARE-WEB-001":
                from remediation.cloudflare_remediation import deploy_managed_waf
                from connectors.provider_credentials import get as provider_credentials
                action_result = deploy_managed_waf(resource, provider_credentials("cloudflare"))
            else:
                return jsonify(error="No reviewed remediation is available for this finding."), 409
            applied = action_result.get("status") == "APPLIED"
            if not applied:
                raise RuntimeError("The provider did not confirm that the configuration update was applied.")
            refreshed = collect(provider)
            snapshot = DEFAULT_DATA_DIR / OUTPUTS[provider]
            snapshot.write_text(json.dumps(refreshed, indent=2, ensure_ascii=False), encoding="utf-8")
            updated_report = run_analysis()
            rescanned = next((r for r in updated_report["resources"]
                              if r.get("provider") == provider and r.get("resource_id") == resource_id), None)
            if rescanned is None:
                raise RuntimeError("The bucket was not returned by the AWS rescan; verification is incomplete.")
            verification = verify_remediation(rescanned, active)
            rescanned["remediation"] = action_result
            rescanned["verification"] = verification
            attach_benchmarks(rescanned)
            DEFAULT_REPORT_PATH.write_text(json.dumps(updated_report, indent=2, ensure_ascii=False), encoding="utf-8")
            outcome = "verified" if verification.get("remediation_verified") else "applied_unverified"
            audit(username, "remediation.completed", resource_id, outcome, verification.get("status", "NOT_EVALUATED"))
            return jsonify(status=outcome, verification=verification, report_url=url_for("resource_detail", provider=provider, resource_id=resource_id)), (200 if outcome == "verified" else 202)
        except Exception as error:
            state = "applied_rescan_failed" if applied else "failed"
            audit(username, "remediation.failed", resource_id, state, str(error)[:500])
            error_text = str(error)
            if provider == "aws" and (type(error).__name__ == "LoginRefreshRequired" or "reauthenticate using 'aws login'" in error_text.lower() or "session has expired" in error_text.lower()):
                error_text = "Windows Hello was accepted, but the AWS CLI credentials have expired. In PowerShell, run `aws login`, then retry. The bucket was not changed."
            return jsonify(error=error_text, action_applied=applied), (202 if applied else 502)

    @app.post("/configuration/passkey/options/<provider>/<path:resource_id>")
    @roles_required("admin")
    def manual_configuration_options(provider, resource_id):
        resource_id = _canonical_resource_id(provider, resource_id)
        payload = request.get_json(silent=True) or {}
        changes = payload.get("changes")
        report = _read_report()
        resource = next((r for r in _base_resources(report) if r.get("provider") == provider and r.get("resource_id") == resource_id), None)
        if not resource:
            return jsonify(error="Resource not found in the latest scan. Rescan before editing."), 404
        if resource.get("is_demo"):
            return jsonify(error="Demo resources are fictional and read-only."), 409
        if provider in {"azure", "cisco", "cloudflare"} and not provider_connection_statuses().get(provider):
            label = {"azure": "Azure", "cisco": "Meraki", "cloudflare": "Cloudflare"}[provider]
            return jsonify(
                error=f"{label} API credentials are not connected. Add and test a provider API credential in Service Connections, then retry. A website password cannot authorize this change.",
                connect_url=url_for("connections_page"),
            ), 409
        try:
            validate_changes(provider, changes)
        except ValueError as error:
            return jsonify(error=str(error)), 400
        if provider == "cisco" and json.dumps(changes.get("expected_rules"), sort_keys=True) != json.dumps(resource.get("metadata", {}).get("firewall_rules", []), sort_keys=True):
            return jsonify(error="Firewall rules differ from the latest scan. Rescan and reopen the editor."), 409
        if provider == "cloudflare":
            active_zone_ids = {z.get("zone_id") for z in resource.get("metadata", {}).get("zones", []) if z.get("status") == "active"}
            if set(changes.get("zones", {})) != active_zone_ids:
                return jsonify(error="Choose settings for the current active zones only. Rescan and reopen the editor."), 409
        credentials = passkey_credentials(g.current_user["id"])
        if not credentials:
            return jsonify(error="Enroll Windows Hello in Settings before approving configuration changes."), 409
        try:
            rp_id, origin = _passkey_site()
            options = generate_authentication_options(
                rp_id=rp_id,
                allow_credentials=[PublicKeyCredentialDescriptor(id=base64url_to_bytes(item["credential_id"])) for item in credentials],
                user_verification=UserVerificationRequirement.REQUIRED,
            )
        except Exception as error:
            return jsonify(error=str(error)), 400
        digest = hashlib.sha256(json.dumps(changes, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        session["manual_change_challenge"] = bytes_to_base64url(options.challenge)
        session["manual_change_expires"] = int(time.time()) + 300
        session["manual_change_origin"] = origin
        session["manual_change_rp_id"] = rp_id
        session["manual_change_provider"] = provider
        session["manual_change_resource"] = resource_id
        session["manual_change_digest"] = digest
        return jsonify(options=json.loads(options_to_json(options)))

    @app.post("/configuration/apply/<provider>/<path:resource_id>")
    @roles_required("admin")
    def manual_configuration_apply(provider, resource_id):
        resource_id = _canonical_resource_id(provider, resource_id)
        payload = request.get_json(silent=True) or {}
        changes = payload.get("changes")
        if payload.get("confirm") is not True:
            return jsonify(error="Confirm the configuration change before continuing."), 400
        challenge = session.pop("manual_change_challenge", None)
        expires = session.pop("manual_change_expires", 0)
        origin = session.pop("manual_change_origin", None)
        rp_id = session.pop("manual_change_rp_id", None)
        expected_provider = session.pop("manual_change_provider", None)
        expected_resource = session.pop("manual_change_resource", None)
        expected_digest = session.pop("manual_change_digest", None)
        digest = hashlib.sha256(json.dumps(changes, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
        if not challenge or int(expires or 0) < time.time() or provider != expected_provider or resource_id != expected_resource or digest != expected_digest:
            return jsonify(error="The approved configuration changed or timed out. Review it and approve again."), 401
        credential = payload.get("credential")
        if not isinstance(credential, dict) or not credential.get("id"):
            return jsonify(error="Windows Hello approval was not received."), 400
        passkey = get_passkey(g.current_user["id"], credential["id"])
        if not passkey:
            return jsonify(error="This Windows Hello key is not registered to your administrator account."), 401
        try:
            verification = verify_authentication_response(
                credential=credential, expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=rp_id, expected_origin=origin,
                credential_public_key=passkey["public_key"],
                credential_current_sign_count=passkey["sign_count"],
                require_user_verification=True,
            )
            update_passkey_usage(passkey["credential_id"], verification.new_sign_count)
        except Exception:
            return jsonify(error="Windows Hello approval could not be verified. Try again."), 401
        report = _read_report()
        resource = next((r for r in _base_resources(report) if r.get("provider") == provider and r.get("resource_id") == resource_id), None)
        if not resource:
            return jsonify(error="Resource is no longer in the latest scan."), 409
        if resource.get("is_demo"):
            return jsonify(error="Demo resources are fictional and read-only."), 409
        username = g.current_user["username"]
        audit(username, "configuration.change_requested", resource_id, "approved", provider)
        applied = False
        try:
            from connectors.provider_credentials import get as provider_credentials
            action = apply_manual_changes(provider, resource, changes, provider_credentials(provider))
            applied = action.get("status") == "APPLIED"
            snapshot = DEFAULT_DATA_DIR / OUTPUTS[provider]
            snapshot.write_text(json.dumps(collect(provider), indent=2, ensure_ascii=False), encoding="utf-8")
            updated_report = run_analysis()
            updated_resource = next((r for r in updated_report["resources"] if r.get("provider") == provider and r.get("resource_id") == resource_id), None)
            if not updated_resource:
                raise RuntimeError("The provider rescan did not return this resource.")
            verification = verify_remediation(updated_resource, resource.get("findings", []))
            updated_resource["manual_configuration"] = action
            updated_resource["verification"] = verification
            attach_benchmarks(updated_resource)
            DEFAULT_REPORT_PATH.write_text(json.dumps(updated_report, indent=2, ensure_ascii=False), encoding="utf-8")
            audit(username, "configuration.change_completed", resource_id, "success", verification.get("status", "NOT_EVALUATED"))
            return jsonify(status="verified" if verification.get("remediation_verified") else "applied", verification=verification), 200
        except Exception as error:
            audit(username, "configuration.change_failed", resource_id, "applied_rescan_failed" if applied else "failed", str(error)[:500])
            return jsonify(error=str(error)[:400], action_applied=applied), 202 if applied else 502

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="Your account does not have permission to open this page or perform this action."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="The requested resource or report was not found."), 404

    return app


app = create_app()


def main():
    host = os.environ.get("MCS_HOST", "127.0.0.1")
    port = int(os.environ.get("MCS_PORT", "8000"))
    from waitress import serve
    display_host = "localhost" if host == "127.0.0.1" else host
    print(f"MultiCloudSecurity dashboard: http://{display_host}:{port}")
    print("Create the first admin with: python -m dashboard.admin create-admin")
    serve(app, host=host, port=port, threads=8)


if __name__ == "__main__":
    main()
