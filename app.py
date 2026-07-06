"""
Flask dashboard for browsing DemoCorp synthetic logs.

This module defines routes and API endpoints only.
Start the server with: python run.py
"""

import csv
import io
import json
import os

from flask import Flask, Response, jsonify, render_template, request

# Project paths
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_DIR = os.path.join(PROJECT_ROOT, "dashboard")
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
SIGNINS_JSON = os.path.join(DATA_DIR, "signins.json")
AUDIT_JSON = os.path.join(DATA_DIR, "auditlogs.json")

app = Flask(
    __name__,
    template_folder=os.path.join(DASHBOARD_DIR, "templates"),
    static_folder=os.path.join(DASHBOARD_DIR, "static"),
)


def _load_json(path: str) -> list[dict]:
    """Load a JSON log file; return empty list if missing."""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _filter_logs(logs: list[dict], filters: dict) -> list[dict]:
    """
    Apply case-insensitive substring filters to log records.
    Only non-empty filter values are applied.
    """
    result = logs
    for key, value in filters.items():
        if not value:
            continue
        needle = value.lower()
        result = [
            row for row in result
            if needle in str(row.get(key, "")).lower()
        ]
    return result


@app.route("/")
def index():
    """Serve the main dashboard page."""
    return render_template("index.html")


@app.route("/api/signins")
def api_signins():
    """Return filtered sign-in logs as JSON."""
    logs = _load_json(SIGNINS_JSON)
    filters = {
        "UserPrincipalName": request.args.get("user", ""),
        "IPAddress": request.args.get("ip", ""),
        "Country": request.args.get("country", ""),
        "AuthenticationResult": request.args.get("result", ""),
        "RiskLevel": request.args.get("risk", ""),
    }
    filtered = _filter_logs(logs, filters)
    return jsonify({"count": len(filtered), "records": filtered})


@app.route("/api/audit")
def api_audit():
    """Return filtered audit logs as JSON."""
    logs = _load_json(AUDIT_JSON)
    filters = {
        "Actor": request.args.get("user", ""),
        "Activity": request.args.get("activity", ""),
        "TargetUser": request.args.get("target", ""),
        "Result": request.args.get("result", ""),
    }
    filtered = _filter_logs(logs, filters)
    return jsonify({"count": len(filtered), "records": filtered})


@app.route("/api/export/<log_type>")
def export_csv(log_type: str):
    """Export current filtered logs as a CSV download."""
    if log_type == "signins":
        logs = _load_json(SIGNINS_JSON)
        filters = {
            "UserPrincipalName": request.args.get("user", ""),
            "IPAddress": request.args.get("ip", ""),
            "Country": request.args.get("country", ""),
            "AuthenticationResult": request.args.get("result", ""),
            "RiskLevel": request.args.get("risk", ""),
        }
        fieldnames = [
            "Timestamp", "UserPrincipalName", "IPAddress", "Country",
            "Device", "AuthenticationResult", "RiskLevel", "ScenarioTag",
        ]
    elif log_type == "audit":
        logs = _load_json(AUDIT_JSON)
        filters = {
            "Actor": request.args.get("user", ""),
            "Activity": request.args.get("activity", ""),
            "TargetUser": request.args.get("target", ""),
            "Result": request.args.get("result", ""),
        }
        fieldnames = [
            "Timestamp", "Actor", "Activity", "TargetUser",
            "Result", "Details", "ScenarioTag",
        ]
    else:
        return jsonify({"error": "Invalid log type"}), 400

    filtered = _filter_logs(logs, filters)

    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(filtered)

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={log_type}_export.csv"},
    )
