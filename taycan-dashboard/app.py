#!/usr/bin/env python3
"""
Taycan Diagnostic Dashboard — Flask Backend

Serves the dashboard UI and provides API endpoints for scanning,
viewing scan history, and trend data.

Usage:
    python app.py
    python app.py --port 8080
    python app.py --no-browser
"""

import threading
import webbrowser
import click
from flask import Flask, render_template, jsonify, request

import config
import scanner
from doip import discover_gateway

app = Flask(__name__)

# Global state for scan progress
scan_state = {
    "running": False,
    "progress": 0,
    "total": 0,
    "message": "",
    "last_result": None,
}
scan_lock = threading.Lock()


# ─── Pages ────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


# ─── API Endpoints ────────────────────────────────────────────────────────

@app.route("/api/status")
def api_status():
    """Connection and vehicle status. Auto-discovers gateway."""
    gw = scanner.auto_discover()
    return jsonify({
        "gateway_reachable": gw is not None,
        "gateway_ip": config.GATEWAY_IP,
        "vin": config.VEHICLE_VIN,
        "model": config.VEHICLE_MODEL,
        "year": config.VEHICLE_YEAR,
        "platform": config.VEHICLE_PLATFORM,
        "battery_capacity_kwh": config.BATTERY_CAPACITY_KWH,
    })


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Trigger a new scan. Returns immediately; poll /api/scan/progress."""
    with scan_lock:
        if scan_state["running"]:
            return jsonify({"error": "Scan already in progress"}), 409

        scan_state["running"] = True
        scan_state["progress"] = 0
        scan_state["total"] = 0
        scan_state["message"] = "Starting..."

    def do_scan():
        def on_progress(current, total, message):
            scan_state["progress"] = current
            scan_state["total"] = total
            scan_state["message"] = message

        try:
            result = scanner.run_scan(progress_callback=on_progress)
            filepath = scanner.save_scan(result)
            scan_state["last_result"] = result
            scan_state["message"] = f"Complete — saved to {filepath}"
        except Exception as e:
            scan_state["last_result"] = {"error": str(e)}
            scan_state["message"] = f"Error: {e}"
        finally:
            scan_state["running"] = False

    thread = threading.Thread(target=do_scan, daemon=True)
    thread.start()

    return jsonify({"status": "started"})


@app.route("/api/scan/progress")
def api_scan_progress():
    """Poll scan progress."""
    return jsonify({
        "running": scan_state["running"],
        "progress": scan_state["progress"],
        "total": scan_state["total"],
        "message": scan_state["message"],
    })


@app.route("/api/scan/latest")
def api_scan_latest():
    """Get the most recent scan result."""
    if scan_state["last_result"]:
        return jsonify(scan_state["last_result"])

    scans = scanner.list_scans()
    if scans:
        data = scanner.load_scan(scans[0]["filename"])
        if data:
            return jsonify(data)

    return jsonify({"error": "No scans available"}), 404


@app.route("/api/scans")
def api_scans():
    """List all saved scans."""
    return jsonify(scanner.list_scans())


@app.route("/api/scans/<filename>")
def api_scan_detail(filename):
    """Load a specific scan."""
    data = scanner.load_scan(filename)
    if data:
        return jsonify(data)
    return jsonify({"error": "Scan not found"}), 404


@app.route("/api/trends")
def api_trends():
    """SoH/SoC trend data for charts."""
    return jsonify(scanner.get_trend_data())


@app.route("/api/ecus")
def api_ecus():
    """List registered ECUs."""
    return jsonify(config.load_ecu_registry())


# ─── Main ─────────────────────────────────────────────────────────────────

@click.command()
@click.option("--host", default="127.0.0.1", help="Bind address")
@click.option("--port", default=5000, help="Port", show_default=True)
@click.option("--no-browser", is_flag=True, help="Don't open browser")
@click.option("--debug", is_flag=True, help="Flask debug mode")
def main(host, port, no_browser, debug):
    """Taycan Diagnostic Dashboard"""
    print(f"\n  Taycan Dashboard — http://{host}:{port}\n")

    # Load latest scan into memory
    scans = scanner.list_scans()
    if scans:
        scan_state["last_result"] = scanner.load_scan(scans[0]["filename"])
        print(f"  Loaded latest scan: {scans[0]['filename']}")
    print(f"  {len(config.load_ecu_registry())} ECUs registered\n")

    if not no_browser and not debug:
        threading.Timer(1.0, lambda: webbrowser.open(
            f"http://{host}:{port}")).start()

    app.run(host=host, port=port, debug=debug)


if __name__ == "__main__":
    main()
