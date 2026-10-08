"""Email Security Analyzer - Flask backend.

Pages are server-rendered; the analyzer talks to a small JSON API. The ML model
(TF-IDF + Multinomial Naive Bayes) is the one trained by train_model.py.
"""
import os
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.exceptions import HTTPException

from services import heuristics
from services.email_parser import InvalidEmailFile, MAX_UPLOAD_BYTES, extract_email_text
from services.model_service import SpamModel
from services.report import build_report_pdf
from io import BytesIO

BASE_DIR = Path(__file__).resolve().parent
MAX_EMAIL_CHARS = 50_000

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + 64 * 1024  # upload limit + form overhead
spam_model = SpamModel(BASE_DIR / "model")

VERDICTS = {
    "high": ("SPAM DETECTED", "This email shows strong signs of spam or phishing."),
    "suspicious": ("SUSPICIOUS EMAIL", "The model is unsure. Review this email carefully."),
    "safe": ("EMAIL APPEARS SAFE", "This email looks like a legitimate message."),
}


class InputError(ValueError):
    """Bad request payload; message is shown to the user."""


def clean_email_text(value) -> str:
    if not isinstance(value, str) or not value.strip():
        raise InputError("No email content provided.")
    text = value.strip()
    if len(text) > MAX_EMAIL_CHARS:
        raise InputError(f"Email is too long (limit {MAX_EMAIL_CHARS:,} characters).")
    return text


def run_analysis(text: str) -> dict:
    """ML prediction (real model) + rule-based analysis, kept in separate sections."""
    model_result = spam_model.predict(text)
    rules = heuristics.analyze_text(text)
    title, subtitle = VERDICTS[model_result["risk_level"]]
    now = datetime.now(timezone.utc)
    return {
        "analyzed_at": now.isoformat(timespec="seconds"),
        "analyzed_at_display": now.strftime("%d %b %Y, %H:%M UTC"),
        "verdict": {"title": title, "subtitle": subtitle},
        "model": model_result,          # comes from the trained model
        "rules": rules,                 # rule-based heuristics (not the model)
        "recommendation": heuristics.recommendation(
            model_result["risk_level"], model_result["prediction"], rules["heuristic_level"],
            any(u["label"] == "Suspicious" for u in rules["urls"])),
    }


# ---- Pages ----------------------------------------------------------------------
def page(template, active, **context):
    return render_template(template, active=active, **context)


@app.route("/")
def home():
    return page("home.html", "home")


@app.route("/analyzer")
def analyzer():
    return page("analyzer.html", "analyzer", client_config=heuristics.client_config(),
                max_chars=MAX_EMAIL_CHARS)


@app.route("/dashboard")
def dashboard():
    return page("dashboard.html", "dashboard", metrics=spam_model.metrics(), info=spam_model.info())


@app.route("/history")
def history():
    return page("history.html", "history")


@app.route("/how-it-works")
def how_it_works():
    return page("how_it_works.html", "how", metrics=spam_model.metrics(), info=spam_model.info())


@app.route("/about")
def about():
    return page("about.html", "about")


@app.route("/predict", methods=["POST"])
def predict():
    """Original form endpoint, kept for backward compatibility: opens the analyzer and runs it."""
    message = request.form.get("message", "").strip()
    if not message:
        return page("analyzer.html", "analyzer", client_config=heuristics.client_config(),
                    max_chars=MAX_EMAIL_CHARS, initial_error="No email content provided."), 400
    return page("analyzer.html", "analyzer", client_config=heuristics.client_config(),
                max_chars=MAX_EMAIL_CHARS, initial_message=message[:MAX_EMAIL_CHARS])


# ---- JSON API -------------------------------------------------------------------
@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    payload = request.get_json(silent=True) or {}
    text = clean_email_text(payload.get("text"))
    return jsonify(run_analysis(text))


@app.route("/api/upload", methods=["POST"])
def api_upload():
    file = request.files.get("file")
    if file is None or not file.filename:
        raise InputError("No file uploaded.")
    try:
        extracted = extract_email_text(file.filename, file.read(MAX_UPLOAD_BYTES + 1))
    except InvalidEmailFile as exc:
        raise InputError(str(exc))
    extracted["text"] = clean_email_text(extracted["text"][:MAX_EMAIL_CHARS])
    return jsonify(extracted)


@app.route("/api/report", methods=["POST"])
def api_report():
    """Re-analyses the posted text server-side, so the PDF never relies on client-supplied results."""
    payload = request.get_json(silent=True) or {}
    text = clean_email_text(payload.get("text"))
    pdf = build_report_pdf(run_analysis(text), text)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return send_file(BytesIO(pdf), mimetype="application/pdf", as_attachment=True,
                     download_name=f"email-security-report-{stamp}.pdf")


@app.route("/api/model-info")
def api_model_info():
    return jsonify({"info": spam_model.info(), "metrics": spam_model.metrics()})


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


# ---- Error handling -------------------------------------------------------------
@app.errorhandler(InputError)
def handle_input_error(exc):
    return jsonify({"error": str(exc)}), 400


@app.errorhandler(HTTPException)
def handle_http_error(exc):
    if request.path.startswith("/api/"):
        message = {413: "File is too large (limit 1 MB).", 404: "Not found.",
                   405: "Method not allowed."}.get(exc.code, "Something went wrong.")
        return jsonify({"error": message}), exc.code
    return exc


@app.errorhandler(Exception)
def handle_unexpected(exc):
    app.logger.exception("Unhandled error")
    if request.path.startswith("/api/"):
        return jsonify({"error": "Unable to analyze email. Please try again."}), 500
    return "Something went wrong.", 500


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "1") == "1")
