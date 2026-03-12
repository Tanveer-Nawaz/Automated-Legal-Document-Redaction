"""
app.py
Flask web application for Automated Legal Document Redaction.
"""

import os
import uuid
import json
from datetime import datetime
from flask import (
    Flask, request, render_template, send_file,
    jsonify, redirect, url_for, flash
)
from werkzeug.utils import secure_filename
from redactor import (
    redact_pdf, redact_text_only, audit_to_csv,
    audit_summary, detect_pii_in_text,
    PYMUPDF_AVAILABLE, SPACY_AVAILABLE
)

# ---------------------------------------------------------------------------
# App config
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.urandom(24)

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
OUTPUT_FOLDER = os.path.join(os.path.dirname(__file__), "outputs")
ALLOWED_EXTENSIONS = {"pdf"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["OUTPUT_FOLDER"] = OUTPUT_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB


# In-memory job store (use a DB for production)
jobs: dict = {}


def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def unique_name(prefix: str, ext: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:8]}.{ext}"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template(
        "index.html",
        pymupdf=PYMUPDF_AVAILABLE,
        spacy=SPACY_AVAILABLE,
    )


@app.route("/upload", methods=["POST"])
def upload():
    if "pdf_file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400

    file = request.files["pdf_file"]
    if file.filename == "":
        return jsonify({"error": "No file selected"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "Only PDF files are allowed"}), 400

    job_id = uuid.uuid4().hex
    safe_name = secure_filename(file.filename)
    input_path = os.path.join(UPLOAD_FOLDER, f"{job_id}_{safe_name}")
    file.save(input_path)

    jobs[job_id] = {
        "id": job_id,
        "original_name": safe_name,
        "input_path": input_path,
        "status": "uploaded",
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }

    return jsonify({"job_id": job_id, "filename": safe_name})


@app.route("/redact/<job_id>", methods=["POST"])
def redact(job_id: str):
    if job_id not in jobs:
        return jsonify({"error": "Job not found"}), 404

    job = jobs[job_id]
    input_path = job["input_path"]

    output_name = unique_name("redacted", "pdf")
    output_path = os.path.join(OUTPUT_FOLDER, output_name)
    csv_name = unique_name("audit", "csv")
    csv_path = os.path.join(OUTPUT_FOLDER, csv_name)

    try:
        if PYMUPDF_AVAILABLE:
            audit, total = redact_pdf(input_path, output_path)
            mode = "PDF redaction"
        else:
            # Fallback: read PDF as text via basic extraction
            audit, total, output_path = _fallback_redact(input_path, output_path)
            mode = "Text-mode redaction (install PyMuPDF for full PDF support)"

        # Save CSV audit log
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            f.write(audit_to_csv(audit))

        summary = audit_summary(audit)

        job.update({
            "status": "done",
            "output_path": output_path,
            "output_name": output_name,
            "csv_path": csv_path,
            "csv_name": csv_name,
            "total_redactions": total,
            "summary": summary,
            "audit": audit,
            "mode": mode,
            "completed_at": datetime.now().isoformat(timespec="seconds"),
        })

        return jsonify({
            "status": "done",
            "total_redactions": total,
            "summary": summary,
            "mode": mode,
            "job_id": job_id,
        })

    except Exception as exc:
        job["status"] = "error"
        job["error"] = str(exc)
        return jsonify({"error": str(exc)}), 500


def _fallback_redact(input_path: str, output_path: str):
    """
    When PyMuPDF is not installed: extract text naively and produce a
    text-based redacted output. Returns (audit, total, actual_output_path).
    """
    # Try to read raw bytes and do minimal text extraction
    with open(input_path, "rb") as f:
        raw = f.read().decode("latin-1", errors="replace")

    # Extract readable text lines (crude but works for demo)
    import re
    lines = re.findall(r'[A-Za-z0-9 ,.\-@:/#\(\)\[\]\'\"\n]{10,}', raw)
    text = "\n".join(lines)

    redacted_text, audit = redact_text_only(text)
    total = len(audit)

    # Save as a plain text file instead of PDF
    txt_output = output_path.replace(".pdf", "_redacted.txt")
    with open(txt_output, "w", encoding="utf-8") as f:
        f.write("=== REDACTED DOCUMENT (TEXT MODE) ===\n")
        f.write("Note: Install PyMuPDF for proper PDF output.\n\n")
        f.write(redacted_text)

    return audit, total, txt_output


@app.route("/preview/<job_id>")
def preview(job_id: str):
    if job_id not in jobs:
        return jsonify({"error": "Job not found"}), 404
    job = jobs[job_id]
    return render_template("result.html", job=job)


@app.route("/download/pdf/<job_id>")
def download_pdf(job_id: str):
    if job_id not in jobs:
        return "Job not found", 404
    job = jobs[job_id]
    return send_file(
        job["output_path"],
        as_attachment=True,
        download_name=f"redacted_{job['original_name']}",
    )


@app.route("/download/csv/<job_id>")
def download_csv(job_id: str):
    if job_id not in jobs:
        return "Job not found", 404
    job = jobs[job_id]
    return send_file(
        job["csv_path"],
        as_attachment=True,
        download_name=f"audit_log_{job['original_name'].replace('.pdf','.csv')}",
        mimetype="text/csv",
    )


@app.route("/audit/<job_id>")
def audit_view(job_id: str):
    if job_id not in jobs:
        return jsonify({"error": "Not found"}), 404
    job = jobs[job_id]
    return jsonify({
        "total": job.get("total_redactions", 0),
        "summary": job.get("summary", {}),
        "records": job.get("audit", []),
    })


if __name__ == "__main__":
    app.run(debug=True, port=5000)
