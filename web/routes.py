from flask import Blueprint, render_template, request, send_file
from src.core.ai_processing import analyze_text_with_ai
from src.reports.generate_json import generate_json_report
from src.reports.generate_markdown import generate_markdown_report
from src.reports.generate_pdf import generate_pdf_report
import os

TEMPLATE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "templates"))
main_blueprint = Blueprint("main", __name__, template_folder=TEMPLATE_DIR)

@main_blueprint.route("/", methods=["GET", "POST"])
def index():
    results = None
    error_message = None
    file_path = None

    if request.method == "POST":
        target = request.form.get("target")
        report_format = request.form.get("format", "json")  # Default to JSON

        print(f"[DEBUG] Received Target: {target}")
        if not target:
            error_message = "Please enter a valid IP address or domain."
            print("[DEBUG] No target provided.")
        else:
            print(f"[DEBUG] Running scan for: {target}")
            results = analyze_text_with_ai(target)
            print(f"[DEBUG] Scan Results: {results}")

            # Generate only the selected report type
            if report_format == "json":
                file_path = generate_json_report(results)
            elif report_format == "md":
                file_path = generate_markdown_report(results)
            elif report_format == "pdf":
                file_path = generate_pdf_report(results)

            # Store file path for download
            if file_path:
                print(f"[DEBUG] Report generated: {file_path}")
                file_path = file_path.replace("\\", "/")

    return render_template("index.html", results=results, error_message=error_message, file_path=file_path)

@main_blueprint.route("/download/<path:filename>")
def download_file(filename):
    file_path = os.path.join("data/reports", filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return "File not found", 404
