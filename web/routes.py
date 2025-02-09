from flask import render_template, request
from src.core.osint_scraper import run_osint_scan  # Import OSINT scanning function

def init_routes(app):
    @app.route("/", methods=["GET", "POST"])
    def index():
        results = None
        error_message = None

        if request.method == "POST":
            target = request.form.get("target")

            if not target:
                error_message = "Please enter a valid IP address or domain."
            else:
                results = run_osint_scan(target)  # Run OSINT scan function

        return render_template("index.html", results=results, error_message=error_message)
