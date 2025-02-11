import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "src")))
from flask import Flask
from web.routes import main_blueprint

# Explicitly define the template folder path
TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), "web/templates")
app = Flask(__name__, template_folder=TEMPLATE_DIR)

# Initialize routes
app.register_blueprint(main_blueprint)

if __name__ == "__main__":
    app.run(debug=True)
