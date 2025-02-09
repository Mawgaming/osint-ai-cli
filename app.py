from flask import Flask
from web.routes import init_routes

app = Flask(__name__)

# Initialize routes
init_routes(app)

if __name__ == "__main__":
    app.run(debug=True)
