from flask import Flask, request
from flask_cors import CORS
from controller.database_controller import database_controller
from controller.phishing_controller import phishing_controller
import os

# Initialize
app = Flask(__name__)
CORS(app)
app.config["CORS_HEADERS"] = "Content-Type"
app.register_blueprint(phishing_controller)
app.register_blueprint(database_controller)

if __name__ == '__main__':
    app.run(port=5555, host='0.0.0.0')  

