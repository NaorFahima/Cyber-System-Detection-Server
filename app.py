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


@app.route('/')
def api_home():
    message = 'Welcome to Cyber System Detection API. You can check the manual on the github page: https://github.com/NaorFahima/Cyber-System-Detection-Server'
    return {"message": message}


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
