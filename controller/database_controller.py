from flask import Blueprint, request
from model.firebase import *
import json

database_controller = Blueprint(
    'database_controller', __name__, url_prefix="/api")


# Create new user and save in database
@database_controller.route("/user", methods=["POST"])
def save_user_details():
    data = json.loads(request.data)
    add_user_details_to_db(data)


# Get user details from uid
@database_controller.route("/user/<uid>", methods=["GET"])
def get_user_details(uid: str):
    return get_user_details_from_db(uid)


# Get reports information from uid
@database_controller.route("/reports/<uid>", methods=["GET"])
def get_user_reports(uid: str):
    return {"data": get_user_reports_from_db(uid)}


# Get phising website list from database
@database_controller.route("/phishing-db", methods=["GET"])
def get_phishing_websites():
    return {"data": read_data_from_collection("phishing_urls")}
