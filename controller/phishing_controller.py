from model.firebase import *
from service.scheduler import remove_job
from utils.url_operation import *
from service.feature_extraction import UrlInformation
from service.phishing_detection import get_phishing_detection_details
from service.scheduler import add_new_job_to_scheduler
from service.email_notification import send_email
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Blueprint, request
import pickle
import json


scheduler = BackgroundScheduler({'apscheduler.timezone': 'Asia/Jerusalem'})
scheduler.start()

# Initialize
clf = pickle.load(open("./service/ml/dtc.pickle", "rb"))

phishing_controller = Blueprint(
    'phishing_controller', __name__, url_prefix="/api")


# Detect given url by user and add new record to database
@phishing_controller.route("/url-detection", methods=["POST"])
def url_detection() -> dict:
    data = json.loads(request.data)
    # Check if the url is valid
    if not is_url_valid(data["url"]):
        return {
            "code": 0,
            "message": "Can't reach Url",
            "url": data["url"],
            "timestamp": datetime.now(),
        }

    # Check if the url exist in database from the same day
    if (result := check_url_in_db(data["url"], "urls")):
        if(result["timestamp"].date() == datetime.today().date()):
            result["timestamp"] = datetime.now()
            add_url_object_to_db(data['uid'], result['domain'], result)
            return result

    # Analyze the url
    url_information = UrlInformation(data["url"], clf)
    new_json = {"domain": url_information.domain, "details": url_information.details, "message": url_information.status["message"], "code": url_information.status[
        "code"], "url": url_information.status["url"], "timestamp": url_information.status["timestamp"], "score": -1, "ip": url_information.ip, "location": url_information.location}
    add_url_object_to_db(data['uid'], url_information.domain, new_json)

    print("###########DONE#############")
    return url_information.status


# Search for similar websites and genreate report and add the report to the database
@phishing_controller.route("/phishing-detection", methods=["POST"])
def phishing_detection(data=None) -> dict:
    if request.data:
        data = json.loads(request.data)
    print(data)
    # Check if the url is valid
    if not is_url_valid(data["url"]):
        return {
            "code": 0,
            "message": "Can't reach Url",
            "url": data["url"],
            "timestamp": datetime.now(),
        }

    domain = extract_domain_name_from_url(data['url'])

    # Check if scheduleScanning if mark
    if data["scheduleScanning"] != "none":
        data["scheduleScanning"] = 7 if data["scheduleScanning"] == "weekly" else 30
        user_details = get_user_details_from_db(data["uid"])
        add_new_job_to_scheduler(scheduler, user_details, data)

    # Check if the report exist in database from the same day
    result = check_report_in_db(data['uid'], domain)
    if (result and result["timestamp"].date() == datetime.today().date()):
        result["timestamp"] = datetime.now()
        update_report_time(data['uid'], domain)

    # Generate new report for url and add to database
    else:
        result = get_phishing_detection_details(data["url"], data["scores"])
        add_report_to_db(data["uid"], {"urls": result, "timestamp": datetime.now(
        ), "domain": domain, "scheduleScanning": data["scheduleScanning"]}, domain)
        for url in result:
            url["timestamp"] = datetime.now()
            add_url_object_to_db(False, url["domain"], url)
    user_details = get_user_details_from_db(data['uid'])
    send_email(user_details["email"], "Cyber System Detection alert update",
               f"Visit the Cyber System Detection website to see your new report regarding {data['url']}")
    print("###########DONE#############")
    return {"result": result}


# Get user urls search history
@phishing_controller.route("/urls/<uid>", methods=["GET"])
def get_user_url_search_history(uid: str) -> dict:
    return {"data": get_urls_from_uid(uid)}


# Update scheduler of domain
@phishing_controller.route("/update-scheduler", methods=["PUT"])
def update_scheduler() -> dict:
    data = json.loads(request.data)
    remove_job(scheduler, data['uid'], data['url'])
    update_scheduler_of_domain_in_db(data['uid'], data['url'])
    return {"result": 200}
