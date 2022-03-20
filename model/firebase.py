
# Use the application default credentials
from firebase_admin import credentials, firestore, initialize_app
from datetime import datetime
from utils.url_operation import extract_domain_name_from_url

cred = credentials.Certificate("./model/database_key.json")
initialize_app(cred)

db = firestore.client()


def add_data_to_db(collection: str, document: str, data: dict, subcollection: str = '') -> None:
    if subcollection == '':
        db.collection(collection).document(document).set(data)
    else:
        domain = extract_domain_name_from_url(data["url"])
        doc_ref = db.collection(collection).document(document)
        doc_ref.collection(subcollection).document(domain).set(data)


def add_report_to_db(uid: str, data: dict, domain: str) -> None:
    doc_ref = db.collection("users").document(uid)
    doc_ref.collection("reports").document(domain).set(data)


def read_data_from_users(collection: str, document: str, subcollection: str = ''):
    data_ref = db.collection(collection).document(document)
    if subcollection != '':
        data_ref = data_ref.collection(subcollection)
    return data_ref.stream()


def read_data_from_collection(collection: str):
    data_ref = db.collection(collection)
    data_list = []
    for url in data_ref.stream():
        data_list.append(url.to_dict())
    return data_list


def get_urls_from_uid(uid: str) -> list:
    urls = read_data_from_users("users", uid, "urls")
    url_list = []
    for url in urls:
        url_list.append(url.to_dict())
    return url_list


def check_url_in_db(url: str, collection: str) -> bool:
    data = read_data_from_collection(collection)
    for url_in_db in data:
        if url == url_in_db["url"]:
            return url_in_db
    return False


def add_url_object_to_db(uid: str, domain: str, url_object: dict) -> None:
    add_data_to_db("urls", domain, url_object)
    if url_object["code"] == -1:
        add_data_to_db("phishing_urls", domain, url_object)
    if uid:
        add_data_to_db("users", uid, url_object, "urls")


def add_user_details_to_db(user_information: dict) -> None:
    try:
        db.collection("users").document(
            user_information["uid"]).update(user_information)
    except:
        db.collection("users").document(
            user_information["uid"]).set(user_information)


def get_user_details_from_db(uid: str) -> dict:
    data_ref = db.collection("users").document(uid)
    return data_ref.get().to_dict()


def get_user_reports_from_db(uid: str) -> list:
    collection = db.collection('users').document(uid).collection('reports')
    reports = []
    for doc in collection.stream():
        reports.append(doc.to_dict())
    return reports


def get_single_report(uid: str, domain: str) -> list:
    document = db.collection('users').document(
        uid).collection('reports').document(domain)
    return document.get().to_dict()


def check_report_in_db(uid: str, domain: str) -> bool:
    reports = get_user_reports_from_db(uid)
    try:
        report = db.collection('users').document(
            uid).collection('reports').document(domain)
        return report.get().to_dict()
    except:
        return False


def update_report_time(uid: str, domain: str) -> None:
    db.collection("users").document(uid).collection("reports").document(
        domain).update({"timestamp": datetime.now()})


def update_scheduler_of_domain_in_db(uid: str, url: str) -> None:
    db.collection("users").document(uid).collection(
        "reports").document(url).update({"scheduleScanning": "none"})
