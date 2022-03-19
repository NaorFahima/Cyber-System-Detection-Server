from utils.url_operation import extract_domain_name_from_url
from service.email_notification import send_email
import controller


def add_new_job_to_scheduler(scheduler: object, user_details: dict, data: dict):
    domain = extract_domain_name_from_url(data['url'])
    remove_job(scheduler, data['uid'], domain)
    print(f"days={data['scheduleScanning']}")
    scheduler.add_job(job, 'interval', days=data["scheduleScanning"],
                      id=f"{data['uid']}-{extract_domain_name_from_url(data['url'])}", args=[user_details, data])


def job(user_details: dict, data: dict):
    controller.phishing_controller.phishing_detection(data)
    send_email(user_details["email"], "Cyber System Detection alert update",
               f"Visit the Cyber System Detection website to see your new report regarding {data['url']}")


def remove_job(scheduler: object, uid: str, domain: str) -> bool:
    try:
        scheduler.remove_job(f"{uid}-{domain}")
        return True
    except:
        print(f"No job was found with the id {uid}-{domain}")
        return False
