# Import smtplib for the actual sending function
import smtplib
import json
import os


# Read Email credentials from environment variables
email_user = os.environ.get('EMAIL_USER')
email_password = os.environ.get('EMAIL_PASSWORD')


def send_email(recipient, subject, body):
    FROM = email_user
    TO = recipient if isinstance(recipient, list) else [recipient]
    SUBJECT = subject
    TEXT = body
    # Prepare actual message
    message = """From: %s\nTo: %s\nSubject: %s\n\n%s
    """ % (FROM, ", ".join(TO), SUBJECT, TEXT)
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.ehlo()
    server.starttls()
    server.login(email_user, email_password)
    server.sendmail(FROM, TO, message)
    server.close()
    print('successfully sent the mail')

