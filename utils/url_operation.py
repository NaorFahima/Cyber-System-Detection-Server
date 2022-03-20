import re
import requests
import dnstwist
from datetime import datetime


def extract_domain_name_from_url(url: str) -> str:
    domain = re.findall(r"://([^/]+)/?", url)[0]
    if re.match(r"^www.", domain):
        domain = domain.replace("www.", "")
    return domain


def is_url_valid(url: str):
    try:
        response = requests.get(url)
        if response.ok:
            return True
    except:
        return False


def genarate_simallier_valid_urls(url: str) -> list:
    domain = extract_domain_name_from_url(url)
    fuzz = dnstwist.Fuzzer(domain)
    fuzz.generate()

    domain_list = []
    for domain in fuzz.domains:
        if domain["fuzzer"] != "homoglyph":
            domain_list.append(add_url_schema(domain["domain"]))
    return domain_list


def add_url_schema(url: str) -> str:
    # Converts the given URL into standard format
    if not re.match(r"^https?", url):
        url = "http://" + url
    return url


# Calculates number of months
def diff_month(d1: datetime, d2: datetime) -> int:
    return (d1.year - d2.year) * 12 + d1.month - d2.month
