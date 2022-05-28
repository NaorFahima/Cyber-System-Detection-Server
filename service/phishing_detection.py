from service.feature_extraction import UrlInformation
from multiprocessing.dummy import Pool as ThreadPool
from utils.url_operation import is_url_valid
import pickle
from utils.url_operation import (
    genarate_simallier_valid_urls,
    extract_domain_name_from_url,
    add_url_schema
)
from service.dom_compare import dom_compare
import requests

clf = pickle.load(open("./service/ml/dtc.pickle", "rb"))
original_url = None
scores = None


def worker(url: str) -> object:
    """thread worker function"""
    print(f"New worker started working on: {url}")
    if not is_url_valid(url):
        return False
    url_information = UrlInformation(url, clf)
    dom_compare_dict = dom_compare(original_url, url)

    # Score calculation: If decision tree says "phishing" => score is determined by dom compare (1-5) else score is 0
    score = round(1 + dom_compare_dict["similarity"]
                  * 4) if url_information.status["code"] == -1 else 0

    if score == 5:
        response = requests.get(url)
        print(
            f"response={extract_domain_name_from_url(response.url)}, url={extract_domain_name_from_url(original_url)}")
        if extract_domain_name_from_url(response.url) == extract_domain_name_from_url(original_url):
            return False

    if score != 0 and scores[score-1]:
        url_information.status.update(dom_compare_dict)
        return {"domain": url_information.domain, "details": url_information.details, "message": url_information.status["message"], "code": url_information.status["code"], "url": url_information.status["url"], "dom_compare": dom_compare_dict, "score": score, "ip": url_information.ip, "location": url_information.location}
    return False


def get_phishing_detection_details(url: str, scores_filter: list) -> list:
    global original_url
    global scores
    scores = scores_filter
    original_url = add_url_schema(extract_domain_name_from_url(url))
    urls = genarate_simallier_valid_urls(url)

    # Make the Pool of workers
    pool = ThreadPool(12)

    # Open the URLs in their own threads
    # and return the results
    results = pool.map(worker, urls)

    # Close the pool and wait for the work to finish
    pool.close()
    pool.join()
    return [result for result in results if result != False]
