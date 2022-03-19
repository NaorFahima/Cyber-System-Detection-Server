import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from whois import whois
from datetime import datetime, date
import time
import numpy as np
from utils.url_operation import add_url_schema, extract_domain_name_from_url, diff_month
from ssl import create_default_context
from enum import Enum
import json


class UrlVariable(Enum):

    IP_ADDRESS = 'ip address'
    VALID_LENGTH = 'valid length'
    SHORTING_SERVICE = 'shortening service'
    AT_SYMBOL = 'at symbol'
    DOUBLE_SLASH_REDIRECTING = 'double slash redirecting'
    HYPHEN_SYMBOL = 'hyphen symbol'
    SUB_DOMAIN = 'sub domain'
    SSL = 'ssl'
    DOMAIN_REGISTRATION_LENGTH = 'domain registration length'
    FAVICON_CURRUNT_DOMAIN = 'favicon currunt domain'
    TRUSTY_PORT = 'trusty port'
    HTTPS_TOKEN = 'https token'
    VALID_REQUEST = 'valid request'
    LEGITIMATE_A_TAGS = 'legitimate a tags'
    LEGITIMATE_LINKS_TAGS = 'legitimate links tags'
    VALID_SSH = 'valid ssh'
    SUBMITING_TO_EMAIL = 'submitting to email'
    ABNORMAL = 'abnormal'
    LEGITIMATE_WEBSITE_FORWARDING = 'legitimate website forwarding'
    STATUS_BAR_ON_MOUSE_OVER = 'status bar on mouse over'
    DISABLE_RIGHT_CLICK = 'disable right click'
    POPUP_WINDOWS = 'popup window'
    IFRAME_REDIRECTION = 'iframe redirection'
    AGE_OF_DOMAIN = 'age of domain'
    DNS_RECORD = 'dns record'
    WEB_TRAFFIC = 'web traffic'
    PAGE_RANK = 'page rank'
    GOOGLE_INDEX = 'google index'
    LEGITIMATE_LINKS_POINTING = 'legitimate links pointing'
    STATISTICAL_REPORT = 'statistical report'


class UrlInformation():

    def __init__(self, url, clf):
        self.url = url
        self.domain = extract_domain_name_from_url(url)
        self.data_set = self.generate_data_set(url)
        self.details = self.generate_dictionary_from_data_set(self.data_set)
        self.status = self.get_status(url, clf)
        self.ip = self.get_domain_ip()
        self.location = self.get_domain_location()

    def get_domain_ip(self):
        try:
            return socket.gethostbyname(self.domain)
        except:
            return None

    def get_domain_location(self):
        response = urllib.request.urlopen(
            f"https://ipinfo.io/{self.ip}/json")
        data = json.load(response)
        return data['timezone']

    def toJSON(self):
        return json.dumps(self, default=lambda o: o.__dict__,
                          sort_keys=True, indent=4)

    def generate_dictionary_from_data_set(self, data_set: list):
        if data_set == -1:
            return -1
        variable = UrlVariable
        dict_keys = [variable.IP_ADDRESS.name, variable.VALID_LENGTH.name, variable.SHORTING_SERVICE.name,
                     variable.AT_SYMBOL.name, variable.DOUBLE_SLASH_REDIRECTING.name, variable.HYPHEN_SYMBOL.name,
                     variable.SUB_DOMAIN.name, variable.SSL.name, variable.DOMAIN_REGISTRATION_LENGTH.name,
                     variable.FAVICON_CURRUNT_DOMAIN.name, variable.TRUSTY_PORT.name, variable.HTTPS_TOKEN.name,
                     variable.VALID_REQUEST.name, variable.LEGITIMATE_A_TAGS.name, variable.LEGITIMATE_LINKS_TAGS.name,
                     variable.VALID_SSH.name, variable.SUBMITING_TO_EMAIL.name, variable.ABNORMAL.name,
                     variable.LEGITIMATE_WEBSITE_FORWARDING.name, variable.STATUS_BAR_ON_MOUSE_OVER.name,
                     variable.DISABLE_RIGHT_CLICK.name, variable.POPUP_WINDOWS.name, variable.IFRAME_REDIRECTION.name,
                     variable.AGE_OF_DOMAIN.name, variable.DNS_RECORD.name, variable.WEB_TRAFFIC.name, variable.PAGE_RANK.name,
                     variable.GOOGLE_INDEX.name, variable.LEGITIMATE_LINKS_POINTING.name, variable.STATISTICAL_REPORT.name]
        url_details = {}
        for index, key in enumerate(dict_keys):
            url_details[key] = data_set[index]

        return url_details

    # Generate data set by extracting the features from the URL
    def generate_data_set(self, url: str) -> list:

        data_set = []

        url = add_url_schema(url)

        # Stores the response of the given URL
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
        except:
            return -1

        if not response.ok:
            return -1

        # Requests all the information about the domain
        try:
            whois_response = whois(self.domain)
        except:
            whois_response = -1

        '''
        1.  Url has ip address 
        2.  Url has valid Length 
        3.  Url has shortening service
        4.  Url has at symbol '@'
        5.  Url has double slash redirecting
        6.  Url has prefix/suffix hyphen symbol '-'
        7.  Url has sub domain
        8.  Url has SSL
        9.  Url has valid domain registration length
        10. Url has favicon from currunt domain
        11. Url has trusty port
        12. Url has https token
        13. Url has valid request
        14. Url has legitimate a tags
        15. Url has legitimate links in tags
        16. Url has valid SFH
        17. Url submitting to email
        18. Url is abnormal
        19. Url has legitimate website forwarding
        20. Url has onMouseOver in the status bar
        21. Url disabling right click
        22. Url has popup window
        23. Url has iframe redirection
        24. Url has legitimate age of domain
        25. Url has dns record
        26. Url has web traffic
        27. Url has valid page rank
        28. Url has google index
        29. Url has legitimate links pointing to page
        30. Url statistical report
        '''

        data_set.append(self.url_has_ip_address(url))
        data_set.append(self.url_has_valid_length(url))
        data_set.append(self.url_has_shortening_service(url))
        data_set.append(self.url_has_at_symbol(url))
        data_set.append(self.url_has_double_slash_redirecting(url))
        data_set.append(self.url_has_prefix_suffix_hyphen_symbol(url))
        data_set.append(self.url_has_sub_domain(url))
        data_set.append(self.url_has_ssl(url))
        data_set.append(self.url_has_valid_domain_registration_length(url))
        data_set.append(self.url_has_favicon_from_currunt_domain(url))
        data_set.append(self.url_has_trusty_port(url))
        data_set.append(self.url_has_https_token(url))
        data_set.append(self.url_has_valid_request(url, soup))
        data_set.append(self.url_has_legitimate_a_tags(url, soup))
        data_set.append(self.url_has_legitimate_links_in_tags(url, soup))
        data_set.append(self.url_has_valid_sfh(url, soup))
        data_set.append(self.url_submitting_to_email(response))
        data_set.append(self.url_is_abnormal(url, whois_response))
        data_set.append(
            self.url_has_legitimate_website_forwarding(url, response))
        data_set.append(
            self.url_has_on_mouse_over_in_the_status_bar(url, response))
        data_set.append(self.url_disabling_right_click(url, response))
        data_set.append(self.url_has_popup_window(url, response))
        data_set.append(self.url_has_iframe_redirection(url, response))
        data_set.append(
            self.url_has_legitimate_age_of_domain(url, whois_response))
        data_set.append(self.url_has_dns_record(url, whois_response))
        data_set.append(self.url_has_web_traffic(url))
        data_set.append(self.url_has_valid_page_rank(url))
        data_set.append(self.url_has_google_index(url))
        data_set.append(
            self.url_has_legitimate_links_pointing_to_page(response))
        data_set.append(self.url_statistical_report(url))

        return data_set

    def get_status(self, url: str, clf) -> dict:
        X_new = []
        X_new = self.data_set

        if type(X_new) != list:
            return {'code': 0, 'message': "Can't reach Url", 'url': url, 'timestamp': datetime.now()}

        print(url,X_new)
        X_new = np.array(X_new).reshape(1, -1)
        prediction = clf.predict(X_new)

        if prediction == -1:
            return {'code': -1, 'message': "Phishing Url", 'url': url, 'timestamp': datetime.now()}
        else:
            return {'code': 1, 'message': "Legitimate Url", 'url': url, 'timestamp': datetime.now()}

    def url_has_ip_address(self, url: str) -> int:
        try:
            response = requests.get(
                f"https://geolocation-db.com/json/{self.ip}")
            data = response.json()
            self.location = data["country_name"]
            if self.ip in url:
                return -1
            else:
                return 1
        except:
            return -1

    def url_has_valid_length(self, url: str) -> int:
        if len(url) < 54:
            return 1
        elif len(url) >= 54 and len(url) <= 75:
            return 0
        else:
            return -1

    def url_has_shortening_service(self, url: str) -> int:
        match = re.search(
            "bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|"
            "yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|"
            "short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|"
            "doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|"
            "db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|"
            "q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|"
            "x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net",
            url,
        )
        if match:
            return -1
        else:
            return 1

    def url_has_at_symbol(self, url: str) -> int:
        if re.findall("@", url):
            return -1
        else:
            return 1

    def url_has_double_slash_redirecting(self, url: str) -> int:
        list = [x.start(0) for x in re.finditer("//", url)]
        if list[len(list) - 1] > 6:
            return -1
        else:
            return 1

    def url_has_prefix_suffix_hyphen_symbol(self, url: str) -> int:
        if re.findall(r"https?://[^\-]+-[^\-]+/", url):
            return -1
        else:
            return 1

    def url_has_sub_domain(self, url: str) -> int:
        if len(re.findall("\.", self.domain)) == 1:
            return 1
        elif len(re.findall("\.", self.domain)) == 2:
            return 0
        else:
            return -1

    def url_has_ssl(self, url: str) -> int:
        try:
            port = '443'
            context = create_default_context()
            with socket.create_connection((self.domain, port)) as socket_connection:
                with context.wrap_socket(socket_connection, server_hostname=self.domain) as sock:
                    certificate = sock.getpeercert()
            return 1
        except:
            return -1

    def url_has_valid_domain_registration_length(self, whois_response: object) -> int:
        try:
            expiration_date = whois_response.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            registration_length = 0
            today = time.strftime("%Y-%m-%d")
            today = datetime.strptime(today, "%Y-%m-%d")
            registration_length = abs((expiration_date - today).days)
            if registration_length / 365 <= 1:
                return -1
            else:
                return 1
        except:
            return -1

    def url_has_favicon_from_currunt_domain(self, url: str) -> int:
        try:
            index = [m.start() for m in re.finditer(r"/", url)][2]
            response = requests.get(url[:index] + '/favicon.ico')
            if response.ok and response.url == url[:index] + '/favicon.ico':
                return 1
            else:
                return -1
        except:
            return -1

    def url_has_trusty_port(self, url: str) -> int:
        port = self.domain.split(":")
        if port:
            return -1
        else:
            return 1

    def url_has_https_token(self, url: str) -> int:
        if re.findall(r"^https://", url):
            return 1
        else:
            return -1

    def url_has_valid_request(self, url: str, soup: object) -> int:
        i = 0
        success = 0
        for img in soup.find_all("img", src=True):
            dots = [x.start(0) for x in re.finditer("\.", img["src"])]
            if url in img["src"] or self.domain in img["src"] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for audio in soup.find_all("audio", src=True):
            dots = [x.start(0) for x in re.finditer("\.", audio["src"])]
            if url in audio["src"] or self.domain in audio["src"] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for embed in soup.find_all("embed", src=True):
            dots = [x.start(0) for x in re.finditer("\.", embed["src"])]
            if url in embed["src"] or self.domain in embed["src"] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for iframe in soup.find_all("iframe", src=True):
            dots = [x.start(0) for x in re.finditer("\.", iframe["src"])]
            if url in iframe["src"] or self.domain in iframe["src"] or len(dots) == 1:
                success = success + 1
            i = i + 1

        if i == 0:
            return 1

        percentage = success / float(i) * 100
        if percentage > 78.0:
            return 1
        elif (percentage >= 78.0) and (percentage < 39.0):
            return 0
        else:
            return -1

    def url_has_legitimate_a_tags(self, url: str, soup: object) -> int:
        percentage = 0
        i = 0
        unsafe = 0

        for a in soup.find_all("a", href=True):
            if (
                "#" in a["href"]
                or "javascript" in a["href"].lower()
                or "mailto" in a["href"].lower()
                or not (url in a["href"] or self.domain in a["href"])
            ):
                unsafe = unsafe + 1
            i = i + 1

        if i == 0:
            return 1

        percentage = unsafe / float(i) * 100
        if percentage < 31.0:
            return 1
        elif (percentage >= 31.0) and (percentage < 67.0):
            return 0
        else:
            return -1

    def url_has_legitimate_links_in_tags(self, url: str, soup: object) -> int:
        i = 0
        success = 0

        for link in soup.find_all("link", href=True):
            dots = [x.start(0) for x in re.finditer("\.", link["href"])]
            if url in link["href"] or self.domain in link["href"] or len(dots) == 1:
                success = success + 1
            i = i + 1

        for script in soup.find_all("script", src=True):
            dots = [x.start(0) for x in re.finditer("\.", script["src"])]
            if url in script["src"] or self.domain in script["src"] or len(dots) == 1:
                success = success + 1
            i = i + 1

        if i == 0:
            return 1

        percentage = success / float(i) * 100

        if percentage < 17.0:
            return 1
        elif (percentage >= 17.0) and (percentage < 81.0):
            return 0
        else:
            return -1

    def url_has_valid_sfh(self, url: str, soup: object) -> int:
        for form in soup.find_all("form", action=True):
            if form["action"] == "" or form["action"] == "about:blank":
                return -1
            elif form["action"][0] != '/' and url not in form["action"] and self.domain not in form["action"]:
                return 0

        return 1

    def url_submitting_to_email(self, response: object) -> int:
        if re.findall(r"[mail\(\)|mailto:?]", response.text):
            return -1
        else:
            return 1

    def url_is_abnormal(self, url: str, whois_response: object) -> int:
        try:
            if whois_response != -1:
                if whois_response['name'] not in url:
                    return 1
                else:
                    return -1
            else:
                return 0
        except:
            return -1

    def url_has_legitimate_website_forwarding(self, url: str, response: str) -> int:
        if len(response.history) <= 1:
            return 1
        elif len(response.history) <= 4:
            return 0
        else:
            return -1

    def url_has_on_mouse_over_in_the_status_bar(self, url: str, response: str) -> int:
        if re.findall("<script>.+onmouseover.+</script>", response.text):
            return -1
        else:
            return 1

    def url_disabling_right_click(self, url: str, response: str) -> int:
        if re.findall(r"event.button ?== ?2", response.text):
            return -1
        else:
            return 1

    def url_has_popup_window(self, url: str, response: str) -> int:
        if re.findall(r"alert\(", response.text):
            return -1
        else:
            return 1

    def url_has_iframe_redirection(self, url: str, response: str) -> int:
        if re.findall(r"[<iframe>|<frameBorder>]", response.text):
            return -1
        else:
            return 1

    def url_has_legitimate_age_of_domain(self, url: str, whois_response: dict) -> int:
        try:
            if diff_month(date.today(), whois_response.creation_date) < 6:
                return -1
            else:
                return 1
        except:
            return -1

    def url_has_dns_record(self, url: str, whois_response: dict) -> int:
        try:
            today = datetime.strptime(time.strftime("%Y-%m-%d"), "%Y-%m-%d")
            registration_length = abs(
                (whois_response.expiration_date - today).days)
            if registration_length / 365 <= 1:
                return -1
            else:
                return 1
        except:
            return -1

    def url_has_web_traffic(self, url: str) -> int:
        try:
            rank = BeautifulSoup(
                urllib.request.urlopen(
                    "http://data.alexa.com/data?cli=10&dat=s&url=" + url
                ).read(),
                "xml",
            ).find("REACH")["RANK"]
            rank = int(rank)
            if rank < 100000:
                return 1
            else:
                return 0
        except:
            return -1

    def url_has_valid_page_rank(self, url: str) -> int:
        try:
            rank_checker_response = requests.post(
                "https://www.checkpagerank.net/index.php", {
                    "name": self.domain}
            )
            global_rank = int(re.findall(
                r"Global Rank: [0-9]+", rank_checker_response.text)[0].split("Global Rank: ")[1])

            if global_rank > 0 and global_rank < 100000:
                return 1
            else:
                return -1
        except:
            return -1

    def url_has_google_index(self, url: str) -> int:
        return 1

    def url_has_legitimate_links_pointing_to_page(self, response: str) -> int:
        number_of_links = len(re.findall(r"<a href=", response.text))
        if number_of_links == 0:
            return -1
        elif number_of_links <= 2:
            return 0
        else:
            return 1

    def url_statistical_report(self, url: str) -> int:
        url_match = re.search(
            "at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly",
            url,
        )
        try:
            ip_match = re.search(
                "146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|"
                "107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|"
                "118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|"
                "216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|"
                "34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|"
                "216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42",
                self.ip,
            )
        except:
            ip_match = False
        if url_match or ip_match:
            return -1
        else:
            return 1
