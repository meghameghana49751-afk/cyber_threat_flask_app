import ipaddress
import re
from bs4 import BeautifulSoup
import requests
import whois
import urllib
import urllib.request
from datetime import datetime
import requests
import json
import csv
import time
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime, timezone


global BASE_SCORE
global PROPERTY_SCORE_WEIGHTAGE
BASE_SCORE = 60  # default trust_ score of url out of 100
PROPERTY_SCORE_WEIGHTAGE = {
    'domain_rank': 0.9,
    'domain_age': 0.3,
    'is_url_shortened': 0.8,
    'hsts_support': 0.1,
    'ip_present': 0.8,
    'url_redirects': 0.2,
    'too_long_url': 0.1,
    'too_deep_url': 0.5,
    'content': 0.1
}



# check whether the link is active or not
# check whether the link is active or not
def validate_url(url):
    try:
        # Add timeout to prevent hanging
        response = requests.get(url, timeout=10, allow_redirects=True)
        return response.status_code
    except requests.exceptions.RequestException as e:
        print(f"URL validation error: {e}")
        # Return appropriate status codes based on error type
        if isinstance(e, requests.exceptions.ConnectionError):
            return 404  # Not found
        elif isinstance(e, requests.exceptions.Timeout):
            return 408  # Timeout
        else:
            return 500  # Server error

def include_protocol(url):
    try:
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            # Try HTTPS first, fallback to HTTP
            url = 'https://' + url
        return url
    except:
        return url

# get domain rank if it exists in top 1M list
def get_domain_rank(domain):

    try:

        with open(
            "static/data/domain-rank.json",
            "r",
            encoding="utf-8"
        ) as f:

            ranks = json.load(f)

        return int(ranks.get(domain, 1000000))

    except Exception as e:

        print("Domain rank error:", e)

        return 1000000

# binary search
def binary_search(arr, x):
    low = 0
    high = len(arr) - 1
    while low <= high:
        mid = (low + high) // 2
        if arr[mid] == x:
            return 1
        elif arr[mid] < x:
            low = mid + 1
        else:
            high = mid - 1
    return 0

# get whois data of domain
def whois_data(domain):
    try:
        w = whois.whois(domain)

        creation_date = w.creation_date
        data = {}

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        age = "Not Given"

        if creation_date:
            try:
                if creation_date.tzinfo is not None:
                    now = datetime.now(timezone.utc)
                else:
                    now = datetime.now()

                age = round((now - creation_date).days / 365.25, 2)

            except Exception:
                age = "Not Given"

        for key, value in w.items():

            if not value:
                continue

            if isinstance(value, list):
                cleaned = []

                for item in value:
                    if isinstance(item, datetime):
                        cleaned.append(item.strftime("%Y-%m-%d"))
                    else:
                        cleaned.append(str(item))

                data[pascal_case(key)] = ", ".join(cleaned)

            else:
                if isinstance(value, datetime):
                    data[pascal_case(key)] = value.strftime("%Y-%m-%d")
                else:
                    data[pascal_case(key)] = str(value)

        return {
            "age": age,
            "data": data
        }

    except Exception as e:
        print(f"WHOIS error for {domain}: {e}")

        return {
            "age": "Not Given",
            "data": {}
        }


def pascal_case(s):
    if not s:
        return s
    # Handle snake_case or any case
    words = s.replace('_', ' ').split()
    return ' '.join(word.capitalize() for word in words)


# check for HSTS support
def hsts_support(url):
    try:

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={
                "User-Agent": "Mozilla/5.0"
            }
        )

        return 1 if (
            "Strict-Transport-Security"
            in response.headers
        ) else 0

    except Exception:
        return 0


# check for URL shortening services
def is_url_shortened(domain):
    try:
        with open('static/data/url-shorteners.txt') as f:
            services_arr = f.read().splitlines()
        
        domain_lower = domain.lower()
        for service in services_arr:
            if service.lower() in domain_lower:
                return 1
        return 0
    except:
        return 0


# check if an IP is present in the URL
def ip_present(url):
    try:
        # Parse the URL to get the hostname
        parsed = urlparse(url)
        hostname = parsed.netloc or parsed.path
        
        # Try to validate if it's an IP address
        ipaddress.ip_address(hostname)
        return 1
    except:
        return 0


# check for website redirects
def url_redirects(url):
    try:
        response = requests.get(url, timeout=10, allow_redirects=True)
        if len(response.history) > 0:
            url_history = []
            for resp in response.history:
                url_history.append(resp.url)
            return url_history
        else:
            return 0
    except Exception as e:
        print(f"Redirect check error: {e}")
        return 0


# check whether the URL is too long 
def too_long_url(url):
    return 1 if len(url) > 75 else 0


# check whether the URL is too deep 
def too_deep_url(url):
    try:
        parsed = urlparse(url)
        path = parsed.path
        slashes = path.count('/')
        return 1 if slashes > 4 else 0
    except:
        return 0


# check content for phishing indicators
def content_check(url):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.content, 'html.parser')

        result = {'onmouseover': 0, 'right-click': 0, 'form': 0, 'iframe': 0, 'login': 0, 'popup': 0}

        # check if onmouseover is enabled
        if soup.find(onmouseover=True):
            result['onmouseover'] = 1

        # check if right-click is disabled
        if soup.find_all(attrs={'oncontextmenu': 'return false;'}):
            result['right-click'] = 1

        # check if there are any forms present
        if soup.find_all('form'):
            result['form'] = 1

        # check if there are any iframes present
        if soup.find_all('iframe'):
            result['iframe'] = 1

        # check if there are any login keyword present
        login_pattern = re.compile(r'password|email|forgotten|login|signin|log-in', re.IGNORECASE)
        if soup.find_all(text=login_pattern):
            result['login'] = 1

        # check for popup elements
        popup_classes = ['popup', 'modal', 'overlay', 'lightbox']
        for popup_class in popup_classes:
            if soup.find_all(class_=re.compile(popup_class, re.IGNORECASE)):
                result['popup'] = 1
                break

        return result
    except Exception as e:
        print(f"Content check error: {e}")
        return 0


def phishtank_search(url):
    try:
        # PhishTank API endpoint
        endpoint = "https://checkurl.phishtank.com/checkurl/"
        
        # Prepare the request with proper headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # Make the request with timeout
        response = requests.post(
            endpoint, 
            data={"url": url, "format": "json"}, 
            headers=headers,
            timeout=10
        )
        
        # Check if response is valid
        if response.status_code == 200 and response.content:
            try:
                data = response.json()
                # Check if the response has the expected structure
                if 'results' in data and 'valid' in data['results']:
                    if data['results']['valid']:
                        return 1
                    else:
                        return 0
                else:
                    print(f"PhishTank unexpected response format: {data}")
                    return 0
            except json.JSONDecodeError as e:
                print(f"PhishTank JSON decode error: {e}, Response: {response.text[:100]}")
                return 0
        else:
            print(f"PhishTank HTTP error: {response.status_code}")
            return 0
            
    except requests.exceptions.Timeout:
        print("PhishTank timeout error")
        return 0
    except requests.exceptions.ConnectionError:
        print("PhishTank connection error")
        return 0
    except Exception as e:
        print(f"PhishTank error: {e}")
        return 0


def get_ip(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print(f"IP lookup error for {domain}: {e}")
        return 0


def get_certificate_details(domain):
    try:

        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:

            with context.wrap_socket(sock, server_hostname=domain) as sslsock:

                cert = sslsock.getpeercert()

                if not cert:
                    return 0

                issuer = dict(x[0] for x in cert['issuer'])

                subject = dict(x[0] for x in cert['subject'])

                issued_by = issuer.get(
                    'organizationName',
                    issuer.get('commonName', 'Unknown')
                )

                issued_to = subject.get(
                    'commonName',
                    'Unknown'
                )

                not_before = datetime.strptime(
                    cert['notBefore'],
                    '%b %d %H:%M:%S %Y %Z'
                )

                not_after = datetime.strptime(
                    cert['notAfter'],
                    '%b %d %H:%M:%S %Y %Z'
                )

                return {
                    "valid": True,
                    "Issued By": issued_by,
                    "Issued To": issued_to,
                    "Valid From": not_before.strftime("%Y-%m-%d"),
                    "Valid Till": not_after.strftime("%Y-%m-%d"),
                    "Days to Expiry": (
                        not_after - datetime.utcnow()
                    ).days
                }

    except Exception as e:

        print(f"SSL certificate error for {domain}: {e}")

        return 0

def calculate_trust_score(current_score, case, value):
    try:
        score = current_score

        if case == 'domain_rank':
            if value == 0 or value >= 1000000:  # not in top 10L rank
                score = current_score  # no change
            elif value < 100000:  # in top 1L rank
                score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE)
            elif value < 500000:  # in 1L - 5L rank
                score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.8)
            else:  # in 5L - 10L rank
                score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_rank'] * BASE_SCORE * 0.6)
            return score

        elif case == 'domain_age':
            if value == 'Not Given' or value is None:
                return current_score
            
            try:
                val = float(value)
            except (TypeError, ValueError):
                return current_score

            if val < 1:  # Less than 1 year - suspicious
                score = current_score - (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE * 1.5)
            elif val < 5:  # 1-5 years - slightly suspicious
                score = current_score - (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE * 0.5)
            elif 5 <= val < 10:  # 5-10 years - neutral
                score = current_score
            elif val >= 10:  # 10+ years - trustworthy
                score = current_score + (PROPERTY_SCORE_WEIGHTAGE['domain_age'] * BASE_SCORE)
            return score

        elif case == 'is_url_shortened':
            if value == 1:
                score = current_score - (PROPERTY_SCORE_WEIGHTAGE['is_url_shortened'] * BASE_SCORE)
            return score

        elif case == 'hsts_support':
            if value == 1:
                score = current_score + (PROPERTY_SCORE_WEIGHTAGE['hsts_support'] * BASE_SCORE)
            else:
                score = current_score - (PROPERTY_SCORE_WEIGHTAGE['hsts_support'] * BASE_SCORE)
            return score

        elif case == 'ip_present':
            if value == 1:
                score = current_score - (PROPERTY_SCORE_WEIGHTAGE['ip_present'] * BASE_SCORE)
            return score

        elif case == 'url_redirects':
            if value and value != 0:
                # Check number of redirects
                if isinstance(value, list):
                    if len(value) > 2:
                        score = current_score - (PROPERTY_SCORE_WEIGHTAGE['url_redirects'] * BASE_SCORE * 1.5)
                    else:
                        score = current_score - (PROPERTY_SCORE_WEIGHTAGE['url_redirects'] * BASE_SCORE)
            return score

        elif case == 'too_long_url':
            if value == 1:
                score = current_score - (PROPERTY_SCORE_WEIGHTAGE['too_long_url'] * BASE_SCORE)
            return score

        elif case == 'too_deep_url':
            if value == 1:
                score = current_score - (PROPERTY_SCORE_WEIGHTAGE['too_deep_url'] * BASE_SCORE)
            return score

        return score
    except Exception as e:
        print(f"Score calculation error for {case}: {e}")
        return current_score