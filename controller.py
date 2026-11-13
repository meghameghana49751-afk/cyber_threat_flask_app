from urllib.parse import urlparse, urlencode, quote, unquote
import tldextract
import model
import socket

global BASE_SCORE
BASE_SCORE = 60  # default trust_ score of url out of 100


def main(url):
    try:
        # Input validation
        url = model.include_protocol(url)
        url_validation = model.validate_url(url)

        # Extract domain
        extracted = tldextract.extract(url)
        domain = extracted.domain + '.' + extracted.suffix
        
        # Handle cases where subdomain might be present
        if extracted.subdomain:
            full_domain = extracted.subdomain + '.' + domain
        else:
            full_domain = domain

        # Default response
        response = {
            'status': 'SUCCESS', 
            'url': url,
            'res': 'Unknown',
            'trust_score': BASE_SCORE
        }
        
        trust_score = BASE_SCORE

        # ================== starting url assessment ==================

        # phishtank check
        phishtank_response = model.phishtank_search(url)
        if phishtank_response:
            response['msg'] = "This is a verified phishing link."
            trust_score -= 30  # Significant penalty for verified phishing

        # website status
        response['response_status'] = str(url_validation) if url_validation else 'Unknown'

        # domain_rank
        domain_rank = model.get_domain_rank(full_domain)
        trust_score = model.calculate_trust_score(trust_score, 'domain_rank', domain_rank)
        
        # Format rank for display
        if domain_rank and domain_rank < 1000000:
            response['rank'] = f'{domain_rank:,}'
        else:
            response['rank'] = '1,000,000+'

        # domain_age and whois_data
        whois_data = model.whois_data(full_domain)
        trust_score = model.calculate_trust_score(trust_score, 'domain_age', whois_data['age'])
        
        if whois_data['age'] == 'Not Given':
            response['age'] = 'Unknown'
        else:
            try:
                response['age'] = f"{round(float(whois_data['age']), 1)} year(s)"
            except:
                response['age'] = str(whois_data['age'])
        
        response['whois'] = whois_data['data']

        # is_url_shortened
        is_url_shortened = model.is_url_shortened(full_domain)
        trust_score = model.calculate_trust_score(trust_score, 'is_url_shortened', is_url_shortened)
        response['is_url_shortened'] = bool(is_url_shortened)

        # hsts_support
        hsts_support = model.hsts_support(url)
        trust_score = model.calculate_trust_score(trust_score, 'hsts_support', hsts_support)
        response['hsts_support'] = bool(hsts_support)

        # ip_present
        ip_present = model.ip_present(url)
        trust_score = model.calculate_trust_score(trust_score, 'ip_present', ip_present)
        response['ip_present'] = bool(ip_present)

        # url_redirects
        url_redirects = model.url_redirects(url)
        trust_score = model.calculate_trust_score(trust_score, 'url_redirects', url_redirects)
        response['url_redirects'] = url_redirects if url_redirects else 0

        # too_long_url
        too_long_url = model.too_long_url(url)
        trust_score = model.calculate_trust_score(trust_score, 'too_long_url', too_long_url)
        response['too_long_url'] = bool(too_long_url)

        # too_deep_url
        too_deep_url = model.too_deep_url(url)
        trust_score = model.calculate_trust_score(trust_score, 'too_deep_url', too_deep_url)
        response['too_deep_url'] = bool(too_deep_url)

        # get ip address
        try:
            ip = model.get_ip(full_domain)
            if ip and ip != 0:
                response['ip'] = ip
            else:
                response['ip'] = 'Unavailable'
        except:
            response['ip'] = 'Unavailable'

        # get_certificate_details
        try:
            ssl_info = model.get_certificate_details(full_domain)
            if ssl_info and ssl_info != 0:
                response['ssl'] = ssl_info
                trust_score += 15
            else:
                response['ssl'] = {'valid': False,'error': 'SSL certificate not available'}
                trust_score -= 5
        except Exception as e:
            print(f"SSL error: {e}")
            response['ssl'] = {'valid': False, 'error': str(e)}

        # Ensure trust score is within bounds
        trust_score = int(max(min(trust_score, 100), 0))
        
        # Determine result based on trust score
        if trust_score >= 60:
            res = "Genuine"
        elif trust_score >= 40:
            res = "Suspicious"
        else:
            res = "Malware"

        response['trust_score'] = trust_score
        response['res'] = res

        return response

    except Exception as e:
        print(f"Controller error: {e}")
        response = {
            'status': 'ERROR', 
            'url': url, 
            'msg': "Some error occurred, please check the URL.",
            'res': 'Unknown',
            'trust_score': 0
        }
        return response