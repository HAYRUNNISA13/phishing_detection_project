import whois
from datetime import datetime

def check_domain_age(url):
    """Checks domain age. New domains are considered high risk."""
    try:
        domain = whois.whois(url)
        creation_date = domain.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        age_days = (datetime.now() - creation_date).days
        return f"Domain age is {age_days} days. (Recent registration is a high-risk indicator)."
    except:
        return "WHOIS data unreachable. Domain status: Suspicious."