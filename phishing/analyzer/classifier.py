import re
import yaml
import entropy

from difflib import SequenceMatcher 

def score_with_fuzzy_matching(domain, keywords):
    score = 0
    splitted_domain = re.split(r"\W+", domain)
    for keyword in keywords['keywords']:
        for word in splitted_domain:
            fuzzy_ratio = SequenceMatcher(None, keyword, word).ratio()
            if int(fuzzy_ratio * 100) > 75 and not 100:
                score += 70
                
    return score

def score_domain_keywords(domain):
    score = 0
    with open('keywords.yaml', 'r') as file:
        keywords = yaml.safe_load(file)    
    for tld in keywords['tlds']:
        if domain.endswith(tld):
            score += 20
    # Check if we have words like 'paypal' in domain
    for keyword in keywords['keywords']:
        if keyword in domain:
            score += keywords['keywords'][keyword]
    
    # Fuzzy matching words in domain with keywords
    score += score_with_fuzzy_matching(domain, keywords)
    return score

def score_recovered_data(domain, authority):
    score = 0
    score += score_domain_keywords(domain)
    # Free Let's Encrypt ceertificates are suspicious
    if authority == "Let's Encrypt":
        score += 10
    # Lot's of dashes
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3
    # Highly nested domains
    if domain.count('.') >= 3:
        score += domain.count('.') * 3
    # Check entropy
    score += int(round(entropy.shannon_entropy(domain) * 50))
    return score
