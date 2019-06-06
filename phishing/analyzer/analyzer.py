import certstream

from functools import partial
from phishing.analyzer.scanner import connect_to_domain
from phishing.analyzer.classifier import score_recovered_data

def filter(message, context, logs):
    if message['message_type'] == "heartbeat":
        return
    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']
        authority = message['data']['chain'][0]['subject']['aggregated']
        domain = None
        
        if all_domains:
            domain = all_domains[0]

        if not domain:
            return

        if domain.startswith('*.'):
            domain = domain[2:]
        
        score = score_recovered_data(domain, authority)
        http_code, https_code, open_dir = connect_to_domain(domain)

        if score > 10:
            logs.write("{} {} {} {} {}\n".format(score, domain, http_code, 
                                        https_code, open_dir))
            logs.flush()

            print("{} {} {} {} {}".format(score, domain, http_code, 
                                        https_code, open_dir))

def analyze():
    with open("logs", "a") as logs:
        certstream.listen_for_events(partial(filter, logs=logs), "wss://certstream.calidog.io")
