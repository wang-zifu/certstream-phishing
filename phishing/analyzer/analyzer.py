import certstream

from functools import partial
from phishing.analyzer.classifier import Classifier

class Analyzer:
    def __init__(self):
        self.scoring = Classifier()

    @staticmethod
    def filter(message, context, analyzer_context):
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
                
            # Delete the wildcard
            if domain.startswith('*.'):
                domain = domain[2:]
            
            score = analyzer_context.scoring.score_recovered_data(domain, authority)

            if score > 80:
                print("[*] {} {}".format(score, domain))

    def analyze(self):
        certstream.listen_for_events(partial(self.filter, analyzer_context=self), 
                                    "wss://certstream.calidog.io")