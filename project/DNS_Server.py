from dnslib.server import DNSServer, DNSLogger, BaseResolver
from dnslib.dns import RR, QTYPE, A, TXT

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------ GLOBAL VARIABLES ------

DNS_SERVER_PORT = 10053
DEFAULT_TTL = 5 * 60

# ------ END GLOBAL VARIABLES ------


class CustomDNSResolver(BaseResolver):

    def __init__(self):
        self.records = []

    def resolve(self, request, handler):
        response = request.reply()
        for record in self.records:
            response.add_answer(record)
        return response


class CustomDNSServer:
    def __init__(self):
        self.resolver = CustomDNSResolver()
        self.logger = DNSLogger("request,reply,truncated,error", False)
        self.server = DNSServer(self.resolver, port=DNS_SERVER_PORT, logger=self.logger)

    def add_A_record(self, domain, ip):
        self.resolver.records.append(RR(domain, QTYPE.A, rdata=A(ip), ttl=DEFAULT_TTL))

    def add_TXT_record(self, domain, txt):
        self.resolver.records.append(RR(domain, QTYPE.TXT, rdata=TXT(txt), ttl=DEFAULT_TTL))

    def start_server(self):
        self.server.start_thread()
