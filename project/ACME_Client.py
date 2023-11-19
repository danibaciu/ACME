import base64
import json
import time
import requests

from datetime import datetime, timedelta, timezone

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from requests.adapters import HTTPAdapter

from HTTP_Server_Challenge import register_challenge_http_server

# ------ GLOBAL VARIABLES ------

# verify_parameter = './pebble.minica.pem'
VERIFY_PARAMETER = False
DOMAIN_RESPONSE = {
    "newNonce": None,
    "revokeCert": None,
    "newAccount": None,
    "newOrder": None
}
KEY = ECC.generate(curve="p256")
SIGNING_ALG = DSS.new(KEY, "fips-186-3")

# ------ END GLOBAL VARIABLES ------


def get_domain_field(key: str):
    return DOMAIN_RESPONSE[key]


def get_key() -> ECC:
    global KEY
    return KEY


def get_sign_alg() -> DSS:
    global SIGNING_ALG
    return SIGNING_ALG


def create_key_authorization(token):
    key = {
            "crv": "P-256",
            "kty": "EC",
            "x": encode_b64(get_key().pointQ.x.to_bytes()),
            "y": encode_b64(get_key().pointQ.y.to_bytes()),
    }

    hash_val = encode_b64(SHA256.new(str.encode(
            json.dumps(key, separators=(',', ':')), encoding="utf-8")).digest())
    key_auth = "{}.{}".format(token, hash_val)

    return key_auth


def encode_b64(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip("=")


class ACMEClient:

    def __init__(self, directory, dns_server):
        self.directory = directory
        self.dns_server = dns_server

        self.account_kid = None

        self.client_session = requests.Session()
        self.jose_session = requests.Session()

        self.starting_success_states, self.starting_failure_states = ["ready", "processing", "valid"], ["invalid"]
        self.final_success_states, self.final_failure_states = ["valid"], ["ready", "invalid", "pending"]

        self.client_session.headers.update({"User-Agent": "dbaciu-eth-netsec"})
        self.client_session.mount('https://', HTTPAdapter(max_retries=0))

        self.jose_session.headers.update(
            {"User-Agent": "dbaciu-eth-netsec", "Content-Type": "application/jose+json"})
        self.jose_session.mount('https://', HTTPAdapter(max_retries=0))

    def get_directory(self):
        directory_request = self.client_session.get(self.directory, verify=VERIFY_PARAMETER)

        if directory_request.status_code == 200:
            jose_request_object = directory_request.json()
            global DOMAIN_RESPONSE
            DOMAIN_RESPONSE = jose_request_object
            return DOMAIN_RESPONSE

    def get_nonce(self):
        request = self.client_session.get(get_domain_field("newNonce"), verify=VERIFY_PARAMETER)
        if request.status_code in [200, 204]:
            return request.headers["Replay-Nonce"]

    def create_account(self):
        response = self.post_jose_session(url=get_domain_field("newAccount"),
                                          json=self.create_jose_jwk(
                                                get_domain_field("newAccount"),
                                                {"termsOfServiceAgreed": True,}
                                            ))

        if response.status_code == 201:
            self.account_kid = response.headers["Location"]
            return response.json()

    def create_jose_jwk(self, url, payload):

        protected = {
            "alg": "ES256",
            "jwk": {
                "crv": "P-256",
                "kid": "1",
                "kty": "EC",
                "x": encode_b64(get_key().pointQ.x.to_bytes()),
                "y": encode_b64(get_key().pointQ.y.to_bytes()),
            },
            "nonce": self.get_nonce(),
            "url": url
        }

        encoded_header = encode_b64(json.dumps(protected))
        encoded_payload = encode_b64(json.dumps(payload))

        sha256_hash = SHA256.new(str.encode("{}.{}".format(
            encoded_header, encoded_payload), encoding="ascii"))

        signature = get_sign_alg().sign(sha256_hash)

        jose_object = {
            "protected": encoded_header,
            "payload": encoded_payload,
            "signature": encode_b64(signature)
        }

        return jose_object

    def create_jose_kid(self, url, payload):

        encoded_header = encode_b64(json.dumps({
            "alg": "ES256",
            "kid": self.account_kid,
            "nonce": self.get_nonce(),
            "url": url
        }))

        if payload == "":
            encoded_payload = ""
            sha256_hash = SHA256.new(str.encode(
                "{}.".format(encoded_header), encoding="ascii"))
        else:
            encoded_payload = encode_b64(json.dumps(payload))
            sha256_hash = SHA256.new(str.encode("{}.{}".format(
                encoded_header, encoded_payload), encoding="ascii"))
        signature = get_sign_alg().sign(sha256_hash)

        kid_jose_object = {
            "protected": encoded_header,
            "payload": encoded_payload,
            "signature": encode_b64(signature)
        }

        return kid_jose_object

    def issue_certificate(self, domains, begin=datetime.now(timezone.utc), duration=timedelta(days=365)):
        response = self.post_jose_session(url=get_domain_field("newOrder"),
                                          json=self.create_jose_kid(get_domain_field("newOrder"), {
                                                "identifiers": [{"type": "dns", "value": domain} for domain in domains],
                                                "notBefore": begin.isoformat(),
                                                "notAfter": (begin + duration).isoformat()
                                            }))

        if response.status_code == 201:
            return response.json(), response.headers["Location"]

    def authorize_certificate(self, auth_url, auth_scheme):
        response = self.post_jose_session(url=auth_url, json=self.create_jose_kid(auth_url, ""))

        if response.status_code == 200:
            jose_request_object = response.json()

            for challenge in jose_request_object["challenges"]:
                key_auth = create_key_authorization(challenge["token"])

                if auth_scheme == "dns01" and challenge["type"] == "dns-01":
                    key_auth = encode_b64(SHA256.new(
                        str.encode(key_auth, encoding="ascii")).digest())

                    self.dns_server.add_TXT_record(
                        "_acme-challenge.{}".format(jose_request_object["identifier"]["value"]), key_auth)
                    return challenge

                elif auth_scheme == "http01" and challenge["type"] == "http-01":
                    register_challenge_http_server(challenge["token"], key_auth)
                    return challenge

    def validate_certificate(self, validate_url):
        response = self.post_jose_session(url=validate_url, json=self.create_jose_kid(validate_url, {}))

        if response.status_code == 200:
            return response.json()

    def poll_resource_status(self, order_url, success_states, failure_states):
        while True:
            response = self.post_jose_session(url=order_url, json=self.create_jose_kid(order_url, ""))

            if response.status_code == 200:
                jose_request_object = response.json()

                if jose_request_object["status"] in success_states:
                    print(f"##########  Resource {order_url} has {jose_request_object['status']} state - Success    ##########")
                    return jose_request_object

                elif jose_request_object["status"] in failure_states:
                    print(f"##########  Resource {order_url} has {jose_request_object['status']} state - Failure    ##########")
                    return False
            time.sleep(1)

    def finalize_certificate(self, order_url, finalize_url, der):
        jose_request_object = self.poll_resource_status(
            order_url, self.starting_success_states, self.starting_failure_states)

        if not jose_request_object:
            return False

        response = self.post_jose_session(url=finalize_url,
                                          json=self.create_jose_kid(
                                                finalize_url,
                                                {"csr": encode_b64(der)}
                                            ))

        if response.status_code == 200:
            try:
                return self.poll_resource_status(order_url, self.final_success_states, self.final_failure_states)["certificate"]
            except Exception as e:
                return False

    def download_certificate(self, certificate_url):
        response = self.post_jose_session(url=certificate_url, json=self.create_jose_kid(certificate_url, ""))
        if response.status_code == 200:
            return response.content

    def revoke_certificate(self, certificate):

        response = self.post_jose_session(url=get_domain_field("revokeCert"),
                                          json=self.create_jose_kid(
                                                get_domain_field("revokeCert"),
                                                {"certificate": encode_b64(certificate)}
                                            ))
        if response.status_code == 200:
            return response.content

    def post_jose_session(self, url, json):
        return self.jose_session.post(
            url,
            json=json,
            verify=VERIFY_PARAMETER
        )

