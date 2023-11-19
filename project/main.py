import argparse
import flask
import os
import threading

from HTTPS_Server import power_on_https_server_using_cert
from Helper_File import obtain_certificate, key_path, cert_path

# ------ GLOBAL VARIABLES ------

http_shutdown_server = flask.Flask(__name__)

# ------ END GLOBAL VARIABLES ------


def start_server_to_use_certificate(args):
    obtain_certificate(args)

    os.system("pkill -f DNS_Server.py")

    power_on_https_server_using_cert(key_path, cert_path)


@http_shutdown_server.route('/shutdown')
def route_shutdown():
    func = flask.request.environ.get('werkzeug.server.shutdown')
    if func is None:
        raise RuntimeError('Not running with the Werkzeug Server')
    func()

    return "Server will be down soon."


def run_http_shutdown_server():
    http_shutdown_server.run(host="0.0.0.0", port=5003, debug=False, threaded=True)


def controller(args):
    http_shutdown_thread = threading.Thread(target=run_http_shutdown_server)
    http_shutdown_thread.start()

    https_server_thread = threading.Thread(target=lambda: start_server_to_use_certificate(args))
    https_server_thread.start()

    http_shutdown_thread.join()
    os._exit(0)


def parse_args():
    cmd_parser = argparse.ArgumentParser(description="dbaciu-eth-netsec")
    cmd_parser.add_argument("challenge", choices=["dns01", "http01"])
    cmd_parser.add_argument("--dir", help="ACME server directory URL", required=True)
    cmd_parser.add_argument("--record", required=True, help="IPv4 address which will be returned in A-record queries")
    cmd_parser.add_argument("--domain", action="append", help="Domain/s for which we want the certificate")
    cmd_parser.add_argument("--revoke", action="store_true", help="Revoke certificate after obtaining it?")

    return cmd_parser.parse_args()


def main():
    cmd_args = parse_args()
    print("Parsed arguments: ", cmd_args)
    controller(cmd_args)


if __name__ == "__main__":
    main()
