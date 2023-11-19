import flask
import threading

# ------ GLOBAL VARIABLES ------

https_server = flask.Flask(__name__)
HTTPS_PORT = 5001

# ------ END GLOBAL VARIABLES ------


@https_server.route("/")
def https_server_get_method():
    return "[200] GET executed successfully !"


def power_on_https_server_using_cert(key_path, cert_path):
    https_server_thread = threading.Thread(target=lambda: https_server.run(
        host="0.0.0.0", port=HTTPS_PORT, debug=False, threaded=True, ssl_context=(cert_path, key_path)))
    https_server_thread.start()
