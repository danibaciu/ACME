""" For reference used https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https/page/2"""

import flask
import threading


# ------ GLOBAL VARIABLES ------

http_challenge_server = flask.Flask(__name__)
HTTP_PORT = 5002
challenges = dict()

# ------ END GLOBAL VARIABLES ------


@http_challenge_server.route('/.well-known/acme-challenge/<string:token>')
def http_challenge(token):
    if token in challenges:
        return flask.Response(challenges[token], mimetype="application/octet-stream")
    else:
        flask.abort(404)


def register_challenge_http_server(token, value):
    challenges[token] = value


def power_on_http_server():
    http_server_thread = threading.Thread(target=lambda: http_challenge_server.run(
        host="0.0.0.0", port=HTTP_PORT, debug=False, threaded=True))
    http_server_thread.start()

