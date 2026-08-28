"""
Issuer for ID360

Flow is available at https://swimlanes.io/u/LHNjN55XM

"""
import json
import os

import redis
from flask import Flask, render_template

import environment
from routes import oidc_openid4vc_hub


app = Flask(__name__)
with open("keys.json", "r", encoding="utf-8") as key_file:
    app.secret_key = json.dumps(json.load(key_file)["appSecretKey"])

myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'local'
mode = environment.currentMode(myenv)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)


oidc_openid4vc_hub.init_app(app, red, mode)


@app.errorhandler(500)
def error_500(error):
    app.logger.error("Unhandled server error", exc_info=error)
    return render_template(
        "openid4vc_hub_error.html",
        error="internal_server_error",
        error_description="An internal error prevented PID issuance.",
    ), 500


if __name__ == '__main__':
    app.run(host=mode.IP, port=mode.port, debug=myenv == 'local')
