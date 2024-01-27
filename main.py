"""
Issuer for ID360

Flow is available at https://swimlanes.io/u/LHNjN55XM

"""
import json
from flask import Flask, request, jsonify, send_file, redirect
from flask_qrcode import QRcode
import didkit
import environment
import redis

import logging
from flask_mobility import Mobility
from routes import issuer_altme, customer_api, oidc
import os
import message
from flask_babel import Babel
from ip2geotools.databases.noncommercial import DbIpCity

app = Flask(__name__)
babel = Babel(app)
app.secret_key = json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])
QRcode(app)
Mobility(app)
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'local'
mode = environment.currentMode(myenv)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)


issuer_altme.init_app(app, red, mode)
customer_api.init_app(app, red, mode)
oidc.init_app(app, red, mode)


@app.errorhandler(500)
def error_500(e):
    """
    For testing purpose
    Send an email if problems
    """
    if mode.server in ['https://talao.co/']:
        message.email('Error 500 issuer id360', 'support@talao.io', str(e))
    logging.warning("redirecting")
    return redirect(mode.server + '/')


@app.route('/id360/static/img/<filename>', methods=['GET'])
def serve_static_img(filename: str):
    try:
        return send_file('./static/img/' + filename, download_name=filename)
    except FileNotFoundError:
        logging.error(filename+" not found")
        return jsonify("not found"), 404


@app.route('/id360/static/<filename>', methods=['GET'])
def serve_static(filename: str):
    try:
        return send_file('./static/' + filename, download_name=filename)
    except FileNotFoundError:
        logging.error(filename+" not found")
        return jsonify("not found"), 404
    

@app.route('/id360/ip', methods=['GET'])
def ip():
    ip_client = request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
    location = DbIpCity.get(ip_client)
    logging.info(location.country)
    return ('ok')


if __name__ == '__main__':
    app.run(host=mode.IP, port=mode.port, debug=True)
