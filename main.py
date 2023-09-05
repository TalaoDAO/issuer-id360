"""
Issuer for ID360

Flow is available at https://swimlanes.io/u/LHNjN55XM

"""
import json
from flask import Flask, render_template, request, jsonify, Response, send_file, session, redirect,url_for
import didkit
import environment
import redis

import logging
import ciso8601
from flask_mobility import Mobility
from routes import issuer_altme
import os



app = Flask(__name__)
app.secret_key = json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])
Mobility(app)
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'local'
mode = environment.currentMode(myenv)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)



issuer_altme.init_app(app,red,mode)



@app.route('/id360/static/<filename>', methods=['GET'])
def serve_static(filename: str):
    try:
        return send_file('./static/' + filename, download_name=filename)
    except FileNotFoundError:
        logging.error(filename+" not found")
        return jsonify("not found"), 404




if __name__ == '__main__':
    app.run(host=mode.IP, port=mode.port, debug=True)
