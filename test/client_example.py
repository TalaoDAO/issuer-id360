from flask import Flask,render_template, request, jsonify, Response, send_file, session, redirect,url_for
import requests
import logging
import json
import redis
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)
MY_SERVER = "https://d775-2a04-cec0-117b-8ede-6668-c4e2-22c0-b9bc.ngrok-free.app"
SERVER="https://talao.co"
def init_app():
    app.add_url_rule('/start_process',  view_func=start_process, methods = ['GET'])
    app.add_url_rule('/view_datas',  view_func=view_datas, methods = ['GET'])
    app.add_url_rule('/callback',  view_func=callback, methods = ['POST'])


def start_process():
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
        "api-key":"api-key-test"
    }
    try:
        response = requests.get(
            SERVER+"/id360/get_code_customer?client_id=customer-test&callback_url="+MY_SERVER+"/callback&browser_callback_url="+MY_SERVER+"/view_datas&api_key=my_optional_api_key", headers=headers)
    except:
        pass
    code=response.json()["code"]
    return redirect(SERVER+"/id360/authenticate_customer/"+code)

def view_datas():
    code = request.args.get("code")
    try:
        return json.loads(red.get(code))
    except:
        return jsonify("no datas")

def callback():

    logging.info("reception of callback")
    logging.info(request.json)
    logging.info(request.headers)

    dossier = request.json
    code=request.json["code"]
    red.setex(code,180,json.dumps(dossier))
    return "ok"


init_app()


if __name__ == '__main__':
    app.run(host="localhost", port=4000, debug=True)