import requests
import json
from flask import Flask, render_template, request, jsonify, redirect, session, Response, send_file
from flask_qrcode import QRcode
import didkit
import os
import environment
import redis
import uuid
import time



token = ""
parcoursPVID = "da73f56e-ec1f-44c0-a275-ba98e25fdc6c"

app = Flask(__name__)
app.secret_key = """json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])"""
qrcode = QRcode(app)

myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'thierry'
myenv="achille"
mode = environment.currentMode(myenv)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)
did_verifier = "did:tz:tz2NQkPq3FFA3zGAyG8kLcWatGbeXpHMu7yk"
DIDAuth = {
    "type": "VerifiablePresentationRequest",
    "query": [
        {
            "type": "DIDAuth"
        }
    ],
    "challenge": "",
    "domain": ""
}


async def loginID360():
    global token
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
    }

    json_data = {
        'username': 'test-achille@talao',
        'password': 'GANZq/7uH0@Dc$4=~.Xl',
    }
    response = requests.post(
        'https://preprod.id360docaposte.com/api/1.0.0/user/login/', headers=headers, json=json_data)
    token = response.json()["token"]
    print(token)
    # return token


async def create_dossier(id):  # return link of kyc ui for user
    print("creating dossier with token "+token)
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token '+token,
        'Content-Type': 'application/json',
    }
    json_data = {
        'callback_url': mode.server+'/kyc/id360/'+id,
        'browser_callback_url': mode.server+'/kyc/issuer/'+id,
        'client_reference': 'any_string',
        'callback_headers': {
            'header_name_1': id,
            'header_name_2': 'header_value_2',
        },
    }
    response = requests.post(
        'https://preprod.id360docaposte.com/api/1.0.0/process/'+parcoursPVID+'/enrollment/',
        headers=headers,
        json=json_data,
    )

    print(response.json())
    idDossier = response.json()["id"]
    red.set(id,  idDossier)

    api_key = response.json()["api_key"]
    link_ui = "https://preprod.id360docaposte.com/static/process_ui/index.html#/enrollment/"+api_key

    # print(link_ui)
    return link_ui


def get_dossier(id):
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token '+token,
    }

    response = requests.get(
        'https://preprod.id360docaposte.com/api/1.0.0/enrollment/'+id+'/report/', headers=headers)
    print(response)


@app.route('/kyc/login')
def login():
    id = str(uuid.uuid1())
    pattern = DIDAuth
    pattern['challenge'] = id
    pattern['domain'] = mode.server
    red.set(id,  json.dumps(pattern))
    url = mode.server+'/kyc/endpoint/' + id + '?issuer=' + did_verifier

    return render_template("login.html", url=url,id=id)        

@app.route('/kyc/issuer/<id>',  defaults={'red': red})
def issuer(id,red):
    time.sleep(5)
    qrcodeContent=red.get(id).decode()
    return render_template("issuer.html", url=qrcodeContent,id=id)      

@app.route('/kyc/endpoint/<id>', methods=['GET', 'POST'],  defaults={'red': red})
async def presentation_endpoint(id, red):
    try:
        my_pattern = json.loads(red.get(id).decode())
    except:
        event_data = json.dumps({"id": id,
                                 "message": "redis decode failed",
                                 "check": "ko",
                                     "type":"login"})
        red.publish('verifier', event_data)
        return jsonify("server error"), 500

    if request.method == 'GET':
        return jsonify(my_pattern)

    if request.method == 'POST':
        # red.delete(id)
        print(request)
        try:
            result = json.loads(await didkit.verify_presentation(request.form['presentation'], json.dumps({"challenge":id,"domain":mode.server})))
            print(result)
            result=False
        except:
            event_data = json.dumps({"id": id,
                                    "check": "ko",
                                     "message": "presentation is not correct",
                                     "type":"login"})
            red.publish('verifier', event_data)
            return jsonify("presentation is not correct"), 403
        if result:
            event_data = json.dumps({"id": id,
                                    "check": "ko",
                                     "message": result,
                                     "type":"login"})
            red.publish('verifier', event_data)
            return jsonify(result), 403
        await loginID360()
        link = await create_dossier(id)
        event_data = json.dumps({"id": id,
                                    "message": "presentation is verified",
                                     "check": "ok", 
                                     "link":link,
                                     "type":"login"
                                    })
        red.publish('verifier', event_data)

        return jsonify("ok"), 200

@app.route('/kyc/verifier_stream', methods = ['GET'],  defaults={'red' : red})
def presentation_stream(red):
    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('verifier')
        for message in pubsub.listen():
            if message['type']=='message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)

@app.route('/kyc/id360/<id>', methods=['GET', 'POST'],  defaults={'red': red})
async def id360callback(id, red):
    event_data = json.dumps({"type":"callback","id": id,"url":""})
    red.publish('verifier', event_data)
    return jsonify("ok"), 200
 
    

if __name__ == '__main__':
   app.run(host="localhost", port=3000, debug=True)
