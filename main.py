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
from datetime import datetime, timedelta
import logging
import pickle
import traceback
import sys
import random
import string
import db
import ciso8601

issuer_key = json.dumps(json.load(open("keys.json", "r"))[
                        'talao_Ed25519_private_key'])
username=json.load(open("keys.json", "r"))['username']
password=json.load(open("keys.json", "r"))['password']
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"
token = ""
parcours_PVID = "da73f56e-ec1f-44c0-a275-ba98e25fdc6c"
parcours_non_substantiel = "0dd7e3c1-c4a4-41a2-8b09-0ec992e38e2a"
app = Flask(__name__)
app.secret_key = """json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])"""
qrcode = QRcode(app)

myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'thierry'
myenv = "achille"
mode = environment.currentMode(myenv)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)
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
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
    }
    json_data = {
        'username': username, 
        'password': password,
    }
    response = requests.post(
        'https://preprod.id360docaposte.com/api/1.0.0/user/login/', headers=headers, json=json_data) #stocker route variable
    if response.status_code==200:
        token = response.json()["token"]
        return token
    else:
        logging.error(response.json())


async def create_dossier(code,token): 
    print("creating dossier with token "+token)
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token '+token,
        'Content-Type': 'application/json',
    }
    json_data = {
        'callback_url': mode.server+'/id360/callback_id360/'+code,
        'browser_callback_url': mode.server+'/id360/issuer/'+code,
        'client_reference': 'any_string',
        'callback_headers': {
            'header_name_1': code,
            'header_name_2': 'header_value_2',
        },
    }
    response = requests.post(
        'https://preprod.id360docaposte.com/api/1.0.0/process/' +
            parcours_non_substantiel+'/enrollment/',
        headers=headers,
        json=json_data,
    )
    if response.status_code==200:
        print(response.json())
        id_dossier = response.json()["id"]
        temp_dict = pickle.loads(red.get(code))
        temp_dict["id_dossier"] = id_dossier
        red.setex(code, 600, pickle.dumps(temp_dict))  

        api_key = response.json()["api_key"]
        link_ui = "https://preprod.id360docaposte.com/static/process_ui/index.html#/enrollment/"+api_key
        return link_ui
    else:
        logging.error(response.json())


async def get_dossier(id_dossier,token):
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token '+token,
    }
    print(id_dossier)
    response = requests.get('https://preprod.id360docaposte.com/api/1.0.0/enrollment/'+str(id_dossier)+'/report/', headers=headers)
    if response.status_code==200:
        print("dossier "+str(id_dossier)+" :")
        print(response.json())
        return response.json()
    else:
        logging.error("error requesting dossier")
        print(response.status_code)
        print(response.json())

characters = string.digits+string.ascii_lowercase
def code_generator():
    code = ''.join(random.choice(characters) for i in range(6))
    return code

@app.route('/id360/get_code')
def get_code():
    """
    curl https:talao.co/id360/get_code -H "apiKey":<your_api_key>
    returns {"code": <code>} 200
    the code returned is useful for one session for one user to get one credential
    returns {"error": <error_description>} 403 
    if an error occured
    """
    api_key=request.headers['apiKey']
    if db.test_api_key(api_key)==False or type(api_key)!=str:
        return jsonify({"code":"error"}),403

    code = code_generator() 
    red.setex(code,600,  "True") 
    return jsonify({"code":code}),200 
    

@app.route('/id360/authenticate/<code>') #authenticate gerer session
def login(code):
    """construciton url + description args + verifier liste callback"""

    try:
        site_callback = request.args['callback']
        client_id = request.args['client_id']
        vc_type = request.args['vc_type']
    except KeyError:
        logging.warning("KeyError in /authenticate")
    """try:
        if red.get(code).decode()!="True":
            return jsonify("invalid link"),403
    except:
        return jsonify("invalid link"),403"""

    #pattern['challenge'] = code
    #pattern['domain'] = mode.server
    red.setex(code,600, pickle.dumps ({"pattern":json.dumps(DIDAuth),"callback":site_callback,"client_id":client_id,"vc_type":vc_type})) 
    url = mode.server+'/id360/endpoint/' + code
    print(site_callback)
    return render_template("login.html", url=url, code=code)


@app.route('/id360/issuer/<code>',  defaults={'red': red}) 
def issuer(code, red):
    print(pickle.loads(red.get(code)))
    return render_template("issuer.html", code=code,callback=pickle.loads(red.get(code))["callback"])


@app.route('/id360/endpoint/<code>', methods=['GET', 'POST'],  defaults={'red': red})
async def presentation_endpoint(code, red):
    """description fonction"""
    try:
        my_pattern = json.loads(pickle.loads(red.get(code))["pattern"])
    except:
        event_data = json.dumps({"code": code,
                                 "message": "redis decode failed",
                                 "check": "ko",
                                     "type": "login","url":pickle.loads(red.get(code))["callback"]})
        red.publish('verifier', event_data)
        return jsonify("server error"), 500 

    if request.method == 'GET':
        return jsonify(my_pattern)

    if request.method == 'POST':
        print(request.form['presentation'])
        try:
            result = json.loads(await didkit.verify_presentation(request.form['presentation'], 
                                                                 #json.dumps({"challenge": code, "domain": mode.server}) #verifier didkit version
                                                                 '{}'
                                                                 ))
            print(result)
            result['errors'] = []
        except:
            event_data = json.dumps({"code": code,
                                    "check": "ko",
                                     "message": "presentation is not correct",
                                     "type": "login"})
            red.publish('verifier', event_data)
            return jsonify("presentation is not correct"), 403
        if result['errors']:
            event_data = json.dumps({"code": code,
                                    "check": "ko",
                                     "message": result,
                                     "type": "login"})
            red.publish('verifier', event_data)
            return jsonify(result), 403
        temp_dict = pickle.loads(red.get(code))
        temp_dict["did"]=json.loads(request.form['presentation'])["holder"]
        red.setex(code,600,  pickle.dumps(temp_dict)) #setex
        print(pickle.loads(red.get(code))["callback"])

        kyc=db.get_user_kyc(pickle.loads(red.get(code))["did"])
        if (not kyc  or kyc[1] == "KO"):
            temp_dict = pickle.loads(red.get(code))
            if not kyc:
                temp_dict["first"] = True 
            else:
                temp_dict["first"] = False
            print(temp_dict["first"])
            red.setex(code,600,  pickle.dumps(temp_dict)) #setex
            token = await loginID360()
            link = await create_dossier(code,token)
            event_data = json.dumps({"code": code,
                                        "message": "presentation is verified",
                                        "check": "ok",
                                        "link": link,
                                        "type": "login"
                                        })
            print("sent "+link)
            red.publish('verifier', event_data)

            return jsonify("ok"), 200
        elif kyc[1] == "OK":
            temp_dict = pickle.loads(red.get(code))
            temp_dict["did"]=json.loads(request.form['presentation'])["holder"]
            temp_dict["id_dossier"]=kyc[2] 
            temp_dict["first"]=False
            """red.setex(code,600,pickle.dumps({"did": json.loads(request.form['presentation'])[
                    "holder"], "id_dossier": kyc[2], "first": False}))"""
            red.setex(code,600,pickle.dumps(temp_dict))
            event_data = json.dumps({"code": code,
                                        "message": "presentation is verified",
                                        "check": "ok",
                                        "link": mode.server+"/id360/issuer/"+code,
                                        "type": "login"
                                        })
            red.publish('verifier', event_data)

            print("sent "+mode.server+"/id360/issuer/"+code)
            return jsonify("ok"), 200  


@app.route('/id360/verifier_stream', methods=['GET'],  defaults={'red': red})
def presentation_stream(red):
    logging.info("stream subscription")

    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('verifier')
        for message in pubsub.listen():
            if message['type'] == 'message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = {"Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"}
    return Response(event_stream(red), headers=headers)

@app.route('/id360/qr_code_stream', methods=['GET'],  defaults={'red': red})
def qr_code_stream(red):
    logging.info("stream subscription")

    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('qr_code')
        for message in pubsub.listen():
            if message['type'] == 'message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = {"Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"}
    return Response(event_stream(red), headers=headers)

@app.route('/id360/issuer_stream', methods=['GET'],  defaults={'red': red})
def issuer_stream(red):
    logging.info("stream subscription")

    def event_stream(red):
        pubsub = red.pubsub()
        pubsub.subscribe('issuer')
        for message in pubsub.listen():
            if message['type'] == 'message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = {"Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no"}
    return Response(event_stream(red), headers=headers)

@app.route('/id360/callback_id360/<code>', methods=['GET', 'POST'],  defaults={'red': red}) 
async def id360callback(code, red):
    logging.info("reception of id360 callback for "+code)
    token = await loginID360()
    id_dossier = pickle.loads(red.get(code))["id_dossier"]
    did = pickle.loads(red.get(code))["did"]
    dossier = await get_dossier(id_dossier,token)
    #print(dossier)
    birth_date=dossier["extracted_data"]["identity"][0]["birth_date"]
    #birth_date=birth_date.replace("-","/")
    timestamp = ciso8601.parse_datetime(birth_date)
    # to get time in seconds:
    timestamp=time.mktime(timestamp.timetuple())
    now= time.time()
    vc_type = pickle.loads(red.get(code))["vc_type"]

    if(dossier["status"]!="OK" or (vc_type=="Over18" and (now-timestamp)<31556926*18 )):
        url = pickle.loads(red.get(code))["callback"]+"/400"
        event_data = json.dumps({"type": "callbackErr", "code": code, "url": url})
        red.publish('qr_code', event_data)
        return jsonify("ok"), 200
    url = mode.server+"/id360/issuer_endpoint/"+code
    event_data = json.dumps({"type": "callback", "code": code, "url": url})
    red.publish('qr_code', event_data) 
    return jsonify("ok"), 200


@app.route('/id360/get_qrcode/<code>', methods=['GET'],  defaults={'red': red})
async def get_qrcode(code, red):
    token = await loginID360()
    id_dossier = pickle.loads(red.get(code))["id_dossier"]
    did = pickle.loads(red.get(code))["did"]
    vc_type = pickle.loads(red.get(code))["vc_type"]
    dossier = await get_dossier(id_dossier,token)
    print(dossier)
    birth_date=dossier["extracted_data"]["identity"][0]["birth_date"]
    #birth_date=birth_date.replace("-","/")
    timestamp = ciso8601.parse_datetime(birth_date)
    # to get time in seconds:
    timestamp=time.mktime(timestamp.timetuple())
    now= time.time()
    print(timestamp)
    print(now)
    print(now-timestamp)
    print((now-timestamp)>31556926*18)
    if pickle.loads(red.get(code))["first"] == True:
        db.insert_kyc(did, dossier["status"], id_dossier)
    else:
        db.update_kyc(did, dossier["status"], id_dossier)
    try:
        if(dossier["status"]=="OK" ): #or dossier["status"]=="KO"
            if(vc_type=="Over18" and (now-timestamp)>31556926*18 ) or vc_type!="Over18":
                return jsonify({"url":mode.server+"/id360/issuer_endpoint/"+code}),200
        else:
            return jsonify({"url":"error"}),200

    except TypeError:
        return jsonify({"url":"not yet"}),200
    except KeyError:
        return jsonify({"url":"error"}),500


@app.route('/id360/issuer_endpoint/<code>', methods = ['GET','POST'],  defaults={'red' : red})
async def vc_endpoint(code, red):  
    """gere type=vc"""
    vc_type=pickle.loads(red.get(code))["vc_type"]
    token = await loginID360()

    dossier= await get_dossier(pickle.loads(red.get(code))["id_dossier"],token)
    #print(dossier["extracted_data"])
    if vc_type=="VerifiableId":
        credential = json.load(open('VerifiableId.jsonld', 'r'))
        credential["credentialSubject"]["familyName"]=dossier["extracted_data"]["identity"][0]["name"]
        credential["credentialSubject"]["firstName"]=dossier["extracted_data"]["identity"][0]["first_names"][0]
        credential["credentialSubject"]["dateOfBirth"]=dossier["extracted_data"]["identity"][0]["birth_date"] #gerer infos disponibles
    if vc_type=="Over18":
        credential = json.load(open('Over18.jsonld', 'r'))
        credential["credentialSubject"]["kycProvider"]="id360"
        credential["credentialSubject"]["kycId"]=pickle.loads(red.get(code))["id_dossier"]
        credential["credentialSubject"]["kycMethod"]=parcours_non_substantiel
    credential["issuer"] = issuer_did 
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
    
    if request.method == 'GET': 
        if vc_type=="VerifiableId":
            credential_manifest = json.load(open('VerifiableId_credential_manifest.json', 'r'))
        if vc_type=="Over18":
            credential_manifest = json.load(open('Over18_credential_manifest.json', 'r'))

        credential_manifest['id'] = str(uuid.uuid1())
        #credential_manifest['evidence']['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())    
        credential['id'] = "urn:uuid:random" # for preview
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + timedelta(seconds = 600)).replace(microsecond=0).isoformat(),
            "credential_manifest" : credential_manifest
        }
        return jsonify(credential_offer)

    else :  #POST
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form['subject_id'] # for preview
        logging.info(request.form['subject_id'])
        #credential['evidence'][0]['id'] = "https://github.com/TalaoDAO/context#evidence"

        try :
            presentation = json.loads(request.form['presentation']) 
        except :
            logging.warning("presentation does not exist")
            return jsonify('Unauthorized'), 401
        if request.form['subject_id'] != presentation['holder'] :
            logging.warning("holder does not match subject")
            return jsonify('Unauthorized'), 401
        print(request.form['presentation'])
        presentation_result = json.loads(await didkit.verify_presentation(request.form['presentation'], '{}'))
        presentation_result['errors']=[]
        if presentation_result['errors'] : #HERE
            logging.warning("presentation failed  %s", presentation_result)
            return jsonify('Unauthorized'), 401
        if pickle.loads(red.get(code))["did"]!=json.loads(request.form['presentation'])["holder"]:
            logging.warning("invalid did  %s", presentation_result)
            return jsonify('Unauthorized'), 401
        print(presentation_result)
        #logging.info('credential = %s', credential)

        # credential signature 
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": issuer_vm
            }
        print(credential)
        signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                issuer_key)
        # followup function call through js
        """data = json.dumps({"code" : code,
                         'message' : 'Ok credential transfered'})
        red.publish('altme-identity', data)
        red.delete(code)"""
        # cerdential sent to wallet
        event_data = json.dumps({"type": "altmeTransfered", "code": code})
        red.publish('issuer', event_data) 
        return jsonify(signed_credential)

@app.route('/id360/static/<filename>',methods=['GET'])
def serve_static(filename):
    logging.info(filename)
    return send_file('./static/'+filename, download_name=filename)

if __name__ == '__main__':
   app.run(host="localhost", port=3000, debug=True)



#url => code
#gerer saut d'étape
#ajouter tous les status id360
