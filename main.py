"""
Issuer for ID360

Flow is available at https://swimlanes.io/u/LHNjN55XM

"""
import requests
import json
from flask import Flask, render_template, request, jsonify, Response, send_file
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
import random
import string
import db
import ciso8601

ISSUER_KEY = json.dumps(json.load(open("keys.json", "r"))['talao_Ed25519_private_key'])
TALAO_USERNAME = json.load(open("keys.json", "r"))['username']
TALAO_PASSWORD = json.load(open("keys.json", "r"))['password']
ISSUER_VM = "did:web:app.altme.io:issuer#key-1"
ISSUER_DID = "did:web:app.altme.io:issuer"
CREDENTIAL_LIFE = 360 # in days
AUTHENTICATION_DELAY = 600 # in seconds
CODE_LIFE = 600 # in seconds the delay between the call of the API to get the code and the reding of the authentication QRcode by the wallet
QRCODE_AUTHENTICATION_LIFE = 600
JOURNEY = "0dd7e3c1-c4a4-41a2-8b09-0ec992e38e2a" # SVID
ID360_URL = 'https://preprod.id360docaposte.com/'
DIDAuth = {
    "type": "VerifiablePresentationRequest",
    "query": [
        {
            "type": "DIDAuth"
        }
    ],
}

app = Flask(__name__)
app.secret_key = """json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])"""
qrcode = QRcode(app)
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'thierry'
myenv = "achille"
mode = environment.currentMode(myenv)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)


def loginID360():
    """
    ID360 API call for login
    return token if ok False if not
    """
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
    }
    json_data = {
        'username': TALAO_USERNAME, 
        'password': TALAO_PASSWORD,
    }
    response = requests.post(ID360_URL + 'api/1.0.0/user/login/', headers=headers, json=json_data)
    if response.status_code==200:
        return response.json()["token"]
    else:
        logging.error(response.json())


def create_dossier(code,token): 
    """
    ID360 API call to create dossier on ID360
    """
    logging.info("creating dossier with token %s", token)
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token ' + token,
        'Content-Type': 'application/json',
    }
    json_data = {
        'callback_url': mode.server+'/id360/callback_id360/' + code,
        'browser_callback_url': mode.server+'/id360/issuer/' + code,
        'client_reference': 'any_string',
        'callback_headers': {
            'header_name_1': code,
            'header_name_2': 'header_value_2',
        },
    }
    response = requests.post(
        ID360_URL + 'api/1.0.0/process/' + JOURNEY + '/enrollment/',
        headers=headers,
        json=json_data,
    )
    if response.status_code==200:
        logging.info(response.json())
        id_dossier = response.json()["id"]
        temp_dict = pickle.loads(red.get(code))
        temp_dict["id_dossier"] = id_dossier
        red.setex(code, CODE_LIFE, pickle.dumps(temp_dict))  

        api_key = response.json()["api_key"]
        return ID360_URL + 'static/process_ui/index.html#/enrollment/' + api_key
    else:
        logging.error(response.json())


def get_dossier(id_dossier,token):
    """
    ID360 API call to get user data
    
    """
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token ' + token,
    }
    response = requests.get(ID360_URL + 'api/1.0.0/enrollment/'+str(id_dossier)+'/report/', headers=headers)
    if response.status_code == 200:
        logging.info("dossier %s : %s", str(id_dossier), response.json())
        return response.json()
    else:
        logging.error("error requesting dossier status : %s", response.status_code)
        print(response.json())


def code_generator():
    """
    Utils, generate a code of 6 caracteres
    """
    characters = string.digits+string.ascii_lowercase
    return ''.join(random.choice(characters) for i in range(6))


@app.route('/id360/get_code')
def get_code():
    """
    This the first call customer side to get its code

    curl https://talao.co/id360/get_code?client_id=<client_id> -H "apiKey":<your_api_key>
    returns {"code": <code>} 200

    the code returned is useful for one session for one user to get one credential
    returns {"error": <error_description>} with status code
    if an error occured
    """
    client_secret = request.headers.get('apiKey')
    client_id = request.args.get('client_id')
    if not client_id or not client_secret :
        return jsonify("Incorrect API call"),400
    if not db.test_api_key(client_id, client_secret) :
        return jsonify("client not found"),404
    code = code_generator() 
    red.setex(code, CODE_LIFE, 'True')
    return jsonify({"code":code})
    

@app.route('/id360/authenticate/<code>') 
def login(code):
    """
    To redirect user to QRcode for wallet authentication

    construciton url + description args + verifier liste callback"""
    try:
        site_callback = request.args['callback']
        client_id = request.args['client_id']
        vc_type = request.args['vc_type']
    except KeyError:
        logging.warning("KeyError in /authenticate")
    """
    try:
        if red.get(code).decode() != "True":
            return jsonify("invalid link"),403
    except:
        return jsonify("invalid link"),403
    """
    # for thierry testing only
    #site_callback = "test"  # for testing only
    #client_id = "1"  # for testing only
    #vc_type = "verifiableid"  # for testing only
    # http://192.168.0.187:5000/id360/authenticate/111111

    DIDAuth['challenge'] = str(uuid.uuid1())
    DIDAuth['domain'] = mode.server
    red.setex(code,QRCODE_AUTHENTICATION_LIFE, pickle.dumps ({
        "pattern":json.dumps(DIDAuth),
        "site_callback":site_callback,
        "client_id":client_id,
        "vc_type":vc_type
    })) 
    url = mode.server+'/id360/endpoint/' + code
    return render_template("login.html", url=url, code=code)


@app.route('/id360/issuer/<code>',  defaults={'red': red}) 
def issuer(code, red):
    """
    This is the call back for browser
    """
    try :
        site_callback = pickle.loads(red.get(code))['site_callback']
    except :
        # TODO
        logging.warning("delay expired to get the browser callback")
        pass
    return render_template("issuer.html", code=code,callback=site_callback)


@app.route('/id360/endpoint/<code>', methods=['GET', 'POST'],  defaults={'red': red})
async def presentation_endpoint(code, red):
    """
    This used to authenticate the wallet
    Protocol is defined here https://w3c-ccg.github.io/vp-request-spec/#did-authentication
    This protocol is between the backend of the issuer and the wallet
    """
    if request.method == 'GET':
        try:
            my_pattern = pickle.loads(red.get(code))["pattern"]
        except:
            event_data = json.dumps({"code": code,
                                "message": "redis decode failed",
                                "check": "ko",
                                "type": "login","url":pickle.loads(red.get(code))["site_callback"]})
            red.publish('verifier', event_data)
            return jsonify("server error"), 500
        return jsonify(my_pattern)

    if request.method == 'POST':
        # create the ID360 token for this journey
        token = loginID360()
        if not token :
            pass # TODO
        result = json.loads(await didkit.verify_presentation(request.form['presentation'], '{}'))
        logging.info('result fo didkit verify = %s',  result['errors'])
        result['errors'] = [] # FIXME 
        if result['errors']:
            event_data = json.dumps({"code": code,
                                    "check": "ko",
                                     "message": result,
                                     "type": "login"})
            red.publish('verifier', event_data)
            return jsonify(result), 403
        # update of code in redis with same delay, we add the ID360 token just created
        temp_dict = pickle.loads(red.get(code))
        temp_dict["did"]=json.loads(request.form['presentation'])["holder"]
        temp_dict['token'] = token
        red.setex(code, AUTHENTICATION_DELAY,  pickle.dumps(temp_dict)) 
        kyc = db.get_user_kyc(pickle.loads(red.get(code))["did"])
        if not kyc  or kyc[1] == "KO" :
            temp_dict = pickle.loads(red.get(code))
            if not kyc:
                temp_dict["first"] = True 
            else:
                temp_dict["first"] = False
            red.setex(code, AUTHENTICATION_DELAY,  pickle.dumps(temp_dict)) #setex
            # we create the dossier for user
            link = create_dossier(code,token)
            event_data = json.dumps({"code": code,
                                        "message": "presentation is verified",
                                        "check": "ok",
                                        "link": link,
                                        "type": "login"
                                        })
            logging.info("sent with link = %s", link)
            red.publish('verifier', event_data)
            return jsonify("ok")
        elif kyc[1] == "OK":
            temp_dict = pickle.loads(red.get(code))
            temp_dict["did"] = json.loads(request.form['presentation'])["holder"]
            temp_dict["id_dossier"] = kyc[2] 
            temp_dict["first"] = False
            """red.setex(code,CODE_LIFE ,pickle.dumps({"did": json.loads(request.form['presentation'])[
                    "holder"], "id_dossier": kyc[2], "first": False}))"""
            red.setex(code, AUTHENTICATION_DELAY, pickle.dumps(temp_dict))
            event_data = json.dumps({"code": code,
                                        "message": "presentation is verified",
                                        "check": "ok",
                                        "link": mode.server+"/id360/issuer/"+code,
                                        "type": "login"
                                        })
            red.publish('verifier', event_data)
            return jsonify("ok"), 200  


@app.route('/id360/verifier_stream', methods=['GET'],  defaults={'red': red})
def presentation_stream(red):
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
def id360callback(code, red):
    """
    Callback route for ID360
    """
    logging.info("reception of id360 callback for %s", code)
    token = pickle.loads(red.get(code))["token"]
    id_dossier = pickle.loads(red.get(code))["id_dossier"]
    did = pickle.loads(red.get(code))["did"]
    logging.info('callback for wallet DID = %s', did)
    dossier = get_dossier(id_dossier,token)
    birth_date = dossier["extracted_data"]["identity"][0].get("birth_date")
    if not birth_date :
        # TODO
        pass
    timestamp = ciso8601.parse_datetime(birth_date)
    # to get time in seconds:
    timestamp=time.mktime(timestamp.timetuple())
    now= time.time()
    vc_type = pickle.loads(red.get(code))["vc_type"]
    if(dossier["status"]!="OK" or (vc_type=="Over18" and (now-timestamp)<31556926*18 )):
        url = pickle.loads(red.get(code))["site_callback"] + "/400"
        event_data = json.dumps({"type": "callbackErr", "code": code, "url": url})
        red.publish('qr_code', event_data)
        return jsonify("ok")
    url = mode.server+"/id360/issuer_endpoint/" + code
    event_data = json.dumps({"type": "callback", "code": code, "url": url})
    red.publish('qr_code', event_data) 
    return jsonify("ok")


@app.route('/id360/get_qrcode/<code>', methods=['GET'],  defaults={'red': red})
def get_qrcode(code, red):
    """
    TODO
    ?????
    """
    token = pickle.loads(red.get(code))["token"]
    id_dossier = pickle.loads(red.get(code))["id_dossier"]
    did = pickle.loads(red.get(code))["did"]
    vc_type = pickle.loads(red.get(code))["vc_type"]
    dossier = get_dossier(id_dossier,token)
    birth_date = dossier["extracted_data"]["identity"][0].get("birth_date")
    # TODO if birthdate == None
    timestamp = ciso8601.parse_datetime(birth_date)
    # to get time in seconds:
    timestamp = time.mktime(timestamp.timetuple())
    now = time.time()
    if pickle.loads(red.get(code))["first"] == True:
        db.insert_kyc(did, dossier["status"], id_dossier)
    else:
        db.update_kyc(did, dossier["status"], id_dossier)
    try:
        if(dossier["status"] == "OK" ): #or dossier["status"]=="KO"
            if(vc_type=="Over18" and (now-timestamp)>31556926*18 ) or vc_type != "Over18":
                return jsonify({"url" : mode.server+"/id360/issuer_endpoint/" + code})
        else:
            return jsonify({"url":"error"})
    except TypeError:
        return jsonify({"url":"not yet"})
    except KeyError:
        return jsonify({"url":"error"}),500


@app.route('/id360/issuer_endpoint/<code>', methods = ['GET','POST'],  defaults={'red' : red})
async def vc_endpoint(code, red):  
    """
    Issuer for verifiableID and Over18 JSON-LD credentials
    Flow is available here https://swimlanes.io/u/XAjNWWtYC

    """
    vc_type=pickle.loads(red.get(code))["vc_type"]
    token = pickle.loads(red.get(code))["token"]
    dossier= get_dossier(pickle.loads(red.get(code))["id_dossier"],token)
    if vc_type=="VerifiableId":
        credential = json.load(open('./verifiable_credentials/VerifiableId.jsonld', 'r'))
        credential["credentialSubject"]["familyName"]=dossier["extracted_data"]["identity"][0]["name"]
        credential["credentialSubject"]["firstName"]=dossier["extracted_data"]["identity"][0]["first_names"][0]
        credential["credentialSubject"]["dateOfBirth"]=dossier["extracted_data"]["identity"][0].get("birth_date", "Not available") #gerer infos disponibles
        # TODO add other data if available
    if vc_type=="Over18":
        credential = json.load(open('./verifiable_credentials/Over18.jsonld', 'r'))
        credential["credentialSubject"]["kycProvider"]="ID360"
        credential["credentialSubject"]["kycId"]=pickle.loads(red.get(code))["id_dossier"]
        credential["credentialSubject"]["kycMethod"] = JOURNEY
    credential["issuer"] = ISSUER_DID
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now() + timedelta(days= CREDENTIAL_LIFE)).isoformat() + "Z"
    
    if request.method == 'GET': 
        if vc_type=="VerifiableId":
            credential_manifest = json.load(open('./credential_manifest/VerifiableId_credential_manifest.json', 'r'))
        if vc_type=="Over18":
            credential_manifest = json.load(open('./credential_manifest/Over18_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = ISSUER_DID
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())    
        credential['id'] = "urn:uuid:random" # for preview only
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + timedelta(seconds = CODE_LIFE)).replace(microsecond=0).isoformat(),
            "credential_manifest" : credential_manifest
        }
        return jsonify(credential_offer)

    else :  #POST
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form['subject_id']
        try :
            presentation = json.loads(request.form['presentation']) 
        except :
            logging.warning("presentation does not exist")
            return jsonify('Unauthorized'), 401
        if request.form['subject_id'] != presentation['holder'] :
            logging.warning("holder does not match subject")
            return jsonify('Unauthorized'), 401
        presentation_result = json.loads(await didkit.verify_presentation(request.form['presentation'], '{}'))
        presentation_result['errors']=[] # FIXME
        if presentation_result['errors'] : 
            logging.warning("presentation failed  %s", presentation_result)
            return jsonify('Unauthorized'), 401
        if pickle.loads(red.get(code))["did"] != json.loads(request.form['presentation'])["holder"]:
            logging.warning("invalid did  %s", presentation_result)
            return jsonify('Unauthorized'), 401
        # credential signature 
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": ISSUER_VM
            }
        signed_credential =  await didkit.issue_credential(
                json.dumps(credential),
                didkit_options.__str__().replace("'", '"'),
                ISSUER_KEY)
        # followup function call through js
        """data = json.dumps({"code" : code,
                         'message' : 'Ok credential transfered'})
        red.publish('altme-identity', data)
        red.delete(code)"""
        # update issuer screen
        event_data = json.dumps({"type": "altmeTransfered", "code": code})
        red.publish('issuer', event_data) 

        # we delete the code and send the credential
        red.delete(code)
        return jsonify(signed_credential)


@app.route('/id360/static/<filename>',methods=['GET'])
def serve_static(filename):
    return send_file('./static/' + filename, download_name=filename)

if __name__ == '__main__':
   app.run(host=mode.IP, port= mode.port, debug=True)

