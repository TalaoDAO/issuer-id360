"""
Issuer for ID360

Flow is available at https://swimlanes.io/u/LHNjN55XM

"""
import requests
import json
from flask import Flask, render_template, request, jsonify, Response, send_file, session, redirect
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
from flask_mobility import Mobility

ISSUER_KEY = json.dumps(json.load(open("keys.json", "r"))[
                        'talao_Ed25519_private_key'])
TALAO_USERNAME = json.load(open("keys.json", "r"))['username']
TALAO_PASSWORD = json.load(open("keys.json", "r"))['password']
ISSUER_VM = "did:web:app.altme.io:issuer#key-1"
ISSUER_DID = "did:web:app.altme.io:issuer"
CREDENTIAL_LIFE = 360  # in days
AUTHENTICATION_DELAY = 600  # in seconds
CODE_LIFE = 600  # in seconds the delay between the call of the API to get the code and the reding of the authentication QRcode by the wallet
QRCODE_AUTHENTICATION_LIFE = 600
JOURNEY = "0dd7e3c1-c4a4-41a2-8b09-0ec992e38e2a"  # SVID
ID360_URL = 'https://preprod.id360docaposte.com/'
ID360_API_KEY = json.load(open("keys.json", "r"))['id360ApiKey']
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
Mobility(app)
myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'thierry'
myenv = "achille"
mode = environment.currentMode(myenv)
red = redis.Redis(host='127.0.0.1', port=6379, db=0)


def loginID360() -> str:
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
    response = requests.post(
        ID360_URL + 'api/1.0.0/user/login/', headers=headers, json=json_data)
    if response.status_code == 200:
        return response.json()["token"]
    else:
        logging.error(response.json())


def create_dossier(code: str, token: str, did: str) -> str:
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
        'client_reference': did,
        'callback_headers': {
            'code': code,
            'api-key': 'api-key-test',
        },
    }
    response = requests.post(
        ID360_URL + 'api/1.0.0/process/' + JOURNEY + '/enrollment/',
        headers=headers,
        json=json_data,
    )
    if response.status_code == 200:
        logging.info(response.json())
        id_dossier = response.json()["id"]
        temp_dict = pickle.loads(red.get(code))
        temp_dict["id_dossier"] = id_dossier
        red.setex(code, CODE_LIFE, pickle.dumps(temp_dict))

        api_key = response.json()["api_key"]
        return ID360_URL + 'static/process_ui/index.html#/enrollment/' + api_key+"?lang=en"
    else:
        logging.error(response.json())


def get_dossier(id_dossier :str, token :str) -> dict:
    """
    ID360 API call to get user data

    """
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token ' + token,
    }
    response = requests.get(
        ID360_URL + 'api/1.0.0/enrollment/'+str(id_dossier)+'/report/', headers=headers)

    if response.status_code == 200:
        # print(response.json())
        # print(response.content)
        # logging.info("dossier %s : %s", str(id_dossier), response.json())
        logging.info("type")
        logging.info(type(response.json()))
        return response.json()
    elif response.status_code == 404:
        logging.warning("dossier "+str(id_dossier)+" exipré")
        return ("expired")
    else:
        # logging.error("error requesting dossier status : %s",response.status_code)
        # print(response.json())
        # print(response.content)
        return response.status_code


@app.route('/id360/get_code')
def get_code():
    """
    This the first call customer side to get its code

    curl https://talao.co/id360/get_code?client_id=<client_id> -H "api-key":<your_api_key>
    returns {"code": <code>} 200

    the code returned is useful for one session for one user to get one credential
    returns {"error": <error_description>} with status code
    if an error occured
    """
    print(request.args)
    client_secret = request.headers.get('api-key')  # changer dans demo
    client_id = request.args.get('client_id')
    did = request.args.get('did')

    if not client_id or not client_secret:
        return jsonify("Incorrect API call"), 400
    if not db.test_api_key(client_id, client_secret):
        return jsonify("client not found"), 404
    # code = code_generator()
    code = str(uuid.uuid1())
    red.setex(code, CODE_LIFE, pickle.dumps({
        "is_code_valid": "True",
        "client_id": client_id,
        "did": did
    }))  # rajouter client_id
    return jsonify({"code": code})


@app.route('/id360/authenticate/<code>')
def login(code : str):
    print(request.args)

    try:
        try:
            print("redis")
            print(pickle.loads(red.get(code)))
            print("logged "+str(session.get('logged')))
        except:
            logging.warning("invalid link3")
            if not request.MOBILE:
                return render_template("error.html")
            else:
                return render_template("error_mobile.html")
        session["logged"] = True

        site_callback = request.args['callback']
        client_id = request.args['client_id']
        vc_type = request.args['vc_type']
        did = pickle.loads(red.get(code))["did"]
        logging.info("kyc status in db : ")
        kyc = db.get_user_kyc(did)
        if not kyc:
            logging.info(did+" never did kyc")
        else:
            logging.info(kyc)
        token = loginID360()
        temp_dict = pickle.loads(red.get(code))
        temp_dict["did"] = did
        temp_dict['token'] = token
        temp_dict["vc_type"] = vc_type
        temp_dict["site_callback"] = site_callback
        temp_dict["client_id"] = client_id

        if not kyc:
            temp_dict["first"] = True
            red.setex(code, AUTHENTICATION_DELAY, pickle.dumps(temp_dict))
            # we create the dossier for user
            link = create_dossier(code, token, did)

            return redirect(link)

        else:
            dossier = get_dossier(kyc[2], token)
            temp_dict["first"] = False
            if kyc[1] == "OK" and dossier != "expired":
                # temp_dict = pickle.loads(red.get(code))
                temp_dict["id_dossier"] = kyc[2]
                red.setex(code, AUTHENTICATION_DELAY, pickle.dumps(temp_dict))
                link = mode.server+"/id360/issuer/"+code
                return redirect(link)
            else:
                red.setex(code, AUTHENTICATION_DELAY,
                          pickle.dumps(temp_dict))  # setex
                # we create the dossier for user
                link = create_dossier(code, token, did)
                return redirect(link)

    except KeyError:
        if not request.MOBILE:
            return render_template("error.html")
        else:
            return render_template("error_mobile.html")


@app.route('/id360/issuer/<code>',  defaults={'red': red})
def issuer(code : str, red):
    """
    This is the call back for browser
    """
    print("redis1")

    try:
        print("redis")
        print(pickle.loads(red.get(code)))
        print("logged "+str(session.get('logged')))
    except:
        logging.warning("invalid link1")
        if not request.MOBILE:
            return render_template("error.html")
        else:
            return render_template("error_mobile.html", error_title="Invalid link", error_description="This code does not coressond to a correct session.", card="VerifiableId")
    if session.get('logged'):
        site_callback = pickle.loads(red.get(code))["site_callback"]
        try:
            code_error = pickle.loads(red.get(code))["code_error"]
            card = pickle.loads(red.get(code))["vc_type"]
            
            if code_error == "410":
                error_title = "KYC Verification Failed"
                error_description = "Sorry, we encountered an issue while verifying your ID. Please try again later." # TODO mettre le vrai message
            if code_error == "411":
                error_title = "Age Verification Failed"
                error_description = "We were unable to verify the required age for " + vc_type + ". Please ensure the information provided is accurate."
            if code_error == "412":
                error_title = "Age Requirement Not Met"
                error_description = "You must be older to obtain this verifiable credential. Please ensure you meet the age requirement."
            if code_error == "413":
                error_title = "Incomplete Information"
                error_description = "Oops! It seems like some required information is missing. Please provide all necessary details to continue."
            print("delete code 266")
            red.delete(code)
            if not request.MOBILE:
                return render_template("error.html")
            else:
                return render_template("error_mobile.html", error_title=error_title, error_description=error_description, card=card,url=site_callback)

        except:
            pass

        vc_type = pickle.loads(red.get(code))["vc_type"]
        if (vc_type == "VerifiableId"):
            verified = "ID"
        else:
            verified = "age"
        if not request.MOBILE:
            return render_template("issuer.html", code=code,  url=mode.server+"/id360/issuer_endpoint/" + code)

        else:
            return render_template("issuer_mobile.html", code=code,  url=site_callback+"?uri="+mode.server+"/id360/issuer_endpoint/" + code, card=vc_type, verified=verified)

    logging.warning("invalid link2")
    if not request.MOBILE:
        return render_template("error.html")
    else:
        return render_template("error_mobile.html")


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
def id360callback(code :str, red):
    """
    Callback route for ID360
    """
    try:
        if request.headers["api-key"] != "api-key-test":
            return jsonify("Unauthorized"), 403
    except KeyError:
        return jsonify("Unauthorized"), 403

    logging.info("reception of id360 callback for %s", code)
    token = pickle.loads(red.get(code))["token"]
    id_dossier = pickle.loads(red.get(code))["id_dossier"]
    did = pickle.loads(red.get(code))["did"]
    vc_type = pickle.loads(red.get(code))["vc_type"]

    logging.info('callback for wallet DID = %s', did)
    print(request.get_json())

    # dossier = get_dossier(id_dossier, token)
    dossier = request.get_json()
    if (dossier["status"] == "NEW" or dossier["status"] == "STARTED"):
        return jsonify("ok"), 200
    try:
        if pickle.loads(red.get(code))["first"] == True:
            db.insert_kyc(did, dossier["status"], id_dossier)
        else:
            db.update_kyc(did, dossier["status"], id_dossier)
    except KeyError:
        red.setex(code, CODE_LIFE, pickle.dumps(
            {"code_error": "413", "vc_type": vc_type}))  # ERROR : saut d'étape
        return jsonify("ok")
    if (dossier["status"] != "OK"):
        red.setex(code, CODE_LIFE, pickle.dumps(
            {"code_error": "410", "vc_type": vc_type}))  # ERROR : KYC KO
        return jsonify("ok")
    if (vc_type == "Over13" or vc_type == "Over15" or vc_type == "Over18"):
        birth_date = dossier["extracted_data"]["identity"][0].get("birth_date")
        if not birth_date:
            print("deleting code 495")
            # ERROR : Age VC demandé mais pas d'âge dans le dossier
            red.setex(code, CODE_LIFE, pickle.dumps(
                {"vc_type": vc_type, "code_error": "411"}))
            return jsonify("ok")
        timestamp = ciso8601.parse_datetime(birth_date)
        timestamp = time.mktime(timestamp.timetuple())
        now = time.time()
    if (vc_type == "Over18" and (now-timestamp) < 31556926*18) or (vc_type == "Over15" and (now-timestamp) < 31556926*15) or (vc_type == "Over13" and (now-timestamp) < 31556926*13):
        print("deleting code 506")
        # ERROR : Over18 demandé mais user mineur
        red.setex(code, CODE_LIFE, pickle.dumps(
            {"code_error": "412", "vc_type": vc_type}))
        # red.delete(code)
        return jsonify("ok")
    url = mode.server+"/id360/issuer_endpoint/" + code
    event_data = json.dumps({"type": "callback", "code": code, "url": url})
    red.publish('qr_code', event_data)
    return jsonify("ok")


@app.route('/id360/issuer_endpoint/<code>', methods=['GET', 'POST'],  defaults={'red': red})
async def vc_endpoint(code :str, red):
    """
    Issuer for verifiableID and Over18 JSON-LD credentials
    Flow is available here https://swimlanes.io/u/XAjNWWtYC

    """
    vc_type = pickle.loads(red.get(code))["vc_type"]
    token = pickle.loads(red.get(code))["token"]
    dossier = get_dossier(pickle.loads(red.get(code))["id_dossier"], token)
    print("dossier :")
    print(dossier)
    credential = json.load(open('./verifiable_credentials/'+vc_type+'.jsonld', 'r'))

    if vc_type == "VerifiableId":
        try:
            credential["credentialSubject"]["familyName"] = dossier["extracted_data"]["identity"][0]["name"]
        except:
            logging.error("no name in dossier")
        try:
            credential["credentialSubject"]["firstName"] = dossier["extracted_data"]["identity"][0]["first_names"][0]
        except:
            pass
        credential["credentialSubject"]["dateOfBirth"] = dossier["extracted_data"]["identity"][0].get(
            "birth_date", "Not available")  # gerer infos disponibles
        # TODO add other data if available
    elif vc_type == "AgeRange":
        birth_date = dossier["extracted_data"]["identity"][0].get(
            "birth_date", "Not available")
        year = birth_date.split('-')[0]
        month = birth_date.split('-')[1]
        day = birth_date.split('-')[2]
        date13 = datetime(int(year) + 13, int(month), int(day))
        date18 = datetime(int(year) + 18, int(month), int(day))
        date25 = datetime(int(year) + 25, int(month), int(day))
        date35 = datetime(int(year) + 35, int(month), int(day))
        date45 = datetime(int(year) + 45, int(month), int(day))
        date55 = datetime(int(year) + 55, int(month), int(day))
        date65 = datetime(int(year) + 65, int(month), int(day))
        
        if datetime.now() < date13 :
            credential['credentialSubject']['ageRange'] = "-13"
        elif datetime.now() < date18 :
            credential['credentialSubject']['ageRange'] = "14-17"
        elif datetime.now() < date25 :
            credential['credentialSubject']['ageRange'] = "18-24"
        elif datetime.now() < date35 :
            credential['credentialSubject']['ageRange'] = "25-34"
        elif datetime.now() < date45 :
            credential['credentialSubject']['ageRange'] = "35-44"
        elif datetime.now() < date55 :
            credential['credentialSubject']['ageRange'] = "45-54"
        elif datetime.now() < date65 :
            credential['credentialSubject']['ageRange'] = "55-64"
        else :
            credential['credentialSubject']['ageRange'] = "65+"
    else:
        credential["credentialSubject"]["kycProvider"] = "ID360"
        credential["credentialSubject"]["kycId"] = pickle.loads(red.get(code))[
            "id_dossier"]
        credential["credentialSubject"]["kycMethod"] = JOURNEY
    credential["issuer"] = ISSUER_DID
    credential['issuanceDate'] = datetime.utcnow().replace(
        microsecond=0).isoformat() + "Z"
    credential['expirationDate'] = (
        datetime.now() + timedelta(days=CREDENTIAL_LIFE)).isoformat() + "Z"

    if request.method == 'GET':

        credential_manifest = json.load(open('./credential_manifest/'+vc_type+'_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = ISSUER_DID
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential['id'] = "urn:uuid:random"  # for preview only
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires": (datetime.now() + timedelta(seconds=CODE_LIFE)).replace(microsecond=0).isoformat(),
            "credential_manifest": credential_manifest
        }
        return jsonify(credential_offer)

    else:  # POST
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form['subject_id']
        try:
            presentation = json.loads(request.form['presentation'])
        except:
            logging.warning("presentation does not exist")
            print("deleting code 608")
            red.delete(code)
            # ERROR : presentation does not exist
            event_data = json.dumps(
                {"type": "error", "code": code, "error": "430"})
            red.publish('issuer', event_data)
            return jsonify('Unauthorized'), 401
        if request.form['subject_id'] != presentation['holder']:
            logging.warning("holder does not match subject")
            print("deleting code 613")
            red.delete(code)
            # ERROR : holder does not match subject
            event_data = json.dumps(
                {"type": "error", "code": code, "error": "431"})
            red.publish('issuer', event_data)
            return jsonify('Unauthorized'), 401
        presentation_result = json.loads(await didkit.verify_presentation(request.form['presentation'], '{}'))
        presentation_result['errors'] = []  # FIXME
        if presentation_result['errors']:  # push erreur sur stream
            logging.warning("presentation failed  %s", presentation_result)
            print("deleting code 620")
            red.delete(code)  # ERROR : presentation failed
            event_data = json.dumps(
                {"type": "error", "code": code, "error": "432"})
            red.publish('issuer', event_data)
            return jsonify('Unauthorized'), 401
        if pickle.loads(red.get(code))["did"] != json.loads(request.form['presentation'])["holder"]:
            logging.warning("invalid did  %s", presentation_result)
            print("deleting code 625")
            red.delete(code)  # ERROR : invalid did
            event_data = json.dumps(
                {"type": "error", "code": code, "error": "433"})
            red.publish('issuer', event_data)
            return jsonify('Unauthorized'), 401
        # credential signature
        didkit_options = {
            "proofPurpose": "assertionMethod",
            "verificationMethod": ISSUER_VM
        }
        signed_credential = await didkit.issue_credential(
            json.dumps(credential),
            didkit_options.__str__().replace("'", '"'),
            ISSUER_KEY)
        # followup function call through js
        """data = json.dumps({"code" : code,
                         'message' : 'Ok credential transfered'})
        red.publish('altme-identity', data)
        red.delete(code)"""
        # update issuer screen
        event_data = json.dumps(
            {"type": "altmeTransfered", "code": code, "vc": vc_type})
        red.publish('issuer', event_data)

        # we delete the code and send the credential
        print("deleting code 647")
        red.delete(code)
        data = {"vc" :  vc_type, "count" : "1" }
        logging.info(requests.post('https://issuer.talao.co/counter/update', data=data).json())
        return jsonify(signed_credential)


@app.route('/id360/static/<filename>', methods=['GET'])
def serve_static(filename : str):
    return send_file('./static/' + filename, download_name=filename)


@app.route('/id360/jeprouvemonage')
def jeprouvemonage():
    return render_template("jeprouvemonage.html", url="https://altme.io")


if __name__ == '__main__':
    app.run(host=mode.IP, port=mode.port, debug=True)


# 30 minutes minimum config parcours
