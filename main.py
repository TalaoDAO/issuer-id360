"""
Issuer for ID360

Flow is available at https://swimlanes.io/u/LHNjN55XM

"""
import requests
import json
from flask import Flask, render_template, request, jsonify, Response, send_file, session, redirect,url_for
from flask_qrcode import QRcode
import didkit
import environment
import redis
import uuid
import time
from datetime import datetime, timedelta
import logging
import pickle
import db
import ciso8601
from flask_mobility import Mobility
from id360 import JOURNEY, URL, ID360_API_KEY, USERNAME, PASSWORD, ISSUER_VM, ISSUER_DID, ISSUER_KEY

ERRORS = json.load(open("errors.json", "r"))
WALLETS = json.load(open("wallets.json", "r"))
CREDENTIAL_LIFE = 360  # in days
AUTHENTICATION_DELAY = 600  # in seconds
CODE_LIFE = 600  # in seconds the delay between the call of the API to get the code and the reding of the authentication QRcode by the wallet
QRCODE_AUTHENTICATION_LIFE = 600
PEP_URL = 'https://pepchecker.com/api/v1/'
BANNED_COUNTRIES = ["AFG", "BRB", "BFA", "KHM", "CYM", "COD", "PRK", "GIB", "HTI", "IRN", "JAM", "JOR",
                    "MLI", "MAR", "MOZ", "MMR", "PAN", "PHL", "SEN", "SSD", "SYR", "TZA", "TTO", "UGA", "ARE", "VUT", "YEM"]
PROD_API_KEY_PEP = json.load(open("keys.json", "r"))['pepApiKey']
ONE_YEAR = 31556926  # seconds
app = Flask(__name__)
app.secret_key = json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])
qrcode = QRcode(app)
Mobility(app)
myenv = "aws"
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
        'username': USERNAME,
        'password': PASSWORD,
    }
    response = requests.post(
        URL + 'api/1.0.0/user/login/', headers=headers, json=json_data)
    if response.status_code == 200:
        token = response.json()["token"]
        return token
    else:
        logging.error(response.json())
        return


def create_dossier(code: str, token: str, did: str) -> str:
    """
    ID360 API call to create dossier on ID360
    """
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
            'api-key': ID360_API_KEY,  # passer api key prod
        },
    }
    response = requests.post(
        URL + 'api/1.0.0/process/' + JOURNEY + '/enrollment/',
        headers=headers,
        json=json_data,
    )
    if response.status_code == 200:
        try:
            temp_dict = pickle.loads(red.get(code))
        except:
            logging.error("redis expired %s", code)
            return
        temp_dict["id_dossier"] = response.json()["id"]
        red.setex(code, CODE_LIFE, pickle.dumps(temp_dict))
        return URL + 'static/process_ui/index.html#/enrollment/' + response.json()["api_key"] + "?lang=fr"
    else:
        logging.error(response.json())
        return


def get_dossier(id_dossier: str, token: str) -> dict:
    """
    ID360 API call to get user data

    """
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token ' + token,
    }
    response = requests.get(URL + 'api/1.0.0/enrollment/' +
                            str(id_dossier)+'/report/', headers=headers)
    if response.status_code == 200: 
        return response.json()
    elif response.status_code == 404:
        logging.warning("dossier "+str(id_dossier)+" expiré")
        return "expired"
    else:
        logging.error("error requesting dossier status : %s",
                      response.status_code)
        return response.status_code


def pep(firstname: str, lastname: str):
    """
    Function checking pep sanctions by name and lastname
    see https://pepchecker.com/
    """
    logging.info("testing pep for %s %s",firstname,lastname)  #  mettre des %s
    response = requests.get(PEP_URL + 'check?firstName=' + firstname + '&lastName=' + lastname, headers={'api-key':  PROD_API_KEY_PEP})
    logging.info('PEP = %s', response.json())
    return not response.json()['sanctionList']


def check_country(country_code: str):
    """
    Function checking high risk countries by country code
    see https://finance.ec.europa.eu/financial-crime/high-risk-third-countries-and-international-context-content-anti-money-laundering-and-countering_en
    """
    if country_code in BANNED_COUNTRIES:
        return
    return True


def check_birth_date(birth_date: str):
    """
    function checking if a birth date is correctly extracted
    """
    if (birth_date == None):
        return "Not available"
    year = birth_date.split("-")[0]
    if int(year) > 2023:
        return str(int(year)-100)+"-"+birth_date.split("-")[1]+"-"+birth_date.split("-")[2]
    else:
        return birth_date


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
    client_secret = request.headers.get('api-key')
    client_id = request.args.get('client_id')
    did = request.args.get('did')
    if not client_id or not client_secret or not did:
        return jsonify("Incorrect API call"), 400
    if not db.test_api_key(client_id, client_secret):
        return jsonify("client not found"), 404
    wallet_callback = WALLETS.get(client_id)[1]
    code = str(uuid.uuid1())
    red.setex(code, CODE_LIFE, pickle.dumps({
        "client_id": client_id,
        "did": did,
        "wallet_callback": wallet_callback
    }))
    return jsonify({"code": code})


@app.route('/id360/authenticate/<code>')
def login(code: str):
    """
    first route redirecting user to id360 ui or issuer if a kyc he already completed a kyc
    """
    token = loginID360()
    if not token:
        return redirect(url_for('error', code_error="internal_error"))
    try:
        did = pickle.loads(red.get(code))["did"]
        wallet_callback = pickle.loads(red.get(code))['wallet_callback']
        client_id = pickle.loads(red.get(code))['client_id']
    except:
        return redirect(url_for('error', code_error="internal_error"))
    try:
        vc_type = request.args['vc_type']
    except KeyError:  # missing an arg
        return redirect(url_for('error', code_error="internal_error"))
    kyc = db.get_user_kyc(did)
    temp_dict = {
        "did":did,
        "token":token,
        "vc_type":vc_type,
        "wallet_callback":wallet_callback,
        "client_id":client_id
    }
    session["logged"] = True
    if not kyc:
        temp_dict["first"] = True
        red.setex(code, AUTHENTICATION_DELAY, pickle.dumps(temp_dict))
        return redirect(create_dossier(code, token, did))
    else:
        dossier = get_dossier(kyc[2], token)
        temp_dict["first"] = False
        if (kyc[1] != "OK" or type(dossier) != dict):
            red.setex(code, AUTHENTICATION_DELAY, pickle.dumps(temp_dict))
            return redirect(create_dossier(code, token, did))
        birth_date = check_birth_date(dossier["identity"].get("birth_date"))
        if vc_type != "VerifiableId" and birth_date == "Not available":
            red.setex(code, AUTHENTICATION_DELAY, pickle.dumps(temp_dict))
            return redirect(create_dossier(code, token, did))
        else:
            if (vc_type == "Over18" or vc_type == "Over15" or vc_type == "Over13"):
                timestamp = time.mktime(ciso8601.parse_datetime(birth_date).timetuple())
                now = time.time()
                if (vc_type == "Over18" and (now-timestamp) < ONE_YEAR*18) or (vc_type == "Over15" and (now-timestamp) < ONE_YEAR*15) or (vc_type == "Over13" and (now-timestamp) < ONE_YEAR*13):
                    return redirect(url_for('error', code_error="age_requirement_failed", card=vc_type))
            temp_dict["id_dossier"] = kyc[2]
            red.setex(code, AUTHENTICATION_DELAY, pickle.dumps(temp_dict))
            link = mode.server+"/id360/issuer/"+code
        return redirect(link)


@app.route('/id360/issuer/<code>',  defaults={'red': red})
def issuer(code: str, red):
    """
    This is the call back for browser
    """
    try:
        pickle.loads(red.get(code))
    except:
        logging.error("redis expired %s", code)
        return redirect(url_for('error', code_error="internal_error"))
    if session.get('logged'):
        try:
            code_error = pickle.loads(red.get(code))["code_error"]
            card = pickle.loads(red.get(code))["vc_type"]
            return redirect(url_for('error', code_error=code_error,card=card))
        except:
            wallet_callback = pickle.loads(red.get(code))["wallet_callback"]
            vc_type = pickle.loads(red.get(code))["vc_type"]
            if vc_type == "VerifiableId":
                verified = "ID"
            elif vc_type == "DefiCompliance":
                verified = "compliance"
            else:
                verified = "age"
            return render_template("issuer_mobile.html", code=code,  url=wallet_callback+"?uri="+mode.server+"/id360/issuer_endpoint/" + code, card=vc_type, verified=verified)
    return redirect(url_for('error', code_error="internal_error"))


@app.route('/id360/issuer_stream', methods=['GET'],  defaults={'red': red})
def issuer_stream(red):
    """
    a stream connected to issuer frontend to know when the verifiable credential has been succesfully added
    """
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
def id360callback(code: str, red):
    """
    Callback route for ID360
    """
    try:
        if request.headers["api-key"] != ID360_API_KEY:
            return jsonify("Unauthorized"), 403
    except KeyError:
        return jsonify("Unauthorized"), 403
    logging.info("reception of id360 callback for %s", code)
    try:
        id_dossier = pickle.loads(red.get(code))["id_dossier"]
        wallet_callback = pickle.loads(red.get(code))["wallet_callback"]
    except:
        logging.error("redis expired %s",code)
        red.setex(code, CODE_LIFE, pickle.dumps(
            {"code_error": "414", "vc_type": "VerifiableId"}))  # ERROR : REDIS EXPIRATION
        return jsonify("ok")
    did = pickle.loads(red.get(code))["did"]
    vc_type = pickle.loads(red.get(code))["vc_type"]
    logging.info('callback for wallet DID = %s is %s', did,request.get_json()["status"])
    dossier = request.get_json()
    if request.get_json()["status"] in ["CANCELED", "FAILED", "KO"]:
        red.setex(code, CODE_LIFE, pickle.dumps(
            {"code_error": "age_verification_failed", "vc_type": vc_type, "wallet_callback": wallet_callback}))  # ERROR : KYC KO
    elif request.get_json()["status"] == "OK":
        token = pickle.loads(red.get(code))["token"]
        dossier = get_dossier(pickle.loads(red.get(code))["id_dossier"], token)
        try:
            if pickle.loads(red.get(code))["first"] == True:
                db.insert_kyc(did, dossier["status"], id_dossier)
            else:
                db.update_kyc(did, dossier["status"], id_dossier)
        except KeyError:
            red.setex(code, CODE_LIFE, pickle.dumps(
                {"code_error": "413", "vc_type": vc_type, "wallet_callback": wallet_callback}))  # ERROR : saut d'étape
            return jsonify("ok")
        if (dossier["status"] != "OK"):
            red.setex(code, CODE_LIFE, pickle.dumps(
                {"code_error": "410", "vc_type": vc_type, "wallet_callback": wallet_callback}))  # ERROR : KYC KO
            return jsonify("KYC KO"), 412
        if (vc_type != "VerifiableId"):
            birth_date = check_birth_date(dossier["identity"].get("birth_date"))
            if not birth_date:
                # ERROR : Age VC demandé mais pas d'âge dans le dossier
                red.setex(code, CODE_LIFE, pickle.dumps(
                    {"vc_type": vc_type, "code_error": "411", "wallet_callback": wallet_callback}))
                return jsonify("ok")
            timestamp = time.mktime(ciso8601.parse_datetime(birth_date).timetuple())
            now = time.time()  
        if (vc_type == "Over18" and (now-timestamp) < ONE_YEAR*18) or (vc_type == "Over15" and (now-timestamp) < ONE_YEAR*15) or (vc_type == "Over13" and (now-timestamp) < ONE_YEAR*13):
            # ERROR : Over18 demandé mais user mineur
            red.setex(code, CODE_LIFE, pickle.dumps(
                {"code_error": "412", "vc_type": vc_type, "wallet_callback": wallet_callback}))
            return jsonify("ok")
        temp_dict = pickle.loads(red.get(code))
        temp_dict["kyc_method"]=dossier.get("id_verification_service")
        temp_dict["level"]=dossier.get("level")
        red.setex(code, CODE_LIFE, pickle.dumps(temp_dict))
    return jsonify("ok")


@app.route('/id360/issuer_endpoint/<code>', methods=['GET', 'POST'],  defaults={'red': red})
async def vc_endpoint(code: str, red):
    """
    Issuer for verifiableID and Over18 JSON-LD credentials
    Flow is available here https://swimlanes.io/u/XAjNWWtYC

    """
    vc_type = pickle.loads(red.get(code))["vc_type"]
    if request.method == 'GET':
        token = pickle.loads(red.get(code))["token"]
        dossier = get_dossier(pickle.loads(red.get(code))["id_dossier"], token)
        logging.info(dossier["identity"])
        credential = json.load(
            open('./verifiable_credentials/'+vc_type+'.jsonld', 'r'))
        if vc_type == "VerifiableId":
            try:
                credential["credentialSubject"]["familyName"] = dossier["identity"]["name"]
            except:
                logging.error("no familyName in dossier")
            try:
                credential["credentialSubject"]["firstName"] = dossier["identity"]["first_names"][0]
            except:
                logging.error("no firstName in dossier")
            try:
                credential["credentialSubject"]["gender"] = dossier["identity"]["gender"]
            except:
                logging.error("no gender in dossier")
            credential["credentialSubject"]["dateOfBirth"] = check_birth_date(
                dossier["identity"].get("birth_date", "Not available"))  # gerer infos disponibles
            # TODO add other data if available
            credential["evidence"][0]["id"] = "https://github.com/TalaoDAO/context/blob/main/context/VerificationMethod.jsonld/" + str(pickle.loads(red.get(code))["id_dossier"])
            credential["evidence"][0]["verificationMethod"] = pickle.loads(red.get(code)).get("kyc_method")
            credential["evidence"][0]["levelOfAssurance"] = pickle.loads(red.get(code)).get("level")
        elif vc_type == "AgeRange":
            birth_date = check_birth_date(
                dossier["identity"].get("birth_date", "Not available"))
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

            if datetime.now() < date13:
                credential['credentialSubject']['ageRange'] = "-13"
            elif datetime.now() < date18:
                credential['credentialSubject']['ageRange'] = "14-17"
            elif datetime.now() < date25:
                credential['credentialSubject']['ageRange'] = "18-24"
            elif datetime.now() < date35:
                credential['credentialSubject']['ageRange'] = "25-34"
            elif datetime.now() < date45:
                credential['credentialSubject']['ageRange'] = "35-44"
            elif datetime.now() < date55:
                credential['credentialSubject']['ageRange'] = "45-54"
            elif datetime.now() < date65:
                credential['credentialSubject']['ageRange'] = "55-64"
            else:
                credential['credentialSubject']['ageRange'] = "65+"
            credential["credentialSubject"]["kycProvider"] = "ID360"
            credential["credentialSubject"]["kycId"] = pickle.loads(red.get(code))[
                "id_dossier"]
            credential["credentialSubject"]["kycMethod"] = JOURNEY
        elif vc_type == "DefiCompliance":

            try:
                first_name = dossier["identity"]["first_names"][0]
                last_name = dossier["identity"]["name"]
                birth_date = check_birth_date(
                    dossier["identity"].get("birth_date", "Not available"))
                country_emission = dossier["steps"]["id_document"]["results"]["id_document_result"][0]["IDMRZCODEPAYSEMISSION"]
                if check_country(country_emission):
                    country_result = "Succeeded"
                else:
                    country_result = "Failed"
                credential['credentialSubject']['countryCheck'] = country_result
                current_date = datetime.now()
                date1 = datetime.strptime(
                    birth_date, '%Y-%m-%d') + timedelta(weeks=18*52)
                if (current_date > date1):
                    credential['credentialSubject']['ageCheck'] = "Succeeded"
                else:
                    credential['credentialSubject']['ageCheck'] = "Failed"
                # check sanction list
                if pep(first_name, last_name):
                    pep_result = "Succeeded"
                else:
                    pep_result = "Failed"
                credential['credentialSubject']['sanctionListCheck'] = pep_result
                # AML compliance
                if credential['credentialSubject']['sanctionListCheck'] == "Succeeded" and credential['credentialSubject']['ageCheck'] == "Succeeded" and credential['credentialSubject']['countryCheck'] == "Succeeded":
                    credential['credentialSubject']['amlComplianceCheck'] = "Succeeded"
                else:
                    credential['credentialSubject']['amlComplianceCheck'] = "Failed"
            except KeyError as e:
                logging.error(e)  # fusionner
                logging.error("miss data to issue a DefiCompliance VC")
        else:
            credential["credentialSubject"]["kycProvider"] = "ID360"
            credential["credentialSubject"]["kycId"] = pickle.loads(red.get(code))[
                "id_dossier"]
            credential["credentialSubject"]["kycMethod"] = JOURNEY

        credential["issuer"] = ISSUER_DID
        credential['issuanceDate'] = datetime.utcnow().replace(
            microsecond=0).isoformat() + "Z"
        if (vc_type == "DefiCompliance"):
            credential['expirationDate'] = (
                datetime.now() + timedelta(days=90)).isoformat() + "Z"
        else:
            credential['expirationDate'] = (
                datetime.now() + timedelta(days=CREDENTIAL_LIFE)).isoformat() + "Z"

        credential_manifest = json.load(
            open('./credential_manifest/'+vc_type+'_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = ISSUER_DID
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())
        credential['id'] = "urn:uuid:random"  # for preview only
        temp_dict = pickle.loads(red.get(code))
        temp_dict["credential"] = credential
        red.setex(code, CODE_LIFE, pickle.dumps(temp_dict))
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires": (datetime.now() + timedelta(seconds=CODE_LIFE)).replace(microsecond=0).isoformat(),
            "credential_manifest": credential_manifest
        }
        return jsonify(credential_offer)

    else:  # POST #réduire appel dossier
        credential = pickle.loads(red.get(code))["credential"]
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form['subject_id']
        try:
            presentation = json.loads(request.form['presentation'])
        except:
            logging.warning("presentation does not exist")
            red.delete(code)
            # ERROR : presentation does not exist
            event_data = json.dumps(
                {"type": "error", "code": code, "error": "430"})
            red.publish('issuer', event_data)
            return jsonify('Unauthorized'), 401
        if request.form['subject_id'] != presentation['holder']:
            logging.warning("holder does not match subject")
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
            red.delete(code)  # ERROR : presentation failed
            event_data = json.dumps(
                {"type": "error", "code": code, "error": "432"})
            red.publish('issuer', event_data)
            return jsonify('Unauthorized'), 401
        if pickle.loads(red.get(code))["did"] != json.loads(request.form['presentation'])["holder"]:
            logging.warning("invalid did  %s", presentation_result)
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
        # update issuer screen
        event_data = json.dumps(
            {"type": "altmeTransfered", "code": code, "vc": vc_type})
        red.publish('issuer', event_data)

        # we delete the code and send the credential
        red.delete(code)
        if vc_type == "DefiCompliance":
            vc_type = "defi"
        data = {"vc":  vc_type.lower(), "count": "1"}
        try:        
            requests.post('https://issuer.talao.co/counter/update', data=data)
        except:
            logging.warning("error updating issuer counter")
        return jsonify(signed_credential)


@app.route('/id360/static/<filename>', methods=['GET'])
def serve_static(filename: str):
    try:
        return send_file('./static/' + filename, download_name=filename)
    except FileNotFoundError:
        logging.error(filename+" not found")
        return jsonify("not found"), 404


@app.route('/id360/error/code_error', methods=['GET'])
def error():
    card = request.args.get("card")
    if not card:
        card="VerifiableId"
    return render_template("error_mobile.html", url=WALLETS["300"][2], error_title=ERRORS[request.args["code_error"]][0], error_description=ERRORS[request.args["code_error"]][1],card=card)


@app.route('/id360/success', methods=['GET'])
def success():
    return render_template("success_mobile.html",card=request.args.get("card"))


if __name__ == '__main__':
    app.run(host=mode.IP, port=mode.port, debug=True)
