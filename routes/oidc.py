"""

https://talao.co/id360/oidc4vc?vc_format=vcsd-jwt&draft=13&vc_format=identitycredential

https://talao.co/id360/oidc4vc?vc_format=jwt_vc_json&draft=13&vc_format=verifiableid


https://talao.co/id360/oidc4vc?format=ldp_vc&type=over18
"""

import requests
import logging
import uuid
import ciso8601
from datetime import datetime, timedelta
import time
import json
from flask import jsonify, redirect, render_template, request, Response
from datetime import datetime, timedelta
from id360 import ID360_API_KEY, ISSUER_DID
import base64


CODE_LIFE = 600  # in seconds the delay between the call of the API to get the code and the reding of the authentication QRcode by the wallet
CREDENTIAL_LIFE = 360  # in days
ONE_YEAR = 31556926  # seconds

VC_TYPE_SUPPORTED = ["Over18", "Over21", "Over13", "Over15", "Over50", "Over65", "Liveness", "VerifiableId", "IdentityCredential", "EudiPid", "Pid", "IndividualVerifiableAttestation"]
VC_FORMAT_SUPPORTED = ["jwt_vc_json", "ldp_vc", "vc+sd-jwt"]

red = None
mode = None
OIDC_URL = "https://talao.co/sandbox/oidc4vc/issuer/api"

ISSUER_ID_JWT = "vqzljjitre" # jwt_vc_json draft 11
ISSUER_ID_JWT_13 = "celebrwtox" # jwt_vc_json draft 13
ISSUER_ID_JSON_LD = "lbeuegiasm" # ldp_vc draft 11
ISSUER_ID_SD_JWT = "allekzsiuo" # baseline draft 13
ISSUER_ID_JWT_VC = "glrafobuwu" # EBSI draft 11
client_secret = json.load(open("keys.json", "r"))["client_secret"]  #jwt_vc_json 
client_secret_jwt_13 = json.load(open("keys.json", "r"))["client_secret_jwt_13"]  #jwt_vc_json draft 13 
client_secret_json_ld = json.load(open("keys.json", "r"))["client_secret_json_ld"]  # ldp_vc
client_secret_sd_jwt = json.load(open("keys.json", "r"))["client_secret_sd_jwt"]  # sd_jwt
client_secret_jwt_vc = json.load(open("keys.json", "r"))["client_secret"]  # sd_jwt



def init_app(app, red_app, mode_app):
    global red, mode
    red = red_app
    mode = mode_app
    app.add_url_rule('/id360/oidc4vc_wait/<code>', view_func=oidc4vc_wait, methods=['GET'])
    app.add_url_rule('/id360/oidc4vc_callback', view_func=oidc4vc_callback, methods=['GET'])
    app.add_url_rule('/id360/oidc4vc', view_func=login_oidc, methods=['GET'])
    app.add_url_rule('/id360/oidc4vc_callback_id360/<code>', view_func=oidc_id360callback, methods=['GET', 'POST'])
    app.add_url_rule('/id360/oidc4vc_stream', view_func=oidc_issuer_stream, methods=['GET'])
    app.add_url_rule('/id360/get_status_kyc/<code>', view_func=get_status_kyc, methods=['GET'])
    app.add_url_rule('/id360/oidc4vc_intro', view_func=intro, methods=['GET'])


def loginID360() -> bool:
    """
    ID360 API call for login
    set token if ok False if not
    """
    headers = {
        'accept': 'application/json',
        'Content-Type': 'application/json',
    }
    json_data = {
        'username': mode.username,
        'password': mode.password,
    }
    try:
        response = requests.post(mode.url + 'api/1.0.0/user/login/', headers=headers, json=json_data)
    except Exception:
        logging.error("loginID360 connection failed")
        return
    if response.status_code == 200:
        token =  response.json()["token"]
        logging.info("token ok from ID360 = %s", token)
        red.set("token", token)
        return True
    else:
        logging.error("login ID360 failed returned status %s", str(response.status_code))
        return


def create_dossier(code: str, format: str, type: str, draft: str) -> str:
    """
    ID360 API call to create dossier on ID360
    """
    try:
        token = red.get("token").decode()
    except Exception:
        loginID360()
    try:
        token = red.get("token").decode()
        logging.info("token in create_dossier = %s", token)
    except Exception:
        logging.error("create_dossier request failed")
        return None
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token ' + token,
        'Content-Type': 'application/json',
    }
    json_data = {
        'callback_url': mode.server+'/id360/oidc4vc_callback_id360/' + code,
        'browser_callback_url': mode.server+'/id360/oidc4vc_wait/' + code,
        'client_reference': "Talao OIDC4VC issuer",
        'callback_headers': {
            'code': code,
            'api-key': ID360_API_KEY,  # passer api key prod
        },
    }
    try:
        response = requests.post(
            mode.url + 'api/1.0.0/process/' + mode.journey_oidc + '/enrollment/',
            headers=headers,
            json=json_data,
        )
    except Exception:
        logging.error("create_dossier request failed")
        return None
    if response.status_code == 200:
        red.setex(code, CODE_LIFE, json.dumps({
            "id_dossier": response.json()["id"],
            "vc_format": format,
            "vc_type": type,
            "vc_draft": draft
        }))
        url = mode.url + 'static/process_ui/index.html#/enrollment/' + \
            response.json()["api_key"] + "?lang=en"
        logging.info("url = %s",url)
        return url
    elif response.status_code == 401:
        # refresh token
        loginID360()
        return create_dossier(code, format, type, draft)
    else:
        logging.error("create_dossier returned status = %s", str(response.status_code))
        return None


def get_dossier(id_dossier: str) -> dict:
    """
    ID360 API call to get user data

    """
    token = red.get("token").decode()
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token ' + token,
    }
    try:
        response = requests.get(mode.url + 'api/1.0.0/enrollment/' +
                                str(id_dossier)+'/report?allow_draft=false',
                                headers=headers)
    except Exception:
        logging.error("get_dossier request connexion failed")
        return
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        logging.warning("dossier %s expired", str(id_dossier))
        return "expired"
    else:
        logging.error("error requesting dossier status : %s",response.status_code)
        return response.status_code


def get_image(url):
    """
    ID360 API call to get user document image

    """
    token = red.get("token").decode()
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token ' + token,
    }
    try:
        response = requests.get(url, headers=headers)
    except Exception:
        logging.error("get_image request failed")
        return
    if response.status_code == 200:
        return base64.b64encode(response.content).decode()
    elif response.status_code == 404:
        logging.warning("get_image 404")
        return "expired"
    else:
        logging.error("error requesting image status : %s",response.status_code)
        return response.status_code


def login_oidc():
    code = str(uuid.uuid4())
    vc_format = request.args.get("format")
    vc_type = request.args.get("type")
    vc_draft = request.args.get('draft')

    if not vc_format or vc_format.lower() == "jwt_vc_json":
        format = "jwt_vc_json"
    elif vc_format == "vcsd-jwt":
        format = "vc+sd-jwt"
    elif vc_format == "ldp_vc":
        format = "ldp_vc"
    elif vc_format == "jwt_vc":
        format = "jwt_vc"
    else:
        return jsonify("This VC format is not supported %s", vc_format)
        
    if not vc_type or vc_type.lower() == "verifiableid":
        type = "VerifiableId"
    elif vc_type.lower() == "eudipid":
        type = "EudiPid"
    elif vc_type.lower() == "pid":
        type = "Pid"
    elif vc_type.lower() == "identitycredential":
        type = "IdentityCredential"
    elif vc_type.lower() == "individualverifiableattestation":
        type = "IndividualVerifiableAttestation"
    else:
        type = vc_type.capitalize()
    if type not in VC_TYPE_SUPPORTED:
        return jsonify("This VC type is not supported %s", vc_type)
    
    if not vc_draft and format == "vc+sd-jwt":
        draft = "13"
    elif not vc_draft and format in ["ldp_vc", "jwt_vc_json"]:
        draft = "11"
    else:
        draft = vc_draft

    logging.info("format = %s", format)
    logging.info("type = %s", type)
    logging.info("draft = %s", draft)

    return redirect(create_dossier(code, format, type, draft))


def oidc4vc_callback():
    if request.args.get("error"):
        return render_template("error.html", error=request.args.get("error").replace("_", " "), error_description=request.args.get("error_description"))
    return render_template("success.html")


def oidc4vc_wait(code):
    return render_template("wait_oidc.html", code=code, server=mode.server)


def get_status_kyc(code):
    try:
        logging.info(json.loads(red.get(code)))
        return jsonify(status=json.loads(red.get(code))["KYC"], url=json.loads(red.get(code))["url"])
    except (KeyError, TypeError):
        return jsonify(status="None")


def oidc_id360callback(code: str):
    """
    Callback route for ID360
    """
    def manage_error(id_dossier, code):
        event_data = json.dumps({
            "type": "KYC",
            "status": "KO",
            "code": code,
            "url": ""})
        red.publish('issuer', event_data)
        red.setex(code, CODE_LIFE, json.dumps({
            "id_dossier": id_dossier,
            "KYC": "KO",
            "url": ""
        }))
        return
    
    try:
        if request.headers["api-key"] != ID360_API_KEY:
            return jsonify("Unauthorized"), 403
    except Exception:
        return jsonify("Unauthorized"), 403
    logging.info("reception of id360 callback for %s", code)
    try:
        code_data = json.loads(red.get(code))
        id_dossier = code_data["id_dossier"] # an integer
        vc_format = code_data['vc_format']
        vc_type = code_data["vc_type"]
        vc_draft = code_data["vc_draft"]
    except Exception:
        logging.error("redis expired %s", code)
        red.setex(code, CODE_LIFE, json.dumps({
            "code_error": "414",
            "vc_type": "VerifiableId"
        }))
        return jsonify("ok")

    logging.info('callback for code = %s is %s', code, request.get_json()["status"])
    if request.get_json()["status"] in ["CANCELED", "FAILED", "KO"]:
        manage_error(id_dossier, code)
        
    elif request.get_json()["status"] == "OK":
        id_dossier = json.loads(red.get(code))["id_dossier"]
        dossier = get_dossier(id_dossier)
        if not dossier:
            manage_error(id_dossier, code)
        if dossier['id_verification_service'] == 'IdNumericExternalMethod': # IN
            payload = dossier["external_methods"]["id_num"]["results"]["id_num_out_token"][0]["payload"]
            print("payload from IN = ", payload)
        else:  # 'SVID_ID360',
            identity = dossier["identity"]
            print("identity from KYC = ", identity)
        if vc_format == "jwt_vc_json":
            vc_filename = vc_type + '_jwt_vc_json.jsonld'
        elif vc_format == "ldp_vc":
            vc_filename = vc_type + '_ldp_vc.jsonld'
        elif vc_format == 'vc+sd-jwt':
            vc_filename = 'IdentityCredential.json'
        else: # ldp_vc
            vc_filename = vc_type + '.jsonld'
        credential = json.load(open('./verifiable_credentials/' + vc_filename,'r'))
        if dossier['id_verification_service'] == 'IdNumericExternalMethod': 
            birth_date = payload.get('birthdate')[:10]
        else:
            birth_date = identity.get("birth_date")[:10]
        if not birth_date:
            logging.warning('No birth date in dossier)')
            birth_date = "1900-00-00"
        timestamp = time.mktime(ciso8601.parse_datetime(birth_date).timetuple())
        now = time.time()
        if vc_format == 'vc+sd-jwt'and vc_type == "IdentityCredential":
            if dossier['id_verification_service'] == 'IdNumericExternalMethod': 
                credential['given_name'] = payload["given_name"]
                credential['family_name'] = payload["family_name"]
                credential['birth_date'] = birth_date
                credential["gender"] = 1 if payload["gender"] == "male" else 0
                credential["issuing_country"] = "FR"
                credential['email'] = payload["email"]
                credential['phone_number'] = payload["phone_number"]
                credential['dateIssued'] = datetime.now().replace(microsecond=0).isoformat()[:10]
            else:
                credential['given_name'] = ' '.join(identity["first_names"])
                credential['family_name'] = identity["name"]
                credential['birth_date'] = birth_date
                credential['dateIssued'] = datetime.now().replace(microsecond=0).isoformat()[:10]
            for age in [13, 15, 18, 21, 50, 65]:
                credential['is_over_' + str(age)] = True if (now-timestamp > ONE_YEAR * age) else False
        
        elif vc_format == 'vc+sd-jwt' and vc_type == "EudiPid":
            if dossier['id_verification_service'] == 'IdNumericExternalMethod': 
                credential['given_name'] = payload["given_name"]
                credential['family_name'] = payload["family_name"]
                credential['birth_date'] = birth_date
                credential["gender"] = 1 if payload["gender"] == "male" else 0
                credential["issuing_country"] = "FR"
                credential["dateIssued"] = datetime.now().replace(microsecond=0).isoformat()[:10],
                credential['email'] = payload["email"]
                credential['phone_number'] = payload["phone_number"]
            else:
                credential['given_name'] = ' '.join(identity["first_names"])
                credential['family_name'] = identity["name"]
                credential['birth_date'] = birth_date
                credential["dateIssued"] = datetime.now().replace(microsecond=0).isoformat()[:10],
            for age in [13, 15, 18, 21, 50, 65]:
                credential['age_over_' + str(age)] = True if (now-timestamp > ONE_YEAR * age) else False
        
        elif vc_format == 'vc+sd-jwt' and vc_type == "Pid":
            if dossier['id_verification_service'] == 'IdNumericExternalMethod': 
                credential['given_name'] = payload["given_name"]
                credential['family_name'] = payload["family_name"]
                credential['birthdate'] = birth_date
                credential["gender"] = payload["gender"]
                credential["issuing_country"] = "FR"
                credential['dateIssued'] = datetime.now().replace(microsecond=0).isoformat()[:10]
            else:
                credential['given_name'] = ' '.join(identity["first_names"])
                credential['family_name'] = identity["name"]
                credential['birthdate'] = birth_date
                credential['dateIssued'] = datetime.now().replace(microsecond=0).isoformat()[:10]
            for age in [12, 14, 16, 18, 21, 65]:
                credential['age_equal_or_over'][str(age)] = True if (now-timestamp > ONE_YEAR * age) else False
        
        elif vc_format in ['jwt_vc_json', 'jwt_vc'] and vc_type in ['VerifiableId', 'IndividualVerifiableAttestation']: # DIIP
            if dossier['id_verification_service'] == 'IdNumericExternalMethod': 
                credential["credentialSubject"]["familyName"] = payload["family_name"]
                credential["credentialSubject"]["firstName"] = payload["given_name"]
                credential["credentialSubject"]["dateOfBirth"] = birth_date
                credential['credentialSubject']['email'] = payload["email"]
                credential['credentialSubject']['phone_number'] = payload["phone_number"]
                credential['credentialSubject']["gender"] = 1 if payload["gender"] == "male" else 0
                credential['credentialSubject']["issuing_country"] = "FR"
                credential["credentialSubject"]["dateIssued"] = datetime.now().replace(microsecond=0).isoformat()[:10]
            else:
                credential["credentialSubject"]["familyName"] = identity["name"]
                credential["credentialSubject"]["firstName"] = ' '.join(identity["first_names"])
                credential["credentialSubject"]["gender"] = 1 if identity["gender"] == "male" else 0
                credential["credentialSubject"]["dateOfBirth"] = birth_date 
                credential["credentialSubject"]["dateIssued"] = datetime.now().replace(microsecond=0).isoformat()[:10]

        elif vc_type == "VerifiableId":
            if dossier['id_verification_service'] == 'IdNumericExternalMethod': 
                credential["credentialSubject"]["familyName"] = payload["family_name"]
                credential["credentialSubject"]["firstName"] = payload["given_name"]
                credential["credentialSubject"]["dateOfBirth"] = birth_date
                credential['credentialSubject']['email'] = payload["email"]
                credential['credentialSubject']['phone_number'] = payload["phone_number"]
                credential['credentialSubject']["gender"] = 1 if payload["gender"] == "male" else 0
                credential['credentialSubject']["issuing_country"] = "FR"
                credential["credentialSubject"]["dateIssued"] = datetime.now().replace(microsecond=0).isoformat()[:10]
            else:
                credential["credentialSubject"]["familyName"] = identity["name"]
                credential["credentialSubject"]["firstName"] = ' '.join(identity["first_names"])
                credential["credentialSubject"]["gender"] = identity["gender"]
                credential["credentialSubject"]["dateOfBirth"] = birth_date 
                credential["credentialSubject"]["dateIssued"] = datetime.now().replace(microsecond=0).isoformat()[:10]

        elif vc_type in ["Over13", "Over15", "Over18", "Over21", "Over50", "Over65"]:
            age = int(vc_type[4:6])        
            if (now-timestamp) < ONE_YEAR * age:
                logging.warning("age below " + str(age))
                manage_error(id_dossier, code)
                return jsonify("Unauthorized"), 403
        
        elif vc_type == "Liveness":
            pass
        
        else:
            logging.error("VC type not supported %s", vc_type)
            pass
        
        # TODO add other data if available
        if vc_format in ["jwt_vc_json", "ldp_vc"]:
            credential["issuer"] = ISSUER_DID
            credential['issuanceDate'] = datetime.now().replace(microsecond=0).isoformat() + "Z"
            credential['expirationDate'] = (datetime.now() + timedelta(days=CREDENTIAL_LIFE)).isoformat() + "Z"
            #credential['id'] = "urn:uuid:random"  # for preview only
            logging.info("credential = %s", credential)
        if vc_format == "jwt_vc_json" and vc_draft == "11":
            cs = client_secret  
            issuer_id = ISSUER_ID_JWT
        if vc_format == "jwt_vc" and vc_draft == "11":
            cs = client_secret_jwt_vc
            issuer_id = ISSUER_ID_JWT_VC
        elif vc_format == "jwt_vc_json" and vc_draft == "13":
            cs = client_secret_jwt_13  
            issuer_id = ISSUER_ID_JWT_13
        elif vc_format == "ldp_vc":
            cs = client_secret_json_ld
            issuer_id = ISSUER_ID_JSON_LD
        elif vc_format == "vc+sd-jwt":
            cs = client_secret_sd_jwt
            issuer_id = ISSUER_ID_SD_JWT

        headers = {
            'Content-Type': 'application/json',
            'X-API-KEY': cs
        }
        data = {
            "vc": {vc_type: credential},
            "issuer_state": code,
            "credential_type": [vc_type],
            "pre-authorized_code": True,
            "user_pin_required": False,
            #"user_pin": str(six_digit_code),
            "callback": mode.server + "/id360/oidc4vc_callback",
            'issuer_id': issuer_id
        }
        resp = requests.post(OIDC_URL, headers=headers, data=json.dumps(data))
        logging.info("status code = %s", resp.status_code)
        logging.info(resp.json())
        try:
            url = resp.json()['redirect_uri']
            logging.info("redirect uri = %s", url)
        except Exception:
            logging.error("error oidc")
            url = "error_oidc"
        event_data = json.dumps({
            "type": "KYC",
            "status": "OK",
            "code": code,
            "url": url
        })
        red.publish('issuer', event_data)
        red.setex(code, CODE_LIFE, json.dumps({
            "id_dossier": id_dossier,
            "KYC": "OK",
            "url": url}))
    return jsonify("ok")


def oidc_issuer_stream():
    """
    a stream connected to issuer frontend to know when the verifiable credential has been succesfully added
    """
    def event_stream():
        pubsub = red.pubsub()
        pubsub.subscribe('issuer')
        for message in pubsub.listen():
            if message['type'] == 'message':
                yield 'data: %s\n\n' % message['data'].decode()
    headers = {
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no"
    }
    return Response(event_stream(), headers=headers)


def intro():
    return render_template("intro.html")
