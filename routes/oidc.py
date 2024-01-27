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


red = None
mode = None

ISSUER_ID_JWT = "vqzljjitre" # jwt_vc_json
ISSUER_ID_JSON_LD = "lbeuegiasm" # ldp_vc
OIDC_URL = "https://talao.co/sandbox/oidc4vc/issuer/api"
client_secret = json.load(open("keys.json", "r"))["client_secret"] #jwt_vc_json 
client_secret_json_ld = json.load(open("keys.json", "r"))["client_secret_json_ld"] # ldp_vc


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
    except:
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


def create_dossier(code: str, format: str, type: str) -> str:
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
        'client_reference': "Talao tests",
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
                  "vc_type": type
                  }))
        url = mode.url + 'static/process_ui/index.html#/enrollment/' + \
            response.json()["api_key"] + "?lang=en"
        logging.info("url = %s",url)
        return url
    elif response.status_code == 401:
        # refresh token
        loginID360()
        return create_dossier(code, format, type)
    else:
        logging.error("create_dossier returned status = %s", str(response.status_code))
        print(response.content)
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
    except:
        logging.error("get_dossier request connexion failed")
        return
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        logging.warning("dossier %s expired", str(id_dossier))
        return "expired"
    else:
        logging.error("error requesting dossier status : %s",
                      response.status_code)
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
    except:
        logging.error("get_image request failed")
        return
    if response.status_code == 200:
        return base64.b64encode(response.content).decode()
    elif response.status_code == 404:
        logging.warning("get_image 404")
        return "expired"
    else:
        logging.error("error requesting image status : %s",
                      response.status_code)
        return response.status_code


def login_oidc():
    code = str(uuid.uuid4())
    format = request.args.get("format")
    type = request.args.get("type")
    if not format:
        format = "jwt_vc_json"
    if not type:
        type = "VerifiableId"
    logging.info("VC format = %s", format )
    logging.info("VC type = %s", type )
    if type not in ["VerifiableId", "Over18"] or format not in ["jwt_vc_json", "ldp_vc"]:
        return jsonify("This VC type or format is not supported")
    return redirect(create_dossier(code, format, type))


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
    try:
        if request.headers["api-key"] != ID360_API_KEY:
            return jsonify("Unauthorized"), 403
    except Exception:
        return jsonify("Unauthorized"), 403
    logging.info("reception of id360 callback for %s", code)
    try:
        code_data = json.loads(red.get(code))
        id_dossier = code_data["id_dossier"]
        vc_format = code_data['vc_format']
        vc_type = code_data["vc_type"]
    except Exception:
        logging.error("redis expired %s", code)
        red.setex(code, CODE_LIFE, json.dumps({
            "code_error": "414",
            "vc_type": "VerifiableId"
        }))
        return jsonify("ok")

    logging.info('callback for code = %s is %s',
                 code, request.get_json()["status"])
    if request.get_json()["status"] in ["CANCELED", "FAILED", "KO"]:
        event_data = json.dumps(
            {"type": "KYC", "status": "KO", "code": code, "url": ""})
        red.publish('issuer', event_data)
        red.setex(code, CODE_LIFE, json.dumps(
            {"id_dossier": id_dossier, "KYC": "KO", "url": ""}))
    elif request.get_json()["status"] == "OK":
        id_dossier = json.loads(red.get(code))["id_dossier"]
        dossier = get_dossier(id_dossier)
        logging.info("dossier = %s", dossier)
        identity = dossier["identity"]
        phone_number = False
        user_pin_required = False
       
        """
        try:
            images = dossier.get("steps").get("id_document").get(
                "input_files").get("id_document_image")
        except AttributeError:
            images = False
        """    
        if vc_format == "jwt_vc_json":
            vc_file_name = vc_type +'_jwt_vc_json.jsonld'
        credential = json.load(
            open('./verifiable_credentials/'+ vc_file_name , 'r'))
        if vc_type == "VerifiableId":
            try:
                credential["credentialSubject"]["familyName"] = identity["name"]
            except Exception:
                logging.error("no familyName in dossier")
            try:
                credential["credentialSubject"]["firstName"] = identity["first_names"][0]
            except Exception:
                logging.error("no firstName in dossier")
            try:
                credential["credentialSubject"]["gender"] = identity["gender"]
            except Exception:
                logging.error("no gender in dossier")
            try:
                credential["credentialSubject"]["dateOfBirth"] = identity.get("birth_date")
            except Exception:
                logging.error("no gender in dossier")
        elif vc_type == "Over18":
            birth_date = identity.get("birth_date")
            timestamp = time.mktime(ciso8601.parse_datetime(birth_date).timetuple())
            now = time.time()
            if now-timestamp < ONE_YEAR*18:
                logging.waring("age below 18")
                return jsonify("Unauthorized"), 403
        else:
            pass

        # TODO add other data if available
        credential["evidence"][0]["id"] = "urn:id360:" + str(id_dossier)
        credential["evidence"][0]["verificationMethod"] = dossier.get("id_verification_service")
        credential["evidence"][0]["levelOfAssurance"] = dossier.get("level")
        credential["evidence"][0]["dossier"] = id_dossier
        credential["evidence"][0]["parcours"] = mode.journey_oidc
        credential["issuer"] = ISSUER_DID
        credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (datetime.now() + timedelta(days=CREDENTIAL_LIFE)).isoformat() + "Z"
        credential['id'] = "urn:uuid:random"  # for preview only
        logging.info(credential)
        url = OIDC_URL
        if vc_format == "jwt_vc_json":
            cs = client_secret  
            issuer_id = ISSUER_ID_JWT
        elif vc_format == "ldp_vc":
            cs = client_secret_json_ld
            issuer_id = ISSUER_ID_JSON_LD
        else:
            logging.error("vc format error")
            cs = client_secret  
            issuer_id = ISSUER_ID_JWT

        headers = {
            'Content-Type': 'application/json',
            'X-API-KEY': cs
        }
        data = {
            "vc": {vc_type: credential},
            "issuer_state": code,
            "credential_type": [vc_type],
            "pre-authorized_code": True,
            "user_pin_required": user_pin_required,
            #"user_pin": str(six_digit_code),
            "callback": mode.server+"/id360/oidc4vc_callback",
            'issuer_id': issuer_id
        }
        resp = requests.post(url, headers=headers, data=json.dumps(data))
        logging.info("status code = %s", resp.status_code)
        logging.info(resp.json())
        try:
            url = resp.json()['redirect_uri']
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
    headers = {"Content-Type": "text/event-stream",
               "Cache-Control": "no-cache",
               "X-Accel-Buffering": "no"}
    return Response(event_stream(), headers=headers)


def intro():
    return render_template("intro.html")
