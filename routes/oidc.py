import message
import requests
from random import randint
import logging
import uuid
import json
from flask import jsonify, redirect, render_template, request, Response
from datetime import datetime, timedelta
from id360 import ID360_API_KEY, ISSUER_VM, ISSUER_DID, ISSUER_KEY
CODE_LIFE = 600  # in seconds the delay between the call of the API to get the code and the reding of the authentication QRcode by the wallet
CREDENTIAL_LIFE = 360  # in days


red = None
mode = None


url = "https://talao.co/sandbox/ebsi/issuer/api/vqzljjitre"
client_secret = json.load(open("keys.json", "r"))["client_secret"]


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
        'username': mode.username,
        'password': mode.password,
    }
    try:
        response = requests.post(
            mode.url + 'api/1.0.0/user/login/', headers=headers, json=json_data)
    except:
        logging.error("loginID360 request failed")
        return
    if response.status_code == 200:
        red.set("token", response.json()["token"])
        return True
    else:
        logging.error("loginID360 returned status %s",
                      str(response.status_code))
        return


def create_dossier(code: str) -> str:
    """
    ID360 API call to create dossier on ID360
    """
    try:
        token = red.get("token").decode()
    except:
        loginID360()
    token = red.get("token").decode()
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token ' + token,
        'Content-Type': 'application/json',
    }
    json_data = {
        'callback_url': mode.server+'/id360/oidc_callback_id360/' + code,
        'browser_callback_url': mode.server+'/id360/oidc_wait/' + code,
        'client_reference': "",
        'callback_headers': {
            'code': code,
            'api-key': ID360_API_KEY,  # passer api key prod
        },
    }
    try:
        response = requests.post(
            mode.url + 'api/1.0.0/process/' + mode.journey + '/enrollment/',
            headers=headers,
            json=json_data,
        )
    except:
        logging.error("create_dossier request failed")
        return
    if response.status_code == 200:
        red.setex(code, CODE_LIFE, json.dumps({
                  "id_dossier": response.json()["id"],
                  }))
        url = mode.url + 'static/process_ui/index.html#/enrollment/' + \
            response.json()["api_key"] + "?lang=en"
        logging.info(url)
        return url
    elif response.status_code == 401:
        loginID360()
        return create_dossier(code)
    else:
        logging.error("create_dossier returned status %s",
                      str(response.status_code))
        return


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
        logging.error("get_dossier request failed")
        return
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        logging.warning("dossier "+str(id_dossier)+" expiré")
        return "expired"
    else:
        logging.error("error requesting dossier status : %s",
                      response.status_code)
        return response.status_code


def init_app(app, red_app, mode_app):
    global red, mode
    red = red_app
    mode = mode_app
    app.add_url_rule('/id360/oidc_wait/<code>',
                     view_func=oidc_wait, methods=['GET'])
    app.add_url_rule('/id360/oidc_callback', view_func=oidc_callback,
                     methods=['GET'])
    app.add_url_rule('/id360/oidc_login', view_func=login_oidc,
                     methods=['GET'])
    app.add_url_rule('/id360/oidc_post', view_func=post_oidc,
                     methods=['POST'])
    app.add_url_rule('/id360/oidc_callback_id360/<code>',
                     view_func=oidc_id360callback, methods=['GET', 'POST'])
    app.add_url_rule('/id360/issuer_stream',
                     view_func=oidc_issuer_stream, methods=['GET'])
    app.add_url_rule('/id360/get_status_kyc/<code>',
                     view_func=get_status_kyc, methods=['GET'])


def login_oidc():
    code = str(uuid.uuid4())
    return redirect(create_dossier(code))


def post_oidc():
    email = request.json["email"]
    code = request.json["code"]
    six_digit_code = randint(100000, 999999)
    logging.info("code pin %s", str(six_digit_code))
    subject = ' Altme secret code'
    message.messageHTML(subject, email, 'code_auth_en', {'code': str(six_digit_code)})
    id_dossier = json.loads(red.get(code))["id_dossier"]
    dossier = get_dossier(id_dossier)
    identity  = dossier["identity"]
    """identity = {
        "name": "Dorier",
        "first_names": ["Achille"],
        "gender": "M",
        "dateOfBirth": "2001-09-10"
    }"""
    vc_type = "VerifiableId"
    credential = json.load(
        open('./verifiable_credentials/'+vc_type+'.jsonld', 'r'))
    try:
        credential["credentialSubject"]["familyName"] = identity["name"]
    except:
        logging.error("no familyName in dossier")
    try:
        credential["credentialSubject"]["firstName"] = identity["first_names"][0]
    except:
        logging.error("no firstName in dossier")
    try:
        credential["credentialSubject"]["gender"] = identity["gender"]
    except:
        logging.error("no gender in dossier")
    credential["credentialSubject"]["dateOfBirth"] = identity.get(
        "birth_date", "Not available")
    # TODO add other data if available
    credential["evidence"][0]["id"] = "https://github.com/TalaoDAO/context/blob/main/context/VerificationMethod.jsonld/" + \
        str(json.loads(red.get(code))["id_dossier"])
    credential["evidence"][0]["verificationMethod"] = dossier.get(
        "id_verification_service")
    credential["evidence"][0]["levelOfAssurance"] = dossier.get("level")
    credential["credentialSubject"]["kycProvider"] = "ID360"
    credential["credentialSubject"]["kycId"] = json.loads(red.get(code))[
        "id_dossier"]
    credential["credentialSubject"]["kycMethod"] = mode.journey

    credential["issuer"] = ISSUER_DID
    credential['issuanceDate'] = datetime.utcnow().replace(
        microsecond=0).isoformat() + "Z"
    credential['expirationDate'] = (
        datetime.now() + timedelta(days=CREDENTIAL_LIFE)).isoformat() + "Z"
    credential['id'] = "urn:uuid:random"  # for preview only

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer '+client_secret
    }
    data = {
        "vc": {"VerifiableId": credential},
        "issuer_state": code,
        "credential_type": ["VerifiableId"],
        "pre-authorized_code": True,
        "user_pin_required": True,
        "user_pin": str(six_digit_code),
        "callback": "http://localhost:3000/id360/oidc_callback"
    }
    resp = requests.post(url, headers=headers, data=json.dumps(data))
    logging.info(resp.json())
    try:
        return jsonify(url=resp.json()['redirect_uri'])
    except KeyError:
        return jsonify(url="error oidc")


def oidc_callback():
    return render_template("success.html")


def oidc_wait(code):
    return render_template("wait_oidc.html", code=code, server=mode.server)


def get_status_kyc(code):
    try:
        return jsonify(status=json.loads(red.get(code))["KYC"])
    except (KeyError, TypeError):
        return jsonify(status="None")


def oidc_id360callback(code: str):
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
        id_dossier = json.loads(red.get(code))["id_dossier"]
    except KeyError:
        logging.error("redis expired %s", code)
        red.setex(code, CODE_LIFE, json.dumps(
            {"code_error": "414", "vc_type": "VerifiableId"}))
        return jsonify("ok")

    logging.info('callback for code = %s is %s',
                 code, request.get_json()["status"])
    if request.get_json()["status"] in ["CANCELED", "FAILED", "KO"]:
        event_data = json.dumps({"type": "KYC", "status": "KO", "code": code})
        red.publish('issuer', event_data)
        red.setex(code, CODE_LIFE, json.dumps(
            {"id_dossier": id_dossier, "KYC": "KO"}))
    elif request.get_json()["status"] == "OK":
        event_data = json.dumps({"type": "KYC", "status": "OK", "code": code})
        red.publish('issuer', event_data)
        red.setex(code, CODE_LIFE, json.dumps(
            {"id_dossier": id_dossier, "KYC": "OK"}))
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
