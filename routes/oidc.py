import sms
import requests
from random import randint
import logging
import uuid
import json
from flask import jsonify, redirect, render_template, request, Response
from datetime import datetime, timedelta
from id360 import ID360_API_KEY, ISSUER_VM, ISSUER_DID, ISSUER_KEY
import base64


CODE_LIFE = 600  # in seconds the delay between the call of the API to get the code and the reding of the authentication QRcode by the wallet
CREDENTIAL_LIFE = 360  # in days


red = None
mode = None

ISSUER_ID_JWT = "vqzljjitre"
ISSUER_ID_JSON_LD = "lbeuegiasm"
OIDC_URL = "https://talao.co/sandbox/oidc4vc/issuer/api"
client_secret = json.load(open("keys.json", "r"))["client_secret"]
client_secret_json_ld = json.load(open("keys.json", "r"))[
    "client_secret_json_ld"]


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


def create_dossier(code: str, format: str) -> str:
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
        'callback_url': mode.server+'/id360/oidc4vc_callback_id360/' + code,
        'browser_callback_url': mode.server+'/id360/oidc4vc_wait/' + code,
        'client_reference': "",
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
    except:
        logging.error("create_dossier request failed")
        return
    if response.status_code == 200:
        red.setex(code, CODE_LIFE, json.dumps({
                  "id_dossier": response.json()["id"],
                  "format": format
                  }))
        url = mode.url + 'static/process_ui/index.html#/enrollment/' + \
            response.json()["api_key"] + "?lang=en"
        logging.info(url)
        return url
    elif response.status_code == 401:
        loginID360()
        return create_dossier(code, format)
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


def init_app(app, red_app, mode_app):
    global red, mode
    red = red_app
    mode = mode_app
    app.add_url_rule('/id360/oidc4vc_wait/<code>',
                     view_func=oidc4vc_wait, methods=['GET'])
    app.add_url_rule('/id360/oidc4vc_callback', view_func=oidc4vc_callback,
                     methods=['GET'])
    app.add_url_rule('/id360/oidc4vc', view_func=login_oidc,
                     methods=['GET'])
    app.add_url_rule('/id360/oidc4vc_callback_id360/<code>',
                     view_func=oidc_id360callback, methods=['GET', 'POST'])
    app.add_url_rule('/id360/oidc4vc_stream',
                     view_func=oidc_issuer_stream, methods=['GET'])
    app.add_url_rule('/id360/get_status_kyc/<code>',
                     view_func=get_status_kyc, methods=['GET'])
    app.add_url_rule('/id360/oidc4vc_intro', view_func=intro,
                     methods=['GET'])


def login_oidc():
    code = str(uuid.uuid4())
    format = request.args.get("format")
    if not format:
        format = "default"
    return redirect(create_dossier(code, format))


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
    except KeyError:
        return jsonify("Unauthorized"), 403
    logging.info("reception of id360 callback for %s", code)
    try:
        id_dossier = json.loads(red.get(code))["id_dossier"]
    except (KeyError, TypeError) as error:
        logging.error("redis expired %s", code)
        red.setex(code, CODE_LIFE, json.dumps(
            {"code_error": "414", "vc_type": "VerifiableId"}))
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
        six_digit_code = randint(100000, 999999)
        logging.info("code pin %s", str(six_digit_code))
        id_dossier = json.loads(red.get(code))["id_dossier"]
        dossier = get_dossier(id_dossier)
        phone_number = False
        try:
            phone_number = dossier.get("external_methods").get("id_num").get(
                "results").get("id_num_out_token")[0].get("payload").get("phone_number")
        except:
            pass
        user_pin_required = False
        if (phone_number):
            user_pin_required = True
            sms.send_code(phone_number, str(six_digit_code))
        logging.info(dossier)
        identity = dossier["identity"]
        try:
            images = dossier.get("steps").get("id_document").get(
                "input_files").get("id_document_image")
        except AttributeError:
            images = False
        vc_type = "VerifiableId_oidc"
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
        try:
            if images:
                credential["credentialSubject"]["idRecto"] = get_image(
                    images[0])
                if (len(images) == 2):
                    credential["credentialSubject"]["idVerso"] = get_image(
                        images[1])
        except Exception as e:
            logging.error(e)
        if identity.get("birth_date"):
            credential["credentialSubject"]["dateOfBirth"] = identity.get(
                "birth_date")
        # TODO add other data if available
        credential["evidence"][0]["id"] = "urn:id360:" + \
            str(json.loads(red.get(code))["id_dossier"])
        credential["evidence"][0]["verificationMethod"] = dossier.get(
            "id_verification_service")
        credential["evidence"][0]["levelOfAssurance"] = dossier.get("level")
        credential["evidence"][0]["dossier"] = json.loads(red.get(code))[
            "id_dossier"]
        credential["evidence"][0]["parcours"] = mode.journey_oidc

        credential["issuer"] = ISSUER_DID
        credential['issuanceDate'] = datetime.utcnow().replace(
            microsecond=0).isoformat() + "Z"
        credential['expirationDate'] = (
            datetime.now() + timedelta(days=CREDENTIAL_LIFE)).isoformat() + "Z"
        credential['id'] = "urn:uuid:random"  # for preview only
        logging.info(credential)
        format = json.loads(red.get(code))["format"]
        cs = client_secret
        url = OIDC_URL
        issuer_id = ISSUER_ID_JWT
        if format == "json-ld":
            cs = client_secret_json_ld
            issuer_id = ISSUER_ID_JSON_LD
        headers = {
            'Content-Type': 'application/json',
            'X-API-KEY': cs
        }
        data = {
            "vc": {"VerifiableId": credential},
            "issuer_state": code,
            "credential_type": ["VerifiableId"],
            "pre-authorized_code": True,
            "user_pin_required": user_pin_required,
            "user_pin": str(six_digit_code),
            "callback": mode.server+"/id360/oidc4vc_callback",
            'issuer_id': issuer_id
        }
        logging.info(url+" "+issuer_id)
        resp = requests.post(url, headers=headers, data=json.dumps(data))
        logging.info(resp.status_code)
        logging.info(resp.json())
        try:
            url = resp.json()['redirect_uri']
        except KeyError:
            logging.error("error oidc")
            url = "error_oidc"
        event_data = json.dumps(
            {"type": "KYC", "status": "OK", "code": code, "url": url})
        red.publish('issuer', event_data)
        red.setex(code, CODE_LIFE, json.dumps(
            {"id_dossier": id_dossier, "KYC": "OK", "url": url}))
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
