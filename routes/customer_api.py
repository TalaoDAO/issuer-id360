from flask import render_template, request, jsonify, Response, send_file, session, redirect,url_for
import db
import json
import uuid
import time
from datetime import datetime, timedelta
import logging
from id360 import ID360_API_KEY
import requests
from datetime import datetime


red=None
mode=None

CODE_LIFE = 600  # in seconds the delay between the call of the API to get the code and the reding of the authentication QRcode by the wallet
AUTHENTICATION_DELAY = 600  # in seconds


def init_app(app,red_app, mode_app) :
    global red,mode
    red=red_app
    mode=mode_app
    app.add_url_rule('/id360/get_code_customer',  view_func=get_code_customer, methods = ['GET'])
    app.add_url_rule('/id360/authenticate_customer/<code>',  view_func=login_customer, methods = ['GET'])
    app.add_url_rule('/id360/callback_id360_customer/<code>',  view_func=id360callback_customer, methods = ['GET', 'POST'])


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
        'username': mode.username_customers,
        'password': mode.password_customers,
    }
    try:
        response = requests.post(
            mode.url_customers + 'api/1.0.0/user/login/', headers=headers, json=json_data)
    except:
        logging.error("loginID360 request failed")
        return
    if response.status_code == 200:
        logging.info("token update")
        red.set("token",response.json()["token"])
        return True
    else:
        logging.error("loginID360 returned status %s",
                      str(response.status_code))
        return


def create_dossier(code: str, browser_callback_url: str,journey_customer: str) -> str:
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
        'callback_url': mode.server+'/id360/callback_id360_customer/' + code,
        'browser_callback_url': browser_callback_url+"?code="+code,
        'callback_headers': {
            'code': code,
            'api-key': ID360_API_KEY,  # passer api key prod
        },
    }
    try:
        response = requests.post(
            mode.url_customers + 'api/1.0.0/process/' + journey_customer + '/enrollment/',
            headers=headers,
            json=json_data,
        )
    except:
        logging.error("create_dossier request failed")
        return
    if response.status_code == 200:
        try:
            temp_dict = json.loads(red.get(code))
        except:
            logging.error("redis expired %s", code)
            return
        temp_dict["id_dossier"] = response.json()["id"]
        red.setex(code, CODE_LIFE, json.dumps(temp_dict))
        return mode.url_customers + 'static/process_ui/index.html#/enrollment/' + response.json()["api_key"] + "?lang=en"
    elif response.status_code == 401:
        loginID360()
        return create_dossier(code,browser_callback_url,journey_customer)
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
        response = requests.get(mode.url_customers + 'api/1.0.0/enrollment/' +
                                str(id_dossier)+'/report?allow_draft=false', headers=headers)
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


def get_code_customer():
    """
    This the first call customer side to get its code

    curl https://talao.co/id360/get_code?client_id=<client_id>&callback_url=<your_endpoint>&browser_callback_url=<website_user_will_be_redirected_on> -H "api-key":<your_api_key>
    returns {"code": <code>} 200

    the code returned is useful for one session for one user
    returns {"error": <error_description>} with status code
    if an error occured
    """
    logging.info(request.headers)
    client_secret = request.headers.get('api-key')
    client_id = request.args.get('client_id')
    callback_url = request.args.get('callback_url')   
    browser_callback_url = request.args.get('browser_callback_url')
    if not client_id or not client_secret or not callback_url or not browser_callback_url:
        return jsonify("Bad request"), 400
    if not json.load(open("customers.json", "r")).get(client_id).get("client_secret")==client_secret:
      logging.warning("api key error")
      return jsonify("Unauthorized"), 401
    code = str(uuid.uuid1())
    red_object = {
        "client_id": client_id,
        "callback_url": callback_url,
        "browser_callback_url": browser_callback_url,
        "journey_customer": json.load(open("customers.json", "r")).get(client_id).get("journey_customer")
    }
    red.setex(code, CODE_LIFE, json.dumps(red_object))
    return jsonify({"code": code})

def login_customer(code: str):
    """
    first route redirecting user to id360 ui or issuer if a kyc he already completed a kyc
    """
    if code=="None":
        logging.warning("code is null")
        return jsonify("code is None")
    try:
        logging.info(json.loads(red.get(code)))
        callback_url = json.loads(red.get(code))["callback_url"]
        logging.info(callback_url)
        browser_callback_url = json.loads(red.get(code))['browser_callback_url']
        logging.info(browser_callback_url)
        client_id = json.loads(red.get(code))['client_id']
        logging.info(client_id)
        journey_customer = json.loads(red.get(code))['journey_customer']
        logging.info(journey_customer)
    except Exception as error:
        logging.error("code invalid")
        return redirect(url_for('error', code_error="internal_error"))
    return redirect(create_dossier(code, browser_callback_url,journey_customer))

def id360callback_customer(code: str):
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
    except KeyError as e:
        logging.error("redis expired %s %s",code,e)
        red.setex(code, CODE_LIFE, json.dumps(
            {"code_error": "414", "vc_type": "VerifiableId"}))  # ERROR : REDIS EXPIRATION
        return jsonify("ok")
    status= request.get_json()["status"]
    logging.info('callback for %s is %s',code,status)
    dossier = request.get_json()
    if status in ["CANCELED", "FAILED", "KO"]:
        logging.error(status)
        logging.warning(dossier)
        response = requests.post(
            json.loads(red.get(code))["callback_url"],
            json={"code":code,"success":False,"description":""}
        )
        logging.info("POST request to callback_url returned %s",response.status_code)
    elif status == "OK":
        dossier = get_dossier(json.loads(red.get(code))["id_dossier"])
        kyc_method= dossier.get("id_verification_service")
        level= dossier.get("level")
        dossier = dossier.get("steps").get("id_document").get("results").get("id_document_result")[0].get("result").get("extraction")
        dossier_clean={
            "code":code,
            "name": dossier.get("MRZ_surname"),
            "first_name": dossier.get("MRZ_first_name")[0],
            "first_names": dossier.get("MRZ_first_name"),
            "address": dossier.get("OCR_address"), #can be wrong
            "nationality": dossier.get("MRZ_nationality"),
            "birth_date": dossier.get("MRZ_birth_date"),
            "gender":dossier.get("MRZ_sex"),
            "birth_place": dossier.get("OCR_birth_place"),
            "country_emission": dossier.get("MRZ_issuing_country"),
            "verificationMethod":kyc_method,
            "levelOfAssurance":level,
            "success":True,
            "issuanceDate":datetime.utcnow().replace(
            microsecond=0).isoformat() + "Z"
        }
        headers = {'Content-Type': 'application/json'}
        api_key = json.loads(red.get(code)).get("api_key")
        if api_key:
            headers.update({"api-key":api_key})
        response = requests.post(json.loads(red.get(code))["callback_url"], headers=headers, data = json.dumps(dossier_clean))
        logging.info("POST request to callback_url returned %s",response.status_code)
    return jsonify("ok")