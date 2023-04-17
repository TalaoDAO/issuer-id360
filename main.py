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
import sqlite3 as sql
import pickle
import traceback
import sys
try:
    sql.connect("database.db").cursor().execute(
        "CREATE TABLE IF NOT EXISTS kycs (did TEXT PRIMARY KEY, status TEXT, id  TEXT)")
except:
    logging.warning("error DB")
    None

issuer_key = json.dumps(json.load(open("keys.json", "r"))[
                        'talao_Ed25519_private_key'])
issuer_vm = "did:web:app.altme.io:issuer#key-1"
issuer_did = "did:web:app.altme.io:issuer"
token = ""
parcoursPVID = "da73f56e-ec1f-44c0-a275-ba98e25fdc6c"
parcoursNonSubstantiel = "0dd7e3c1-c4a4-41a2-8b09-0ec992e38e2a"
app = Flask(__name__)
app.secret_key = """json.dumps(json.load(open("keys.json", "r"))["appSecretKey"])"""
qrcode = QRcode(app)

myenv = os.getenv('MYENV')
if not myenv:
    myenv = 'thierry'
myenv = "achille"
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
        'callback_url': mode.server+'/id360/id360/'+id,
        'browser_callback_url': mode.server+'/id360/issuer/'+id,
        'client_reference': 'any_string',
        'callback_headers': {
            'header_name_1': id,
            'header_name_2': 'header_value_2',
        },
    }
    response = requests.post(
        'https://preprod.id360docaposte.com/api/1.0.0/process/' +
            parcoursNonSubstantiel+'/enrollment/',
        headers=headers,
        json=json_data,
    )

    print(response.json())
    idDossier = response.json()["id"]
    newObj = pickle.loads(red.get(id))
    newObj["idDossier"] = idDossier
    red.set(id,  pickle.dumps(newObj))

    api_key = response.json()["api_key"]
    link_ui = "https://preprod.id360docaposte.com/static/process_ui/index.html#/enrollment/"+api_key

    # print(link_ui)
    return link_ui


async def get_dossier(id):
    headers = {
        'accept': 'application/json',
        'Authorization': 'Token '+token,
    }
    print(id)
    response = requests.get(
        'https://preprod.id360docaposte.com/api/1.0.0/enrollment/'+str(id)+'/report/', headers=headers)
    print("dossier "+str(id)+" :")
    print(response)
    return (response.json())

@app.route('/id360/get_link')
def get_link():
    try:
            with sql.connect("database.db") as con:
                cur = con.cursor()
                # print(pickle.loads(red.get(id).decode()))
                cur.execute("select * from customers where apiKey='" +
                            request.headers['apiKey']+"'")
                max = cur.fetchone()
                if max==None:
                    return jsonify("bad apiKey"),403
    except sql.Error as er:
            logging.error('SQLite error: %s', ' '.join(er.args))
    finally:
            con.close()
    id = str(uuid.uuid1())
    red.set(id,  "True")
    url = mode.server+'/id360/login/' + id + '?issuer=' + did_verifier

    return jsonify({"url":url}),200

@app.route('/id360/login/<id>')
def login(id):
    try:
        site_callback = request.args['callback']
    except KeyError:
        print("KeyError")
    try:
        if red.get(id).decode()!="True":
            return jsonify("invalid link"),403
    except:
        return jsonify("invalid link"),403

    id = id
    pattern = DIDAuth
    pattern['challenge'] = id
    pattern['domain'] = mode.server
    red.set(id,  json.dumps(pattern))
    url = mode.server+'/id360/endpoint/' + id + '?issuer=' + did_verifier+"&callback="+site_callback

    return render_template("login.html", url=url, id=id)


@app.route('/id360/issuer/<id>',  defaults={'red': red})
def issuer(id, red):
    # time.sleep(5)
    # qrcodeContent=red.get(id).decode()
    print(pickle.loads(red.get(id)))
    return render_template("issuer.html", id=id,callback=pickle.loads(red.get(id))["callback"])


@app.route('/id360/endpoint/<id>', methods=['GET', 'POST'],  defaults={'red': red})
async def presentation_endpoint(id, red):
    try:
        site_callback = request.args['callback']
    except KeyError:
        print("KeyErrorEndpoint")
    try:
        my_pattern = json.loads(red.get(id).decode())
    except:
        event_data = json.dumps({"id": id,
                                 "message": "redis decode failed",
                                 "check": "ko",
                                     "type": "login","url":site_callback})
        red.publish('verifier', event_data)
        return jsonify("server error"), 500 

    if request.method == 'GET':
        return jsonify(my_pattern)

    if request.method == 'POST':
        # red.delete(id)
        print(request)
        print(request.form['presentation'])
        try:
            #result = json.loads(await didkit.verify_presentation(request.form['presentation'], '{}'))
            result = json.loads(await didkit.verify_presentation(request.form['presentation'], json.dumps({"challenge": id, "domain": mode.server})))
            print(result)
            result = False
        except:
            event_data = json.dumps({"id": id,
                                    "check": "ko",
                                     "message": "presentation is not correct",
                                     "type": "login"})
            red.publish('verifier', event_data)
            return jsonify("presentation is not correct"), 403
        if result:
            event_data = json.dumps({"id": id,
                                    "check": "ko",
                                     "message": result,
                                     "type": "login"})
            red.publish('verifier', event_data)
            return jsonify(result), 403
        red.set(id,  pickle.dumps(
            {"did": json.loads(request.form['presentation'])["holder"],"callback":site_callback}))
        print(pickle.loads(red.get(id))["callback"])
        # session["did"]=json.loads(request.form['presentation'])["holder"]

        try:
            with sql.connect("database.db") as con:
                cur = con.cursor()
                print(pickle.loads(red.get(id)))
                # print(pickle.loads(red.get(id).decode()))
                cur.execute("select * from kycs where did='" +
                            pickle.loads(red.get(id))["did"]+"'")
                max = cur.fetchone()
        except sql.Error as er:
            logging.error('SQLite error: %s', ' '.join(er.args))
        finally:
            con.close()
        print(max)
        if (max == None or max[1] == "KO"):
            newObj = pickle.loads(red.get(id))
            if max == None:
                newObj["first"] = True
            else:
                newObj["first"] = False
            print(newObj["first"])
            red.set(id, pickle.dumps(newObj))
            await loginID360()
            link = await create_dossier(id)
            event_data = json.dumps({"id": id,
                                        "message": "presentation is verified",
                                        "check": "ok",
                                        "link": link,
                                        "type": "login"
                                        })
            print("sent "+link)
            red.publish('verifier', event_data)

            return jsonify("ok"), 200
        elif max[1] == "OK":
            newObj = pickle.loads(red.get(id))
            newObj["did"]=json.loads(request.form['presentation'])["holder"]
            newObj["idDossier"]=max[2]
            newObj["first"]=False
            """red.set(id, pickle.dumps({"did": json.loads(request.form['presentation'])[
                    "holder"], "idDossier": max[2], "first": False}))"""
            red.set(id,pickle.dumps(newObj))
            event_data = json.dumps({"id": id,
                                        "message": "presentation is verified",
                                        "check": "ok",
                                        "link": mode.server+"/id360/issuer/"+id,
                                        "type": "login"
                                        })
            red.publish('verifier', event_data)

            print("sent "+mode.server+"/id360/issuer/"+id)
            return jsonify("ok"), 200  # si kyc deja dispo dans la db


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


@app.route('/id360/id360/<id>', methods=['GET', 'POST'],  defaults={'red': red})
async def id360callback(id, red):
    await loginID360()
    idDossier = pickle.loads(red.get(id))["idDossier"]
    did = pickle.loads(red.get(id))["did"]
    dossier = await get_dossier(idDossier)
    print(dossier)
    if(dossier["status"]!="OK"):
        url = pickle.loads(red.get(id))["callback"]+"/400"
        event_data = json.dumps({"type": "callbackErr", "id": id, "url": url})
        red.publish('verifier', event_data)
        return jsonify("ok"), 200
    url = mode.server+"/id360/issuer_endpoint/"+id
    event_data = json.dumps({"type": "callback", "id": id, "url": url})
    red.publish('verifier', event_data)
    return jsonify("ok"), 200


@app.route('/id360/get_qrcode/<id>', methods=['GET'],  defaults={'red': red})
async def get_qrcode(id, red):
    await loginID360()
    idDossier = pickle.loads(red.get(id))["idDossier"]
    did = pickle.loads(red.get(id))["did"]
    dossier = await get_dossier(idDossier)
    print(dossier)
    if pickle.loads(red.get(id))["first"] == True:
        try:
            with sql.connect("database.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO kycs (did,status,id) VALUES (?,?,?)",(did, dossier["status"], idDossier))
                con.commit()
                logging.info("kyc successfully added")
        except sql.Error as er: 
            print('SQLite error: %s' % (' '.join(er.args)))
            print("Exception class is: ", er.__class__)
            print('SQLite traceback: ')
            exc_type, exc_value, exc_tb = sys.exc_info()
            print(traceback.format_exception(exc_type, exc_value, exc_tb))

        finally:
            con.close()
    else:
        try:
            with sql.connect("database.db") as con:
                cur = con.cursor()
                print("update kycs set status='"+dossier["status"]+"',id="+str(idDossier)+" where did='"+did+"'")
                cur.execute("update kycs set status='"+dossier["status"]+"',id="+str(idDossier)+" where did='"+did+"'")
                con.commit()
                msg = "kyc successfully updated"
        except:
            con.rollback()
            msg = "error in update operation"
            
        finally:
            con.close()
            logging.info("msg db %s", str(msg))
    try:
        if(dossier["status"]=="OK" ): #or dossier["status"]=="KO"
            #return jsonify(dossier), 200
            return jsonify({"url":mode.server+"/id360/issuer_endpoint/"+id}),200
        else:
            return jsonify({"url":"error"}),200

    except TypeError:
        return jsonify({"url":"not yet"}),200
    except KeyError:
        return jsonify({"url":"error"}),500


@app.route('/id360/issuer_endpoint/<id>', methods = ['GET','POST'],  defaults={'red' : red})
async def vc_endpoint(id, red):  
    await loginID360()

    dossier= await get_dossier(pickle.loads(red.get(id))["idDossier"])
    print(dossier["extracted_data"])
    credential = json.load(open('VerifiableId.jsonld', 'r'))

    credential["issuer"] = issuer_did 
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['expirationDate'] =  (datetime.now() + timedelta(days= 365)).isoformat() + "Z"
    credential["credentialSubject"]["familyName"]=dossier["extracted_data"]["identity"][0]["name"]
    credential["credentialSubject"]["firstName"]=dossier["extracted_data"]["identity"][0]["first_names"][0]
    credential["credentialSubject"]["dateOfBirth"]=dossier["extracted_data"]["identity"][0]["birth_date"]
    if request.method == 'GET': 
        credential_manifest = json.load(open('VerifiableId_credential_manifest.json', 'r'))
        credential_manifest['id'] = str(uuid.uuid1())
        #credential_manifest['evidence']['id'] = str(uuid.uuid1())
        credential_manifest['issuer']['id'] = issuer_did
        credential_manifest['output_descriptors'][0]['id'] = str(uuid.uuid1())    
        credential['id'] = "urn:uuid:random" # for preview
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + timedelta(seconds = 180)).replace(microsecond=0).isoformat(),
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
        presentation_result = json.loads(await didkit.verify_presentation(request.form['presentation'], json.dumps({"challenge": id, "domain": mode.server})))
        if presentation_result['errors'] : #HERE
            logging.warning("presentation failed  %s", presentation_result)
            return jsonify('Unauthorized'), 401
        
        logging.info('credential = %s', credential)

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
        """data = json.dumps({"id" : id,
                         'message' : 'Ok credential transfered'})
        red.publish('altme-identity', data)
        red.delete(id)"""
        # cerdential sent to wallet
        event_data = json.dumps({"type": "altmeTransfered", "id": id})
        red.publish('verifier', event_data)
        return jsonify(signed_credential)


if __name__ == '__main__':
   app.run(host="localhost", port=3000, debug=True)

#qr code
#followup
#api link