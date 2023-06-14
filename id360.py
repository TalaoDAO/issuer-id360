import json

JOURNEY = "cf30908f-d1a9-4109-8248-5b68df16c6b8"  # SVID
URL = 'https://id360docaposte.com/'
ID360_API_KEY = json.load(open("keys.json", "r"))['id360ApiKey']
USERNAME = json.load(open("keys.json", "r"))['username_prod']
PASSWORD = json.load(open("keys.json", "r"))['password_prod']
ISSUER_VM = "did:web:app.altme.io:issuer#key-1"
ISSUER_DID = "did:web:app.altme.io:issuer"
ISSUER_KEY = json.dumps(json.load(open("keys.json", "r"))[
                        'talao_Ed25519_private_key'])