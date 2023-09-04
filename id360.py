import json

ID360_API_KEY = json.load(open("keys.json", "r"))['id360ApiKey']
ISSUER_VM = "did:web:app.altme.io:issuer#key-1"
ISSUER_DID = "did:web:app.altme.io:issuer"
ISSUER_KEY = json.dumps(json.load(open("keys.json", "r"))[
                        'talao_Ed25519_private_key'])