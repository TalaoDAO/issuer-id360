import json

with open("keys.json", "r", encoding="utf-8") as key_file:
    keys = json.load(key_file)

ID360_API_KEY = keys["id360ApiKey"]
OPENID4VC_HUB_API_KEY = keys["openid4vc-hub"]

del keys
