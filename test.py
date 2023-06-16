import json
WALLETS = json.load(open("wallets.json", "r"))
print(WALLETS.get("10","")[1])