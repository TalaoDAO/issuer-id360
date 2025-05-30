import socket
import logging
import sys
import json
logging.basicConfig(level=logging.INFO)

ngrok = "https://32c4275aca1c.ngrok.app"

class currentMode():
    def __init__(self, myenv):
        self.test = True
        self.myenv = myenv

        # En Prod chez AWS
        self.port = 3000
        if self.myenv == 'aws':
            self.server = "https://talao.co"
            self.IP = 'localhost'
            self.journey_fr = "cf30908f-d1a9-4109-8248-5b68df16c6b8"
            self.journey = "e7831d5d-0111-48ec-b9ab-ce6cc5886d73"
            self.journey_oidc = "cf30908f-d1a9-4109-8248-5b68df16c6b8"
            self.url = 'https://id360docaposte.com/'
            self.url_customers = 'https://preprod.id360docaposte.com/'
            self.username = json.load(open("keys.json", "r"))['username_prod']
            self.password = json.load(open("keys.json", "r"))['password_prod']
            self.username_customers = json.load(
                open("keys.json", "r"))['username']
            self.password_customers = json.load(
                open("keys.json", "r"))['password']
        elif self.myenv == 'local':
            self.server = ngrok
            self.IP = extract_ip()
            self.journey = "2ebe20ac-f801-4daa-9d7f-bf0a6354ab2e"
            self.journey_oidc = "2ebe20ac-f801-4daa-9d7f-bf0a6354ab2e"
            self.url = 'https://preprod.id360docaposte.com/'
            self.url_customers = 'https://preprod.id360docaposte.com/'
            self.username = json.load(open("keys.json", "r"))['username']
            self.password = json.load(open("keys.json", "r"))['password']
            self.username_customers = json.load(
                open("keys.json", "r"))['username']
            self.password_customers = json.load(
                open("keys.json", "r"))['password']


def extract_ip():
    st = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        st.connect(('10.255.255.255', 1))
        IP = st.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        st.close()
    return IP
