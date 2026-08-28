import json
import socket


ngrok = "https://32c4275aca1c.ngrok.app"


class currentMode():
    def __init__(self, myenv):
        with open("keys.json", "r", encoding="utf-8") as key_file:
            keys = json.load(key_file)

        self.port = 3000
        if myenv == 'aws':
            self.server = "https://talao.co"
            self.IP = 'localhost'
            self.journey_fr = "cf30908f-d1a9-4109-8248-5b68df16c6b8"
            self.journey = "e7831d5d-0111-48ec-b9ab-ce6cc5886d73"
            self.journey_oidc = "cf30908f-d1a9-4109-8248-5b68df16c6b8"
            self.url = 'https://id360docaposte.com/'
            self.url_customers = 'https://preprod.id360docaposte.com/'
            self.username = keys['username_prod']
            self.password = keys['password_prod']
            self.username_customers = keys['username']
            self.password_customers = keys['password']
        elif myenv == 'local':
            self.server = ngrok
            self.IP = extract_ip()
            self.journey = "2ebe20ac-f801-4daa-9d7f-bf0a6354ab2e"
            self.journey_oidc = "2ebe20ac-f801-4daa-9d7f-bf0a6354ab2e"
            self.url = 'https://preprod.id360docaposte.com/'
            self.url_customers = 'https://preprod.id360docaposte.com/'
            self.username = keys['username']
            self.password = keys['password']
            self.username_customers = keys['username']
            self.password_customers = keys['password']


def extract_ip():
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ip_socket:
            ip_socket.connect(('10.255.255.255', 1))
            return ip_socket.getsockname()[0]
    except OSError:
        return '127.0.0.1'
