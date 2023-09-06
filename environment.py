import socket
import logging
import sys
import json
logging.basicConfig(level=logging.INFO)

class currentMode() :
	def __init__(self, myenv):
		self.test = True
		self.myenv = myenv
		
		# En Prod chez AWS 
		if self.myenv == 'aws':
			self.server = "https://talao.co"
			self.IP = 'localhost'
			self.port = 3000
			self.journey = "cf30908f-d1a9-4109-8248-5b68df16c6b8"
			self.journey_customer = "5a1f40a7-0e0a-4c9c-94b1-4e9ec7736c21"
			self.url='https://id360docaposte.com/'
			self.url_customers='https://preprod.id360docaposte.com/'
			self.username=json.load(open("keys.json", "r"))['username_prod']
			self.password=json.load(open("keys.json", "r"))['password_prod']
			self.username_customers=json.load(open("keys.json", "r"))['username']
			self.password_customers=json.load(open("keys.json", "r"))['password']
		elif self.myenv == 'local':
			self.server = "https://53ac-2a04-cec0-11df-2c18-2b28-649-42e4-ff98.ngrok-free.app"
			self.IP = 'localhost'
			self.port = 3000
			self.journey = "2ebe20ac-f801-4daa-9d7f-bf0a6354ab2e"
			self.journey_customer = "5a1f40a7-0e0a-4c9c-94b1-4e9ec7736c21"
			self.url='https://preprod.id360docaposte.com/'
			self.username=json.load(open("keys.json", "r"))['username']
			self.password=json.load(open("keys.json", "r"))['password']
			self.username_customers=json.load(open("keys.json", "r"))['username']
			self.password_customers=json.load(open("keys.json", "r"))['password']



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
