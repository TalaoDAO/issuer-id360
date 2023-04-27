import socket
import logging
import sys

logging.basicConfig(level=logging.INFO)

class currentMode() :
	def __init__(self, myenv):
		self.test = True
		self.myenv = myenv
		
		# En Prod chez AWS 
		if self.myenv == 'aws':
			self.server = 'https://talao.co/'
			self.IP = '18.190.21.227' 
		elif self.myenv == 'thierry' :
			self.server = 'http://' + extract_ip() + ':5000/'
			self.IP = extract_ip()
			self.port = 5000
		elif self.myenv == 'achille' :
			#self.server = 'localhost' + ':3000/'
			self.server = "https://talao.co"
			#self.server = "https://130b-86-229-94-232.ngrok-free.app"
			self.IP = 'localhost'
			self.port = 3000
		else :
			logging.error('environment variable problem')
			sys.exit()

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
