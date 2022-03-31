"""
referances:
sectret message taken from : http://montypython.50webs.com/scripts/Holy_Grail/Scene22.htm
"""
import socket
import ssl
from server import iphost, port
s_iphost, s_port = iphost, port


iphost, port = "127.0.0.1", "2223"

sectret_msg = """BRIDGEKEEPER: Stop! What... is your name?

GALAHAD: 'Sir Galahad of Camelot'.

BRIDGEKEEPER: What... is your quest?

GALAHAD: I seek the Grail.

BRIDGEKEEPER: What... is your favorite color?

GALAHAD: Blue. No, yel-- auuuuuuuugh!

BRIDGEKEEPER: Hee hee heh. Stop! What... is your name?

ARTHUR: It is 'Arthur', King of the Britons.

BRIDGEKEEPER: What... is your quest?

ARTHUR: To seek the Holy Grail.

BRIDGEKEEPER: What... is the air-speed velocity of an unladen swallow?

ARTHUR: What do you mean? An African or European swallow?

BRIDGEKEEPER: Huh? I-- I don't know that. Auuuuuuuugh!

BEDEVERE: How do know so much about swallows?

ARTHUR: Well, you have to know these things when you're a king, you know."""

class Client:
    def __init__(self, cert_path, iphost, port):
        self.cert_pth = cert_path


        self.ip = iphost
        self.port = port

        self.connection_context = ssl.SSLContext()
        self.connection_context.verify_mode = ssl.CERT_REQUIRED

        #self.connection_context.load_cert_chain(certfile=self.cert_pth,password="dees")
        self.connection_context

        self.listen_socket = None
        self.ssl_socket = None

    def setup(self):
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.bind((self.ip, int(self.port)))

        self.ssl_socket = ssl.wrap_socket(self.listen_socket,
                                          ca_certs=self.cert_pth,
                                          cert_reqs=ssl.CERT_REQUIRED,
                                          do_handshake_on_connect=True)

    def handelConnection(self):
        conn = self.ssl_socket
        pass

    def connect(self, server_ip, server_socket):
        self.setup()
        try:
            self.ssl_socket.connect((server_ip, server_socket))
            self.ssl_socket.do_handshake()
            self.handelConnection()
        except:
            self.ssl_socket.close()


if __name__ == '__main__':
    cert_path = "data/keys/ca.crt"
    s = Client(cert_path, iphost, port)
    s.connect(s_iphost, s_port)