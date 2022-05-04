"""
referances:
sectret message taken from : http://montypython.50webs.com/scripts/Holy_Grail/Scene22.htm
"""
import socket
import ssl
from server import iphost, port

s_iphost, s_port = iphost, port
#iphost, port = "127.0.0.1", "2223"
iphost, port = "10.9.0.6", "2223"
#destination = "10.9.0.6"
sectret_msg = """
BRIDGEKEEPER: Hee hee heh. Stop! What... is your name?
ARTHUR: It is 'Arthur', King of the Britons.
BRIDGEKEEPER: What... is your quest?
ARTHUR: To seek the Holy Grail.
BRIDGEKEEPER: What... is the air-speed velocity of an unladen swallow?
ARTHUR: What do you mean? An African or European swallow?
BRIDGEKEEPER: Huh? I-- I don't know that. Auuuuuuuugh!
BEDEVERE: How do know so much about swallows?
ARTHUR: Well, you have to know these things when you're a king, you know.@"""


class Client:
    def __init__(self, cert_path, iphost, port):
        self.ca_cert_pth = cert_path

        self.ip = iphost
        self.port = port

        self.connection_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, capath=self.ca_cert_pth)

        # self.connection_context.load_cert_chain(certfile=self.ca_cert_pth, password="dees")

        self.listen_socket = None
        self.ssl_socket = None
        self.connection = None

    def setup(self):
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.listen_socket.bind((self.ip, int(self.port)))

        self.connection = ssl.wrap_socket(self.listen_socket,
                                          ca_certs=self.ca_cert_pth,
                                          cert_reqs=ssl.CERT_REQUIRED,
                                          do_handshake_on_connect=True,
                                          server_side=False)

    def handelConnection(self):
        received_str_tot = ""
        conn = self.connection
        try:
            response_length = 0
            conn.sendall(bytes(sectret_msg, 'utf-8'))
            print("sent secret msg")

            while response_length < len(sectret_msg):
                data = conn.recv(16)

                d_len = len(data)
                if d_len == 0:
                    d_len +=1
                response_length += d_len

                #print(f"received back: {data}")
                received_str_tot += data.decode("UTF-8")

        finally:
            #print(received_str_tot)
            if received_str_tot == sectret_msg:
                print("sent and received identical \n Success!")
            print("closing connection")
            conn.close()

    def connect(self, server_ip, server_socket):
        self.setup()
        try:
            self.connection.connect((server_ip, server_socket))
            self.connection.do_handshake()
            # self.connection.do_handshake()
            self.handelConnection()
        except:

            self.connection.close()


if __name__ == '__main__':
    cert_path = "data/keys/ca.crt"
    s = Client(cert_path, iphost, port)
    s.connect(s_iphost, int(s_port))
