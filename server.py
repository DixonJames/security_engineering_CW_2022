import socket, ssl

iphost, port = "127.0.0.1", "2222"


class Server:
    def __init__(self, cert_path, priv_key_path, iphost, port):
        self.cert_pth = cert_path
        self.priv_key_pth = priv_key_path

        self.ip= iphost
        self.port = port

        self.connection_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        self.connection_context.load_cert_chain(certfile=self.cert_pth, keyfile=self.priv_key_pth, password="dees")

        self.listen_socket  =None
        """
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
        context.set_ciphers('AES256+ECDH:AES256+EDH')
        """

    def setup(self):
        self.listen_socket = socket.socket()
        self.listen_socket.bind((self.ip, int(self.port)))

    def runComminication(self, cli_connection):
        recieved_data= cli_connection.recv(1024)
        while recieved_data is not None:
            print(recieved_data.decode("UFT-8"))
            recieved_data = cli_connection.recv(1024)

    def run(self):
        self.setup()
        #listen for connection
        self.listen_socket.listen(0)

        while True:
            client_socket, client_address  = self.listen_socket.accept()
            cli_connection = self.connection_context.wrap_socket(client_socket, server_side=True, do_handshake_on_connect=True, suppress_ragged_eofs=True)

            try:
                self.runComminication(cli_connection)
            except:
                cli_connection.shutdown(socket.SHUT_RDWR)
                cli_connection.close()




if __name__ == '__main__':
    cert_path = "data/keys/server.crt"
    priv_key_path = "data/keys/server.key"
    s = Server(cert_path, priv_key_path, iphost, port)
    s.run()