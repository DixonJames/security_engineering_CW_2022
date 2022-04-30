import socket, ssl

iphost, port = "127.0.0.1", "22239"


class Server:
    def __init__(self,ca_cert_path, cert_path, priv_key_path, iphost, port):
        self.ca_cert_path = ca_cert_path
        self.cert_pth = cert_path
        self.priv_key_pth = priv_key_path

        self.ip = iphost
        self.port = port

        self.listen_socket = None
        self.sslSettings = None
        sslSettings = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, capath=self.ca_cert_path)
        sslSettings.load_cert_chain(self.cert_pth, keyfile=self.priv_key_pth, password="dees")
        sslSettings.verify_mode=ssl.CERT_NONE
        self.sslSettings = sslSettings

        """
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # optional
        context.set_ciphers('AES256+ECDH:AES256+EDH')
        """

    def socketCreation(self):
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.bind((self.ip, int(self.port)))


    def runComminication(self, cli_connection):
        received_data = cli_connection.recv(16)
        received_string_tot = ""
        while received_data is not None:
            received_str = received_data.decode("UTF-8")
            print(f"received: {received_str}")
            try:
                print(f"echoing back received msg")
                while received_data is not None:

                    cli_connection.sendall(bytes(received_str, 'utf-8'))

                    received_data = cli_connection.recv(16)
                    received_str = received_data.decode("UTF-8")
                    received_string_tot += received_str

                    if "@" in received_str:
                        cli_connection.sendall(bytes(received_str, 'utf-8'))
                        received_data = None


            finally:
                # Clean up the connection
                print("Received data:")
                print(received_string_tot)
                print("no more data to echo back")
                #cli_connection.close()



    def run(self):

        self.socketCreation()
        # listen for connection
        self.listen_socket.listen(1)
        secure_connection = None

        while True:
            server_sock, client_address = self.listen_socket.accept()
            #make connection SLL

            print(f"connection from {client_address}")
            try:
                secure_connection = self.sslSettings.wrap_socket(server_sock, server_side=True, do_handshake_on_connect=True)
                self.runComminication(secure_connection)

            finally:

                server_sock.close()
                secure_connection.shutdown(socket.SHUT_RDWR)
                exit(2)


if __name__ == '__main__':
    ca_cer_path = "data/keys/ca.crt"
    cert_path = "data/keys/server.crt"
    priv_key_path = "data/keys/server.key"
    s = Server(ca_cer_path, cert_path, priv_key_path, iphost, port)
    s.run()
