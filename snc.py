import argparse
import base64
import socket
import select
import sys
import queue
import json
from base64 import b64decode

from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes


def create_socket():
        global serverSocket
        serverSocket = socket.socket()



# Binding the socket and listening for connections
def decryptutil(password,result):
    b64 = json.loads(result)
    json_k = ['nonce', 'salt', 'ciphertext', 'tag']
    jv = {k: b64decode(b64[k]) for k in json_k}
    key = PBKDF2(password=password, salt=jv['salt'], count = 1000)

    cipher = AES.new(key, AES.MODE_GCM, nonce=jv['nonce'])

    plaintext = cipher.decrypt_and_verify(jv['ciphertext'], jv['tag'])

    # A readable client socket has data
    sys.stdout.write(plaintext.decode("utf-8"))


def encryptutil():
    while True:

        pin = 'abhi'
        msg = sys.stdin.readline()
        msg_binary = msg.encode()
        if msg:
            result = encrypt(msg_binary, pin)
            s.send(result.encode())
        else:
            break



def encrypt(data,pin):


    nonce = get_random_bytes(16)
    salt = get_random_bytes(16)

    # get key
    key = PBKDF2(password = pin,salt = salt)
    # print("in encrypt key :  ", key)

    # get cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce = nonce)

    # encrypt to get cypher text
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # making jason object
    json_k = ['nonce', 'salt', 'ciphertext', 'tag']
    json_v = [base64.b64encode(x).decode('utf-8') for x in (nonce, salt, ciphertext, tag)]
    result = json.dumps(dict(zip(json_k, json_v)))
    return result



def bind_socket(port):
    try:
        # print("Binding the Port: " + str(port))
        serverSocket.bind(("localhost", port))
        serverSocket.listen(5)
    except socket.error as msg:
        # print("Socket Binding error : " + str(msg) + "\n" + "Retrying ...")
        bind_socket()


def multiclient_accept(key):


    # Sockets from which we expect to read
    std_input = sys.stdin
    inputs = [serverSocket, std_input]

    # Sockets to which we expect to write
    outputs = []
    flag = 0

    try:
        while inputs:

            # Wait for at least one of the sockets to be ready for processing
            readable, writable, exceptional = select.select(inputs, outputs, inputs)

            # Handle inputs
            for skt in readable:
                if skt is serverSocket:
                    # A "readable" server socket is ready to accept a connection
                    connection, client_address = serverSocket.accept()
                    inputs.append(connection)
                elif skt is sys.stdin:
                    for s in inputs:
                        if s != sys.stdin and s != serverSocket:
                            if flag == 0:
                                msg = sys.stdin.readline()
                                flag = 1
                                msg_binary = msg.encode()
                                if len(msg) != 0:
                                    result = encrypt(msg_binary, key)
                                    s.send(result.encode())
                                else:
                                    exit(0)

                else:
                    client_response = skt.recv(4096)
                    if client_response.decode("utf-8") == "ok":
                        flag = 0
                    elif client_response and client_response.decode("utf-8") != 'ok':
                        decryptutil(key, client_response)
                        skt.send(b'ok')
                    else:
                        exit(0)

    except KeyboardInterrupt:
        serverSocket.close()
        exit(0)

def errorMessage(msg):
    sys.stderr.write(msg)
    exit(1)

def server(key, listen):
    create_socket()
    bind_socket(listen)
    multiclient_accept(key)

def client(key, host, port):
    clientSocket = socket.socket()

    clientSocket.connect((host, port))

    # Sockets from which we expect to read
    std_input = sys.stdin
    inputs = [clientSocket, std_input]

    # Sockets to which we expect to write
    outputs = []

    # Outgoing message queues (socket:Queue)
    message_queues = {}

    flag = 0

    try:
        while inputs:

            # Wait for at least one of the sockets to be ready for processing
            readable, writable, exceptional = select.select(inputs, outputs, inputs)

            # Handle inputs
            for skt in readable:
                if skt is sys.stdin:
                    # reading from stdin to send to server
                    # while True:
                    if flag == 0:
                        msg = sys.stdin.readline()
                        flag = 1
                        msg_binary = msg.encode()
                        if len(msg) != 0:
                            result = encrypt(msg_binary, key)
                            clientSocket.send(result.encode())
                        else:
                            exit(0)

                else:
                    # receive and decrypt logic
                    server_response = skt.recv(4096)
                    if server_response.decode("utf-8") == "ok":
                        flag = 0
                    elif server_response and server_response.decode("utf-8") != "ok":
                        decryptutil(key, server_response)
                        skt.send(b'ok')
                    else:
                        exit(0)
    except KeyboardInterrupt:
        clientSocket.close()
        exit(0)


def main():

    # socket_accept()


    parser = argparse.ArgumentParser()
    parser.add_argument("-k", "--key", help="Key", type=str, required=True)
    parser.add_argument("-l", "--listen", help="Port number", type=int, required=False)
    parser.add_argument("destination", nargs='?')
    parser.add_argument("port", nargs='?')
    args = parser.parse_args()

    if args.key and args.listen and not args.destination and not args.port:
        server(args.key, args.listen)
    elif args.key and args.destination and args.port and not args.listen:
        client(args.key, args.destination, int(args.port))
    else:
        print("Incorrect usage of arguments.\n Usage : snc [-l] [--key KEY] [destination] [port]")


main()