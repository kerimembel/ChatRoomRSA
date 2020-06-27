import socket
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

clients = {}
public_keys = {}

def accept_incoming_connections():
    """Sets up handling for incoming clients."""

    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        client.send(bytes("Type your name and press enter!", "utf8"))
        Thread(target=handle_client, args=(client,)).start()


def handle_client(client):  # Takes client socket as argument.
    """Handles a single client connection."""
    #Key pair for each client
    keyPair = RSA.generate(1024)
    pubKey = keyPair.publickey()
    pubKeyPEM = pubKey.exportKey()
    privKeyPEM = keyPair.exportKey()

    name = client.recv(BUFSIZ).decode("utf8")
    #Write public keys of users into a file
    with open(name+"_pub.bin","w") as f:
        f.write(pubKeyPEM.decode('ascii'))
    
    #Send private keys of users to them
    client.send(bytes("@"+privKeyPEM.decode('ascii'), "utf-8"))
    message = 'Welcome %s! Type "quit" to exit.' % name
    client.send(bytes(message, "utf-8"))
  
    clients[client] = name

    while True:
        msg = client.recv(BUFSIZ)
        if msg != bytes("quit", "utf8"):
            msg = msg.decode()
            print(msg)
            if(msg.startswith('@')):
                parsed_msg = msg.split(":")
                to = parsed_msg[0][1:].lower()
                broadcast(bytes(parsed_msg[1] +":"+ parsed_msg[2],"utf-8"), name+" : ",to)
            elif(msg.startswith('')):
                pass

        else:
            client.send(bytes("quit", "utf-8"))
            client.close()
            del clients[client]
            broadcast(bytes("%s has left the chat.\n" % name, "utf-8"))
            break


def broadcast(msg, name="",to=""): 

    for sock in clients:
        if(to!="" and clients[sock] == to):
            sock.send(bytes(name, "utf-8")+msg)
        elif(to==""):
        #else:
            sock.send(bytes(name, "utf-8")+msg)
    

LOCALHOST = "127.0.0.1"
PORT = 65534
BUFSIZ = 1024

SERVER = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
SERVER.bind((LOCALHOST, PORT))

SERVER.listen(2)
print("Waiting for connection...")
ACCEPT_THREAD = Thread(target=accept_incoming_connections)
ACCEPT_THREAD.start()
ACCEPT_THREAD.join()
SERVER.close()

