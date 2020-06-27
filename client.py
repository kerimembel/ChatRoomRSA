import socket
from threading import Thread
from Encryption import AESCipher
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import string 
import random

#Create random symmetric key
key = ''.join(random.choices(string.ascii_uppercase + string.digits, k = 10))
print("Random generated key of user : " , key)
aes = AESCipher(key)

priv_key = ''
def receive():
    """Handles receiving of messages."""
    while True:
        try:
            msg = client.recv(BUFSIZ).decode("utf-8")
            #print(msg)
            if(msg[0] == "@"):
                priv_key = msg[1:]
            elif(':' in msg):
              
                parsed_msg = msg.split(':')
                private_key = RSA.importKey(priv_key)
                decryptor = PKCS1_OAEP.new(private_key)
                decrypted_key = decryptor.decrypt(binascii.unhexlify(bytes(parsed_msg[2],"utf-8")))
                print("Randomly generated key from the sender : ",decrypted_key.decode("utf-8"))              
                new_aes = AESCipher(decrypted_key.decode("utf-8"))
                decrypted = new_aes.decrypt(bytes(parsed_msg[1],"utf-8"))

                print(parsed_msg[0]+":"+decrypted.decode())
            else:
                print(msg)
        except OSError:  # Possibly client has left the chat.
            break


SERVER = "127.0.0.1"
PORT = 65534
BUFSIZ = 1024
#key = input("Enter the symmetric key you want to use : ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((SERVER, PORT))

receive_thread = Thread(target=receive)
receive_thread.start()

while True:
    msg = input()
    parsed_msg = msg.split(':')
    if(len(parsed_msg)>1):
        #Take the recievers public key to encrypt symmetric key
        try:
            with open(parsed_msg[0][1:]+"_pub.bin","r") as pub_file:
                pub_key = RSA.importKey(pub_file.read())
                encryptor = PKCS1_OAEP.new(pub_key)
                encrypted_key = encryptor.encrypt(bytes(key,"utf-8"))
        except FileNotFoundError:
            print("There is no user named " ,parsed_msg[0][1:] )
            break
            
        cipher = aes.encrypt(parsed_msg[1]) + bytes(":" ,"utf-8") + binascii.hexlify(encrypted_key)
        client.send(bytes(parsed_msg[0]+':',"utf-8")+cipher)
    else:
        client.send(bytes(msg,"utf-8"))


    if msg == "quit":
        client.close()
        break

