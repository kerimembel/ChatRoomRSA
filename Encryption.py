from Cryptodome.Cipher import AES
import hashlib
import base64
from Cryptodome import Random

class AESCipher:    #AES in Cipher Block Chaining Mode

    def __init__( self, key ):
        self.block_size = 16
        self.key = hashlib.sha256(key.encode('utf-8')).digest()

    def encrypt( self, raw ):
        raw = pad(raw,self.block_size)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw.encode('utf-8') ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt(enc[16:]),self.block_size)


#Padding functions
def pad(s,BS):
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)


def unpad(s,BS):
    return s[0:-s[-1]]