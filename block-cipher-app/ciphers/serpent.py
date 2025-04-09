from ciphers import serpent_ref
import codecs

serpent_ref.O.show = lambda *args: None


# Function to reverse a string
def revString(s):
    s = s[::-1]
    return s

class _serpent:
    def __init__(self,key):
        size = serpent_ref.keyLengthInBitsOf(key)
        key = codecs.encode(key, 'hex') #bytearray to binary string
        key = key.decode('utf-8') #get normal string
        rawKey = serpent_ref.convertToBitstring(key.lower()[::-1], size)
        self.userKey = serpent_ref.makeLongKey(rawKey)

    def encrypt(self,block):
        plainText = serpent_ref.convertToBitstring(revString(block.hex()), 128)
        cipherText = serpent_ref.encrypt(plainText, self.userKey)
        return codecs.decode(serpent_ref.bitstring2hexstring(cipherText)[::-1], "hex_codec")


    def decrypt(self,block):
        cipherText = serpent_ref.convertToBitstring(revString(block.hex()), 128)
        plainText = serpent_ref.decrypt(cipherText, self.userKey)
        return codecs.decode(serpent_ref.bitstring2hexstring(plainText)[::-1], "hex_codec")

class serpent_cbc:
    def __init__(self, key, iv):
        if len(iv) != 16: raise Exception("Bad IV size")
        self.ctx = _serpent(key)
        self._state = iv

    def encrypt(self, plaintext):
        ciphertext = b""
        n = len(plaintext)
        rem = n % 16
        for i in range(0, len(plaintext), 16):
            block = bytearray(b"\0"*16)
            for j in range(len(plaintext[i:i+16])):
                block[j] = plaintext[i+j] ^ self._state[j]
            if (i+j) >= n-1:                                    #PADDING
                block = b"".join([block[:rem], self._state[rem:16]])
            '''while len(block) < 16:
                block += self._state[len(block)]'''
            self._state = self.ctx.encrypt(bytes(block))            
            #print(self._state)
            ciphertext = b"".join([ciphertext, self._state])
            #print(self._state.hex())
        return ciphertext

    def decrypt(self, ciphertext):
        plaintext = b""
        for i in range(0, len(ciphertext), 16):
            block = self.ctx.decrypt(ciphertext[i:i+16])
            tmp = bytearray(b"\0"*16)
            for j in range(len(block)):
                tmp[j] = self._state[j] ^ block[j]
            self._state = ciphertext[i:i+16]
            #plaintext += tmp
            plaintext = b"".join([plaintext, tmp])
        return plaintext


if __name__ == '__main__':
    ctx = _serpent("\0"*32)
    buff = ctx.encrypt("\0"*16)
    print (buff.encode('hex'))

    ctx = _serpent("\0"*32)
    print (ctx.decrypt(buff).encode('hex'),"\n")

    ctx = serpent_cbc("\0"*32, "\0"*16)
    buff = ctx.encrypt("abcdefghijklmnopqrstuvwxyz0123456789")
    print (buff.encode('hex'))

    ctx = serpent_cbc("\0"*32, "\0"*16)
    print (ctx.decrypt(buff))