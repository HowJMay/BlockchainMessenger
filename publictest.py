from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Cipher import AES, PKCS1_OAEP
# http://pycryptodome.readthedocs.io/en/latest/src/signature/pkcs1_pss.html
from Cryptodome.Hash import SHA256
from Cryptodome import Random
from Cryptodome.Signature import pss

secret_code = "blockchaimessenger"
key = RSA.generate(1024)
encrypted_key = key.export_key(passphrase=secret_code, pkcs=8,
                              protection="scryptAndAES128-CBC")

#file_out.write(encrypted_key)

data = "I met aliens in UFO. Here is the map.".encode("utf-8")
#file_out = open("encrypted_data.bin", "wb")

#recipient_key = RSA.import_key(open("receiver.pem").read())
recipient_key = key.publickey()
session_key = get_random_bytes(16)

# Encrypt the session key with the public RSA key
cipher_rsa = PKCS1_OAEP.new(recipient_key)
enc_session_key = cipher_rsa.encrypt(session_key)

# Encrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX)
ciphertext, tag = cipher_aes.encrypt_and_digest(data)
#[ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]

print (ciphertext)
print(key.export_key())
print(key.publickey().export_key())

private_key = key


# Decrypt the session key with the private RSA key
cipher_rsa = PKCS1_OAEP.new(private_key)
session_key = cipher_rsa.decrypt(enc_session_key)

# Decrypt the data with the AES session key
cipher_aes = AES.new(session_key, AES.MODE_EAX, cipher_aes.nonce)
data = cipher_aes.decrypt_and_verify(ciphertext, tag)
print(data.decode("utf-8"))
#########################################################################  signature  #########################################################################
message = 'To be signed'.encode('utf-8')
h = SHA256.new(message)
print('h = ' + str(h))
signature = pss.new(key).sign(h)
print('signature = ' + str(signature))

verifier = pss.new(recipient_key)
try:
    verifier.verify(h, signature)
    print ("The signature is authentic.")
except (ValueError, TypeError):
    print ("The signature is not authentic.")


