from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Cipher import AES, PKCS1_OAEP

from Cryptodome.Hash import SHA256
from Cryptodome import Random
from Cryptodome.Signature import pss


def generate_private_key(secret_code = "blockchaimessenger", save_secret_code = True):
        
    key = RSA.generate(1024)
    encrypted_key = key.export_key(passphrase=secret_code, pkcs=8, protection="scryptAndAES128-CBC")
    
    if save_secret_code:
        f = open('./passphrase.pem', 'wb')
        f.write(secret_code.encode('utf-8'))
        f.close()
        """
        the passphrase can be read easily with the following codes

        f = open('./passphrase.pem', 'rb')
        psw = f.read().decode('utf-8')
        """
    
    f = open('./privatekey.pem','wb')
    f.write(encrypted_key)
    f.close()

    return key

def encrypt_messege(messege, key):
    data = messege.encode('utf-8')
    recipient_key = key.publickey()
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    # the session key is used for only one time
    """
    TODO 
    PKCS1_OAEP can only encrypt messeges slightly shorter than the RSA modulus (a few hundred bytes).
    Therefore, for the pratical usage, we developers need to separate the whole messege into several 
    small pieces which suits the size of PKCS1_OAEP
    """
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    return [enc_session_key, cipher_aes.nonce, tag, ciphertext]

def decrypt_messege(key, enc_session_key, nonce, tag, ciphertext):
    # Decrypt the session key with the private RSA key
    cipher_rsa = PKCS1_OAEP.new(key.publickey())
    session_key = cipher_rsa.decrypt(enc_session_key)

    # Decrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    messege = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return messege


def signature(sign_messege, key):
    messege = sign_messege.encode('utf-8')
    h = SHA256.new(messege)
    signature = pss.new(key).sign(h)

    return signature

def verify_signature(sign_messege, signature, key):
    h = h = SHA256.new(sign_messege)
    verifier = pss.new(key.publickey())
    try:
        verifier.verify(h, signature)
        print ("The signature is authentic.")
        return True
    except (ValueError, TypeError):
        print ("The signature is not authentic.")
        return False
    
