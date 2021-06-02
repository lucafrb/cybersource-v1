from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from base64 import b64encode


def cybersource_v1_encryption(publickey, ccnumber):
    if ("-BEGIN PUBLIC KEY-" not in publickey):
        format_public_key = "-----BEGIN PUBLIC KEY-----\n{publicKey}\n-----END PUBLIC KEY-----".format(
            publicKey=publickey)
    else:
        format_public_key = publickey
    key = RSA.importKey(format_public_key)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256.SHA256Hash())
    cipher_text = cipher.encrypt(ccnumber.encode())
    encryptedCCnumber = b64encode(cipher_text)
    return encryptedCCnumber


print(cybersource_v1_encryption("publickey", "credit_card_number"))