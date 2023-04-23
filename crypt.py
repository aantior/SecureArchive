import os.path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import sys

default_public_key_pem = b'''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr5KXC5mgYxRGsYnClbf3
1oscj7z6ZaKahhJfHyHg0UrRc3tZ6UYvrwlPdV4KYCPCyeUpn6bhlC8LzXYM/W9G
dRUcvbQA719ma1R4y4I4pFJELEgFwTtCtC1tEXaeAHyI9IgQe9oXvBYCLUesRmvp
HpTKGbiq8sywc1COaoZkX7UQrC7S3nB4c+As7EW9Vr19TIE5pw8+5lmaekx/NPy3
IyfQ/fPSTTu/z/sZiMFSQ4RXNF/Baa1yFlbUApqxtfzYubsFA4am4rTazJpH8v+g
hb9sp/jNU7CuWnw2BwDay8sWbDybaF50sYGcKUwU1Nc8/q1pccvfE5nZ9XIheZjn
7QIDAQAB
-----END PUBLIC KEY-----'''

def encryptmessage(data):
    if os.path.exists("public_key.pem"):
        public_key_pem = readkey("public_key.pem")
    else:
        public_key_pem = default_public_key_pem
    if isinstance(data, str):
        data = data.encode('utf-8')
    encrypted_message = encrypt(public_key_pem, data)
    if isinstance(encrypted_message, bytes):
        encrypted_message = encrypted_message.decode('utf-8')
    return encrypted_message

def decryptmessage(data):
    if os.path.exists("private_key.pem"):
        private_key_pem = readkey("private_key.pem")
    else:
        return None
    if isinstance(data, str):
        data = data.encode('utf-8')
    decrypted_message = decrypt(private_key_pem, data)
    return decrypted_message.decode('utf-8')

def router(argv):
    print(argv, len(argv))
    if len(argv) not in [3, 4]:
        print(
            "Usage: \tpython encrypt_data.py encrypt <public_key_file> <data> or \n \tpython encrypt_data.py encrypt <data>")
        return

    mode = argv[1]
    data = None

    if mode == "encrypt":
        if len(argv) == 3:
            data = argv[2].encode('utf-8')
            public_key_pem = default_public_key_pem
        elif len(argv) == 4:
            public_key_pem = argv[2]
            public_key_pem = readkey(public_key_pem)
            data = argv[3].encode('utf-8')
            # print(f"public_key_pem = {public_key_pem}")
            # print(f"default_public_key_pem = {default_public_key_pem}")
        encrypted_data_base64 = encrypt(public_key_pem, data)
        print(f"encrypted_data_base64 = {encrypted_data_base64}")
        return encrypted_data_base64
    elif mode == "decrypt" and len(argv) == 4:
        private_key_pem = argv[2]
        private_key_pem = readkey(private_key_pem)
        data = argv[3].encode('utf-8')
        decrypted_data = decrypt(private_key_pem, data)
        print(f"decrypted_data = {decrypted_data}")
        return decrypted_data
    else:
        print("Usage: \tpython encrypt_data.py encrypt <public_key_file> <data> or \n \tpython encrypt_data.py encrypt <data>")
        return None

def main():
    router(sys.argv)

def readkey(KeyFileName):
    if KeyFileName is not None and KeyFileName.endswith('.pem'):
        with open(KeyFileName, 'rb') as f:
            key = f.read()
    return key

def decrypt(private_key_pem, encrypted_data_base64):
    decrypted_data = None
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    encrypted_data = base64.b64decode(encrypted_data_base64)
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_data

def encrypt(public_key_pem, data):
    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_data_base64 = base64.b64encode(encrypted_data)
    return encrypted_data_base64

if __name__ == "__main__":
    main()
