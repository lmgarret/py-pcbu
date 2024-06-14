import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_KEY_SIZE = 256
IV_SIZE = 16
SALT_SIZE = 16
ITERATIONS = 65535

def generate_key(pwd: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=ITERATIONS,
        length=AES_KEY_SIZE // 8
    )
    return kdf.derive(pwd.encode())

def encrypt_aes(src: bytes, pwd: str):
    salt: bytes = os.urandom(SALT_SIZE)
    key: bytes = generate_key(pwd, salt)
    iv: bytes = os.urandom(IV_SIZE)

    timestamp = int(time.time() * 1000).to_bytes(8) # current time millis

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(timestamp + src) + encryptor.finalize()

    return iv + salt + ciphertext + encryptor.tag

def decrypt_aes(src: bytes, pwd: str) -> bytes:
    iv = src[:IV_SIZE]
    salt = src[IV_SIZE:IV_SIZE + SALT_SIZE]
    ciphertext = src[IV_SIZE + SALT_SIZE:-16]
    tag = src[-16:]

    key = generate_key(pwd, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
