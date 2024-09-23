import os
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

AES_KEY_SIZE = 256
IV_SIZE = 16
SALT_SIZE = 16
GCM_TAG_SIZE = 16
ITERATIONS = 65535
TIMESTAMP_SIZE = 8
TIMESTAMP_TIMEOUT = 20_000


def current_time_millis() -> int:
    return int(time.time() * 1000)


def generate_key(pwd: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        iterations=ITERATIONS,
        length=AES_KEY_SIZE // 8,
    )
    return kdf.derive(pwd.encode())


def encrypt_aes(src: bytes, pwd: str) -> bytes:
    salt: bytes = os.urandom(SALT_SIZE)
    key: bytes = generate_key(pwd, salt)
    iv: bytes = os.urandom(IV_SIZE)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    encryptor = cipher.encryptor()

    timestamp = current_time_millis().to_bytes(
        8, byteorder="big"
    )  # current time millis
    ciphertext = encryptor.update(timestamp + src) + encryptor.finalize()

    return iv + salt + ciphertext + encryptor.tag


def decrypt_aes(src: bytes, pwd: str) -> bytes:
    iv = src[:IV_SIZE]
    salt = src[IV_SIZE : IV_SIZE + SALT_SIZE]
    ciphertext = src[IV_SIZE + SALT_SIZE : -GCM_TAG_SIZE]
    tag = src[-GCM_TAG_SIZE:]

    key = generate_key(pwd, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    timestamp = int.from_bytes(plaintext[:TIMESTAMP_SIZE], byteorder="big")
    time_diff = current_time_millis() - timestamp
    if time_diff < -TIMESTAMP_TIMEOUT or time_diff > TIMESTAMP_TIMEOUT:
        raise Exception("Invalid timestamp on AES data!")
    return plaintext[TIMESTAMP_SIZE:]
