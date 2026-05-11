
# crypto_algorithms.py

from Crypto.Cipher import AES, DES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from config import (
    AES_KEY_SIZE,
    AES_BLOCK_SIZE,
    DES_KEY_SIZE,
    DES_BLOCK_SIZE,
    TDES_KEY_SIZE,
    TDES_BLOCK_SIZE
)

# =========================================================
# AES
# =========================================================

AES_KEY = get_random_bytes(AES_KEY_SIZE)
AES_IV = get_random_bytes(AES_BLOCK_SIZE)


def encrypt_aes(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded_data = pad(plaintext, AES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


def decrypt_aes(ciphertext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    decrypted_data = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_data, AES_BLOCK_SIZE)
    return plaintext


# =========================================================
# DES
# =========================================================

DES_KEY = get_random_bytes(DES_KEY_SIZE)
DES_IV = get_random_bytes(DES_BLOCK_SIZE)


def encrypt_des(plaintext):
    cipher = DES.new(DES_KEY, DES.MODE_CBC, DES_IV)
    padded_data = pad(plaintext, DES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


def decrypt_des(ciphertext):
    cipher = DES.new(DES_KEY, DES.MODE_CBC, DES_IV)
    decrypted_data = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_data, DES_BLOCK_SIZE)
    return plaintext


# =========================================================
# 3DES
# =========================================================

TDES_KEY = DES3.adjust_key_parity(
    get_random_bytes(TDES_KEY_SIZE)
)

TDES_IV = get_random_bytes(TDES_BLOCK_SIZE)


def encrypt_3des(plaintext):
    cipher = DES3.new(TDES_KEY, DES3.MODE_CBC, TDES_IV)
    padded_data = pad(plaintext, TDES_BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded_data)
    return ciphertext


def decrypt_3des(ciphertext):
    cipher = DES3.new(TDES_KEY, DES3.MODE_CBC, TDES_IV)
    decrypted_data = cipher.decrypt(ciphertext)
    plaintext = unpad(decrypted_data, TDES_BLOCK_SIZE)
    return plaintext