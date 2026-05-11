# demo_output.py
#
# Generates readable encryption/decryption demonstration output
# using the custom AES, DES, and 3DES implementations.

import os
import base64

from data_generator import generate_application_plaintext

import custom_aes
import custom_des
import custom_3des


RESULTS_DIR = "results"
OUTPUT_FILE = os.path.join(RESULTS_DIR, "encryption_decryption_demo.txt")


AES_KEY = b"1234567890ABCDEF"
AES_IV = b"ABCDEF1234567890"

DES_KEY = b"12345678"
DES_IV = b"ABCDEFGH"

TDES_KEY = b"12345678ABCDEFGH87654321"
TDES_IV = b"HGFEDCBA"


ALGORITHMS = {
    "Custom AES": {
        "encrypt": lambda plaintext: custom_aes.encrypt_cbc(
            plaintext,
            AES_KEY,
            AES_IV
        ),
        "decrypt": lambda ciphertext: custom_aes.decrypt_cbc(
            ciphertext,
            AES_KEY,
            AES_IV
        )
    },
    "Custom DES": {
        "encrypt": lambda plaintext: custom_des.encrypt_cbc(
            plaintext,
            DES_KEY,
            DES_IV
        ),
        "decrypt": lambda ciphertext: custom_des.decrypt_cbc(
            ciphertext,
            DES_KEY,
            DES_IV
        )
    },
    "Custom 3DES": {
        "encrypt": lambda plaintext: custom_3des.encrypt_3des_cbc(
            plaintext,
            TDES_KEY,
            TDES_IV
        ),
        "decrypt": lambda ciphertext: custom_3des.decrypt_3des_cbc(
            ciphertext,
            TDES_KEY,
            TDES_IV
        )
    }
}


def shorten_bytes(data, length=500):
    """
    Return a shortened printable version of byte data.
    """
    text = data.decode(errors="replace")

    if len(text) <= length:
        return text

    return text[:length] + "\n... [output truncated] ..."


def encode_ciphertext(ciphertext, length=500):
    """
    Convert ciphertext bytes into printable Base64 text.
    """
    encoded = base64.b64encode(ciphertext).decode()

    if len(encoded) <= length:
        return encoded

    return encoded[:length] + "\n... [ciphertext truncated] ..."


def generate_demo_output():
    """
    Generate demonstration output showing:
    - original plaintext
    - ciphertext sample
    - recovered plaintext
    - correctness check
    """

    os.makedirs(RESULTS_DIR, exist_ok=True)

    plaintext = generate_application_plaintext(2048)

    with open(OUTPUT_FILE, "w") as file:
        file.write("Encryption and Decryption Demonstration\n")
        file.write("=" * 60 + "\n\n")

        file.write("Implementation Type:\n")
        file.write("-" * 60 + "\n")
        file.write("Custom AES, custom DES, and custom 3DES implementations\n\n")

        file.write("Original Plaintext Sample:\n")
        file.write("-" * 60 + "\n")
        file.write(shorten_bytes(plaintext))
        file.write("\n\n")

        for algorithm_name, funcs in ALGORITHMS.items():
            ciphertext = funcs["encrypt"](plaintext)
            recovered_plaintext = funcs["decrypt"](ciphertext)

            file.write(f"{algorithm_name} Results\n")
            file.write("=" * 60 + "\n")

            file.write("Ciphertext Sample, Base64 Encoded:\n")
            file.write("-" * 60 + "\n")
            file.write(encode_ciphertext(ciphertext))
            file.write("\n\n")

            file.write("Recovered Plaintext Sample:\n")
            file.write("-" * 60 + "\n")
            file.write(shorten_bytes(recovered_plaintext))
            file.write("\n\n")

            file.write("Correctness Check:\n")
            file.write("-" * 60 + "\n")

            if plaintext == recovered_plaintext:
                file.write("PASS: decrypted plaintext matches original plaintext.\n\n")
            else:
                file.write("FAIL: decrypted plaintext does not match original plaintext.\n\n")

            file.write("Ciphertext Size:\n")
            file.write("-" * 60 + "\n")
            file.write(f"{len(ciphertext)} bytes\n\n")

    print(f"Demo output saved to: {OUTPUT_FILE}")