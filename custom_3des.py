# custom_3des.py
#
# Custom 3DES implementation built on top of custom DES.

from custom_des import (
    encrypt_block,
    decrypt_block,
    pkcs7_pad,
    pkcs7_unpad,
    xor_bytes
)


# ============================================================
# 3DES Key Handling
# ============================================================

def split_3des_key(key):
    """
    Split a 24-byte 3DES key into three 8-byte DES keys.
    """
    if len(key) != 24:
        raise ValueError("3DES key must be exactly 24 bytes.")

    key1 = key[0:8]
    key2 = key[8:16]
    key3 = key[16:24]

    return key1, key2, key3


# ============================================================
# 3DES Block Encryption
# ============================================================

def encrypt_3des_block(block, key):
    """
    Encrypt one 8-byte block using 3DES EDE mode.

    EDE:
        Encrypt with K1
        Decrypt with K2
        Encrypt with K3
    """
    if len(block) != 8:
        raise ValueError("3DES block must be exactly 8 bytes.")

    key1, key2, key3 = split_3des_key(key)

    stage1 = encrypt_block(block, key1)
    stage2 = decrypt_block(stage1, key2)
    stage3 = encrypt_block(stage2, key3)

    return stage3


def decrypt_3des_block(block, key):
    """
    Decrypt one 8-byte block using 3DES EDE mode.
    """
    if len(block) != 8:
        raise ValueError("3DES block must be exactly 8 bytes.")

    key1, key2, key3 = split_3des_key(key)

    stage1 = decrypt_block(block, key3)
    stage2 = encrypt_block(stage1, key2)
    stage3 = decrypt_block(stage2, key1)

    return stage3


# ============================================================
# 3DES CBC Mode
# ============================================================

def encrypt_3des_cbc(plaintext, key, iv):
    """
    Encrypt a full plaintext message using custom 3DES CBC mode.
    """
    if len(key) != 24:
        raise ValueError("3DES key must be exactly 24 bytes.")

    if len(iv) != 8:
        raise ValueError("3DES IV must be exactly 8 bytes.")

    padded_plaintext = pkcs7_pad(plaintext, 8)

    ciphertext = b""
    previous_block = iv

    for block_start in range(0, len(padded_plaintext), 8):
        plaintext_block = padded_plaintext[block_start:block_start + 8]

        mixed_block = xor_bytes(plaintext_block, previous_block)

        encrypted_block = encrypt_3des_block(mixed_block, key)

        ciphertext += encrypted_block

        previous_block = encrypted_block

    return ciphertext


def decrypt_3des_cbc(ciphertext, key, iv):
    """
    Decrypt a full ciphertext message using custom 3DES CBC mode.
    """
    if len(key) != 24:
        raise ValueError("3DES key must be exactly 24 bytes.")

    if len(iv) != 8:
        raise ValueError("3DES IV must be exactly 8 bytes.")

    if len(ciphertext) == 0 or len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext must be a non-empty multiple of 8 bytes.")

    padded_plaintext = b""
    previous_block = iv

    for block_start in range(0, len(ciphertext), 8):
        ciphertext_block = ciphertext[block_start:block_start + 8]

        decrypted_block = decrypt_3des_block(ciphertext_block, key)

        plaintext_block = xor_bytes(decrypted_block, previous_block)

        padded_plaintext += plaintext_block

        previous_block = ciphertext_block

    plaintext = pkcs7_unpad(padded_plaintext, 8)

    return plaintext


# ============================================================
# Self Test
# ============================================================

def self_test():
    """
    Test custom 3DES CBC mode.
    """
    key = b"12345678ABCDEFGH87654321"
    iv = b"ABCDEFGH"

    plaintext = (
        b"This is a custom 3DES CBC mode implementation test "
        b"using multiple plaintext blocks."
    )

    ciphertext = encrypt_3des_cbc(plaintext, key, iv)

    recovered = decrypt_3des_cbc(ciphertext, key, iv)

    print("Custom 3DES CBC Test")
    print("--------------------")
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"Recovered:  {recovered}")

    if recovered == plaintext:
        print("PASS: Custom 3DES CBC works.")
    else:
        print("FAIL: Custom 3DES CBC failed.")


if __name__ == "__main__":
    self_test()