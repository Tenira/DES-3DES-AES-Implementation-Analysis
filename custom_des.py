# custom_des.py
#
# Phase 1:
# Custom DES implementation for a single 64-bit block.
#
# This file implements:
# - DES initial permutation
# - final permutation
# - key schedule
# - Feistel round function
# - 16-round DES encryption
# - 16-round DES decryption

# ============================================================
# DES Permutation Tables
# ============================================================

INITIAL_PERMUTATION = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

FINAL_PERMUTATION = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

EXPANSION_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

PERMUTATION_FUNCTION = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
]

PERMUTED_CHOICE_1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
]

PERMUTED_CHOICE_2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
]

SHIFT_SCHEDULE = [
    1, 1, 2, 2,
    2, 2, 2, 2,
    1, 2, 2, 2,
    2, 2, 2, 1
]

# ============================================================
# DES S-Boxes
# ============================================================

S_BOXES = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ]
]


# ============================================================
# Helper Functions
# ============================================================

def bytes_to_bits(data):
    """
    Convert bytes into a list of bits.
    Each bit is represented as an integer 0 or 1.
    """
    bits = []

    for byte in data:
        for bit_position in range(7, -1, -1):
            bits.append((byte >> bit_position) & 1)

    return bits


def bits_to_bytes(bits):
    """
    Convert a list of bits into bytes.
    """
    output = bytearray()

    for i in range(0, len(bits), 8):
        byte_bits = bits[i:i + 8]

        value = 0
        for bit in byte_bits:
            value = (value << 1) | bit

        output.append(value)

    return bytes(output)


def permute(bits, table):
    """
    Apply a DES permutation table.

    DES tables are 1-indexed, so each table entry is reduced by 1
    to index into the Python list.
    """
    return [bits[position - 1] for position in table]


def left_rotate(bits, shift_amount):
    """
    Circular left shift.
    """
    return bits[shift_amount:] + bits[:shift_amount]


def xor_bits(bits_a, bits_b):
    """
    XOR two equal-length bit lists.
    """
    return [a ^ b for a, b in zip(bits_a, bits_b)]


# ============================================================
# Key Schedule
# ============================================================

def generate_round_keys(key):
    """
    Generate the 16 DES round keys.

    Input:
        key: 8-byte DES key

    Output:
        list of 16 round keys, each 48 bits
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    key_bits = bytes_to_bits(key)

    # PC-1 removes parity bits and compresses 64-bit key to 56 bits.
    permuted_key = permute(key_bits, PERMUTED_CHOICE_1)

    left_half = permuted_key[:28]
    right_half = permuted_key[28:]

    round_keys = []

    for shift_amount in SHIFT_SCHEDULE:
        left_half = left_rotate(left_half, shift_amount)
        right_half = left_rotate(right_half, shift_amount)

        combined_key = left_half + right_half

        # PC-2 compresses 56-bit shifted key to 48-bit round key.
        round_key = permute(combined_key, PERMUTED_CHOICE_2)

        round_keys.append(round_key)

    return round_keys


# ============================================================
# Feistel Round Function
# ============================================================

def s_box_substitution(bits_48):
    """
    Apply the 8 DES S-boxes.

    Input:
        48-bit list

    Output:
        32-bit list
    """
    output_bits = []

    for box_index in range(8):
        chunk = bits_48[box_index * 6:(box_index + 1) * 6]

        row = (chunk[0] << 1) | chunk[5]
        column = (
            (chunk[1] << 3) |
            (chunk[2] << 2) |
            (chunk[3] << 1) |
            chunk[4]
        )

        s_box_value = S_BOXES[box_index][row][column]

        for bit_position in range(3, -1, -1):
            output_bits.append((s_box_value >> bit_position) & 1)

    return output_bits


def feistel(right_half, round_key):
    """
    DES Feistel function.

    Steps:
    1. Expand 32-bit right half to 48 bits
    2. XOR with round key
    3. Apply S-box substitution to compress back to 32 bits
    4. Apply permutation function P
    """
    expanded_right = permute(right_half, EXPANSION_TABLE)

    mixed_bits = xor_bits(expanded_right, round_key)

    substituted_bits = s_box_substitution(mixed_bits)

    permuted_bits = permute(substituted_bits, PERMUTATION_FUNCTION)

    return permuted_bits


# ============================================================
# DES Block Encryption and Decryption
# ============================================================

def encrypt_block(block, key):
    """
    Encrypt one 8-byte block using DES.
    """
    if len(block) != 8:
        raise ValueError("DES block must be exactly 8 bytes.")

    round_keys = generate_round_keys(key)

    block_bits = bytes_to_bits(block)

    permuted_block = permute(block_bits, INITIAL_PERMUTATION)

    left_half = permuted_block[:32]
    right_half = permuted_block[32:]

    for round_number in range(16):
        previous_left = left_half
        previous_right = right_half

        left_half = previous_right
        right_half = xor_bits(previous_left, feistel(previous_right, round_keys[round_number]))

    # DES swaps the halves after the 16th round before final permutation.
    combined_block = right_half + left_half

    final_bits = permute(combined_block, FINAL_PERMUTATION)

    return bits_to_bytes(final_bits)


def decrypt_block(block, key):
    """
    Decrypt one 8-byte block using DES.
    """
    if len(block) != 8:
        raise ValueError("DES block must be exactly 8 bytes.")

    round_keys = generate_round_keys(key)
    round_keys.reverse()

    block_bits = bytes_to_bits(block)

    permuted_block = permute(block_bits, INITIAL_PERMUTATION)

    left_half = permuted_block[:32]
    right_half = permuted_block[32:]

    for round_number in range(16):
        previous_left = left_half
        previous_right = right_half

        left_half = previous_right
        right_half = xor_bits(previous_left, feistel(previous_right, round_keys[round_number]))

    combined_block = right_half + left_half

    final_bits = permute(combined_block, FINAL_PERMUTATION)

    return bits_to_bytes(final_bits)

# ============================================================
# Phase 2: Padding and CBC Mode
# ============================================================

def pkcs7_pad(data, block_size=8):
    """
    Apply PKCS#7 padding.
    DES uses an 8-byte block size.
    """
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding


def pkcs7_unpad(padded_data, block_size=8):
    """
    Remove PKCS#7 padding.
    """
    if len(padded_data) == 0 or len(padded_data) % block_size != 0:
        raise ValueError("Invalid padded data length.")

    padding_length = padded_data[-1]

    if padding_length < 1 or padding_length > block_size:
        raise ValueError("Invalid padding length.")

    padding = padded_data[-padding_length:]

    if padding != bytes([padding_length]) * padding_length:
        raise ValueError("Invalid PKCS#7 padding.")

    return padded_data[:-padding_length]


def xor_bytes(bytes_a, bytes_b):
    """
    XOR two equal-length byte strings.
    """
    return bytes(a ^ b for a, b in zip(bytes_a, bytes_b))


def encrypt_cbc(plaintext, key, iv):
    """
    Encrypt a full plaintext message using custom DES in CBC mode.

    CBC encryption:
        C_i = DES_encrypt(P_i XOR C_{i-1})
    where C_0 is the IV.
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    if len(iv) != 8:
        raise ValueError("DES IV must be exactly 8 bytes.")

    padded_plaintext = pkcs7_pad(plaintext, 8)

    ciphertext = b""
    previous_block = iv

    for block_start in range(0, len(padded_plaintext), 8):
        plaintext_block = padded_plaintext[block_start:block_start + 8]

        mixed_block = xor_bytes(plaintext_block, previous_block)

        encrypted_block = encrypt_block(mixed_block, key)

        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext


def decrypt_cbc(ciphertext, key, iv):
    """
    Decrypt a full ciphertext message using custom DES in CBC mode.

    CBC decryption:
        P_i = DES_decrypt(C_i) XOR C_{i-1}
    where C_0 is the IV.
    """
    if len(key) != 8:
        raise ValueError("DES key must be exactly 8 bytes.")

    if len(iv) != 8:
        raise ValueError("DES IV must be exactly 8 bytes.")

    if len(ciphertext) == 0 or len(ciphertext) % 8 != 0:
        raise ValueError("Ciphertext must be a non-empty multiple of 8 bytes.")

    padded_plaintext = b""
    previous_block = iv

    for block_start in range(0, len(ciphertext), 8):
        ciphertext_block = ciphertext[block_start:block_start + 8]

        decrypted_block = decrypt_block(ciphertext_block, key)

        plaintext_block = xor_bytes(decrypted_block, previous_block)

        padded_plaintext += plaintext_block
        previous_block = ciphertext_block

    plaintext = pkcs7_unpad(padded_plaintext, 8)

    return plaintext

def self_test():
    """
    Run custom DES block and CBC tests.
    """
    key = b"12345678"
    iv = b"ABCDEFGH"

    plaintext_block = b"TESTDATA"
    ciphertext_block = encrypt_block(plaintext_block, key)
    recovered_block = decrypt_block(ciphertext_block, key)

    print("Custom DES Phase 1 Block Test")
    print("-----------------------------")
    print(f"Plaintext Block:  {plaintext_block}")
    print(f"Ciphertext Block: {ciphertext_block.hex()}")
    print(f"Recovered Block:  {recovered_block}")

    if recovered_block == plaintext_block:
        print("PASS: Block encryption/decryption works.")
    else:
        print("FAIL: Block encryption/decryption failed.")

    print()

    plaintext_message = (
        b"This is a longer message that requires multiple DES blocks "
        b"and PKCS7 padding."
    )

    ciphertext_message = encrypt_cbc(plaintext_message, key, iv)
    recovered_message = decrypt_cbc(ciphertext_message, key, iv)

    print("Custom DES Phase 2 CBC Test")
    print("---------------------------")
    print(f"Plaintext Message:  {plaintext_message}")
    print(f"Ciphertext Message: {ciphertext_message.hex()}")
    print(f"Recovered Message:  {recovered_message}")

    if recovered_message == plaintext_message:
        print("PASS: CBC encryption/decryption works.")
    else:
        print("FAIL: CBC encryption/decryption failed.")

if __name__ == "__main__":
    self_test()