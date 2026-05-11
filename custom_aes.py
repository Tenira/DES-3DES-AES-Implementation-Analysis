# custom_aes.py
#
# Custom AES-128 implementation.
# Phase 1: single-block AES encryption/decryption.

# AES uses 16-byte blocks and a 16-byte key for AES-128.

S_BOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

INV_S_BOX = [0] * 256
for i, value in enumerate(S_BOX):
    INV_S_BOX[value] = i

RCON = [
    0x00,
    0x01,0x02,0x04,0x08,0x10,
    0x20,0x40,0x80,0x1B,0x36
]


def bytes_to_matrix(block):
    return [list(block[i:i + 4]) for i in range(0, 16, 4)]


def matrix_to_bytes(matrix):
    return bytes(sum(matrix, []))


def xor_words(word_a, word_b):
    return [a ^ b for a, b in zip(word_a, word_b)]


def sub_word(word):
    return [S_BOX[b] for b in word]


def rot_word(word):
    return word[1:] + word[:1]


def key_expansion(key):
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes.")

    key_columns = bytes_to_matrix(key)
    i = 4

    while len(key_columns) < 44:
        temp = key_columns[-1].copy()

        if i % 4 == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= RCON[i // 4]

        new_word = xor_words(key_columns[-4], temp)
        key_columns.append(new_word)
        i += 1

    round_keys = [
        key_columns[4 * i:4 * (i + 1)]
        for i in range(11)
    ]

    return round_keys


def add_round_key(state, round_key):
    for column in range(4):
        for row in range(4):
            state[column][row] ^= round_key[column][row]


def sub_bytes(state):
    for column in range(4):
        for row in range(4):
            state[column][row] = S_BOX[state[column][row]]


def inv_sub_bytes(state):
    for column in range(4):
        for row in range(4):
            state[column][row] = INV_S_BOX[state[column][row]]


def shift_rows(state):
    # Convert column-major to row shifts.
    for row in range(1, 4):
        row_values = [state[column][row] for column in range(4)]
        row_values = row_values[row:] + row_values[:row]

        for column in range(4):
            state[column][row] = row_values[column]


def inv_shift_rows(state):
    for row in range(1, 4):
        row_values = [state[column][row] for column in range(4)]
        row_values = row_values[-row:] + row_values[:-row]

        for column in range(4):
            state[column][row] = row_values[column]


def galois_multiply(a, b):
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        high_bit_set = a & 0x80
        a = (a << 1) & 0xFF

        if high_bit_set:
            a ^= 0x1B

        b >>= 1

    return result


def mix_single_column(column):
    a0, a1, a2, a3 = column

    column[0] = (
        galois_multiply(a0, 2) ^
        galois_multiply(a1, 3) ^
        a2 ^
        a3
    )

    column[1] = (
        a0 ^
        galois_multiply(a1, 2) ^
        galois_multiply(a2, 3) ^
        a3
    )

    column[2] = (
        a0 ^
        a1 ^
        galois_multiply(a2, 2) ^
        galois_multiply(a3, 3)
    )

    column[3] = (
        galois_multiply(a0, 3) ^
        a1 ^
        a2 ^
        galois_multiply(a3, 2)
    )


def mix_columns(state):
    for column in state:
        mix_single_column(column)


def inv_mix_single_column(column):
    a0, a1, a2, a3 = column

    column[0] = (
        galois_multiply(a0, 14) ^
        galois_multiply(a1, 11) ^
        galois_multiply(a2, 13) ^
        galois_multiply(a3, 9)
    )

    column[1] = (
        galois_multiply(a0, 9) ^
        galois_multiply(a1, 14) ^
        galois_multiply(a2, 11) ^
        galois_multiply(a3, 13)
    )

    column[2] = (
        galois_multiply(a0, 13) ^
        galois_multiply(a1, 9) ^
        galois_multiply(a2, 14) ^
        galois_multiply(a3, 11)
    )

    column[3] = (
        galois_multiply(a0, 11) ^
        galois_multiply(a1, 13) ^
        galois_multiply(a2, 9) ^
        galois_multiply(a3, 14)
    )


def inv_mix_columns(state):
    for column in state:
        inv_mix_single_column(column)


def encrypt_block(block, key):
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes.")

    round_keys = key_expansion(key)
    state = bytes_to_matrix(block)

    add_round_key(state, round_keys[0])

    for round_number in range(1, 10):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_number])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[10])

    return matrix_to_bytes(state)


def decrypt_block(block, key):
    if len(block) != 16:
        raise ValueError("AES block must be exactly 16 bytes.")

    round_keys = key_expansion(key)
    state = bytes_to_matrix(block)

    add_round_key(state, round_keys[10])
    inv_shift_rows(state)
    inv_sub_bytes(state)

    for round_number in range(9, 0, -1):
        add_round_key(state, round_keys[round_number])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)

    add_round_key(state, round_keys[0])

    return matrix_to_bytes(state)

# ============================================================
# AES CBC Mode + PKCS#7 Padding
# ============================================================

def pkcs7_pad(data, block_size=16):
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding


def pkcs7_unpad(padded_data, block_size=16):
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
    return bytes(a ^ b for a, b in zip(bytes_a, bytes_b))


def encrypt_cbc(plaintext, key, iv):
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes.")

    if len(iv) != 16:
        raise ValueError("AES IV must be exactly 16 bytes.")

    padded_plaintext = pkcs7_pad(plaintext, 16)

    ciphertext = b""
    previous_block = iv

    for block_start in range(0, len(padded_plaintext), 16):
        plaintext_block = padded_plaintext[block_start:block_start + 16]
        mixed_block = xor_bytes(plaintext_block, previous_block)
        encrypted_block = encrypt_block(mixed_block, key)

        ciphertext += encrypted_block
        previous_block = encrypted_block

    return ciphertext


def decrypt_cbc(ciphertext, key, iv):
    if len(key) != 16:
        raise ValueError("AES-128 key must be exactly 16 bytes.")

    if len(iv) != 16:
        raise ValueError("AES IV must be exactly 16 bytes.")

    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        raise ValueError("Ciphertext must be a non-empty multiple of 16 bytes.")

    padded_plaintext = b""
    previous_block = iv

    for block_start in range(0, len(ciphertext), 16):
        ciphertext_block = ciphertext[block_start:block_start + 16]

        decrypted_block = decrypt_block(ciphertext_block, key)
        plaintext_block = xor_bytes(decrypted_block, previous_block)

        padded_plaintext += plaintext_block
        previous_block = ciphertext_block

    return pkcs7_unpad(padded_plaintext, 16)

def self_test():
    key = b"1234567890ABCDEF"
    plaintext_block = b"ABCDEFGHIJKLMNOP"

    ciphertext_block = encrypt_block(plaintext_block, key)
    recovered_block = decrypt_block(ciphertext_block, key)

    print("Custom AES-128 Phase 1 Block Test")
    print("---------------------------------")
    print(f"Plaintext:  {plaintext_block}")
    print(f"Ciphertext: {ciphertext_block.hex()}")
    print(f"Recovered:  {recovered_block}")

    if recovered_block == plaintext_block:
        print("PASS: AES block encryption/decryption works.")
    else:
        print("FAIL: AES block encryption/decryption failed.")


if __name__ == "__main__":
    self_test()