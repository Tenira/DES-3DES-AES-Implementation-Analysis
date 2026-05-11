# data_generator.py

import os
import json
import random
import string
import uuid
from datetime import datetime, timedelta


def generate_repeated_plaintext(size_bytes):
    return b"A" * size_bytes


def generate_random_plaintext(size_bytes):
    return os.urandom(size_bytes)


def random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choices(characters, k=length))


def generate_application_plaintext(size_bytes):
    """
    Generate realistic application-style JSON plaintext.

    This simulates data from web applications, user sessions,
    transactions, logs, and messages.
    """

    records = []

    while len(json.dumps(records).encode()) < size_bytes:
        record = {
            "record_id": str(uuid.uuid4()),
            "timestamp": (
                datetime.now() -
                timedelta(seconds=random.randint(0, 1_000_000))
            ).isoformat(),
            "user": {
                "user_id": random.randint(100000, 999999),
                "username": random_string(10),
                "email": f"{random_string(8)}@example.com",
                "role": random.choice(["student", "admin", "engineer", "guest"]),
                "permissions": random.sample(
                    ["read", "write", "delete", "execute", "share"],
                    k=random.randint(1, 3)
                )
            },
            "session": {
                "session_id": random_string(32),
                "ip_address": (
                    f"{random.randint(1, 255)}."
                    f"{random.randint(0, 255)}."
                    f"{random.randint(0, 255)}."
                    f"{random.randint(1, 255)}"
                ),
                "device": random.choice(["laptop", "phone", "tablet", "desktop"]),
                "browser": random.choice(["Firefox", "Chrome", "Safari", "Edge"])
            },
            "transaction": {
                "amount": round(random.uniform(1.00, 5000.00), 2),
                "currency": "USD",
                "status": random.choice(["approved", "pending", "failed"]),
                "merchant_id": random.randint(1000, 9999)
            },
            "message": random_string(random.randint(80, 200))
        }

        records.append(record)

    json_text = json.dumps(records, indent=2)

    return json_text.encode()[:size_bytes]