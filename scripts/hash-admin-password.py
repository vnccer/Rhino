#!/usr/bin/env python3
import base64
import hashlib
import secrets
from getpass import getpass


def hash_password(password: str, iterations: int = 600_000) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    encoded_salt = base64.urlsafe_b64encode(salt).decode().rstrip("=")
    encoded_digest = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return f"pbkdf2_sha256${iterations}${encoded_salt}${encoded_digest}"


password = getpass("Administrator password: ")
confirmation = getpass("Confirm password: ")
if len(password) < 12:
    raise SystemExit("Password must contain at least 12 characters.")
if password != confirmation:
    raise SystemExit("Passwords do not match.")
print(hash_password(password))
