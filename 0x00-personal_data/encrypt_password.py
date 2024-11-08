#!/usr/bin/env python3
"""Module that handles protection of password PII data."""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes password with the bcrypt algorithm."""
    encoded_password = password.encode('utf-8')
    salt = bcrypt.gensalt(5)
    return bcrypt.hashpw(encoded_password, salt)


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Compares a password to a hashed password."""
    encoded_pwd = password.encode('utf-8')
    return bcrypt.checkpw(encoded_pwd, hashed_password)
