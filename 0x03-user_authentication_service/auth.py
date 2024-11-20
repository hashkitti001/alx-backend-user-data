#!/usr/bin/env python3
"""Module for doing auth stuff."""
import bcrypt


def _hash_password(password: str) -> bytes:
    """Hashes a plain text password with the Bluefish algo."""
    salt = bcrypt.gensalt()
    hashed_pwd = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_pwd
de

