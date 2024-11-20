#!/usr/bin/env python3
"""Module containing Flask app for defining endpoints."""
from flask import Flask, jsonify, request
from auth import Auth

AUTH = Auth()
app = Flask(__name__)


@app.route('/', methods=["GET"], strict_slashes=False)
def welcome() -> str:
    """GET /
    Return:
       - The home endpoint's payload.
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def register_user() -> str:
    """POST /users
    Return: 
        - The account creation payload.
    """
    email, password = request.form.get("email"), request.form.get("password")
    try:
        AUTH.register_user(email=email, password=password)
        return jsonify({"email": email, "password": password})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
