#!/usr/bin/env python3
""" Module of Auth routes."""
from flask import request
from typing import List, TypeVar

class Auth:
    """A class for auth routes."""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
         """Checks if a path requires authentication."""
         return False
    
    def authorization_header(self, request=None) -> str:
        """Gets the authorization header field from the request."""
        return None
    
    def current_user(self, request=None) -> TypeVar('User'): # type: ignore
        """Gets the current user."""
