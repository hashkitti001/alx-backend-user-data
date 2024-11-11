#!/usr/bin/env python3
""" Module of Auth routes."""
import re
from flask import request
from typing import List, TypeVar


class Auth:
    """A class for auth routes."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Checks if a path requires authentication."""

        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                regex = ''
                if excluded_paths[-1] == '*':
                    regex = '{}.*'.format(excluded_paths[0:-1])
                elif exclusion_path[-1] == '/':
                    regex = '{}/*'.format(exclusion_path[0:-1])
                else:
                    regex = '{}/*'.format(exclusion_path)
                if re.match(regex, path):
                    return False
            return True

    def authorization_header(self, request=None) -> str:
        """Gets the authorization header field from the request."""
        if request is None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):  # type: ignore
        """Gets the current user."""