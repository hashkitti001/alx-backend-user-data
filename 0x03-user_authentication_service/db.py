#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine, tuple_
from sqlalchemy.exc import InvalidRequestError, NoResultFound
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session

from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Creates a new user."""
        try:
            new_user = User(email=email, 
                            hashed_password=hashed_password)
            self.__session.add(new_user)
            self.__session.commit()
        except Exception:
            self.__session.rollback()
            new_user = None
        return new_user

    def find_user_by(self, **kwargs) -> User:
        """Returns a list of users filtered by a particular criteria."""
        fields, values = [], []
        for key, val in kwargs.items():
            if hasattr(User, key):
                fields.append(getattr(User, key))
                values.append(val)
            else:
                raise InvalidRequestError()
            result = self.__session.query(User).filter(
                tuple_(*fields)._in([tuple(values)])
            ).first()
            if result is None:
                raise NoResultFound()
            return result
    
    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates a user record with the aid of the find_user_by."""
        user = self.find_user_by(id=user_id)
        if user is None:
            return None
        update_src = {}
        for key, value in kwargs.items():
            if hasattr(User, key):
                update_src[getattr(User, key)] = value
            else:
                raise ValueError()
            self.__session.query(User).filter(
                User.id == user_id
                ).update(
                    update_src,
                    synchronize_session=False
                )

