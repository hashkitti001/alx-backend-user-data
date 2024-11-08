#!/usr/bin/env python3
"""Module that obfuscates a log message."""
from typing import List
import logging
import re
import os
import mysql
import mysql.connector

PII_FIELDS = ('name', 'email', 'password', 'ssn', 'phone')


def filter_datum(fields: List[str],
                 redaction: str,
                 message: str,
                 seperator: str) -> str:
    """Returns the log message with obfuscated PII fields."""
    pattern = r"(" + "|".join(fields) + r")=([^" + seperator + r"]+)"
    return re.sub(pattern, r"\1=" + redaction, message)


def get_logger() -> logging.Logger:
    """Defines a new logger for user data."""
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger


def get_db():
    """Connects to a MySQL database."""
    DB_USERNAME = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    DB_PASSWORD = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    DB_HOST = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    DB_NAME = os.getenv('PERSONAL_DATA_DB_NAME', '')

    try:
        cnx = mysql.connector.connect(
            user=DB_USERNAME,
            password=DB_PASSWORD,
            database=DB_NAME,
            host=DB_HOST,
            port=3306
        )
        return cnx
    except Exception as e:
        logging.warning(e)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')
    SEPARATOR = ";"

    def __init__(self, fields):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filters values in incoming log records using filter_datum."""
        msg = super(RedactingFormatter, self).format(record)
        txt = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return txt


def main() -> None:
    """Logs info about user records in a MySQL table."""
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    cols = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cur:
        cur.execute(query)
        rows = cur.fetchall()
        for row in rows:
            records = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(cols, row),
            )
            msg = '{};'.format('; '.join(list(records)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


if __name__ == "__main__":
    main()
