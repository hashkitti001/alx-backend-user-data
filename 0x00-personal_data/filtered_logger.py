#!/usr/bin/env python3
"""Module that obfuscates a log message."""
from typing import List
import logging
import re

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

# if __name__ == "__main__":
#     main()