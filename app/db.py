import psycopg

from app.config import settings


def get_conn() -> psycopg.Connection:
    # A short connect timeout: when the database is down the request should fail fast and
    # be logged, not hang until nginx gives up.
    return psycopg.connect(settings.database_url, connect_timeout=5)
