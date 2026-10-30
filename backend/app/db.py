from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

import mysql.connector
from mysql.connector.pooling import MySQLConnectionPool

from .config import settings


pool = MySQLConnectionPool(
    pool_name="rca_dashboard_pool",
    pool_size=5,
    pool_reset_session=True,
    host=settings.db_host,
    port=settings.db_port,
    user=settings.db_user,
    password=settings.db_password,
    database=settings.db_name,
    connection_timeout=5,
    charset="utf8mb4",
    collation="utf8mb4_unicode_ci",
    use_unicode=True,
    use_pure=True,
)


@contextmanager
def database_cursor(*, commit: bool = False) -> Iterator[tuple[object, object]]:
    connection = pool.get_connection()
    cursor = connection.cursor(dictionary=True)
    try:
        yield connection, cursor
        if commit:
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        cursor.close()
        connection.close()
