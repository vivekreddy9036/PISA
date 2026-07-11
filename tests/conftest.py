import sqlite3
import pytest
import config
from pisa.db.models import create_tables


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test.db")
    with sqlite3.connect(db_path) as conn:
        create_tables(conn)
    return db_path
