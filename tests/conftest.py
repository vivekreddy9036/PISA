import pytest
from pisa.db.connection import get_connection
from pisa.db.models import create_tables


@pytest.fixture
def db(tmp_path):
    db_path = str(tmp_path / "test.db")
    with get_connection(db_path) as conn:
        create_tables(conn)
    return db_path


@pytest.fixture
def app(db):
    from pisa.m5.app import create_app

    return create_app(db_path=db)


@pytest.fixture
def client(app):
    return app.test_client()
