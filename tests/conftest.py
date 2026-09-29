from collections.abc import Generator

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine

from backend.app.database import get_session
from backend.app.main import app


@pytest.fixture
def test_engine(tmp_path):
    database_engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}")
    SQLModel.metadata.create_all(database_engine)
    return database_engine


@pytest.fixture
def db_session(test_engine) -> Generator[Session, None, None]:
    with Session(test_engine) as session:
        yield session


@pytest.fixture
def api_client(test_engine) -> Generator[TestClient, None, None]:
    def override_session():
        with Session(test_engine) as session:
            yield session

    app.dependency_overrides[get_session] = override_session
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()