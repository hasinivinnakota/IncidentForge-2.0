"""SQLite engine and SQLModel session lifecycle."""

from collections.abc import Generator
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

from .config import get_settings


def _ensure_sqlite_parent(database_url: str) -> None:
    if database_url.startswith("sqlite:///") and not database_url.startswith("sqlite:////"):
        database_path = Path(database_url.removeprefix("sqlite:///"))
        database_path.parent.mkdir(parents=True, exist_ok=True)


def create_database_engine(database_url: str | None = None):
    """Create an engine for the configured database URL."""
    url = database_url or get_settings().database_url
    _ensure_sqlite_parent(url)
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


engine = create_database_engine()


def init_db(database_engine=engine) -> None:
    """Create missing tables without altering existing data."""
    SQLModel.metadata.create_all(database_engine)


def get_session() -> Generator[Session, None, None]:
    """Yield a request-scoped database session."""
    with Session(engine) as session:
        yield session