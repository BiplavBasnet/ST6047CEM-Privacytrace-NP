from collections.abc import Generator

from sqlalchemy.orm import Session

from app.database import get_db as _get_db

get_db = _get_db


def get_db_session() -> Generator[Session, None, None]:
    """FastAPI dependency for database sessions."""
    yield from get_db()
