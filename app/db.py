from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import make_url
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


class Database:
    def __init__(self, url):
        parsed = make_url(url)
        if parsed.get_backend_name() != "sqlite":
            raise ValueError("This demo supports SQLite only")
        memory = not parsed.database or parsed.database == ":memory:"
        if not memory:
            Path(parsed.database).parent.mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(
            url, connect_args={"check_same_thread": False, "timeout": 30},
            **({"poolclass": StaticPool} if memory else {}),
        )

        @event.listens_for(self.engine, "connect")
        def configure(connection, _):
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA journal_mode=WAL")

        self.Session = sessionmaker(self.engine, expire_on_commit=False)
