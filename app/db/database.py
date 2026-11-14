from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker
from app.core.config import settings


class Base(DeclarativeBase):
    pass


engine = create_engine(settings.database_url, pool_pre_ping=True, hide_parameters=True,
                       connect_args={"check_same_thread": False, "timeout": 30}
                       if settings.database_url.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def init_db():
    from app.db import models  # noqa: F401
    from app.db.migrations import migrate
    with engine.begin() as connection:
        migrate(connection, Base.metadata)
