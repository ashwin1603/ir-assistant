import os

os.environ["RATE_LIMIT_ENABLED"] = "false"
os.environ["COLLECTOR_API_KEY"] = "test-collector-key"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.auth.security import hash_password
from app.db import Base, get_db
from app.main import app
from app.models import User

engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestSessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base.metadata.create_all(bind=engine)


def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture(autouse=True)
def reset_tables():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)


@pytest.fixture()
def db_session():
    db = TestSessionLocal()
    yield db
    db.close()


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def seed_users(db_session):
    db_session.add_all(
        [
            User(username="test_admin", password_hash=hash_password("TestAdminPass123!"), role="admin"),
            User(username="test_analyst", password_hash=hash_password("TestAnalystPass123!"), role="analyst"),
            User(username="test_viewer", password_hash=hash_password("TestViewerPass123!"), role="viewer"),
        ]
    )
    db_session.commit()
