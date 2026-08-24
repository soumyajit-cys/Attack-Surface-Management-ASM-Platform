import os

os.environ["JWT_SECRET"] = "test-secret-please-change"
os.environ["DATABASE_URL"] = (
    "postgresql://sentinel:sentinelpass@localhost:5432/sentinelasm_test"
)
os.environ["REDIS_URL"] = "redis://localhost:6379/15"

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

from config import settings
from models import Base
from utils.database import get_db
from utils.redis_client import get_redis
from workers.celery_app import celery


@pytest.fixture(scope="session", autouse=True)
def _setup_database():
    engine = create_engine(
        settings.database_url,
        poolclass=NullPool,
    )
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    engine.dispose()
    yield


@pytest.fixture(autouse=True)
def _clean_state(db):
    get_redis().flushdb()
    # Disable FK constraints, truncate, re-enable
    db.execute(text("SET session_replication_role = 'replica'"))
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(text(f"TRUNCATE TABLE {table.name} CASCADE"))
    db.execute(text("SET session_replication_role = 'origin'"))
    db.commit()
    yield
    get_redis().flushdb()
    db.execute(text("SET session_replication_role = 'replica'"))
    for table in reversed(Base.metadata.sorted_tables):
        db.execute(text(f"TRUNCATE TABLE {table.name} CASCADE"))
    db.execute(text("SET session_replication_role = 'origin'"))
    db.commit()


@pytest.fixture()
def db():
    engine = create_engine(settings.database_url, poolclass=NullPool)
    TestingSession = sessionmaker(bind=engine)
    session = TestingSession()
    yield session
    session.close()
    engine.dispose()


@pytest.fixture()
def client(db):
    celery.conf.task_always_eager = True

    def override_get_db():
        yield db

    from main import app

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()


@pytest.fixture()
def org_factory(db):
    def make(name, username, email, role="admin"):
        from models.organization import Organization
        from models.user import User
        from auth.security import hash_password

        org = Organization(name=name)
        db.add(org)
        db.flush()
        user = User(
            organization_id=org.id,
            username=username,
            email=email,
            password_hash=hash_password("password123"),
            role=role,
        )
        db.add(user)
        db.flush()
        return org, user

    return make


@pytest.fixture()
def auth_headers(client):
    def _headers(username, password="password123"):
        response = client.post(
            "/auth/login",
            json={"username": username, "password": password},
        )
        assert response.status_code == 200, response.text
        token = response.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}

    return _headers