"""Tests for the test-DB guard in conftest."""

import pytest

from tests.db_guard import assert_safe_test_db, assert_safe_test_redis


class TestDbGuard:
    def test_scratch_allowed(self):
        assert_safe_test_db("postgresql://u:p@localhost/scratch_foo")

    def test_test_allowed(self):
        assert_safe_test_db("postgresql://u:p@localhost/test_bar")

    def test_production_rejected(self):
        with pytest.raises(RuntimeError, match="Refusing"):
            assert_safe_test_db("postgresql://u:p@localhost/sentinelasm")

    def test_empty_rejected(self):
        with pytest.raises(RuntimeError, match="Refusing"):
            assert_safe_test_db("postgresql://u:p@localhost/")

    def test_redis_local_allowed(self):
        assert_safe_test_redis("redis://localhost:6379/15")

    def test_redis_remote_rejected(self):
        with pytest.raises(RuntimeError, match="Refusing"):
            assert_safe_test_redis("redis://remote-host:6379/0")
