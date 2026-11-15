"""Tests for the test-DB guard in conftest."""

import pytest

from tests.conftest import _assert_safe_test_db


class TestDbGuard:
    def test_scratch_allowed(self):
        _assert_safe_test_db("postgresql://u:p@localhost/scratch_foo")

    def test_test_allowed(self):
        _assert_safe_test_db("postgresql://u:p@localhost/test_bar")

    def test_production_rejected(self):
        with pytest.raises(RuntimeError, match="Refusing"):
            _assert_safe_test_db("postgresql://u:p@localhost/sentinelasm")

    def test_empty_rejected(self):
        with pytest.raises(RuntimeError, match="Refusing"):
            _assert_safe_test_db("postgresql://u:p@localhost/")
