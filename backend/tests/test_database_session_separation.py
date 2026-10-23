
from app.core import database


def test_runtime_session_factory_uses_runtime_engine():
    """Runtime sessions must use the least-privilege application engine."""
    assert database.async_session_factory.kw["bind"] is database.engine


def test_admin_session_factory_uses_admin_engine():
    """Administrative sessions must use the separate admin engine."""
    assert database.admin_session_factory.kw["bind"] is database.admin_engine


def test_runtime_and_admin_engines_are_separate():
    """Runtime requests must not share the administrative engine."""
    assert database.engine is not database.admin_engine
    assert (
        database.async_session_factory.kw["bind"]
        is not database.admin_session_factory.kw["bind"]
    )
